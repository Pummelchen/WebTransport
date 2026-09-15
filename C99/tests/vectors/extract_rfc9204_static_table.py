#!/usr/bin/env python3
"""Extract RFC 9204 appendix A's QPACK static table.

The static table is 99 name/value pairs that every QPACK implementation must
agree on byte for byte: an encoder that indexes entry 17 as something else
produces a header section its peer decodes into different field lines, and
nothing in the exchange would say so. The table is therefore read from the RFC's
own ASCII table rather than typed into C, and the extraction is checked before
anything is written:

  - the indices are 0..98 with no gap and no repeat, so a row read twice or a
    mis-parsed index stops generation;
  - a row PRINTED OVER SEVERAL LINES is joined rather than dropped: appendix A
    wraps a long cell and warns that "any line breaks that appear within field
    names or values are due to formatting", so a continuation line belongs to the
    row above it and is never a row of its own;
  - every name is non-empty, has no whitespace around it and no '|' in it, which
    is what a row split in the wrong place would produce;
  - a name that starts with ':' is a pseudo-header, which is a valid name and not a
    row that was split in the wrong place;
  - the value may be empty (the table has many) but may not be only whitespace.

    python3 tests/vectors/extract_rfc9204_static_table.py [rfc9204.txt] [--check]

With no arguments it looks for `/tmp/rfc9204.txt` and writes
`src/http3/qpack_static_table.h`. With `--check` it re-extracts and compares
against the committed header, which is how the committed table stays the RFC's.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# The table is implementation data, not a test fixture: the codec reads it, so it
# is generated into the source tree, where `--check` keeps it the RFC's.
HEADER = HERE.parent.parent / "src" / "http3" / "qpack_static_table.h"

TABLE_SIZE = 99

# One PHYSICAL line of appendix A's ASCII table: | index | name | value |. Only the first line of a row carries
# the index: the RFC wraps a long cell and leaves the index and the other cell blank on the continuation, so
# `\d*` rather than `\d+` is what lets a wrapped row be recognised instead of dropped.
ROW = re.compile(r"^\s*\|\s*(\d*)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|\s*$")


def join_wrapped(previous: str, fragment: str) -> str:
    """Append one continuation of a wrapped cell to the cell it continues.

    The break is the text renderer's, not the value's. It happens after a '-' or a '/' with nothing inserted
    (`application/dns-` then `message`), and at a space, which the break consumes and the join therefore has to
    put back (`text/html;` then `charset=utf-8` is `text/html; charset=utf-8`). So a fragment that ends in a
    delimiter continues with no separator and anything else continues with the space the break stood for.
    """
    if previous.endswith(("-", "/")):
        return previous + fragment
    return previous + " " + fragment


def extract(text: str) -> list[tuple[str, str]]:
    # The headings are matched as whole lines: the table of contents prints them
    # too, and a substring search finds that copy first and reads an empty section.
    start_match = re.search(r"^Appendix A\.  Static Table$", text, re.MULTILINE)
    if start_match is None:
        raise ValueError("the RFC text has no Appendix A heading")
    end_match = re.search(r"^Appendix B\.", text[start_match.end():], re.MULTILINE)
    if end_match is None:
        raise ValueError("the RFC text has no Appendix B heading after Appendix A")
    start = start_match.end()
    end = start + end_match.start()
    rows: list[tuple[int, str, str]] = []
    for line in text[start:end].splitlines():
        match = ROW.match(line)
        if match is None:
            continue
        index_text = match.group(1)
        name = match.group(2)
        value = match.group(3)
        if not index_text:
            # A continuation line, which belongs to the row above it. It repeats whichever cell the RFC
            # wrapped; a line that continues neither cell is not something to skip silently.
            if not rows:
                raise ValueError("the table begins with a continuation line")
            if not name and not value:
                raise ValueError("a continuation line continues neither the name nor the value")
            if name:
                rows[-1] = (rows[-1][0], join_wrapped(rows[-1][1], name), rows[-1][2])
            if value:
                rows[-1] = (rows[-1][0], rows[-1][1], join_wrapped(rows[-1][2], value))
            continue
        index = int(index_text)
        if index == 0 and not name:
            continue  # the column headings are not a row
        rows.append((index, name, value))

    if len(rows) != TABLE_SIZE:
        raise ValueError(f"expected {TABLE_SIZE} rows, read {len(rows)}")

    entries: list[tuple[str, str]] = []
    for position, (index, name, value) in enumerate(rows):
        if index != position:
            raise ValueError(f"row {position} carries index {index}: the table has a gap or a repeat")
        if not name:
            raise ValueError(f"entry {index} has no name")
        if name != name.strip() or "|" in name or " " in name:
            raise ValueError(f"entry {index}'s name is malformed: {name!r}")
        if value != value.strip() or "|" in value:
            raise ValueError(f"entry {index}'s value is malformed: {value!r}")
        entries.append((name, value))
    return entries


def c_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render(entries: list[tuple[str, str]]) -> str:
    lines = []
    for name, value in entries:
        lines.append(f"    {{{c_string(name)}, {c_string(value)}}},")
    body = "\n".join(lines)
    return f"""/* Generated by tests/vectors/extract_rfc9204_static_table.py -- do not edit.
 *
 * RFC 9204 appendix A's QPACK static table: 99 name/value pairs every
 * implementation must agree on byte for byte, since an encoder that indexes an
 * entry as one field and a decoder that reads it as another produce two different
 * header sections with nothing in the exchange to say so.
 *
 * THE TABLE IS THE RFC'S, EXTRACTED, NOT TRANSCRIBED. The script reads the
 * appendix's own ASCII table and refuses to write it unless the indices are 0..98
 * with no gap or repeat, every name is well formed, and the pseudo-headers are
 * where the table keeps them. `--check` re-extracts and compares against this
 * file.
 */

#ifndef WT_RFC9204_STATIC_TABLE_H
#define WT_RFC9204_STATIC_TABLE_H

#include <stddef.h>

/* The number of entries, which RFC 9204 section 3.1 fixes at 99. */
#define WT_RFC9204_STATIC_TABLE_SIZE {len(entries)}U

typedef struct wt_rfc9204_static_entry {{
  const char *name;
  const char *value;
}} wt_rfc9204_static_entry_t;

/* Indexed by the table's own index, so entry 0 is the first row. */
static const wt_rfc9204_static_entry_t WT_RFC9204_STATIC_TABLE[WT_RFC9204_STATIC_TABLE_SIZE] = {{
{body}
}};

#endif /* WT_RFC9204_STATIC_TABLE_H */
"""


def main(argv) -> int:
    check = "--check" in argv
    args = [a for a in argv[1:] if not a.startswith("--")]
    source = Path(args[0]) if args else Path("/tmp/rfc9204.txt")
    if not source.exists():
        print(f"rfc9204 text not found at {source}", file=sys.stderr)
        return 2
    entries = extract(source.read_text(encoding="utf-8"))
    rendered = render(entries)
    if check:
        if not HEADER.exists():
            print("no committed header to check", file=sys.stderr)
            return 1
        if HEADER.read_text(encoding="utf-8") != rendered:
            print("the committed static table is not the RFC's", file=sys.stderr)
            return 1
        print("rfc9204 static table: committed entries match the RFC")
        return 0
    HEADER.write_text(rendered, encoding="utf-8")
    print(f"rfc9204 static table: wrote {len(entries)} entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
