#!/usr/bin/env python3
"""Extract RFC 7541 appendix B's Huffman code, which QPACK reuses (RFC 9204 section 4.1.2).

The code is 257 entries -- one per octet plus EOS -- and it is shared between two
protocols that must agree bit for bit, so it is read from the RFC rather than typed
into C. Nothing is written until the extraction has been checked against
properties the table has to have for a decoder to work at all:

  - 257 rows, symbols 0..255 in order and EOS last;
  - each row's stated length matches its bit string, and its hexadecimal code
    matches the bit string read as a number;
  - the code is prefix-free: no code is a prefix of another;
  - EOS is thirty one-bits, which is what RFC 7541 section 5.2 makes padding out
    of;
  - the code is CANONICAL in the sense the RFC's own note describes, so the
    first-code/first-symbol index per length (which is what a fast decoder uses)
    can be derived and checked against every entry.

It also extracts appendix C.4.1's worked example -- the Huffman-coded
`:authority: www.example.com` from a real header block -- so the decoder has one
vector that did not come from this implementation.

    python3 tests/vectors/extract_rfc7541_huffman.py [rfc7541.txt] [--check]

With no arguments it looks for `/tmp/rfc7541.txt` and writes
`src/http3/qpack_huffman_table.h`. With `--check` it re-extracts and compares
against the committed header.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HEADER = HERE.parent.parent / "src" / "http3" / "qpack_huffman_table.h"
# The RFC's worked example is a TEST vector, so it is generated beside the other
# vectors rather than into the source tree: the table is implementation data and
# the example is evidence.
VECTORS = HERE / "rfc7541_huffman_vectors.h"

SYMBOLS = 257
EOS = 256
MAX_BITS = 30

# A row is an optional ASCII representation ("' '", "'|'" or "EOS"), the symbol in
# parentheses, the code as a bit string, the same code as hex, and the length in
# brackets. The ASCII column is matched loosely: it contains quotes, an escaped
# quote and -- for symbol 124 -- a pipe, so any tighter pattern loses a row.
ROW = re.compile(r"^\s*(.*?)\s*\(\s*(\d+)\)\s+\|([01|]+?)\s+([0-9a-fA-F]+)\s+\[\s*(\d+)\]\s*$")
# One or more hex groups, including a lone byte: the dump wraps, so the last
# line of a block is often a single group.
HEX_DUMP = re.compile(r"^\s*([0-9a-fA-F]{2,4}(?:\s+[0-9a-fA-F]{2,4})*)\s+\|")


def section(text: str, start_pattern: str, stop_pattern: str) -> str:
    start = re.search(start_pattern, text, re.MULTILINE)
    if start is None:
        raise ValueError(f"no heading matching {start_pattern!r}")
    stop = re.search(stop_pattern, text[start.end() :], re.MULTILINE)
    if stop is None:
        raise ValueError(f"no heading matching {stop_pattern!r} after {start_pattern!r}")
    return text[start.end() : start.end() + stop.start()]


def extract_table(text: str) -> list[tuple[int, int, int]]:
    body = section(text, r"^Appendix B\.  Huffman Code$", r"^Appendix C\.")
    rows: list[tuple[int, int, int]] = []
    for line in body.splitlines():
        match = ROW.match(line)
        if match is None:
            continue
        symbol = int(match.group(2))
        bits_text = match.group(3).replace("|", "")
        code = int(match.group(4), 16)
        length = int(match.group(5))
        if len(bits_text) != length:
            raise ValueError(f"symbol {symbol}: bit string is {len(bits_text)} bits, row says {length}")
        if int(bits_text, 2) != code:
            raise ValueError(f"symbol {symbol}: hex {code:x} is not the bit string {bits_text}")
        if length == 0 or length > MAX_BITS:
            raise ValueError(f"symbol {symbol}: length {length} is outside 1..{MAX_BITS}")
        rows.append((symbol, code, length))

    if len(rows) != SYMBOLS:
        raise ValueError(f"expected {SYMBOLS} rows, read {len(rows)}")
    for position, (symbol, _, _) in enumerate(rows):
        if symbol != position:
            raise ValueError(f"row {position} is symbol {symbol}: the table has a gap, a repeat or a bad order")

    # Prefix-free, which is what makes the code decodable at all.
    for symbol, code, length in rows:
        for other, other_code, other_length in rows:
            if other == symbol or other_length < length:
                continue
            if (other_code >> (other_length - length)) == code:
                raise ValueError(f"symbol {symbol}'s code is a prefix of symbol {other}'s")
    if rows[EOS][1] != (1 << MAX_BITS) - 1:
        raise ValueError("EOS is not thirty one-bits, so padding would not be its prefix")
    return rows


def canonical_index(rows: list[tuple[int, int, int]]):
    """Check the code is canonical and return (sorted entries, per-length ranges).

    The sorted list is by (length, code), which is the order a decoder walks: the
    symbol for a code of length L is the one at `offset + (code - first_code)`.
    HPACK's table is printed in SYMBOL order, so that list is not the table's own
    order and has to be built here.
    """
    sorted_rows = sorted(rows, key=lambda row: (row[2], row[1]))
    ranges = []
    code = 0
    offset = 0
    for length in range(1, MAX_BITS + 1):
        entries = [row for row in sorted_rows if row[2] == length]
        ranges.append((code, offset, len(entries)))
        for index, (_, entry_code, _) in enumerate(entries):
            if entry_code != code + index:
                raise ValueError(f"length {length}: code {entry_code:x} breaks the canonical order at offset {index}")
        code = (code + len(entries)) << 1
        offset += len(entries)
    if offset != SYMBOLS:
        raise ValueError(f"the index covers {offset} symbols, not {SYMBOLS}")
    return sorted_rows, ranges


def extract_example(text: str) -> tuple[bytes, bytes]:
    """C.4.1's Huffman-coded :authority value, and the plaintext it decodes to."""
    body = section(text, r"^C\.4\.1\.  First Request$", r"^C\.4\.2\.")
    # Only the FIRST hex dump: the "Decoding process" below it prints one
    # representation per line, and collecting those too would splice the block
    # together with its own explanation.
    lines = body.splitlines()
    try:
        marker = next(i for i, line in enumerate(lines) if "Hex dump of encoded data:" in line)
    except StopIteration:
        raise ValueError("C.4.1 has no hex dump") from None
    hex_lines = []
    for line in lines[marker + 1 :]:
        match = HEX_DUMP.match(line)
        if match is not None:
            hex_lines.append(match.group(1))
            continue
        if hex_lines and not line.strip():
            break
    if not hex_lines:
        raise ValueError("C.4.1 has no hex dump")
    block = bytes.fromhex("".join(part.replace(" ", "") for part in hex_lines))

    # The block is 82 86 84 (three indexed fields), 41 (literal, incremental
    # indexing, name index 1), 8c (a 12-byte string with the H bit set) and those
    # twelve bytes -- checked rather than assumed, so a change in what the RFC
    # prints stops the extraction.
    expected_prefix = bytes([0x82, 0x86, 0x84, 0x41])
    if block[:4] != expected_prefix:
        raise ValueError(f"C.4.1's block does not begin with the three indexed fields: {block[:4].hex()}")
    length_byte = block[4]
    if (length_byte & 0x80) == 0:
        raise ValueError("C.4.1's :authority string is not marked Huffman-coded")
    length = length_byte & 0x7F
    if len(block) != 5 + length:
        raise ValueError(f"C.4.1's block is {len(block)} bytes for a {length}-byte string")
    coded = block[5:]

    plaintext = None
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith(":authority:"):
            plaintext = stripped[len(":authority:") :].strip().encode()
    if plaintext is None:
        raise ValueError("C.4.1 does not state the :authority value")
    return coded, plaintext


def c_bytes(values, per_line: int, indent: str = "    ") -> str:
    lines = []
    for index in range(0, len(values), per_line):
        chunk = ", ".join(values[index : index + per_line])
        lines.append(f"{indent}{chunk},")
    return "\n".join(lines)


def render(rows, sorted_rows, ranges, coded: bytes, plaintext: bytes) -> str:
    code_lines = "\n".join("    {0x%08xU, %dU}," % (code, length) for (_, code, length) in rows)
    sorted_lines = "\n".join(
        "    {0x%08xU, %dU, %dU}," % (code, length, symbol) for (symbol, code, length) in sorted_rows
    )
    index_lines = "\n".join(
        "    /* length %2d */ {0x%08xU, %dU, %dU}," % (length, entry[0], entry[1], entry[2])
        for length, entry in enumerate(ranges, start=1)
    )
    "\n".join(
        "    " + ", ".join(f"0x{value:02x}U" for value in coded[index : index + 8]) + ","
        for index in range(0, len(coded), 8)
    )
    "\n".join(
        "    " + ", ".join(f"0x{value:02x}U" for value in plaintext[index : index + 8]) + ","
        for index in range(0, len(plaintext), 8)
    )
    return f"""/* Generated by tests/vectors/extract_rfc7541_huffman.py -- do not edit.
 *
 * RFC 7541 appendix B's Huffman code, which QPACK reuses (RFC 9204 section
 * 4.1.2): one code per octet plus EOS. The script checks that the table is
 * symbol-ordered and prefix-free, that EOS is thirty one-bits (which is what
 * padding is made of) and that the code is canonical, then derives the decode
 * index from it.
 *
 * THE TABLE IS THE RFC'S, EXTRACTED, NOT TRANSCRIBED, and appendix C.4.1's worked
 * example is included as the one vector the decoder is checked against.
 * `--check` re-extracts and compares against this file.
 */

#ifndef WT_QPACK_HUFFMAN_TABLE_H
#define WT_QPACK_HUFFMAN_TABLE_H

#include <stddef.h>
#include <stdint.h>

/* One code per octet plus the end-of-string symbol. */
#define WT_RFC7541_HUFFMAN_SYMBOLS {SYMBOLS}U
#define WT_RFC7541_HUFFMAN_EOS {EOS}U
#define WT_RFC7541_HUFFMAN_MAX_BITS {MAX_BITS}U

typedef struct wt_rfc7541_huffman_code {{
  uint32_t code;
  uint8_t bits;
}} wt_rfc7541_huffman_code_t;

/* Indexed by symbol, in the appendix's own order; the EOS entry is last. This is
 * what an encoder needs. */
static const wt_rfc7541_huffman_code_t WT_RFC7541_HUFFMAN_CODES[WT_RFC7541_HUFFMAN_SYMBOLS] = {{
{code_lines}
}};

/* The decode side: every entry by (length, code), which is the order a decoder
 * walks, and one range per length giving where that length's codes start in the
 * array and what the smallest of them is. The appendix prints the table in SYMBOL
 * order, so this array is not in that order -- the script builds it and checks the
 * canonical property against every entry. */
typedef struct wt_rfc7541_huffman_entry {{
  uint32_t code;
  uint8_t bits;
  uint16_t symbol;
}} wt_rfc7541_huffman_entry_t;

static const wt_rfc7541_huffman_entry_t
    WT_RFC7541_HUFFMAN_BY_CODE[WT_RFC7541_HUFFMAN_SYMBOLS] = {{
{sorted_lines}
}};

typedef struct wt_rfc7541_huffman_range {{
  uint32_t first_code;
  uint16_t offset;
  uint16_t count;
}} wt_rfc7541_huffman_range_t;

static const wt_rfc7541_huffman_range_t
    WT_RFC7541_HUFFMAN_RANGES[WT_RFC7541_HUFFMAN_MAX_BITS] = {{
{index_lines}
}};

#endif /* WT_QPACK_HUFFMAN_TABLE_H */
"""


def render_vectors(coded: bytes, plaintext: bytes) -> str:
    coded_lines = "\n".join(
        "    " + ", ".join(f"0x{value:02x}U" for value in coded[index : index + 8]) + ","
        for index in range(0, len(coded), 8)
    )
    plaintext_lines = "\n".join(
        "    " + ", ".join(f"0x{value:02x}U" for value in plaintext[index : index + 8]) + ","
        for index in range(0, len(plaintext), 8)
    )
    return f"""/* Generated by tests/vectors/extract_rfc7541_huffman.py -- do not edit.
 *
 * RFC 7541 appendix C.4.1's worked example: the Huffman-coded `:authority` value
 * from its first encoded header block, and the plaintext the RFC decodes it to.
 * It is the one Huffman vector in this project that did not come from this
 * implementation, which is why the decoder is checked against it.
 */

#ifndef WT_RFC7541_HUFFMAN_VECTORS_H
#define WT_RFC7541_HUFFMAN_VECTORS_H

#include <stdint.h>

#define WT_RFC7541_HUFFMAN_EXAMPLE_LENGTH {len(coded)}U
static const uint8_t WT_RFC7541_HUFFMAN_EXAMPLE[WT_RFC7541_HUFFMAN_EXAMPLE_LENGTH] = {{
{coded_lines}
}};

#define WT_RFC7541_HUFFMAN_EXAMPLE_PLAINTEXT_LENGTH {len(plaintext)}U
static const uint8_t WT_RFC7541_HUFFMAN_EXAMPLE_PLAINTEXT
    [WT_RFC7541_HUFFMAN_EXAMPLE_PLAINTEXT_LENGTH] = {{
{plaintext_lines}
}};

#endif /* WT_RFC7541_HUFFMAN_VECTORS_H */
"""


def main(argv) -> int:
    check = "--check" in argv
    args = [a for a in argv[1:] if not a.startswith("--")]
    source = Path(args[0]) if args else Path("/tmp/rfc7541.txt")
    if not source.exists():
        print(f"rfc7541 text not found at {source}", file=sys.stderr)
        return 2
    text = source.read_text(encoding="utf-8")
    rows = extract_table(text)
    sorted_rows, ranges = canonical_index(rows)
    coded, plaintext = extract_example(text)
    rendered = render(rows, sorted_rows, ranges, coded, plaintext)
    vectors = render_vectors(coded, plaintext)
    if check:
        for path, wanted in ((HEADER, rendered), (VECTORS, vectors)):
            if not path.exists():
                print(f"no committed file to check at {path}", file=sys.stderr)
                return 1
            if path.read_text(encoding="utf-8") != wanted:
                print(f"{path} is not what the RFC says", file=sys.stderr)
                return 1
        print("rfc7541 Huffman: committed code and example match the RFC")
        return 0
    HEADER.write_text(rendered, encoding="utf-8")
    VECTORS.write_text(vectors, encoding="utf-8")
    print(f"rfc7541 Huffman: wrote {len(rows)} codes and a {len(coded)}-byte example")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
