#!/usr/bin/env python3
"""Find dead local variables that a `(void)` cast is hiding from the compiler.

`(void)name;` is the idiomatic way to say "this parameter is unused" in C, and the compiler is
right to accept it. Used on a *local* variable that is assigned and never read, it does the
opposite: it silences `-Wunused-but-set-variable`, which is the warning that would have caught
the bug. `cc -Wall -Wextra -Wunused-but-set-variable -Werror` does not fire on
`C99/src/quic/transport_parameters.c`, because `start` and `start_offset` are cast to void
three lines after being computed -- the cast *is* the use.

So this checks the two cases separately:

  - a name that appears in some function's parameter list is an unused-parameter suppression,
    which is deliberate and correct;
  - anything else is a local, and is reported when nothing but its declaration, its assignments
    and the `(void)` cast mention it.

Exit status is 0 when the tree is clean and 1 with one line per finding otherwise.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOTS = ("C99/src", "C99/apps")

VOID_CAST = r"\(void\)\s*%s\s*;"
# An assignment target: `name =`, but not `==`, `!=`, `<=`, `>=` or a compound operator.
ASSIGNMENT = r"(?<![=!<>+\-*/%%&|^])\b%s\s*=(?!=)"
DECLARATION = (
    r"\b(?:size_t|int|unsigned|signed|char|void|long|short|float|double|"
    r"[a-z_][a-z0-9_]*_t|struct\s+[a-z_][a-z0-9_]*)\s*\**\s*%s\b"
)


def parameter_names(text: str) -> set[str]:
    """Names appearing inside any parenthesised function signature in `text`.

    Approximate on purpose: a name that is a parameter anywhere is treated as a parameter
    everywhere, which errs toward silence. The alternative -- resolving the enclosing scope of
    every cast -- is a parser, and this check only needs to not cry wolf.
    """
    names: set[str] = set()
    for match in re.finditer(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(([^;{}]*)\)\s*\{", text):
        for word in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", match.group(1)):
            names.add(word)
    return names


def dead_locals(text: str) -> list[str]:
    parameters = parameter_names(text)
    findings: list[str] = []
    for match in re.finditer(r"\(void\)\s*([A-Za-z_][A-Za-z0-9_]*)\s*;", text):
        name = match.group(1)
        if name in parameters:
            continue
        stripped = re.sub(VOID_CAST % re.escape(name), "", text)
        stripped = re.sub(ASSIGNMENT % re.escape(name), "", stripped)
        stripped = re.sub(DECLARATION % re.escape(name), "", stripped)
        if not re.search(r"\b%s\b" % re.escape(name), stripped):
            line = text[: match.start()].count("\n") + 1
            findings.append(f"{line}: (void){name}; -- local, set but never read")
    return findings


def main() -> int:
    total = 0
    for root in ROOTS:
        base = pathlib.Path(root)
        if not base.is_dir():
            print(f"unused-locals: {root} is missing", file=sys.stderr)
            return 1
        for path in sorted(base.rglob("*.c")):
            findings = dead_locals(path.read_text(encoding="utf-8"))
            for finding in findings:
                print(f"{path}:{finding}")
            total += len(findings)

    if total:
        print(f"unused-locals: {total} dead local(s) hidden by a (void) cast")
        return 1
    print("unused-locals: no dead locals hidden by a (void) cast")
    return 0


if __name__ == "__main__":
    sys.exit(main())
