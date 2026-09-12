#!/usr/bin/env python3
"""Extract RFC 7748's X25519 test vectors, and check them with an independent ladder.

RFC 7748 section 5.2 gives two (scalar, u-coordinate) pairs with their outputs, and
section 6.1 gives a complete Diffie-Hellman example: two private keys, the two public
keys they produce, and the shared secret. Those are the vectors for the key agreement,
and they are read from the RFC's own hex rather than transcribed.

The section 6.1 block sits above an X448 block whose labels are IDENTICAL -- "Alice's
private key, a:" appears twice in the same section -- so the extraction is checked in
two ways that do not depend on the labels:

  - every value must be 32 bytes, which an X448 key is not (those are 56);
  - a ladder implemented here from section 5 of the same document must reproduce every
    value from the inputs beside it: X25519(a, 9) must be Alice's public key,
    X25519(b, 9) Bob's, and X25519(a, Bob's public key) their shared secret.

The ladder is an oracle, not production code: if it is wrong, the RFC's own vectors say
so and generation stops rather than writing a vector a wrong implementation would pass.
It is deliberately the plain textbook algorithm -- no attempt at constant time, because
nothing here runs against a peer.

    python3 tests/vectors/extract_rfc7748_x25519.py [rfc7748.txt] [--check]

With no arguments it looks for `/tmp/rfc7748.txt` and writes
`tests/vectors/rfc7748_vectors.h`. With `--check` it re-extracts and compares against
the committed header.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HEADER = HERE / "rfc7748_vectors.h"

P = (1 << 255) - 19
A24 = 121665
BITS = 255
BASE_POINT = bytes([9] + [0] * 31)

# A label on its own line, three or more spaces in. The RFC prints the Diffie-Hellman
# example that way: the label, then the hex on the line below it.
LABELLED = re.compile(r"^\s{3,}([A-Za-z][A-Za-z',() 0-9]*?):\s*$")
# A line that is only hex, three or more spaces in: the value under a label.
BARE = re.compile(r"^\s{3,}([0-9a-f]{16,})\s*$")
# The labels section 5.2 puts above each value. The value is the next non-blank line.
POSITIONAL = re.compile(r"^\s+(Input scalar|Input u-coordinate|Output u-coordinate):")


def x25519(scalar: bytes, u_coordinate: bytes) -> bytes:
    """RFC 7748 section 5's ladder, written the way the document writes it."""
    if len(scalar) != 32 or len(u_coordinate) != 32:
        raise SystemExit("X25519 takes 32-byte scalars and coordinates")

    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k_int = int.from_bytes(bytes(k), "little")

    # The u-coordinate is masked to 255 bits and reduced, as section 5 requires.
    x1 = int.from_bytes(u_coordinate, "little") & ((1 << 255) - 1)
    x1 %= P

    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(BITS - 1, -1, -1):
        k_t = (k_int >> t) & 1
        swap ^= k_t
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t

        a = (x2 + z2) % P
        aa = (a * a) % P
        b = (x2 - z2) % P
        bb = (b * b) % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = (d * a) % P
        cb = (c * b) % P
        x3 = ((da + cb) % P) ** 2 % P
        z3 = (x1 * (((da - cb) % P) ** 2)) % P
        x2 = (aa * bb) % P
        z2 = (e * ((aa + A24 * e) % P)) % P

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def section(lines: list[str], start: str, end: str | None) -> list[str]:
    first = next(i for i, line in enumerate(lines) if line.startswith(start))
    if end is None:
        return lines[first:]
    last = next(
        (i for i, line in enumerate(lines) if i > first and line.startswith(end)),
        len(lines),
    )
    return lines[first:last]


def labelled(lines: list[str], label: str, occurrence: int = 1) -> bytes:
    """The hex under a label, taking the next non-blank line as the value."""
    seen = 0
    for index, line in enumerate(lines):
        found = LABELLED.match(line)
        if found is None or found.group(1) != label:
            continue
        seen += 1
        if seen != occurrence:
            continue
        for follow in lines[index + 1 :]:
            if follow.strip() == "":
                continue
            token = BARE.match(follow)
            if token is None:
                raise SystemExit(f"the value under {label!r} is not hex: {follow!r}")
            return bytes.fromhex(token.group(1))
        raise SystemExit(f"{label!r} has no value under it")
    raise SystemExit(f"no {label!r} (occurrence {occurrence})")


def positional_values(lines: list[str]) -> list[tuple[str, bytes]]:
    """The `label: value` pairs of section 5.2, in order.

    The value is the next non-blank line after its label, because the RFC follows each
    one with a base-10 rendering of the same number -- which a regex over hex lines
    cannot tell from a value, since a long string of decimal digits is also a string of
    hex digits. Reading by position is what makes the two unambiguous.
    """
    values: list[tuple[str, bytes]] = []
    for index, line in enumerate(lines):
        found = POSITIONAL.match(line)
        if found is None:
            continue
        for follow in lines[index + 1 :]:
            if follow.strip() == "":
                continue
            token = BARE.match(follow)
            if token is None:
                raise SystemExit(
                    f"the value under {found.group(1)!r} is not hex: {follow!r}"
                )
            values.append((found.group(1), bytes.fromhex(token.group(1))))
            break
    return values


def extract(rfc: str) -> dict[str, bytes]:
    lines = rfc.splitlines()
    out: dict[str, bytes] = {}

    # Section 5.2's two X25519 scalar-multiplication vectors. Each is a scalar, a
    # u-coordinate and an output, in that order, and each is 32 bytes: the X448 vectors
    # below them are 56, so a length check is what says the right ones were read.
    vectors = section(lines, "5.2.  Test Vectors", "5.2.1.")
    pairs = positional_values(vectors)
    # Each of the two X25519 vectors is a scalar, a u-coordinate and an output; the X448
    # ones that follow are 56 bytes and are not taken. Six 32-byte values, in order.
    wanted = pairs[:6]
    if len(wanted) != 6:
        raise SystemExit(f"expected six values in 5.2, found {len(pairs)}")
    for index in range(2):
        base = index * 3
        expected_labels = ("Input scalar", "Input u-coordinate", "Output u-coordinate")
        for offset, label in enumerate(expected_labels):
            if wanted[base + offset][0] != label:
                raise SystemExit(
                    f"5.2 vector {index + 1}: expected {label!r}, found "
                    f"{wanted[base + offset][0]!r}"
                )
            if len(wanted[base + offset][1]) != 32:
                raise SystemExit(
                    f"5.2 vector {index + 1}: {label!r} is not 32 bytes"
                )
        out[f"SCALAR_{index + 1}"] = wanted[base][1]
        out[f"U_COORDINATE_{index + 1}"] = wanted[base + 1][1]
        out[f"OUTPUT_{index + 1}"] = wanted[base + 2][1]

    # Section 6.1's Diffie-Hellman example, stopped at the X448 subsection, whose labels
    # are word for word the same.
    example = section(lines, "6.1.  Curve25519", None)
    x448_at = next(
        (i for i, line in enumerate(example) if "X448" in line), len(example)
    )
    example = example[:x448_at]
    out["ALICE_PRIVATE"] = labelled(example, "Alice's private key, a")
    out["ALICE_PUBLIC"] = labelled(example, "Alice's public key, X25519(a, 9)")
    out["BOB_PRIVATE"] = labelled(example, "Bob's private key, b")
    out["BOB_PUBLIC"] = labelled(example, "Bob's public key, X25519(b, 9)")
    out["SHARED_SECRET"] = labelled(example, "Their shared secret, K")
    return out


def self_check(values: dict[str, bytes]) -> None:
    for name, value in values.items():
        if len(value) != 32:
            raise SystemExit(f"{name} is {len(value)} bytes, not 32")

    # The ladder against the RFC's own scalar-multiplication vectors: this is what makes
    # the oracle trustworthy before it is used on the Diffie-Hellman example below.
    for index in (1, 2):
        got = x25519(values[f"SCALAR_{index}"], values[f"U_COORDINATE_{index}"])
        if got != values[f"OUTPUT_{index}"]:
            raise SystemExit(
                f"the ladder does not reproduce output {index}: "
                f"{got.hex()} != {values[f'OUTPUT_{index}'].hex()}"
            )

    # And the example: both public keys from their private keys, and the shared secret
    # from Alice's private key and Bob's public key.
    if x25519(values["ALICE_PRIVATE"], BASE_POINT) != values["ALICE_PUBLIC"]:
        raise SystemExit("Alice's public key does not derive from her private key")
    if x25519(values["BOB_PRIVATE"], BASE_POINT) != values["BOB_PUBLIC"]:
        raise SystemExit("Bob's public key does not derive from his private key")
    if x25519(values["ALICE_PRIVATE"], values["BOB_PUBLIC"]) != values["SHARED_SECRET"]:
        raise SystemExit("the shared secret does not derive from the pair")
    # The other direction agrees, which is the property the whole exchange rests on.
    if x25519(values["BOB_PRIVATE"], values["ALICE_PUBLIC"]) != values["SHARED_SECRET"]:
        raise SystemExit("the shared secret is not symmetric")


def render(values: dict[str, bytes]) -> str:
    def c_array(name: str, data: bytes, comment: str) -> str:
        lines = []
        line = "    "
        for index, byte in enumerate(data):
            line += f"0x{byte:02x}, "
            if index % 12 == 11:
                lines.append(line.rstrip())
                line = "    "
        if line.strip():
            lines.append(line.rstrip())
        body = "\n".join(lines)
        return (
            f"/* {comment} */\n"
            f"#define WT_RFC7748_{name}_LEN {len(data)}\n"
            f"static const uint8_t WT_RFC7748_{name}[WT_RFC7748_{name}_LEN] = {{\n"
            f"{body}\n}};\n"
        )

    return (
        "/* Generated by tests/vectors/extract_rfc7748_x25519.py -- do not edit.\n"
        " *\n"
        " * RFC 7748's X25519 vectors, read from the RFC's own hex and checked before\n"
        " * they are written: a ladder implemented from the same document's section 5\n"
        " * must reproduce both scalar-multiplication vectors of section 5.2 and all\n"
        " * five values of section 6.1's Diffie-Hellman example from the inputs printed\n"
        " * beside them. If it does not, generation stops rather than writing a vector a\n"
        " * wrong implementation would pass.\n"
        " */\n\n"
        "#ifndef WT_RFC7748_VECTORS_H\n"
        "#define WT_RFC7748_VECTORS_H\n\n"
        "#include <stdint.h>\n\n"
        + "\n".join(
            [
                c_array("SCALAR_1", values["SCALAR_1"],
                        "RFC 7748 5.2: the first input scalar."),
                c_array("U_COORDINATE_1", values["U_COORDINATE_1"],
                        "RFC 7748 5.2: with SCALAR_1, the first input u-coordinate."),
                c_array("OUTPUT_1", values["OUTPUT_1"],
                        "RFC 7748 5.2: the output for the first pair."),
                c_array("SCALAR_2", values["SCALAR_2"],
                        "RFC 7748 5.2: the second input scalar (2^255 - 1 + 1)."),
                c_array("U_COORDINATE_2", values["U_COORDINATE_2"],
                        "RFC 7748 5.2: with SCALAR_2, the second input u-coordinate."),
                c_array("OUTPUT_2", values["OUTPUT_2"],
                        "RFC 7748 5.2: the output for the second pair."),
                c_array("ALICE_PRIVATE", values["ALICE_PRIVATE"],
                        "RFC 7748 6.1: Alice's private key."),
                c_array("ALICE_PUBLIC", values["ALICE_PUBLIC"],
                        "RFC 7748 6.1: X25519(ALICE_PRIVATE, 9)."),
                c_array("BOB_PRIVATE", values["BOB_PRIVATE"],
                        "RFC 7748 6.1: Bob's private key."),
                c_array("BOB_PUBLIC", values["BOB_PUBLIC"],
                        "RFC 7748 6.1: X25519(BOB_PRIVATE, 9)."),
                c_array("SHARED_SECRET", values["SHARED_SECRET"],
                        "RFC 7748 6.1: the shared secret, either way round."),
            ]
        )
        + "\n#endif /* WT_RFC7748_VECTORS_H */\n"
    )


def main(argv: list[str]) -> int:
    check = "--check" in argv
    args = [a for a in argv[1:] if not a.startswith("--")]
    source = Path(args[0]) if args else Path("/tmp/rfc7748.txt")
    if not source.exists():
        print(f"rfc7748 text not found at {source}", file=sys.stderr)
        return 2
    values = extract(source.read_text(encoding="utf-8"))
    self_check(values)
    rendered = render(values)
    if check:
        if not HEADER.exists():
            print("no committed header to check", file=sys.stderr)
            return 1
        if HEADER.read_text(encoding="utf-8") != rendered:
            print("the committed vectors are not the RFC's", file=sys.stderr)
            return 1
        print("rfc7748 x25519: committed vectors match the RFC")
        return 0
    HEADER.write_text(rendered, encoding="utf-8")
    print(f"rfc7748 x25519: wrote {len(values)} values")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
