#!/usr/bin/env python3
"""Extract RFC 9001 appendix A.4's Retry packet and its integrity tag.

The Retry integrity tag (RFC 9001 section 5.8) is what lets a client tell a Retry
the server sent from one an attacker injected, so what the implementation
produces for the document's own packet has to be checked against the document.
A.4 prints one Retry packet, tag included, in response to A.2's client Initial.

Nothing is written until the extraction has been checked structurally, because a
hex block read from the wrong place is exactly the kind of mistake that makes a
test pass against a wrong implementation:

  - the packet parses as a version-1 Retry: long header, type bits 3, a
    zero-length Destination Connection ID, a Source Connection ID of 1..20 bytes,
    a non-empty token, and exactly sixteen bytes of tag at the end;
  - the tag the RFC prints beside the packet is that trailing sixteen bytes, and
    the bytes the implementation must authenticate are the packet without them;
  - the original destination connection ID A.4 names in prose is the Destination
    Connection ID of A.2's client Initial packet, read from that packet's own hex
    rather than from the sentence, so a typo in either place fails the check.

    python3 tests/vectors/extract_rfc9001_retry.py [rfc9001.txt] [--check]

With no arguments it looks for `/tmp/rfc9001.txt` and writes
`tests/vectors/rfc9001_retry.h`. With `--check` it re-extracts and compares
against the committed header, which is how the committed bytes stay the RFC's.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HEADER = HERE / "rfc9001_retry.h"

TAG_LENGTH = 16
MAX_CONNECTION_ID_LENGTH = 20
RETRY_TYPE_BITS = 3

# A line of the RFC that is nothing but hex groups, which is how the documents
# print packets. Prose lines that mention a hex value do not match.
HEX_ONLY_LINE = re.compile(r"^[0-9a-f]{2,}(?: [0-9a-f]{2,})*$")


def section_lines(text: str, start: str, stop: str) -> list[str]:
    """The lines of one appendix section, from its heading to the next.

    The headings are matched as whole lines rather than as substrings: the table
    of contents prints each one too, with the page number after it, and a
    substring search finds that copy first and reads an empty section.
    """
    start_match = re.search(start, text, re.MULTILINE)
    if start_match is None:
        raise ValueError(f"the RFC text has no heading matching {start!r}")
    stop_match = re.search(stop, text[start_match.end() :], re.MULTILINE)
    if stop_match is None:
        raise ValueError(f"the RFC text has no heading matching {stop!r} after {start!r}")
    end_at = start_match.end() + stop_match.start()
    return text[start_match.end() : end_at].splitlines()


def hex_blocks(lines: list[str]) -> list[bytes]:
    """Every contiguous block of hex in these lines, in the order printed.

    A section can print several: A.2 shows the payload, the unprotected header,
    the masked header and finally the protected packet. Callers take the block
    they mean rather than concatenating the section, which would splice a header
    onto a payload.
    """
    blocks: list[bytes] = []
    current: list[str] = []
    for line in lines:
        candidate = line.strip()
        if HEX_ONLY_LINE.match(candidate):
            current.append(candidate.replace(" ", ""))
        elif current:
            blocks.append(bytes.fromhex("".join(current)))
            current = []
    if current:
        blocks.append(bytes.fromhex("".join(current)))
    if not blocks:
        raise ValueError("no hex block found")
    return blocks


def last_hex_block(lines: list[str]) -> bytes:
    """The last block printed in a section, which is the packet it concludes."""
    return hex_blocks(lines)[-1]


def client_initial_destination_connection_id(text: str) -> bytes:
    """The Destination Connection ID of A.2's client Initial, from its own hex."""
    lines = section_lines(text, r"^A\.2\.  Client Initial$", r"^A\.3\.  Server Initial$")
    packet = last_hex_block(lines)
    if len(packet) < 7:
        raise ValueError("the client Initial packet is too short to hold a header")
    if packet[0] & 0x80 == 0:
        raise ValueError("the client Initial does not begin with a long header")
    if int.from_bytes(packet[1:5], "big") != 1:
        raise ValueError("the client Initial is not version 1")
    length = packet[5]
    if length > MAX_CONNECTION_ID_LENGTH:
        raise ValueError("the client Initial's connection ID is longer than the protocol allows")
    if length == 0 or len(packet) < 6 + length:
        raise ValueError("the client Initial's connection ID is missing or empty")
    return packet[6 : 6 + length]


def extract(text: str) -> tuple[bytes, bytes, bytes]:
    """(original destination connection ID, Retry packet, integrity tag)."""
    lines = section_lines(text, r"^A\.4\.  Retry$", r"^A\.5\.  ChaCha20")
    packet = last_hex_block(lines)
    if len(packet) <= TAG_LENGTH:
        raise ValueError("the Retry packet is too short to carry a tag")
    if packet[0] & 0x80 == 0:
        raise ValueError("the Retry packet does not begin with a long header")
    if (packet[0] >> 4) & 0x03 != RETRY_TYPE_BITS:
        raise ValueError("the first byte's type bits are not Retry")
    if int.from_bytes(packet[1:5], "big") != 1:
        raise ValueError("the Retry packet is not version 1")
    destination_length = packet[5]
    if destination_length != 0:
        raise ValueError("a Retry packet's Destination Connection ID is zero length by definition")
    source_length = packet[6]
    if source_length == 0 or source_length > MAX_CONNECTION_ID_LENGTH:
        raise ValueError("the Retry packet's Source Connection ID length is out of range")
    first_tag_byte = 7 + source_length
    if first_tag_byte >= len(packet) - TAG_LENGTH:
        raise ValueError("the Retry packet carries no token")
    tag = packet[len(packet) - TAG_LENGTH :]

    # The connection ID A.4 names is written in prose beside the packet; the
    # sentence is not trusted on its own, so it has to agree with A.2's packet.
    named = re.search(r"0x([0-9a-f]{16})", "\n".join(lines))
    if named is None:
        raise ValueError("A.4 does not name an original destination connection ID")
    original = bytes.fromhex(named.group(1))
    from_packet = client_initial_destination_connection_id(text)
    if original != from_packet:
        raise ValueError(
            "A.4's original destination connection ID is not A.2's client Initial's: "
            f"{original.hex()} against {from_packet.hex()}"
        )
    return original, packet, tag


def render(original: bytes, packet: bytes, tag: bytes) -> str:
    def body(values: bytes) -> str:
        lines = []
        for index in range(0, len(values), 8):
            chunk = ", ".join(f"0x{value:02x}U" for value in values[index : index + 8])
            lines.append(f"    {chunk},")
        return "\n".join(lines)

    return f"""/* Generated by tests/vectors/extract_rfc9001_retry.py -- do not edit.
 *
 * RFC 9001 appendix A.4's Retry packet and the integrity tag it prints with it.
 * The tag is what a client uses to tell a Retry the server sent from one an
 * attacker injected (section 5.8), so the value this implementation produces for
 * the document's own packet is asserted against the document's own tag rather
 * than against a round trip through the same code.
 *
 * THE BYTES ARE THE RFC'S, EXTRACTED, NOT TRANSCRIBED. The script refuses to
 * write a block that does not parse as a version-1 Retry whose original
 * destination connection ID agrees with A.2's client Initial packet, so a bad
 * extraction stops generation rather than producing a vector a wrong
 * implementation would pass. `--check` re-extracts and compares against this
 * file.
 */

#ifndef WT_RFC9001_RETRY_H
#define WT_RFC9001_RETRY_H

#include <stdint.h>

/* The client-chosen connection ID the tag is bound to. It is authenticated but
 * is not part of the Retry packet on the wire (section 5.8). */
#define WT_RFC9001_RETRY_ODCID_LEN {len(original)}
static const uint8_t WT_RFC9001_RETRY_ODCID[WT_RFC9001_RETRY_ODCID_LEN] = {{
{body(original)}
}};

/* The whole Retry packet as A.4 prints it: header, token, then the tag. */
#define WT_RFC9001_RETRY_PACKET_LEN {len(packet)}
static const uint8_t WT_RFC9001_RETRY_PACKET[WT_RFC9001_RETRY_PACKET_LEN] = {{
{body(packet)}
}};

/* The last sixteen bytes of that packet, which the implementation must
 * reproduce from the packet without them. */
#define WT_RFC9001_RETRY_TAG_LEN {len(tag)}
static const uint8_t WT_RFC9001_RETRY_TAG[WT_RFC9001_RETRY_TAG_LEN] = {{
{body(tag)}
}};

#endif /* WT_RFC9001_RETRY_H */
"""


def main(argv) -> int:
    check = "--check" in argv
    args = [a for a in argv[1:] if not a.startswith("--")]
    source = Path(args[0]) if args else Path("/tmp/rfc9001.txt")
    if not source.exists():
        print(f"rfc9001 text not found at {source}", file=sys.stderr)
        return 2
    original, packet, tag = extract(source.read_text(encoding="utf-8"))
    rendered = render(original, packet, tag)
    if check:
        if not HEADER.exists():
            print("no committed header to check", file=sys.stderr)
            return 1
        if HEADER.read_text(encoding="utf-8") != rendered:
            print("the committed header is not the RFC's Retry packet", file=sys.stderr)
            return 1
        print("rfc9001 Retry: committed bytes match the RFC")
        return 0
    HEADER.write_text(rendered, encoding="utf-8")
    print(
        f"rfc9001 Retry: wrote {len(packet)} bytes of packet and {len(tag)} bytes of tag "
        f"for an original connection ID of {len(original)} bytes"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
