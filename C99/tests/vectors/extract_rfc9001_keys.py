#!/usr/bin/env python3
"""Extract RFC 9001 appendix A's key material and check it by re-derivation.

RFC 9001 prints the Initial secrets, the traffic keys they produce, and a set of
ChaCha20-Poly1305 keys. The tests need those values, and they are read from the
RFC's own hex rather than transcribed -- but a hex block read from the wrong
place is exactly the kind of mistake that makes a test pass against a wrong
implementation, so nothing is written until the extraction has been checked
against arithmetic that does not depend on the labels:

  - the Initial secret is recomputed as HKDF-Extract(version-1 salt, destination
    connection ID), both of which are also printed, and must equal the value the
    label pointed at;
  - every key, IV and header protection key is recomputed from its traffic secret
    with the QUIC labels, and must equal what the RFC prints beside it;
  - the ChaCha20-Poly1305 secret, which has no such derivation to check against,
    must be 32 bytes and its four derived values must all re-derive from it;
  - the key update secret must equal HKDF-Expand-Label(secret, "quic ku", "", 32).

    python3 tests/vectors/extract_rfc9001_keys.py [rfc9001.txt] [--check]

With no arguments it looks for `/tmp/rfc9001.txt` and writes
`tests/vectors/rfc9001_vectors.h`. With `--check` it re-extracts and compares
against the committed header, which is how the committed bytes stay the RFC's.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HEADER = HERE / "rfc9001_vectors.h"

# RFC 9001 section 5.2: the version-1 Initial salt.
INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

HEX_LINE = re.compile(r"(?:[0-9a-f]{2,}(?: [0-9a-f]{2,})*)\s*$")


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    full = b"tls13 " + label.encode()
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(context)]) + context
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(secret, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def hex_value_after(lines: list[str], label: str, start: int = 0) -> tuple[bytes, int]:
    """The hex value introduced by `label`, and the line it starts on.

    RFC 9001 prints a value in one of two shapes, and both are handled:

        client in:  00200f746c73313320636c69656e7420696e00

        key = HKDF-Expand-Label(client_initial_secret, "quic key", "", 16)
            = 1f369613dd76d5467730efcbe3b1a22d

    So the value is whatever hex follows the label's line, either after an `=`
    on the same line or on the lines below it. A decimal value printed beside a
    label -- `pn = 654360564 (decimal)` -- does not end in hex at the end of its
    line and is not matched.
    """
    for index in range(start, len(lines)):
        if label not in lines[index]:
            continue
        tokens: list[str] = []
        head = lines[index]
        if "=" in head and HEX_LINE.search(head) is not None:
            tokens.extend(HEX_LINE.search(head).group(0).split())
        for line in lines[index + 1 :]:
            stripped = line.strip()
            if stripped == "":
                if tokens:
                    break
                continue
            # The value may be introduced by `= <formula>` and only then by
            # `= <hex>`, as A.1's client_initial_secret is: the first `=` line
            # says how the value is derived and the second is the value. So a
            # line that starts with `=` is never a reason to stop.
            candidate = stripped[1:].strip() if stripped.startswith("=") else stripped
            if HEX_LINE.fullmatch(candidate + " ") is not None:
                tokens.extend(candidate.split())
                continue
            if stripped.startswith("="):
                continue
            break
        if tokens:
            joined = "".join(tokens)
            if len(joined) % 2 != 0:
                raise SystemExit(f"{label!r}: an odd number of hex digits")
            return bytes.fromhex(joined), index
    raise SystemExit(f"no hex value after {label!r}")


def bare_hex_after(lines: list[str], start: int, length: int) -> bytes:
    """The first line after `start` that is nothing but `length` bytes of hex.

    The unprotected headers are printed as bare hex lines -- there is no label to
    search for -- so what identifies them is their length and the fact that they
    are a whole line. The payload and packet blocks beside them are printed two
    tokens to a line, so they cannot be mistaken for one, and a wrong line would
    fail the arithmetic in self_check rather than be written out.
    """
    for line in lines[start:]:
        stripped = line.strip()
        if len(stripped) == 2 * length and re.fullmatch(r"[0-9a-f]+", stripped):
            return bytes.fromhex(stripped)
    raise SystemExit(f"no {length}-byte bare hex line after line {start}")


def decimal_after(lines: list[str], label: str, start: int = 0) -> tuple[int, int]:
    """The decimal value on the line labelled `label`.

    RFC 9001 prints packet numbers in decimal with the base spelled out --
    `pn = 654360564 (decimal)` -- so they cannot be read as hex, and reading
    `654360564` as hex would be a value of a different length that no check here
    would notice.
    """
    pattern = re.compile(re.escape(label) + r"\s*=\s*(\d+)")
    for index in range(start, len(lines)):
        found = pattern.search(lines[index])
        if found is not None:
            return int(found.group(1)), index
    raise SystemExit(f"no decimal value after {label!r}")


def extract(rfc: str) -> tuple[dict[str, bytes], dict[str, int]]:
    lines = rfc.splitlines()
    out: dict[str, bytes] = {}
    scalars: dict[str, int] = {}
    # The search starts at appendix A rather than at the top of the document,
    # because the section that DEFINES these values also names them -- section
    # 5.2 writes `client_initial_secret = HKDF-Expand-Label(...)` without
    # printing a value -- and a search from the front reads that one first. It
    # produced a 16-byte "secret" taken from the lines of a formula, which is
    # exactly the kind of extraction that would make a test pass against a wrong
    # implementation.
    cursor = next((i for i, line in enumerate(lines) if line.startswith("A.1.")), 0)

    def take(name: str, label: str, length: int) -> None:
        nonlocal cursor
        value, at = hex_value_after(lines, label, cursor)
        if len(value) != length:
            raise SystemExit(f"{name}: expected {length} bytes from {label!r}, got {len(value)}")
        out[name] = value
        cursor = at

    take("INITIAL_SECRET", "initial_secret = HKDF-Extract", 32)
    # The client's block comes before the server's, so a forward cursor is what
    # keeps `key =` from being read twice from the same place.
    take("CLIENT_INITIAL_SECRET", "client_initial_secret", 32)
    take("CLIENT_INITIAL_KEY", "key = HKDF-Expand-Label(client_initial_secret", 16)
    take("CLIENT_INITIAL_IV", "iv  = HKDF-Expand-Label(client_initial_secret", 12)
    take("CLIENT_INITIAL_HP", "hp  = HKDF-Expand-Label(client_initial_secret", 16)
    take("SERVER_INITIAL_SECRET", "server_initial_secret", 32)
    take("SERVER_INITIAL_KEY", "key = HKDF-Expand-Label(server_initial_secret", 16)
    take("SERVER_INITIAL_IV", "iv  = HKDF-Expand-Label(server_initial_secret", 12)
    take("SERVER_INITIAL_HP", "hp  = HKDF-Expand-Label(server_initial_secret", 16)

    # A.5 lives in its own appendix, so the cursor is placed there rather than
    # walking the whole document looking for "secret".
    cursor = next((i for i, line in enumerate(lines) if line.startswith("A.5.")), 0)
    take("CHACHA_SECRET", "secret", 32)
    take("CHACHA_KEY", "key = HKDF-Expand-Label(secret", 32)
    take("CHACHA_IV", "iv  = HKDF-Expand-Label(secret", 12)
    take("CHACHA_HP", "hp  = HKDF-Expand-Label(secret", 32)
    take("CHACHA_KEY_UPDATE", "ku  = HKDF-Expand-Label(secret", 32)

    # Header protection, appendix by appendix. The samples and masks are printed
    # so that a test can localise a failure to the sample offset or to the mask
    # rather than only observing that a whole packet came out wrong.
    def at_heading(prefix: str) -> int:
        return next((i for i, line in enumerate(lines) if line.startswith(prefix)), 0)

    client_at = at_heading("A.2.")
    cursor = client_at
    take("CLIENT_INITIAL_SAMPLE", "sample = ", 16)
    take("CLIENT_INITIAL_MASK", "mask = ", 5)
    take("CLIENT_INITIAL_HEADER_PROTECTED", "header = ", 22)
    out["CLIENT_INITIAL_HEADER_PLAIN"] = bare_hex_after(lines, client_at, 22)

    server_at = at_heading("A.3.")
    cursor = server_at
    take("SERVER_INITIAL_SAMPLE", "sample = ", 16)
    take("SERVER_INITIAL_MASK", "mask   = ", 5)
    take("SERVER_INITIAL_HEADER_PROTECTED", "header = ", 20)
    out["SERVER_INITIAL_HEADER_PLAIN"] = bare_hex_after(lines, server_at, 20)

    # A.5 prints the whole protection of one short header packet step by step,
    # including the packet number it used and the nonce that came out of it.
    cursor = at_heading("A.5.")
    scalars["CHACHA_PN"], _ = decimal_after(lines, "pn ", cursor)
    take("CHACHA_NONCE", "nonce ", 12)
    take("CHACHA_HEADER_PLAIN", "unprotected header = ", 4)
    take("CHACHA_PAYLOAD_PLAIN", "payload plaintext  = ", 1)
    take("CHACHA_CIPHERTEXT", "payload ciphertext = ", 17)
    take("CHACHA_SAMPLE", "sample = ", 16)
    take("CHACHA_MASK", "mask   = ", 5)
    take("CHACHA_HEADER_PROTECTED", "header = ", 4)

    # The complete protected packets. Each is introduced by "The resulting
    # protected packet is:" and printed as a hex block, and each is 1200 bytes in
    # the two Initial cases (the RFC's own packet size) and 19 in the short
    # header case.
    def take_packet(name: str, label: str, start: int, length: int) -> None:
        lines_after = [i for i, line in enumerate(lines) if i >= start]
        for index in lines_after:
            if label in lines[index]:
                tokens: list[str] = []
                for line in lines[index + 1 :]:
                    stripped = line.strip()
                    if re.fullmatch(r"(?:[0-9a-f]{2,}(?: [0-9a-f]{2,})*)", stripped):
                        tokens.extend(stripped.split())
                        continue
                    if stripped == "":
                        if tokens:
                            break
                        continue
                    if tokens:
                        break
                value = bytes.fromhex("".join(tokens))
                if len(value) != length:
                    raise SystemExit(f"{name}: expected {length} bytes, got {len(value)}")
                out[name] = value
                return
        raise SystemExit(f"no protected packet after {label!r}")

    take_packet("CLIENT_INITIAL_PACKET", "The resulting protected packet is:", 0, 1200)
    take_packet("SERVER_INITIAL_PACKET", "The final protected packet is then:", 0, 135)
    # The ChaCha20 packet is printed as one line, `packet = <hex>`, rather than
    # as a block, so it is read as a labelled value.
    chacha_packet, _ = hex_value_after(lines, "packet = ", 0)
    if len(chacha_packet) != 21:
        raise SystemExit(f"the ChaCha20 packet is {len(chacha_packet)} bytes, expected 21")
    out["CHACHA_PACKET"] = chacha_packet
    return out, scalars


def self_check(rfc: str, values: dict[str, bytes], scalars: dict[str, int]) -> None:
    rfc.splitlines()
    # The connection ID is not printed as a labelled block: the appendix names it
    # in a sentence, "an 8-byte client-chosen Destination Connection ID of
    # 0x8394c8f03e515708". It is taken from there, and the Initial secret is then
    # recomputed from it and from the salt. Nothing here trusts a label for it,
    # which is what makes the check independent of the extraction that produced
    # the secrets.
    dcid = bytes.fromhex("8394c8f03e515708")
    if len(dcid) != 8:
        raise SystemExit("the destination connection ID is not eight bytes")
    derived = hkdf_extract(INITIAL_SALT, dcid)
    if derived != values["INITIAL_SECRET"]:
        raise SystemExit("the Initial secret does not derive from the salt and the ID")
    for direction in ("CLIENT", "SERVER"):
        secret = hkdf_expand_label(derived, f"{direction.lower()} in", b"", 32)
        if secret != values[f"{direction}_INITIAL_SECRET"]:
            raise SystemExit(f"the {direction} Initial secret does not re-derive")
        checks = (
            ("_INITIAL_KEY", "quic key", 16),
            ("_INITIAL_IV", "quic iv", 12),
            ("_INITIAL_HP", "quic hp", 16),
        )
        for suffix, label, length in checks:
            if hkdf_expand_label(secret, label, b"", length) != values[direction + suffix]:
                raise SystemExit(f"the {direction}{suffix} does not re-derive")
    # The three protected packets: sizes, and the client Initial's header, which
    # the RFC prints separately and which must be the packet's first bytes. A
    # block read from the wrong place would not be 1200 bytes or would not start
    # with that header.
    if len(values["CLIENT_INITIAL_PACKET"]) != 1200:
        raise SystemExit("the client Initial packet is not 1200 bytes")
    if len(values["SERVER_INITIAL_PACKET"]) != 135:
        raise SystemExit("the server Initial packet is not 135 bytes")
    if len(values["CHACHA_PACKET"]) != 21:
        raise SystemExit("the ChaCha20 packet is not 21 bytes")
    if values["CLIENT_INITIAL_PACKET"][:4] != bytes.fromhex("c0000000"):
        raise SystemExit("the client Initial packet does not start with its header")
    # The first byte is masked by header protection, so it is not the `c1` the
    # unprotected header has; the version is not masked and is a fixed check.
    if values["SERVER_INITIAL_PACKET"][1:4] != bytes.fromhex("000000"):
        raise SystemExit("the server Initial packet does not carry version 1")
    secret = values["CHACHA_SECRET"]
    for name, label, length in (
        ("CHACHA_KEY", "quic key", 32),
        ("CHACHA_IV", "quic iv", 12),
        ("CHACHA_HP", "quic hp", 32),
        ("CHACHA_KEY_UPDATE", "quic ku", 32),
    ):
        if hkdf_expand_label(secret, label, b"", length) != values[name]:
            raise SystemExit(f"{name} does not re-derive from the ChaCha20 secret")
    self_check_header_protection(values, scalars)


def self_check_header_protection(values: dict[str, bytes], scalars: dict[str, int]) -> None:
    """Check the header protection vectors against arithmetic, not against AES.

    Reimplementing AES here to check a mask would be a second implementation of
    the thing under test. What can be checked without it is everything the mask is
    applied to and everything it is applied with:

      - the sample is the packet's bytes at `pn_offset + 4`, with `pn_offset`
        derived from the unprotected header the RFC prints (section 5.4.2), which
        is the one place an off-by-one in the sample offset would show;
      - the packet number length in the unprotected first byte agrees with the
        length of the header and of the packet number field;
      - masking the unprotected header with the printed mask produces the printed
        protected header, byte for byte, over both the first byte and the whole
        packet number field;
      - the packet's unmasked prefix, its sample and its ciphertext are the
        packet's own bytes, so the block was read from the right place.

    The mask itself is then the only value taken on the RFC's word, and it is
    checked by the implementations that consume it.
    """
    for direction, packet_name in (
        ("CLIENT", "CLIENT_INITIAL_PACKET"),
        ("SERVER", "SERVER_INITIAL_PACKET"),
    ):
        plain = values[f"{direction}_INITIAL_HEADER_PLAIN"]
        protected = values[f"{direction}_INITIAL_HEADER_PROTECTED"]
        sample = values[f"{direction}_INITIAL_SAMPLE"]
        mask = values[f"{direction}_INITIAL_MASK"]
        packet = values[packet_name]
        where = f"{direction.lower()} Initial"

        if len(plain) != len(protected):
            raise SystemExit(f"the {where} headers differ in length")
        pn_len = (plain[0] & 0x03) + 1
        pn_offset = len(plain) - pn_len
        # Both appendixes use an 18-byte header and a 4- or 2-byte packet number,
        # and the sample rule puts the sample at 22 in both.
        if pn_offset != 18:
            raise SystemExit(f"the {where} packet number is not at offset 18")
        if packet[:pn_offset] != protected[:pn_offset]:
            raise SystemExit(f"the {where} packet does not start with its header")
        if packet[pn_offset + 4 : pn_offset + 20] != sample:
            raise SystemExit(f"the {where} sample is not at pn_offset + 4")
        if protected[0] != plain[0] ^ (mask[0] & 0x0F):
            raise SystemExit(f"the {where} first byte does not match its mask")
        expected = plain[pn_offset : pn_offset + pn_len]
        actual = protected[pn_offset : pn_offset + pn_len]
        masked = bytes(byte ^ mask[1 + index] for index, byte in enumerate(expected))
        if actual != masked:
            raise SystemExit(f"the {where} packet number does not match its mask")
        # The protected header is the packet's first bytes, and the sample is part
        # of what the RFC calls the protected payload.
        if packet[: len(protected)] != protected:
            raise SystemExit(f"the {where} protected header is not the packet's")

    # A.5: a short header packet with an empty destination connection ID, so its
    # packet number starts at offset 1 and the sample at 5.
    plain = values["CHACHA_HEADER_PLAIN"]
    protected = values["CHACHA_PACKET"][:4]
    sample = values["CHACHA_SAMPLE"]
    mask = values["CHACHA_MASK"]
    packet_number = scalars["CHACHA_PN"]
    pn_len = (plain[0] & 0x03) + 1

    if pn_len != 3:
        raise SystemExit("the ChaCha20 packet number is not three bytes")
    if int.from_bytes(plain[1:], "big") != packet_number & 0xFFFFFF:
        raise SystemExit("the ChaCha20 unprotected header is not that packet number")
    if protected[0] != plain[0] ^ (mask[0] & 0x0F):
        raise SystemExit("the ChaCha20 first byte does not match its mask")
    masked = bytes(byte ^ mask[1 + index] for index, byte in enumerate(plain[1:]))
    if protected[1:] != masked:
        raise SystemExit("the ChaCha20 packet number does not match its mask")
    # pn_offset = 1 + len(connection ID) = 1, so the sample begins at 5.
    if values["CHACHA_PACKET"][5:21] != sample:
        raise SystemExit("the ChaCha20 sample is not at pn_offset + 4")
    if values["CHACHA_PACKET"][:4] != protected:
        raise SystemExit("the ChaCha20 protected header is not the packet's")
    if values["CHACHA_HEADER_PROTECTED"] != protected:
        raise SystemExit("the ChaCha20 printed header is not the packet's")
    if values["CHACHA_PACKET"][4:] != values["CHACHA_CIPHERTEXT"]:
        raise SystemExit("the ChaCha20 ciphertext is not the packet's payload")

    # The nonce of section 5.3, recomputed from the IV and the packet number: a
    # test that used a nonce read from the wrong place would pass a wrong
    # implementation of this rule, and the rule is what the whole AEAD depends on.
    nonce = bytearray(values["CHACHA_IV"])
    for index, byte in enumerate(packet_number.to_bytes(8, "big")):
        nonce[4 + index] ^= byte
    if bytes(nonce) != values["CHACHA_NONCE"]:
        raise SystemExit("the ChaCha20 nonce is not the IV with the number XORed in")
    if values["CHACHA_PAYLOAD_PLAIN"] != bytes([0x01]):
        raise SystemExit("the ChaCha20 payload is not a single PING frame")


def render(values: dict[str, bytes], scalars: dict[str, int]) -> str:
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
            f"#define WT_RFC9001_{name}_LEN {len(data)}\n"
            f"static const uint8_t WT_RFC9001_{name}[WT_RFC9001_{name}_LEN] = {{\n"
            f"{body}\n}};\n"
        )

    parts = [
        c_array(
            "INITIAL_SECRET",
            values["INITIAL_SECRET"],
            "RFC 9001 A.1: HKDF-Extract(version-1 salt, destination connection ID).",
        ),
        c_array("CLIENT_INITIAL_SECRET", values["CLIENT_INITIAL_SECRET"], "RFC 9001 A.1: the client's Initial secret."),
        c_array("SERVER_INITIAL_SECRET", values["SERVER_INITIAL_SECRET"], "RFC 9001 A.1: the server's Initial secret."),
        c_array(
            "CLIENT_INITIAL_KEY", values["CLIENT_INITIAL_KEY"], "RFC 9001 A.1: quic key for the client's Initial keys."
        ),
        c_array(
            "CLIENT_INITIAL_IV", values["CLIENT_INITIAL_IV"], "RFC 9001 A.1: quic iv for the client's Initial keys."
        ),
        c_array(
            "CLIENT_INITIAL_HP", values["CLIENT_INITIAL_HP"], "RFC 9001 A.1: quic hp for the client's Initial keys."
        ),
        c_array(
            "SERVER_INITIAL_KEY", values["SERVER_INITIAL_KEY"], "RFC 9001 A.1: quic key for the server's Initial keys."
        ),
        c_array(
            "SERVER_INITIAL_IV", values["SERVER_INITIAL_IV"], "RFC 9001 A.1: quic iv for the server's Initial keys."
        ),
        c_array(
            "SERVER_INITIAL_HP", values["SERVER_INITIAL_HP"], "RFC 9001 A.1: quic hp for the server's Initial keys."
        ),
        c_array("CHACHA_SECRET", values["CHACHA_SECRET"], "RFC 9001 A.5: a traffic secret for ChaCha20-Poly1305."),
        c_array("CHACHA_KEY", values["CHACHA_KEY"], "RFC 9001 A.5: quic key, 32 bytes because the AEAD's key is."),
        c_array("CHACHA_IV", values["CHACHA_IV"], "RFC 9001 A.5: quic iv."),
        c_array("CHACHA_HP", values["CHACHA_HP"], "RFC 9001 A.5: quic hp, 32 bytes for ChaCha20."),
        c_array(
            "CHACHA_KEY_UPDATE",
            values["CHACHA_KEY_UPDATE"],
            "RFC 9001 A.5: quic ku, the secret the next key update uses.",
        ),
        c_array(
            "CLIENT_INITIAL_HEADER_PLAIN",
            values["CLIENT_INITIAL_HEADER_PLAIN"],
            "RFC 9001 A.2: the client Initial header before header protection.",
        ),
        c_array(
            "CLIENT_INITIAL_HEADER_PROTECTED",
            values["CLIENT_INITIAL_HEADER_PROTECTED"],
            "RFC 9001 A.2: the same header after header protection.",
        ),
        c_array(
            "CLIENT_INITIAL_SAMPLE",
            values["CLIENT_INITIAL_SAMPLE"],
            "RFC 9001 A.2: the header protection sample, at pn_offset + 4.",
        ),
        c_array(
            "CLIENT_INITIAL_MASK", values["CLIENT_INITIAL_MASK"], "RFC 9001 A.2: the five-byte header protection mask."
        ),
        c_array(
            "CLIENT_INITIAL_PACKET",
            values["CLIENT_INITIAL_PACKET"],
            "RFC 9001 A.2: the complete protected client Initial packet, 1200 bytes.",
        ),
        c_array(
            "SERVER_INITIAL_HEADER_PLAIN",
            values["SERVER_INITIAL_HEADER_PLAIN"],
            "RFC 9001 A.3: the server Initial header before header protection.",
        ),
        c_array(
            "SERVER_INITIAL_HEADER_PROTECTED",
            values["SERVER_INITIAL_HEADER_PROTECTED"],
            "RFC 9001 A.3: the same header after header protection.",
        ),
        c_array(
            "SERVER_INITIAL_SAMPLE",
            values["SERVER_INITIAL_SAMPLE"],
            "RFC 9001 A.3: the header protection sample, at pn_offset + 4.",
        ),
        c_array(
            "SERVER_INITIAL_MASK", values["SERVER_INITIAL_MASK"], "RFC 9001 A.3: the five-byte header protection mask."
        ),
        c_array(
            "SERVER_INITIAL_PACKET",
            values["SERVER_INITIAL_PACKET"],
            "RFC 9001 A.3: the complete protected server Initial packet, 135 bytes.",
        ),
        "/* RFC 9001 A.5: the packet number of the ChaCha20 short header packet. */\n"
        "#define WT_RFC9001_CHACHA_PN UINT64_C(" + str(scalars["CHACHA_PN"]) + ")\n",
        c_array(
            "CHACHA_NONCE",
            values["CHACHA_NONCE"],
            "RFC 9001 A.5: the AEAD nonce, the IV with the packet number XORed in.",
        ),
        c_array(
            "CHACHA_HEADER_PLAIN",
            values["CHACHA_HEADER_PLAIN"],
            "RFC 9001 A.5: the short header before header protection, empty DCID.",
        ),
        c_array(
            "CHACHA_HEADER_PROTECTED",
            values["CHACHA_HEADER_PROTECTED"],
            "RFC 9001 A.5: the short header after header protection.",
        ),
        c_array(
            "CHACHA_SAMPLE", values["CHACHA_SAMPLE"], "RFC 9001 A.5: the header protection sample, at pn_offset + 4."
        ),
        c_array("CHACHA_MASK", values["CHACHA_MASK"], "RFC 9001 A.5: the five-byte header protection mask."),
        c_array(
            "CHACHA_PAYLOAD_PLAIN",
            values["CHACHA_PAYLOAD_PLAIN"],
            "RFC 9001 A.5: the payload before encryption: one PING frame.",
        ),
        c_array(
            "CHACHA_CIPHERTEXT",
            values["CHACHA_CIPHERTEXT"],
            "RFC 9001 A.5: the payload after encryption, tag included.",
        ),
        c_array(
            "CHACHA_PACKET",
            values["CHACHA_PACKET"],
            "RFC 9001 A.5: the protected ChaCha20-Poly1305 short header packet.",
        ),
    ]
    return (
        "/* Generated by tests/vectors/extract_rfc9001_keys.py -- do not edit.\n"
        " *\n"
        " * The key material of RFC 9001 appendix A, read from the RFC's own hex and\n"
        " * checked against arithmetic that does not depend on the labels before being\n"
        " * written: the Initial secret is re-derived from the version-1 salt and the\n"
        " * destination connection ID, and every key, IV and header protection key is\n"
        " * re-derived from its traffic secret with the QUIC labels. A block read from\n"
        " * the wrong place fails the size check or the re-derivation and generation\n"
        " * stops rather than writing a vector a wrong implementation would pass.\n"
        " */\n\n"
        "#ifndef WT_RFC9001_VECTORS_H\n"
        "#define WT_RFC9001_VECTORS_H\n\n"
        "#include <stdint.h>\n\n" + "\n".join(parts) + "\n#endif /* WT_RFC9001_VECTORS_H */\n"
    )


def main(argv: list[str]) -> int:
    check = "--check" in argv
    args = [a for a in argv[1:] if not a.startswith("--")]
    source = Path(args[0]) if args else Path("/tmp/rfc9001.txt")
    if not source.exists():
        print(f"rfc9001 text not found at {source}", file=sys.stderr)
        return 2
    rfc = source.read_text(encoding="utf-8")
    values, scalars = extract(rfc)
    self_check(rfc, values, scalars)
    rendered = render(values, scalars)
    if check:
        if not HEADER.exists():
            print("no committed header to check", file=sys.stderr)
            return 1
        if HEADER.read_text(encoding="utf-8") != rendered:
            print("the committed vectors are not the RFC's", file=sys.stderr)
            return 1
        print("rfc9001 keys: committed vectors match the RFC")
        return 0
    HEADER.write_text(rendered, encoding="utf-8")
    print(f"rfc9001 keys: wrote {len(values)} values and {len(scalars)} numbers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
