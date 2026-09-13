"""Open one QUIC packet with a traffic secret from a keylog, independently (WT-135).

RFC 9001's vectors in the C99 tree cover the INITIAL epoch; nothing covers HANDSHAKE, and a packet this client sent
with a secret the peer's own keylog confirms could not be read by that peer. This script is the second
implementation: it derives `quic key`/`quic iv`/`quic hp` from a secret, removes header protection and opens the
AEAD -- and if it succeeds where the peer failed, the difference is in the packet rather than in the keys.

Usage:  decrypt_packet.py <kind: initial|handshake|application> <secret-hex> <packet-number> <packet-hex>
Requires: the `cryptography` package (already present in the aioquic peer image).
"""

import binascii
import hashlib
import hmac
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand, HKDF


def expand_label(secret: bytes, label: str, length: int) -> bytes:
    """RFC 8446 section 7.1's HKDF-Expand-Label with the TLS 1.3 label prefix."""
    full = b"tls13 " + label.encode()
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(secret)


def varint_read(data: bytes, offset: int):
    first = data[offset]
    prefix = first >> 6
    length = 1 << prefix
    value = first & 0x3F
    for i in range(1, length):
        value = (value << 8) | data[offset + i]
    return value, offset + length


INITIAL_SALT = binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")  # RFC 9001 section 5.2


def initial_client_secret(dcid: bytes) -> bytes:
    """RFC 9001 section 5.2: the Initial secret comes from the connection ID, so no keylog is needed."""
    # HKDF-EXTRACT, not extract-then-expand: RFC 9001 section 5.2's initial_secret IS the PRK, and asking
    # `cryptography`'s HKDF for 32 bytes would give Expand(PRK, "", 32) -- HMAC(PRK, 0x01) -- which is a different
    # value and was this tool's bug for one round.
    initial_secret = hmac.new(INITIAL_SALT, dcid, hashlib.sha256).digest()
    return expand_label(initial_secret, "client in", 32)


def open_packet(secret: bytes, packet: bytearray, packet_number: int, long_header: bool,
                initial: bool = False) -> int:
    """Derive the keys, remove header protection and open the AEAD. Returns 0 on success."""
    key = expand_label(secret, "quic key", 16)
    iv = expand_label(secret, "quic iv", 12)
    hp = expand_label(secret, "quic hp", 16)

    if long_header:
        offset = 5
        dcid_len = packet[offset]
        offset += 1 + dcid_len
        scid_len = packet[offset]
        offset += 1 + scid_len
        if initial:
            # An Initial packet carries a Token field between the source connection ID and the Length, and
            # skipping it is what kept this tool from opening one for a round.
            token_length, offset = varint_read(packet, offset)
            offset += token_length
        _, offset = varint_read(packet, offset)
    else:
        offset = 1
    pn_offset = offset

    for candidate in (1, 2, 3, 4):
        sample_offset = pn_offset + 4
        if sample_offset + 16 > len(packet):
            continue
        sample = bytes(packet[sample_offset:sample_offset + 16])
        mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)
        header = bytearray(packet[:pn_offset + candidate])
        if long_header:
            header[0] ^= mask[0] & 0x0F
        else:
            header[0] ^= mask[0] & 0x1F
        for i in range(candidate):
            header[pn_offset + i] ^= mask[1 + i]
        truncated = int.from_bytes(header[pn_offset:pn_offset + candidate], "big")
        full_pn = truncated
        nonce = bytearray(iv)
        pn_bytes = full_pn.to_bytes(8, "big")
        for i in range(8):
            nonce[4 + i] ^= pn_bytes[i]
        try:
            plaintext = AESGCM(key).decrypt(bytes(nonce), bytes(packet[pn_offset + candidate:]), bytes(header))
        except Exception as error:  # noqa: BLE001 - reporting the failure is the point
            print(f"pn_length={candidate}: AEAD failed ({error})")
            continue
        print(f"pn_length={candidate}: OPENED packet_number={full_pn} plaintext={plaintext.hex()}")
        return 0
    print("no packet number length opened the packet")
    return 1


def main() -> int:
    if sys.argv[1] == "initial-from-dcid":
        # RFC 9001 section 5.2: the Initial secret comes from the connection ID, so no keylog is needed.
        packet = bytearray(binascii.unhexlify(sys.argv[2]))
        dcid = bytes(packet[6:6 + packet[5]])
        return open_packet(initial_client_secret(dcid), packet, 0, True, initial=True)
    kind = sys.argv[1]
    secret = binascii.unhexlify(sys.argv[2])
    packet_number = int(sys.argv[3])
    packet = bytearray(binascii.unhexlify(sys.argv[4]))
    return open_packet(secret, packet, packet_number, kind in ("initial", "handshake"))


if __name__ == "__main__":
    sys.exit(main())
