"""Open one QUIC packet with a traffic secret from a keylog, independently (WT-135).

RFC 9001's vectors in the C99 tree cover the INITIAL epoch; nothing covers HANDSHAKE, and a packet this client sent
with a secret the peer's own keylog confirms could not be read by that peer. This script is the second
implementation: it derives `quic key`/`quic iv`/`quic hp` from a secret, removes header protection and opens the
AEAD -- and if it succeeds where the peer failed, the difference is in the packet rather than in the keys.

Usage:  decrypt_packet.py <kind: initial|handshake|application> <secret-hex> <packet-number> <packet-hex>
Requires: the `cryptography` package (already present in the aioquic peer image).
"""

import binascii
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


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


def main() -> int:
    kind = sys.argv[1]
    secret = binascii.unhexlify(sys.argv[2])
    packet_number = int(sys.argv[3])
    packet = bytearray(binascii.unhexlify(sys.argv[4]))

    key = expand_label(secret, "quic key", 16)
    iv = expand_label(secret, "quic iv", 12)
    hp = expand_label(secret, "quic hp", 16)

    # Walk the long header to the packet number field: version(4) dcid_len dcid scid_len scid length pn.
    offset = 5
    dcid_len = packet[offset]
    offset += 1 + dcid_len
    scid_len = packet[offset]
    offset += 1 + scid_len
    _, offset = varint_read(packet, offset)
    pn_offset = offset
    pn_length = 4 if kind == "initial" else 2  # this client uses one byte for Handshake; try both below

    for candidate in (1, 2, 3, 4):
        sample_offset = pn_offset + 4
        if sample_offset + 16 > len(packet):
            continue
        sample = bytes(packet[sample_offset:sample_offset + 16])
        mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)
        header = bytearray(packet[:pn_offset + candidate])
        header[0] ^= mask[0] & 0x0F
        for i in range(candidate):
            header[pn_offset + i] ^= mask[1 + i]
        truncated = int.from_bytes(header[pn_offset:pn_offset + candidate], "big")
        # Reconstruct the full number from the largest seen (we log it, so the truncated value is used as is when
        # it fits, which it does for the small numbers of a handshake).
        full_pn = truncated if truncated >= (packet_number & 0xFF) - 128 else truncated
        nonce = bytearray(iv)
        pn_bytes = full_pn.to_bytes(8, "big")
        for i in range(8):
            nonce[12 - 8 + i] ^= pn_bytes[i]
        aad = bytes(header)
        ciphertext = bytes(packet[pn_offset + candidate:])
        try:
            plaintext = AESGCM(key).decrypt(bytes(nonce), ciphertext, aad)
        except Exception as error:  # noqa: BLE001 - the point is to report the failure
            print(f"pn_length={candidate}: AEAD failed ({error})")
            continue
        print(f"pn_length={candidate}: OPENED, packet_number={full_pn}, plaintext={plaintext[:24].hex()}")
        return 0
    print("no packet number length opened the packet")
    return 1


if __name__ == "__main__":
    sys.exit(main())
