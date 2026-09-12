#!/usr/bin/env python3
"""Extract RFC 8448's 1-RTT key schedule trace, and check every value by re-deriving it.

RFC 8448 section 3 prints a complete TLS 1.3 handshake with every intermediate value
of the key schedule: the two extracts that build it out of PSK and ECDHE, the two
"derived" steps that chain it, the handshake and application traffic secrets, the
record traffic keys, the Finished keys and verify data, and the transcript hash at
each point where the schedule consumes one. It also prints the handshake messages
themselves, which is what makes the trace checkable: the messages can be hashed and
the result compared with the hash the schedule says it used.

The tests need those values, and a value read from the wrong place in a 3,800 line
document is exactly the mistake that makes a test pass against a wrong
implementation. So nothing is written until the whole schedule has been recomputed
from first principles and agreed with what the labels point at:

  - each `extract secret` step is recomputed as HMAC(salt, IKM);
  - each `derive secret` step is recomputed as HKDF-Expand-Label(PRK, label, hash);
  - each traffic key is recomputed as HKDF-Expand-Label(PRK, "key"/"iv", "");
  - each Finished key is recomputed as HKDF-Expand-Label(PRK, "finished", ""), and
    each verify data as HMAC(that key, transcript hash);
  - the schedule is checked as a chain: the salt of each extract is the output of
    the "derived" step before it, and the PRK of each derivation is the secret the
    step before it produced;
  - and the transcript hashes are checked against the extracted handshake messages,
    so a message read from the wrong place fails here rather than producing a vector
    a wrong implementation would pass.

    python3 tests/vectors/extract_rfc8448_keyschedule.py [rfc8448.txt] [--check]

With no arguments it looks for `/tmp/rfc8448.txt` and writes
`tests/vectors/rfc8448_vectors.h`. With `--check` it re-extracts and compares against
the committed header, which is how the committed bytes stay the RFC's.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HEADER = HERE / "rfc8448_vectors.h"

# The section to read. Section 3 is the simple 1-RTT handshake, which exercises the
# whole schedule once; the later sections repeat parts of it for 0-RTT, retry and
# client authentication, and reading them too would mean deciding which of several
# occurrences of a label is the one meant.
SECTION_START = "3.  Simple 1-RTT Handshake"
SECTION_END = "4.  Resumed 0-RTT Handshake"

# The page furniture of the plain-text RFC, which interrupts a value's hex between
# the lines that belong to it and would otherwise be read as part of the value.
NOISE = re.compile(r"^(Thomson|RFC 8448\b|\x0c|\[Page)")

# A value line inside a step: an optional two-word name, an optional octet count,
# and the hex, which may continue on the following lines.
VALUE = re.compile(r"^\s+([A-Za-z][A-Za-z0-9 _-]*?)\s*"
                   r"(?:\((\d+) octets?\))?\s*:\s*(.*)$")

# A step header: who did it, what they did, and the label they did it under.
# Every kind of step the trace prints, not only the ones a vector comes from: a
# step's values are delimited by the next step header, so a kind that is not matched
# lets the previous step's window swallow its values. That is how the server's
# abbreviated "res master" step first read the ticket nonce of the resumption step
# below it as its transcript hash.
# Every kind of step the trace prints, not only the ones a vector comes from: a
# step's values are delimited by the next step header, so a kind that is not matched
# lets the previous step's window swallow its values. Two of the kinds below -- the
# traffic key derivations and the message constructions -- have no quoted label, and
# one of the derivations carries "for handshake" or "for master" where the others
# have nothing, so the header is matched loosely and taken apart afterwards.
STEP = re.compile(
    r"^\s*\{(\w+)\}\s+"
    r"(extract secret|derive secret|calculate finished|generate resumption secret"
    r"|derive write traffic keys|derive read traffic keys|construct|create"
    r"|send|receive)\b(.*)$"
)
QUALIFIER = re.compile(r"\bfor (handshake|master)\b")
QUOTED = re.compile(r'"([^"]+)"')

HEX_ONLY = re.compile(r"^[0-9a-f]{2}(?: [0-9a-f]{2})*$")

# The four record traffic key sets RFC 8448 section 3 prints, one per direction of
# each epoch, with the secret each is derived from. The trace's "(same as ...)" notes
# are about the READ keys of the other side, which are these same values.
KEY_SETS = (
    ("SERVER_HANDSHAKE_KEY", "SERVER_HANDSHAKE_IV", "SERVER_HANDSHAKE_SECRET"),
    ("SERVER_APPLICATION_KEY", "SERVER_APPLICATION_IV", "SERVER_APPLICATION_SECRET"),
    ("CLIENT_HANDSHAKE_KEY", "CLIENT_HANDSHAKE_IV", "CLIENT_HANDSHAKE_SECRET"),
    ("CLIENT_APPLICATION_KEY", "CLIENT_APPLICATION_IV", "CLIENT_APPLICATION_SECRET"),
)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    full = b"tls13 " + label.encode()
    info = (
        length.to_bytes(2, "big")
        + bytes([len(full)])
        + full
        + bytes([len(context)])
        + context
    )
    return hkdf_expand(secret, info, length)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def clean_section(rfc: str) -> list[str]:
    lines = rfc.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(SECTION_START))
    end = next(i for i, line in enumerate(lines) if line.startswith(SECTION_END))
    return ["" if NOISE.match(line) else line for line in lines[start:end]]


def read_value(lines: list[str], index: int) -> tuple[str, bytes, int]:
    """One value at `index`: its name, its bytes, and the line after it.

    A value is `name (N octets): hex`, continued on the lines below until the
    declared number of octets has been read -- not until a blank line, because a
    page break lands in the middle of a long value and the lines it inserts are
    blank once the page furniture is removed. A bare `name: 0 (all zero octets)` is
    the trace's way of writing a salt of zeroes. The count is checked against what
    was read, so a value cut short is refused rather than silently shorter than the
    document says it is.
    """
    found = VALUE.match(lines[index])
    if found is None:
        raise SystemExit(f"line {index}: not a value line")
    name, count, text = found.group(1).strip(), found.group(2), found.group(3)
    text = text.strip()
    if count is None:
        if "all zero octets" not in text:
            raise SystemExit(f"line {index}: {name!r} has no octet count")
        return name, bytes(32), index + 1

    expected = int(count)
    tokens: list[str] = []
    if text != "" and text != "(empty)":
        if not HEX_ONLY.match(text):
            raise SystemExit(f"line {index}: {name!r} has unreadable hex {text!r}")
        tokens.append(text)
    probe = index + 1
    read = len(tokens[0].split()) if tokens else 0
    while read < expected and probe < len(lines):
        stripped = lines[probe].strip()
        if stripped == "":
            probe += 1
            continue
        if not HEX_ONLY.match(stripped):
            break
        tokens.append(stripped)
        read += len(stripped.split())
        probe += 1
    value = bytes.fromhex("".join(tokens).replace(" ", "")) if tokens else b""
    if len(value) != expected:
        raise SystemExit(
            f"line {index}: {name!r} says {expected} octets, read {len(value)}"
        )
    return name, value, probe


def parse_values(lines: list[str], at: int, limit: int) -> dict[str, bytes]:
    """Every named value printed between `at` and `limit`."""
    values: dict[str, bytes] = {}
    index = at
    while index < limit:
        if VALUE.match(lines[index]) is None:
            index += 1
            continue
        name, value, index = read_value(lines, index)
        values[name] = value
    return values


def parse_steps(lines: list[str]) -> list[dict]:
    headers = [
        (index, STEP.match(line)) for index, line in enumerate(lines) if STEP.match(line)
    ]
    steps = []
    for position, (index, found) in enumerate(headers):
        limit = headers[position + 1][0] if position + 1 < len(headers) else len(lines)
        rest = found.group(3)
        qualifier = QUALIFIER.search(rest)
        quoted = QUOTED.search(rest)
        steps.append(
            {
                "actor": found.group(1),
                "kind": found.group(2),
                "qualifier": qualifier.group(1) if qualifier else None,
                "label": quoted.group(1) if quoted else rest.strip().rstrip(":").strip(),
                "values": parse_values(lines, index + 1, limit),
            }
        )
    return steps


def take(steps: list[dict], kind: str, label: str, qualifier: str | None = None,
         actor: str = "server", occurrence: int = 1,
         require: str | None = None) -> dict:
    """The `occurrence`-th step of its kind, in document order.

    A forward search rather than a dictionary keyed by label, because RFC 8448
    prints the same label more than once -- the client repeats the server's
    derivations, and "derived" is a label of two different steps -- so the order is
    what identifies a step. `require` names a value the step must have printed: the
    trace abbreviates a repeated step to "(same as server)" and prints no values
    under it, and those steps are not the ones a vector can come from.
    """
    seen = 0
    for step in steps:
        if step["kind"] != kind or step["label"] != label:
            continue
        if qualifier is not None and step["qualifier"] != qualifier:
            continue
        if step["actor"] != actor:
            continue
        if require is not None and require not in step["values"]:
            continue
        seen += 1
        if seen == occurrence:
            return step
    raise SystemExit(f"no {kind} step for {label!r} ({qualifier!r}, {actor})")


def extract(rfc: str) -> dict[str, bytes]:
    lines = clean_section(rfc)
    steps = parse_steps(lines)
    out: dict[str, bytes] = {}

    # The extracts, which are HMAC with the salt as the key. The IKM of the
    # handshake extract is the ECDHE shared secret, and the IKM of the master
    # extract is a string of zeroes -- both of which the checks below rely on.
    early = take(steps, "extract secret", "early", require="secret")
    handshake = take(steps, "extract secret", "handshake", require="secret")
    master = take(steps, "extract secret", "master", require="secret")
    out["ECDHE"] = handshake["values"]["IKM"]
    out["EARLY_SECRET"] = early["values"]["secret"]
    out["HANDSHAKE_SECRET"] = handshake["values"]["secret"]
    out["MASTER_SECRET"] = master["values"]["secret"]

    derived_for_handshake = take(steps, "derive secret", "tls13 derived", "handshake", require="expanded")
    derived_for_master = take(steps, "derive secret", "tls13 derived", "master", require="expanded")
    out["EMPTY_HASH"] = derived_for_handshake["values"]["hash"]
    # The "derived" steps' outputs. They are printed twice in the trace -- once as
    # the derivation and once as the next extract's salt -- which is what lets
    # self_check require them to be the same bytes.
    out["DERIVED_FOR_HANDSHAKE"] = derived_for_handshake["values"]["expanded"]
    out["DERIVED_FOR_MASTER"] = derived_for_master["values"]["expanded"]
    check_chain(early, derived_for_handshake, handshake, "handshake")
    check_chain(handshake, derived_for_master, master, "master")

    out["CLIENT_HANDSHAKE_SECRET"] = take(
        steps, "derive secret", "tls13 c hs traffic", require="expanded"
    )["values"]["expanded"]
    out["SERVER_HANDSHAKE_SECRET"] = take(
        steps, "derive secret", "tls13 s hs traffic", require="expanded"
    )["values"]["expanded"]
    out["HASH_AFTER_SERVER_HELLO"] = take(
        steps, "derive secret", "tls13 c hs traffic", require="expanded"
    )["values"]["hash"]

    out["CLIENT_APPLICATION_SECRET"] = take(
        steps, "derive secret", "tls13 c ap traffic", require="expanded"
    )["values"]["expanded"]
    out["SERVER_APPLICATION_SECRET"] = take(
        steps, "derive secret", "tls13 s ap traffic", require="expanded"
    )["values"]["expanded"]
    out["EXPORTER_MASTER"] = take(steps, "derive secret", "tls13 exp master", require="expanded")["values"][
        "expanded"
    ]
    out["HASH_AFTER_SERVER_FINISHED"] = take(
        steps, "derive secret", "tls13 c ap traffic", require="expanded"
    )["values"]["hash"]
    # The resumption master secret is the one derivation only the client prints in
    # full: the server's line says "(same as client)".
    resumption = take(steps, "derive secret", "tls13 res master", actor="client",
                      require="expanded")
    out["RESUMPTION_MASTER"] = resumption["values"]["expanded"]
    out["HASH_AFTER_CLIENT_FINISHED"] = resumption["values"]["hash"]

    # The Finished steps. The `hash` field is empty in the trace: it is the context
    # of the HKDF expansion (empty, because the label has none), not the transcript
    # the MAC is taken over, which is why the verify data is checked in transit
    # below rather than here.
    server_finished = take(steps, "calculate finished", "tls13 finished",
                           require="finished")
    client_finished = take(steps, "calculate finished", "tls13 finished",
                           actor="client", require="finished")
    out["SERVER_FINISHED_KEY"] = server_finished["values"]["expanded"]
    out["SERVER_FINISHED"] = server_finished["values"]["finished"]
    out["CLIENT_FINISHED_KEY"] = client_finished["values"]["expanded"]
    out["CLIENT_FINISHED"] = client_finished["values"]["finished"]

    # The handshake messages, in the order the transcript consumes them. These are
    # the messages the trace's own transcript hashes are over, so extracting them
    # wrongly fails the hash checks in self_check.
    for name, label, message_type in (
        ("CLIENT_HELLO", "ClientHello", 0x01),
        ("SERVER_HELLO", "ServerHello", 0x02),
        ("ENCRYPTED_EXTENSIONS", "EncryptedExtensions", 0x08),
        ("CERTIFICATE", "Certificate", 0x0B),
        ("CERTIFICATE_VERIFY", "CertificateVerify", 0x0F),
        ("SERVER_FINISHED_MESSAGE", "Finished", 0x14),
    ):
        message = take_message(lines, label, message_type)
        out[name] = message

    # The record traffic keys, one set per direction of each epoch.
    keys = [step for step in steps if "key expanded" in step["values"]]
    if len(keys) != len(KEY_SETS):
        raise SystemExit(
            f"expected {len(KEY_SETS)} traffic key steps, found {len(keys)}"
        )
    for key_name, iv_name, secret_name in KEY_SETS:
        # Which secret a key set belongs to is decided by the PRK the trace printed
        # beside it, not by the order the steps appear in: the order is the
        # document's, and a vector keyed on it would be a vector keyed on a page
        # layout.
        matching = [step for step in keys if step["values"]["PRK"] == out[secret_name]]
        if len(matching) != 1:
            raise SystemExit(
                f"{len(matching)} traffic key steps use {secret_name}"
            )
        out[key_name] = matching[0]["values"]["key expanded"]
        out[iv_name] = matching[0]["values"]["iv expanded"]

    # The client's Finished message, which the transcript consumes last.
    out["CLIENT_FINISHED_MESSAGE"] = take_message(lines, "Finished", 0x14, occurrence=2)

    # Both sides' ephemeral x25519 key pairs. They are what makes RFC 8448's ECDHE
    # checkable against the key agreement rather than only against itself: the shared
    # secret the schedule consumes must be X25519(client private, server public), and each
    # public key must be X25519(private, 9). The ladder that checks those is in the C
    # test, where it is itself checked against RFC 7748's vectors; this file takes the
    # bytes and checks what it can without a curve implementation.
    for actor, prefix in (("client", "CLIENT_X25519"), ("server", "SERVER_X25519")):
        step = take(steps, "create", "an ephemeral x25519 key pair", actor=actor,
                    require="private key")
        out[prefix + "_PRIVATE"] = step["values"]["private key"]
        out[prefix + "_PUBLIC"] = step["values"]["public key"]
    return out


def take_message(lines: list[str], label: str, message_type: int,
                 occurrence: int = 1) -> bytes:
    """A printed handshake message: `Label (N octets):` and its hex.

    The length in the label is checked against the message's own header as well as
    against what was read, so a block taken from the wrong place is refused twice
    over.
    """
    seen = 0
    for index, line in enumerate(lines):
        found = VALUE.match(line)
        if found is None or found.group(1).strip() != label or found.group(2) is None:
            continue
        seen += 1
        if seen != occurrence:
            continue
        name, message, _ = read_value(lines, index)
        if name != label:
            raise SystemExit(f"expected {label!r} at line {index}, found {name!r}")
        if message[0] != message_type:
            raise SystemExit(
                f"{label}: starts with {message[0]:#04x}, expected {message_type:#04x}"
            )
        declared = int.from_bytes(message[1:4], "big") + 4
        if declared != len(message):
            raise SystemExit(
                f"{label}: header says {declared} octets, extracted {len(message)}"
            )
        return message
    raise SystemExit(f"no {label} message (occurrence {occurrence})")


def check_chain(before: dict, derived: dict, extract: dict, what: str) -> None:
    """The "derived" step's output must be the next extract's salt.

    This is the check that makes the schedule a chain rather than a set of values:
    RFC 8448 prints the derived secret and then prints it again as the salt of the
    extract that consumes it, and the two must be the same bytes.
    """
    if derived["values"]["expanded"] != extract["values"]["salt"]:
        raise SystemExit(
            f'the "derived" step for {what} is not the salt of its extract'
        )
    if extract["kind"] != "extract secret":
        raise SystemExit(f"the {what} step after a derivation is not an extract")


def self_check(values: dict[str, bytes]) -> None:
    """Recompute the whole schedule and the three transcript checkpoints."""
    empty_hash = hashlib.sha256(b"").digest()
    if values["EMPTY_HASH"] != empty_hash:
        raise SystemExit("the empty transcript hash is not SHA-256 of the empty string")

    # The two ephemeral key pairs: four 32-byte values, all distinct, and none of them the
    # shared secret. The derivations that connect them are checked in C, where the ladder
    # has RFC 7748's vectors behind it.
    keys = {}
    for name in ("CLIENT_X25519_PRIVATE", "CLIENT_X25519_PUBLIC",
                 "SERVER_X25519_PRIVATE", "SERVER_X25519_PUBLIC"):
        if len(values[name]) != 32:
            raise SystemExit(f"{name} is not 32 bytes")
        if values[name] in keys.values():
            raise SystemExit(f"{name} repeats another key")
        keys[name] = values[name]
    if values["ECDHE"] in keys.values():
        raise SystemExit("the shared secret is one of the keys, which cannot be")

    early = hkdf_extract(bytes(32), bytes(32))
    if early != values["EARLY_SECRET"]:
        raise SystemExit("the early secret does not re-derive")
    derived = hkdf_expand_label(early, "derived", empty_hash, 32)
    handshake = hkdf_extract(derived, values["ECDHE"])
    if handshake != values["HANDSHAKE_SECRET"]:
        raise SystemExit("the handshake secret does not re-derive from the ECDHE")
    derived_master = hkdf_expand_label(handshake, "derived", empty_hash, 32)
    master = hkdf_extract(derived_master, bytes(32))
    if master != values["MASTER_SECRET"]:
        raise SystemExit("the master secret does not re-derive")

    # The transcript, built from the extracted messages and compared with the hash
    # the schedule says it used at each point.
    transcript = b""
    points = (
        ("HASH_AFTER_SERVER_HELLO", ("CLIENT_HELLO", "SERVER_HELLO")),
        ("HASH_AFTER_SERVER_FINISHED",
         ("CLIENT_HELLO", "SERVER_HELLO", "ENCRYPTED_EXTENSIONS", "CERTIFICATE",
          "CERTIFICATE_VERIFY", "SERVER_FINISHED_MESSAGE")),
        ("HASH_AFTER_CLIENT_FINISHED",
         ("CLIENT_HELLO", "SERVER_HELLO", "ENCRYPTED_EXTENSIONS", "CERTIFICATE",
          "CERTIFICATE_VERIFY", "SERVER_FINISHED_MESSAGE", "CLIENT_FINISHED_MESSAGE")),
    )
    consumed = 0
    for name, order in points:
        while consumed < len(order):
            transcript += values[order[consumed]]
            consumed += 1
        if hashlib.sha256(transcript).digest() != values[name]:
            raise SystemExit(f"{name} is not the hash of the extracted messages")

    # The handshake traffic secrets, from the handshake secret and that hash.
    for name, label in (
        ("CLIENT_HANDSHAKE_SECRET", "c hs traffic"),
        ("SERVER_HANDSHAKE_SECRET", "s hs traffic"),
    ):
        want = hkdf_expand_label(handshake, label, values["HASH_AFTER_SERVER_HELLO"], 32)
        if want != values[name]:
            raise SystemExit(f"{name} does not re-derive")

    for name, label in (
        ("CLIENT_APPLICATION_SECRET", "c ap traffic"),
        ("SERVER_APPLICATION_SECRET", "s ap traffic"),
        ("EXPORTER_MASTER", "exp master"),
    ):
        want = hkdf_expand_label(master, label, values["HASH_AFTER_SERVER_FINISHED"], 32)
        if want != values[name]:
            raise SystemExit(f"{name} does not re-derive")
    want = hkdf_expand_label(master, "res master", values["HASH_AFTER_CLIENT_FINISHED"], 32)
    if want != values["RESUMPTION_MASTER"]:
        raise SystemExit("the resumption master secret does not re-derive")

    # The traffic keys and the Finished keys and verify data, each from the secret
    # its step printed as the PRK.
    for key_name, iv_name, secret_name in KEY_SETS:
        if hkdf_expand_label(values[secret_name], "key", b"", 16) != values[key_name]:
            raise SystemExit(f"{key_name} does not re-derive")
        if hkdf_expand_label(values[secret_name], "iv", b"", 12) != values[iv_name]:
            raise SystemExit(f"{iv_name} does not re-derive")

    for key_name, data_name, secret_name, transcript_name in (
        ("SERVER_FINISHED_KEY", "SERVER_FINISHED", "SERVER_HANDSHAKE_SECRET",
         "SERVER_FINISHED_TRANSCRIPT"),
        ("CLIENT_FINISHED_KEY", "CLIENT_FINISHED", "CLIENT_HANDSHAKE_SECRET",
         "HASH_AFTER_SERVER_FINISHED"),
    ):
        if hkdf_expand_label(values[secret_name], "finished", b"", 32) != values[key_name]:
            raise SystemExit(f"{key_name} does not re-derive")
        if transcript_name == "SERVER_FINISHED_TRANSCRIPT":
            # The server's Finished is over the transcript through
            # CertificateVerify, which the RFC does not print as a step hash. It is
            # the transcript with the server's Finished message not yet absorbed.
            through = hashlib.sha256(
                b"".join(
                    values[name]
                    for name in ("CLIENT_HELLO", "SERVER_HELLO",
                                 "ENCRYPTED_EXTENSIONS", "CERTIFICATE",
                                 "CERTIFICATE_VERIFY")
                )
            ).digest()
        else:
            through = values[transcript_name]
        if hmac.new(values[key_name], through, hashlib.sha256).digest() != values[data_name]:
            raise SystemExit(f"{data_name} does not re-derive from its transcript")


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
            f"#define WT_RFC8448_{name}_LEN {len(data)}\n"
            f"static const uint8_t WT_RFC8448_{name}[WT_RFC8448_{name}_LEN] = {{\n"
            f"{body}\n}};\n"
        )

    parts = [
        c_array("ECDHE", values["ECDHE"],
                "RFC 8448 section 3: the x25519 shared secret, the handshake extract's IKM."),
        c_array("EMPTY_HASH", values["EMPTY_HASH"],
                "SHA-256 of the empty string, the hash both \"derived\" steps use."),
        c_array("DERIVED_FOR_HANDSHAKE", values["DERIVED_FOR_HANDSHAKE"],
                "Derive-Secret(early_secret, \"derived\", \"\"), the handshake extract's salt."),
        c_array("DERIVED_FOR_MASTER", values["DERIVED_FOR_MASTER"],
                "Derive-Secret(handshake_secret, \"derived\", \"\"), the master extract's salt."),
        c_array("EARLY_SECRET", values["EARLY_SECRET"],
                "The Early Secret, HKDF-Extract of a zero PSK."),
        c_array("HANDSHAKE_SECRET", values["HANDSHAKE_SECRET"],
                "The Handshake Secret."),
        c_array("MASTER_SECRET", values["MASTER_SECRET"], "The Master Secret."),
        c_array("CLIENT_HANDSHAKE_SECRET", values["CLIENT_HANDSHAKE_SECRET"],
                "client_handshake_traffic_secret, from Hash(ClientHello..ServerHello)."),
        c_array("SERVER_HANDSHAKE_SECRET", values["SERVER_HANDSHAKE_SECRET"],
                "server_handshake_traffic_secret."),
        c_array("CLIENT_APPLICATION_SECRET", values["CLIENT_APPLICATION_SECRET"],
                "client_application_traffic_secret_0, from Hash(ClientHello..server Finished)."),
        c_array("SERVER_APPLICATION_SECRET", values["SERVER_APPLICATION_SECRET"],
                "server_application_traffic_secret_0."),
        c_array("EXPORTER_MASTER", values["EXPORTER_MASTER"],
                "exporter_master_secret."),
        c_array("RESUMPTION_MASTER", values["RESUMPTION_MASTER"],
                "resumption_master_secret, from Hash(ClientHello..client Finished)."),
        c_array("SERVER_HANDSHAKE_KEY", values["SERVER_HANDSHAKE_KEY"],
                "The server's handshake record key, HKDF-Expand-Label(secret, \"key\")."),
        c_array("SERVER_HANDSHAKE_IV", values["SERVER_HANDSHAKE_IV"],
                "The server's handshake record IV."),
        c_array("SERVER_APPLICATION_KEY", values["SERVER_APPLICATION_KEY"],
                "The server's application record key."),
        c_array("SERVER_APPLICATION_IV", values["SERVER_APPLICATION_IV"],
                "The server's application record IV."),
        c_array("CLIENT_APPLICATION_KEY", values["CLIENT_APPLICATION_KEY"],
                "The client's application record key."),
        c_array("CLIENT_APPLICATION_IV", values["CLIENT_APPLICATION_IV"],
                "The client's application record IV."),
        c_array("CLIENT_HANDSHAKE_KEY", values["CLIENT_HANDSHAKE_KEY"],
                "The client's handshake record key."),
        c_array("CLIENT_HANDSHAKE_IV", values["CLIENT_HANDSHAKE_IV"],
                "The client's handshake record IV."),
        c_array("SERVER_FINISHED_KEY", values["SERVER_FINISHED_KEY"],
                "The server's Finished key, HKDF-Expand-Label(secret, \"finished\")."),
        c_array("SERVER_FINISHED", values["SERVER_FINISHED"],
                "The server's Finished verify_data."),
        c_array("CLIENT_FINISHED_KEY", values["CLIENT_FINISHED_KEY"],
                "The client's Finished key."),
        c_array("CLIENT_FINISHED", values["CLIENT_FINISHED"],
                "The client's Finished verify_data."),
        c_array("HASH_AFTER_SERVER_HELLO", values["HASH_AFTER_SERVER_HELLO"],
                "Hash(ClientHello..ServerHello), the handshake secrets' transcript."),
        c_array("HASH_AFTER_SERVER_FINISHED", values["HASH_AFTER_SERVER_FINISHED"],
                "Hash(ClientHello..server Finished), the application secrets' transcript."),
        c_array("HASH_AFTER_CLIENT_FINISHED", values["HASH_AFTER_CLIENT_FINISHED"],
                "Hash(ClientHello..client Finished), the resumption secret's transcript."),
        c_array("CLIENT_HELLO", values["CLIENT_HELLO"],
                "RFC 8448: the ClientHello, the first message in the transcript."),
        c_array("SERVER_HELLO", values["SERVER_HELLO"], "The ServerHello."),
        c_array("ENCRYPTED_EXTENSIONS", values["ENCRYPTED_EXTENSIONS"],
                "The EncryptedExtensions."),
        c_array("CERTIFICATE", values["CERTIFICATE"], "The server's Certificate."),
        c_array("CERTIFICATE_VERIFY", values["CERTIFICATE_VERIFY"],
                "The server's CertificateVerify."),
        c_array("SERVER_FINISHED_MESSAGE", values["SERVER_FINISHED_MESSAGE"],
                "The server's Finished message, header included."),
        c_array("CLIENT_FINISHED_MESSAGE", values["CLIENT_FINISHED_MESSAGE"],
                "The client's Finished message, header included."),
        c_array("CLIENT_X25519_PRIVATE", values["CLIENT_X25519_PRIVATE"],
                "RFC 8448 section 3: the client's ephemeral x25519 private key."),
        c_array("CLIENT_X25519_PUBLIC", values["CLIENT_X25519_PUBLIC"],
                "RFC 8448 section 3: X25519(client private, 9), sent in the ClientHello."),
        c_array("SERVER_X25519_PRIVATE", values["SERVER_X25519_PRIVATE"],
                "RFC 8448 section 3: the server's ephemeral x25519 private key."),
        c_array("SERVER_X25519_PUBLIC", values["SERVER_X25519_PUBLIC"],
                "RFC 8448 section 3: X25519(server private, 9), sent in the ServerHello."),
    ]
    return (
        "/* Generated by tests/vectors/extract_rfc8448_keyschedule.py -- do not edit.\n"
        " *\n"
        " * RFC 8448 section 3's key schedule trace, read from the RFC's own hex and\n"
        " * checked before it is written: every extract is recomputed as HMAC(salt, IKM),\n"
        " * every derivation as HKDF-Expand-Label(PRK, label, hash), every traffic and\n"
        " * Finished key from the secret its step names, the schedule is checked as a\n"
        " * chain, and the transcript hashes are checked against the handshake messages\n"
        " * extracted beside them. A value read from the wrong place fails the check and\n"
        " * generation stops rather than writing a vector a wrong implementation would\n"
        " * pass.\n"
        " */\n\n"
        "#ifndef WT_RFC8448_VECTORS_H\n"
        "#define WT_RFC8448_VECTORS_H\n\n"
        "#include <stdint.h>\n\n"
        + "\n".join(parts)
        + "\n#endif /* WT_RFC8448_VECTORS_H */\n"
    )


def main(argv: list[str]) -> int:
    check = "--check" in argv
    args = [a for a in argv[1:] if not a.startswith("--")]
    source = Path(args[0]) if args else Path("/tmp/rfc8448.txt")
    if not source.exists():
        print(f"rfc8448 text not found at {source}", file=sys.stderr)
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
        print("rfc8448 key schedule: committed vectors match the RFC")
        return 0
    HEADER.write_text(rendered, encoding="utf-8")
    print(f"rfc8448 key schedule: wrote {len(values)} values")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
