#!/usr/bin/env python3
"""
Extract per-step tshark QUIC verbose dissection from a real capture.

Input:
  fixtures/captures/quic-real.pcapng   — real QUIC pcap (loopback addresses)
  fixtures/captures/quic-real.keys     — SSLKEYLOGFILE

Output:
  web/quic-dissection.json             — per-step tshark -V text for the Raw toggle

Steps (6 total, matching the educational swimlane):
  0 → frame 1: ClientHello (QUIC Initial CRYPTO)
  1 → frame 2: ServerHello + EE + Cert + CertVerify + Finished (Initial+Handshake)
  2 → frame 3: Client Finished (Handshake)
  3 → frame 4: HTTP/3 GET (1-RTT)
  4 → frame 5: HTTP/3 200 (1-RTT)
  5 → frame 6: Session ticket / CONNECTION_CLOSE (1-RTT)
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PCAP = ROOT / "fixtures" / "captures" / "quic-real.pcapng"
KEYS = ROOT / "fixtures" / "captures" / "quic-real.keys"
OUT  = ROOT / "web" / "quic-dissection.json"


def get_frame_count(pcap: Path, keys: Path) -> int:
    result = subprocess.run(
        ["tshark", "-r", str(pcap), "-o", f"tls.keylog_file:{keys}", "-T", "fields", "-e", "frame.number"],
        capture_output=True, text=True,
    )
    lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
    return len(lines)


def get_frame_text(pcap: Path, keys: Path, frame_no: int) -> str:
    """Return tshark -V text for a single frame, QUIC+TLS sections only."""
    result = subprocess.run(
        [
            "tshark", "-r", str(pcap),
            "-o", f"tls.keylog_file:{keys}",
            "-V",
            "-Y", f"frame.number == {frame_no}",
        ],
        capture_output=True, text=True,
    )
    text = result.stdout

    # Keep only from QUIC section onward (skip frame/Ethernet/IP/UDP boilerplate)
    quic_start = text.find("QUIC IETF")
    if quic_start == -1:
        quic_start = text.find("QUIC")
    if quic_start == -1:
        return text.strip()
    return text[quic_start:].strip()


def get_frame_summary(pcap: Path, keys: Path, frame_no: int) -> str:
    """Return the one-line tshark summary for a frame."""
    result = subprocess.run(
        [
            "tshark", "-r", str(pcap),
            "-o", f"tls.keylog_file:{keys}",
            "-Y", f"frame.number == {frame_no}",
        ],
        capture_output=True, text=True,
    )
    for line in result.stdout.splitlines():
        line = line.strip()
        if line:
            return line
    return f"Frame {frame_no}"


def map_frame_to_step(frame_text: str, frame_no: int, step_slots: list) -> int | None:
    """Return which educational step this frame fills, or None."""
    text = frame_text

    has_initial = "Packet Type: Initial" in text
    has_handshake_pkt = "Packet Type: Handshake" in text
    has_short = "Header Form: Short" in text or ("Short Header" in text and "Long Header" not in text)
    has_client_hello = "Client Hello" in text and "Handshake Type: Client Hello" in text
    has_server_hello = "Handshake Type: Server Hello" in text
    has_certificate = "Handshake Type: Certificate" in text and "Certificate Verify" in text
    has_client_fin = has_handshake_pkt and "Handshake Type: Finished" in text and not has_server_hello

    if step_slots[0] is None and has_initial and has_client_hello:
        return 0
    if step_slots[1] is None and (has_initial or has_handshake_pkt) and has_server_hello:
        return 1
    if step_slots[2] is None and has_client_fin:
        return 2
    if has_short:
        for i in range(3, 6):
            if step_slots[i] is None:
                return i
    return None


def make_fallback_steps() -> list[dict]:
    """Fallback when real capture isn't available — hand-authored verbose text."""
    return [
        {
            "step": i,
            "frame": i + 1,
            "summary": s,
            "text": t,
            "source": "fallback",
        }
        for i, s, t in [
            (
                0,
                "1   0.000000 127.0.0.1 → 127.0.0.1 QUIC 1232 Initial, DCID=…, CRYPTO [ClientHello]",
                """QUIC IETF
    QUIC Connection information
        [Connection Number: 0]
    Header Form: Long Header (1)
    Packet Type: Initial (0)
    Version: 1 (0x00000001)
    Destination Connection ID Length: 8
    Destination Connection ID: ba1eb020f02c9a27
    Source Connection ID Length: 8
    Source Connection ID: abca19b215c99a3a
    Token Length: 0
    [Packet Number: 0]
    CRYPTO
        Frame Type: CRYPTO (0x0000000000000006)
        Offset: 0
        Length: 452
        TLSv1.3 Record Layer: Handshake Protocol: Client Hello
            Handshake Protocol: Client Hello
                Handshake Type: Client Hello (1)
                Version: TLS 1.2 (0x0303)
                Random: (32 bytes)
                Extension: server_name
                Extension: supported_versions → TLS 1.3
                Extension: key_share (x25519)
                Extension: quic_transport_parameters""",
            ),
            (
                1,
                "2   0.002000 127.0.0.1 → 127.0.0.1 QUIC 1232 Initial+Handshake, [ServerHello+EE+Cert+Finished]",
                """QUIC IETF
    Header Form: Long Header (1)
    Packet Type: Initial (0)
    [Packet Number: 0]
    CRYPTO
        TLSv1.3 Record Layer: Handshake Protocol: Server Hello
            Handshake Type: Server Hello (2)
            Extension: supported_versions → TLS 1.3
            Extension: key_share (x25519)
QUIC IETF
    Packet Type: Handshake (2)
    [Packet Number: 0]
    CRYPTO
        TLSv1.3 Record Layer: Handshake Protocol: Encrypted Extensions
            Handshake Type: Encrypted Extensions (8)
        TLSv1.3 Record Layer: Handshake Protocol: Certificate
            Handshake Type: Certificate (11)
        TLSv1.3 Record Layer: Handshake Protocol: Certificate Verify
            Handshake Type: Certificate Verify (15)
        TLSv1.3 Record Layer: Handshake Protocol: Finished
            Handshake Type: Finished (20)""",
            ),
            (
                2,
                "3   0.004000 127.0.0.1 → 127.0.0.1 QUIC 128 Handshake, CRYPTO [Finished]",
                """QUIC IETF
    Header Form: Long Header (1)
    Packet Type: Handshake (2)
    [Packet Number: 0]
    CRYPTO
        TLSv1.3 Record Layer: Handshake Protocol: Finished
            Handshake Type: Finished (20)
            Verify Data: (32 bytes)""",
            ),
            (
                3,
                "4   0.005000 127.0.0.1 → 127.0.0.1 QUIC 128 1-RTT, STREAM id=0 [HTTP/3 GET /]",
                """QUIC IETF
    Header Form: Short Header (1-RTT)
    Fixed Bit: True
    Spin Bit: False
    Key Phase: 0
    [Packet Number: 1]
    STREAM
        Frame Type: STREAM (0x0000000000000008)
        Stream ID: 0
        Offset: 0
        Length: 25
        HTTP/3 HEADERS frame
            GET / HTTP/1.1
            :method: GET
            :scheme: https
            :authority: localhost
            :path: /""",
            ),
            (
                4,
                "5   0.006000 127.0.0.1 → 127.0.0.1 QUIC 128 1-RTT, STREAM id=0 [HTTP/3 200 OK]",
                """QUIC IETF
    Header Form: Short Header (1-RTT)
    [Packet Number: 1]
    STREAM
        Frame Type: STREAM (0x0000000000000008)
        Stream ID: 0
        HTTP/3 HEADERS frame
            :status: 200
            content-type: text/plain
        HTTP/3 DATA frame
            Hello from HTTP/3""",
            ),
            (
                5,
                "6   0.008000 127.0.0.1 → 127.0.0.1 QUIC 128 1-RTT, CRYPTO [NewSessionTicket], CONNECTION_CLOSE",
                """QUIC IETF
    Header Form: Short Header (1-RTT)
    [Packet Number: 2]
    CRYPTO
        TLSv1.3 Record Layer: Handshake Protocol: New Session Ticket
            Handshake Type: New Session Ticket (4)
            Ticket Lifetime: 3600
            Ticket Nonce Length: 1
            Ticket: (opaque bytes)
    CONNECTION_CLOSE
        Frame Type: CONNECTION_CLOSE (0x000000000000001c)
        Error Code: 0 (no error)""",
            ),
        ]
    ]


def main() -> None:
    if not PCAP.exists() or not KEYS.exists():
        print(f"WARN: real capture missing — writing fallback dissection")
        result = {"steps": make_fallback_steps(), "source": "fallback"}
    else:
        total = get_frame_count(PCAP, KEYS)
        print(f"Found {total} frames in {PCAP.name}")

        step_slots: list[dict | None] = [None] * 6

        for frame_no in range(1, total + 1):
            text = get_frame_text(PCAP, KEYS, frame_no)
            summary = get_frame_summary(PCAP, KEYS, frame_no)
            step = map_frame_to_step(text, frame_no, step_slots)
            if step is not None:
                step_slots[step] = {
                    "step": step,
                    "frame": frame_no,
                    "summary": summary,
                    "text": text,
                    "source": "tshark",
                }
                filled = sum(1 for s in step_slots if s is not None)
                print(f"  Frame {frame_no:2d} → step {step}  ({filled}/6 filled)")
                if filled == 6:
                    break

        # Fill any gaps with fallback
        fallback = make_fallback_steps()
        for i, s in enumerate(step_slots):
            if s is None:
                print(f"  Step {i}: no matching frame found — using fallback")
                step_slots[i] = fallback[i]

        real = sum(1 for s in step_slots if s and s.get("source") == "tshark")
        result = {
            "steps": step_slots,
            "source": "tshark",
            "pcap": PCAP.name,
            "real_steps": real,
        }
        print(f"  {real}/6 steps from real tshark decode")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2))
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
