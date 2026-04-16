#!/usr/bin/env python3
"""
Generate a real QUIC/HTTP3 capture with SSLKEYLOGFILE for Wireshark decryption.

Outputs:
  fixtures/captures/quic-real.pcapng   — real QUIC pcap with loopback addresses
  fixtures/captures/quic-real.keys     — SSLKEYLOGFILE for tshark decryption
  fixtures/captures/quic-http3.pcapng  — copy with student-facing addresses (replaces synthetic)
  fixtures/captures/quic-http3.keys    — keylog for the address-rewritten copy

Usage:
  python3 scripts/generate_quic_capture.py
"""

import asyncio
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "fixtures" / "captures"

try:
    from aioquic.asyncio import connect, serve
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived, H3Event
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import QuicEvent, StreamDataReceived
except ImportError:
    sys.exit("aioquic not installed: pip3 install aioquic")

PORT = 14433
CLIENT_ADDR = "127.0.0.1"
FAKE_CLIENT = "192.168.1.10"
FAKE_SERVER = "93.184.216.34"


# ── Server ────────────────────────────────────────────────────────────────────

class H3ServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3: H3Connection | None = None

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._h3 is None:
            self._h3 = H3Connection(self._quic, enable_webtransport=False)
        for h3_event in self._h3.handle_event(event):
            self._h3_event_received(h3_event)

    def _h3_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            headers = {k: v for k, v in event.headers}
            path = headers.get(b":path", b"/").decode()
            self._h3.send_headers(
                stream_id=event.stream_id,
                headers=[
                    (b":status", b"200"),
                    (b"content-type", b"text/plain"),
                ],
            )
            self._h3.send_data(
                stream_id=event.stream_id,
                data=b"Hello from HTTP/3\n",
                end_stream=True,
            )


# ── Client ────────────────────────────────────────────────────────────────────

class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3: H3Connection | None = None
        self._response_waiter: asyncio.Future | None = None
        self._response_data = b""

    async def get(self, path: str) -> bytes:
        if self._h3 is None:
            self._h3 = H3Connection(self._quic, enable_webtransport=False)
        stream_id = self._quic.get_next_available_stream_id()
        self._h3.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", path.encode()),
            ],
        )
        self._h3.send_data(stream_id=stream_id, data=b"", end_stream=True)
        self._response_waiter = asyncio.get_event_loop().create_future()
        self.transmit()
        return await asyncio.wait_for(self._response_waiter, timeout=10)

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._h3 is None:
            self._h3 = H3Connection(self._quic, enable_webtransport=False)
        for h3_event in self._h3.handle_event(event):
            self._h3_event_received(h3_event)

    def _h3_event_received(self, event: H3Event) -> None:
        if isinstance(event, DataReceived):
            self._response_data += event.data
            if event.stream_ended and self._response_waiter and not self._response_waiter.done():
                self._response_waiter.set_result(self._response_data)


# ── TLS cert helpers ──────────────────────────────────────────────────────────

def gen_self_signed(cert_path: Path, key_path: Path) -> None:
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path), "-out", str(cert_path),
            "-sha256", "-days", "1", "-nodes",
            "-subj", "/CN=localhost",
        ],
        check=True, capture_output=True,
    )


# ── Address rewrite ───────────────────────────────────────────────────────────

def rewrite_addresses(src: Path, dst: Path) -> None:
    """Use reordercap+editcap or bitwise replacement to swap loopback → student addresses."""
    # editcap doesn't rewrite IP addresses; we do it with a Python struct patch.
    import struct

    raw = src.read_bytes()

    def ip_bytes(addr: str) -> bytes:
        return bytes(int(x) for x in addr.split("."))

    lo_client = ip_bytes("127.0.0.1")
    lo_server = ip_bytes("127.0.0.1")  # both sides are 127.0.0.1
    fake_client = ip_bytes(FAKE_CLIENT)
    fake_server = ip_bytes(FAKE_SERVER)

    # Replace client-side packets: src=127.0.0.1 dst=127.0.0.1 (same!), so we
    # need to distinguish by port direction. Simpler: replace all occurrences of
    # 127.0.0.1 in pairs — even offset → FAKE_CLIENT, odd → FAKE_SERVER.
    # Actually just do two passes keyed on port-based heuristic would be complex.
    # Easiest: replace first occurrence in each IP header as client, second as server.
    # For a pedagogically correct result we just use tcprewrite if available.
    try:
        result = subprocess.run(
            ["tcprewrite",
             f"--srcipmap=127.0.0.1:{FAKE_CLIENT}",
             f"--dstipmap=127.0.0.1:{FAKE_SERVER}",
             f"--infile={src}", f"--outfile={dst}"],
            capture_output=True,
        )
        if result.returncode == 0:
            return
    except FileNotFoundError:
        pass

    # Fallback: bitwise replace all 127.0.0.1 alternating client/server.
    # This works because in a two-party conversation the addresses always alternate.
    out = bytearray(raw)
    needle = lo_client
    replacements = [fake_client, fake_server]
    i = 0
    r = 0
    while True:
        pos = raw.find(needle, i)
        if pos == -1:
            break
        out[pos:pos+4] = replacements[r % 2]
        r += 1
        i = pos + 4
    dst.write_bytes(bytes(out))


# ── Main ──────────────────────────────────────────────────────────────────────

async def run_capture(keys_path: Path, pcap_path: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        cert = tmp / "cert.pem"
        key = tmp / "key.pem"
        gen_self_signed(cert, key)

        server_keys = open(keys_path, "w")
        client_keys = open(keys_path, "a")  # same file; both sides write

        server_cfg = QuicConfiguration(
            alpn_protocols=H3_ALPN,
            is_client=False,
            secrets_log_file=server_keys,
        )
        server_cfg.load_cert_chain(str(cert), str(key))

        client_cfg = QuicConfiguration(
            alpn_protocols=H3_ALPN,
            is_client=True,
            secrets_log_file=client_keys,
        )
        client_cfg.verify_mode = False  # accept self-signed

        # Start tcpdump before server
        cap_proc = subprocess.Popen(
            ["tcpdump", "-i", "lo0", "-U", "-w", str(pcap_path),
             f"udp port {PORT}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        await asyncio.sleep(0.5)

        server = await serve(
            CLIENT_ADDR, PORT,
            configuration=server_cfg,
            create_protocol=H3ServerProtocol,
        )

        await asyncio.sleep(0.3)

        async with connect(
            CLIENT_ADDR, PORT,
            configuration=client_cfg,
            create_protocol=H3ClientProtocol,
        ) as client:
            response = await client.get("/")
            assert b"Hello" in response, f"unexpected response: {response!r}"
            # Wait for session ticket to be delivered (needed for tshark full decode)
            await asyncio.sleep(0.5)

        server.close()
        await asyncio.sleep(0.5)

        server_keys.close()
        client_keys.close()

        cap_proc.send_signal(signal.SIGINT)
        try:
            cap_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cap_proc.kill()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    raw_pcap = OUT / "quic-real.pcapng"
    raw_keys = OUT / "quic-real.keys"
    final_pcap = OUT / "quic-http3.pcapng"
    final_keys = OUT / "quic-http3.keys"

    print("Generating real QUIC capture...")
    asyncio.run(run_capture(raw_keys, raw_pcap))

    if not raw_pcap.exists() or raw_pcap.stat().st_size < 100:
        sys.exit(f"ERROR: capture file is missing or empty: {raw_pcap}")

    print(f"  Captured {raw_pcap.stat().st_size} bytes → {raw_pcap}")
    print(f"  Key log  {raw_keys.stat().st_size} bytes → {raw_keys}")

    # Rewrite addresses for student-facing pcap
    print("Rewriting addresses...")
    rewrite_addresses(raw_pcap, final_pcap)
    shutil.copy(raw_keys, final_keys)
    print(f"  → {final_pcap}")

    print("Done.")


if __name__ == "__main__":
    main()
