#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "fixtures" / "capture-src"
OUT_DIR = ROOT / "fixtures" / "captures"

CLIENT_IP = "192.168.1.10"
SERVER_IP = "93.184.216.34"


def hx(*parts: str) -> str:
    return " ".join(parts)


SCENARIOS = {
    "freak": {
        "transport": "tcp",
        "ports": (55000, 443),
        "packets": [
            ("I", hx(
                "16 03 01 00 6d 01 00 00 69 03 03 7f 3a 9b 2c 00",
                "d4 e1 8a 6f 29 73 b5 17 42 8c a0 3e 55 f8 91 c2",
                "00 00 04 00 03 00 08 01 00 00 3c 00 0f 00 01 01",
            )),
            ("O", hx(
                "16 03 03 00 31 02 00 00 2d 03 03 a8 c4 e1 f0 6a",
                "2b 19 d7 83 4e f5 c0 b1 a2 38 9d e7 54 6c 0f 11",
                "22 33 44 55 66 77 88 99 00 00 03 00 00 16 03 03",
                "00 88 0c 00 00 84 00 40 a1 b2 c3 d4 e5 f6 07 18",
            )),
            ("I", hx(
                "16 03 03 00 56 10 00 00 52 40 5a 11 22 33 44 55",
                "66 77 88 99 aa bb cc dd ee ff 00 11 22 33 44 55",
                "14 03 03 00 01 01 16 03 03 00 28 ab cd ef 01 23",
            )),
            ("O", hx(
                "14 03 03 00 01 01 16 03 03 00 28 c4 d8 ec 00 14",
                "28 3c 50 64 78 8c a0 b4 c8 dc f0 04 18 2c 40 54",
            )),
            ("I", hx(
                "17 03 03 00 c0 9a bc de f0 12 34 56 78 9a bc de",
                "f0 12 34 56 78 9a bc de f0 12 34 56 78 9a bc de",
            )),
            ("O", hx(
                "17 03 03 01 20 aa bb cc dd ee ff 00 11 22 33 44",
                "55 66 77 88 99 aa bb cc dd ee ff 00 11 22 33 44",
            )),
        ],
    },
    "logjam": {
        "transport": "tcp",
        "ports": (55000, 443),
        "packets": [
            ("I", hx(
                "16 03 01 00 71 01 00 00 6d 03 03 7f 3a 9b 2c 00",
                "d4 e1 8a 6f 29 73 b5 17 42 8c a0 3e 55 f8 91 c2",
                "00 00 04 00 11 00 12 01 00 00 40 00 0f 00 01 01",
            )),
            ("O", hx(
                "16 03 03 00 81 02 00 00 7d 03 03 a8 c4 e1 f0 6a",
                "2b 19 d7 83 4e f5 c0 b1 a2 38 9d e7 54 6c 0f 11",
                "22 33 44 55 66 77 88 99 00 11 00 00 16 03 03 02",
                "2c 0c 00 02 28 00 80 9f a3 b1 c7 d5 02 01 02 00",
            )),
            ("I", hx(
                "16 03 03 00 46 10 00 00 42 40 7a 91 c2 d3 e4 f5",
                "06 17 28 39 4a 5b 6c 7d 8e 9f a0 b1 c2 d3 e4 f5",
                "14 03 03 00 01 01 16 03 03 00 28 ab cd ef 01 23",
            )),
            ("O", hx(
                "14 03 03 00 01 01 16 03 03 00 28 c4 d8 ec 00 14",
                "28 3c 50 64 78 8c a0 b4 c8 dc f0 04 18 2c 40 54",
            )),
            ("I", hx(
                "17 03 03 00 c8 44 55 66 77 88 99 aa bb cc dd ee",
                "ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee",
            )),
            ("O", hx(
                "17 03 03 01 24 10 20 30 40 50 60 70 80 90 a0 b0",
                "c0 d0 e0 f0 01 11 21 31 41 51 61 71 81 91 a1 b1",
            )),
        ],
    },
    "alpn-mismatch": {
        "transport": "tcp",
        "ports": (55001, 443),
        "packets": [
            ("I", hx(
                "16 03 01 00 8d 01 00 00 89 03 03 7f 3a 9b 2c 00",
                "d4 e1 8a 6f 29 73 b5 17 42 8c a0 3e 55 f8 91 c2",
                "00 00 06 13 02 13 01 13 03 01 00 00 5a 00 10 00",
                "05 00 03 02 68 32 00 2b 00 03 02 03 04 00 33 00",
            )),
            ("O", hx(
                "16 03 03 00 9b 02 00 00 97 03 03 a8 c4 e1 f0 00",
                "6a 2b 19 d7 83 4e f5 c0 b1 a2 38 9d e7 54 6c 0f",
                "20 e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9",
                "13 02 00 00 2f 00 2b 00 02 03 04 00 33 00 24 00",
            )),
            ("O", hx(
                "17 03 03 00 13 a1 b2 c3 d4 e5 f6 07 18 29 3a 4b",
                "5c 6d 6e 02 78 7f 81 92 10 22 33 44 55 66 77 88",
            )),
            ("O", "01 01 08 0a 00 10 00 00 00 00 00 00 00 00 00 00"),
        ],
    },
    "ocsp-revoked": {
        "transport": "tcp",
        "ports": (55002, 443),
        "packets": [
            ("I", hx(
                "16 03 01 02 00 01 00 01 fc 03 03 7f 3a 9b 2c 00",
                "d4 e1 8a 6f 29 73 b5 17 42 8c a0 3e 55 f8 91 c2",
                "20 e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9",
                "24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 d6",
            )),
            ("O", hx(
                "16 03 03 00 9b 02 00 00 97 03 03 a8 c4 e1 f0 00",
                "6a 2b 19 d7 83 4e f5 c0 b1 a2 38 9d e7 54 6c 0f",
                "20 e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9",
                "13 02 00 00 2f 00 2b 00 02 03 04 00 33 00 24 00",
            )),
            ("O", hx(
                "17 03 03 0b 50 16 00 00 00 0b 4a 0b 00 0b 46 00",
                "0b 42 00 00 05 30 82 04 6c 30 82 03 54 a0 03 02",
                "01 02 a3 82 01 10 30 82 01 0c 0a 01 00 30 82 01",
                "08 a0 82 01 04 18 0f 32 30 32 35 30 31 31 35 30",
            )),
            ("I", hx(
                "17 03 03 00 15 ff ee dd cc bb aa 99 88 77 66 55",
                "44 33 22 11 00 2c 91 7a 5e",
            )),
        ],
    },
    "quic-http3": {
        "transport": "udp",
        "ports": (55003, 443),
        "packets": [
            ("I", hx(
                "c3 00 00 00 01 08 83 94 c8 f0 3e 51 57 08 00 44",
                "9e 7b 9a ec 34 00 44 f2 00 00 18 06 00 40 75 00",
                "01 00 00 71 03 03 7f 3a 9b 2c 00 d4 e1 8a 6f 29",
            )),
            ("O", hx(
                "cf 00 00 00 01 08 83 94 c8 f0 3e 51 57 08 00 88",
                "9e 7b 9a ec 35 00 44 f3 00 00 42 06 00 40 76 00",
                "02 00 00 97 03 03 a8 c4 e1 f0 00 2b 00 02 03 04",
            )),
            ("I", hx(
                "e1 40 5c 9f 12 34 56 78 9a bc de f0 00 00 22 06",
                "00 00 1e 14 00 00 30 ab cd ef 01 23 45 67 89 ab",
            )),
            ("I", hx(
                "41 9a bc de f0 12 34 56 78 00 01 04 00 00 00 01",
                "82 84 41 8a 08 9d 5c 0b 81 70 dc 78",
            )),
            ("O", hx(
                "42 9a bc de f0 98 76 54 32 00 01 04 00 00 00 01",
                "88 5f 92 49 7c a5 89 d3 4d 1f 43 ae",
            )),
            ("O", hx(
                "43 9a bc de f0 aa bb cc dd 00 00 08 00 00 04 d2",
                "3c 68 31 3e 68 74 6d 6c",
            )),
        ],
    },
}


def write_hexdump(path: Path, packets: list[tuple[str, str]]) -> None:
    lines: list[str] = []
    for direction, payload in packets:
        lines.append(f"{direction} 000000 {payload}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="ascii")


def run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, check=True, text=True, capture_output=True)
    return proc.stdout


def tshark_summary(pcap_path: Path) -> list[dict[str, str]]:
    out = run([
        "tshark", "-r", str(pcap_path), "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
    ])
    rows = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        row = {
            "frame": parts[0] if len(parts) > 0 else "",
            "src": parts[1] if len(parts) > 1 else "",
            "dst": parts[2] if len(parts) > 2 else "",
            "protocol": parts[3] if len(parts) > 3 else "",
            "info": parts[4] if len(parts) > 4 else "",
        }
        rows.append(row)
    return rows


def build() -> None:
    SRC_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, object] = {}
    preserved_real_fixtures = {
        "alpn-mismatch": OUT_DIR / "alpn-mismatch.pcap",
    }

    for name, spec in SCENARIOS.items():
        src_txt = SRC_DIR / f"{name}.txt"
        write_hexdump(src_txt, spec["packets"])

        preserved = preserved_real_fixtures.get(name)
        if preserved and preserved.exists():
            manifest[name] = {
                "pcap": str(preserved.relative_to(ROOT)),
                "source": str(src_txt.relative_to(ROOT)),
                "packet_count": len(tshark_summary(preserved)),
                "summary": tshark_summary(preserved),
            }
            continue

        out_pcap = OUT_DIR / f"{name}.pcapng"

        if spec["transport"] == "tcp":
            transport_args = ["-T", f"{spec['ports'][0]},{spec['ports'][1]}"]
        else:
            transport_args = ["-u", f"{spec['ports'][0]},{spec['ports'][1]}"]

        run([
            "text2pcap", "-q", "-D",
            "-4", f"{CLIENT_IP},{SERVER_IP}",
            *transport_args,
            str(src_txt), str(out_pcap),
        ])

        manifest[name] = {
            "pcap": str(out_pcap.relative_to(ROOT)),
            "source": str(src_txt.relative_to(ROOT)),
            "packet_count": len(spec["packets"]),
            "summary": tshark_summary(out_pcap),
        }

    (OUT_DIR / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )


if __name__ == "__main__":
    build()
    subprocess.run(
        ["python3", str(ROOT / "scripts" / "refresh_capture_manifest.py")],
        check=True,
    )
