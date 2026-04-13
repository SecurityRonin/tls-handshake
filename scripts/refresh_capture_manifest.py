#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CAPTURE_DIR = ROOT / "fixtures" / "captures"


def run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, check=True, text=True, capture_output=True)
    return proc.stdout


def tshark_summary(path: Path) -> list[dict[str, str]]:
    out = run([
        "tshark", "-r", str(path), "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
    ])
    rows: list[dict[str, str]] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        rows.append({
            "frame": parts[0] if len(parts) > 0 else "",
            "src": parts[1] if len(parts) > 1 else "",
            "dst": parts[2] if len(parts) > 2 else "",
            "protocol": parts[3] if len(parts) > 3 else "",
            "info": parts[4] if len(parts) > 4 else "",
        })
    return rows


def build_manifest() -> dict[str, object]:
    manifest: dict[str, object] = {}
    for path in sorted(CAPTURE_DIR.glob("*.pcap*")):
        manifest[path.stem] = {
            "pcap": str(path.relative_to(ROOT)),
            "packet_count": len(tshark_summary(path)),
            "summary": tshark_summary(path),
        }
    return manifest


if __name__ == "__main__":
    manifest = build_manifest()
    (CAPTURE_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
