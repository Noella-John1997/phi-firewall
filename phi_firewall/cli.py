"""`phi-firewall` command line."""
from __future__ import annotations

import argparse
import json
import sys

from .audit import verify_chain
from .detectors import DetectionEngine
from .policy import load_policy
from .redaction import BlockedContent, Redactor
from .vault import generate_key


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="phi-firewall")
    sub = p.add_subparsers(dest="cmd", required=True)

    sv = sub.add_parser("serve", help="run the proxy")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)

    sc = sub.add_parser("scan", help="show what would be redacted in a piece of text")
    sc.add_argument("text", nargs="?", help="text to scan (or pipe it in)")
    sc.add_argument("--policy")

    sub.add_parser("gen-key", help="print a new base64 AES-256 master key")

    va = sub.add_parser("verify-audit", help="check an audit log's hash chain")
    va.add_argument("path", nargs="?", default="audit.jsonl")

    a = p.parse_args(argv)
    if a.cmd == "serve":
        import uvicorn
        uvicorn.run("phi_firewall.proxy.app:app", factory=True, host=a.host, port=a.port)
    elif a.cmd == "scan":
        text = a.text if a.text is not None else sys.stdin.read()
        engine = DetectionEngine()
        for sp in engine.detect(text):
            print(f"  {sp.entity:<12} {sp.score:.2f}  {sp.text!r}")
        try:
            res = Redactor(engine, load_policy(a.policy)).redact(text)
            print("\nLLM would see:\n" + res.text)
        except BlockedContent as e:
            print(f"\nBLOCKED: {e}")
            return 2
    elif a.cmd == "gen-key":
        print(f"k1:{generate_key()}")
    elif a.cmd == "verify-audit":
        ok, bad = verify_chain(a.path)
        print(json.dumps({"ok": ok, "first_bad_line": bad}))
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
