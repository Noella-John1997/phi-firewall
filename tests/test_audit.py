import json

from phi_firewall.audit import AuditLog, verify_chain


def test_chain_verifies(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(5):
        log.write("chat", n=i)
    assert verify_chain(p) == (True, None)


def test_tampering_is_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(5):
        log.write("chat", n=i)
    lines = p.read_text().splitlines()
    rec = json.loads(lines[2]); rec["n"] = 999
    lines[2] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")
    assert verify_chain(p) == (False, 3)


def test_deleted_line_is_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(4):
        log.write("chat", n=i)
    lines = p.read_text().splitlines()
    del lines[1]
    p.write_text("\n".join(lines) + "\n")
    assert verify_chain(p)[0] is False


def test_chain_continues_after_restart(tmp_path):
    p = tmp_path / "a.jsonl"
    AuditLog(p).write("one")
    AuditLog(p).write("two")  # new instance picks up the last hash
    assert verify_chain(p) == (True, None)
