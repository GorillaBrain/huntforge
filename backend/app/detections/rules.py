"""Rule catalogue and analytics.

Every analytic is deterministic: the same events and parameters always yield the same findings.
Analytics only *read* events; they return Finding objects that always reference supporting event ids.
Severity (impact if true) and confidence (likelihood it is malicious given the evidence) are independent.
"""
from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta

INTERNAL_NETS = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7")]


def is_internal(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in INTERNAL_NETS)


def _dt(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Finding:
    rule_id: str
    severity: str
    confidence: float
    ts: str
    entity_type: str
    entity_value: str
    title: str
    explanation: str
    event_ids: list[int]
    evidence: dict = field(default_factory=dict)
    key: str = ""  # stable discriminator used for deduplication


@dataclass
class RuleDef:
    id: str
    name: str
    description: str
    technique: str
    severity: str
    logic: str
    data_sources: list[str]
    false_positives: str
    limitations: str
    steps: list[str]
    params: dict
    fn: callable = None


def _fetch(conn: sqlite3.Connection, where: str, args: list, ing: int | None):
    sql = f"SELECT * FROM events WHERE {where}"
    if ing is not None:
        sql += " AND ingestion_id = ?"
        args = args + [ing]
    sql += " ORDER BY ts, id"
    return [dict(r) for r in conn.execute(sql, args)]


def _raw(e: dict) -> dict:
    try:
        return json.loads(e["raw"])
    except (TypeError, ValueError):
        return {}


def _clusters(events: list[dict], gap_min: float):
    """Split time-ordered events into clusters whose consecutive gaps are <= gap_min."""
    cur: list[dict] = []
    for e in events:
        if cur and (_dt(e["ts"]) - _dt(cur[-1]["ts"])) > timedelta(minutes=gap_min):
            yield cur
            cur = []
        cur.append(e)
    if cur:
        yield cur


def _failed_clusters(conn, p, ing):
    fails = _fetch(conn, "event_type='authentication' AND outcome='failure' AND src_ip IS NOT NULL", [], ing)
    by_ip: dict[str, list[dict]] = {}
    for e in fails:
        by_ip.setdefault(e["src_ip"], []).append(e)
    for ip in sorted(by_ip):
        for c in _clusters(by_ip[ip], p["window_minutes"]):
            if len(c) >= p["threshold"]:
                yield ip, c


# ---- HF-001 -------------------------------------------------------------------------
def brute_force(conn, p, ing):
    out = []
    for ip, c in _failed_clusters(conn, p, ing):
        users = sorted({e["username"] for e in c if e["username"]})
        hosts = sorted({e["hostname"] for e in c if e["hostname"]})
        sev = "high" if len(c) >= p["threshold"] * 2 else "medium"
        out.append(Finding("HF-001", sev, 0.7 if len(users) > 1 or len(c) >= p["threshold"] * 2 else 0.55, c[-1]["ts"],
                           "ip", ip, f"Repeated failed logins from {ip}",
                           f"{len(c)} failed authentications from {ip} with no gap larger than {p['window_minutes']} min "
                           f"(threshold {p['threshold']}), between {c[0]['ts']} and {c[-1]['ts']}. "
                           f"Targeted accounts: {', '.join(users) or 'unknown'}.",
                           [e["id"] for e in c],
                           {"source_ip": ip, "failure_count": len(c), "targeted_users": users, "targeted_hosts": hosts,
                            "first_seen": c[0]["ts"], "last_seen": c[-1]["ts"], "window_minutes": p["window_minutes"],
                            "threshold": p["threshold"]},
                           key=f"{ip}|{c[0]['id']}"))
    return out


# ---- HF-002 -------------------------------------------------------------------------
def success_after_failures(conn, p, ing):
    out = []
    succ = _fetch(conn, "event_type='authentication' AND outcome='success' AND src_ip IS NOT NULL", [], ing)
    for ip, c in _failed_clusters(conn, p, ing):
        end = _dt(c[-1]["ts"])
        failed_users = {e["username"] for e in c if e["username"]}
        for s in succ:
            if s["src_ip"] != ip:
                continue
            delta = _dt(s["ts"]) - end
            if timedelta(0) <= delta <= timedelta(minutes=p["success_window_minutes"]):
                same_user = s["username"] in failed_users
                out.append(Finding("HF-002", "critical" if same_user else "high", 0.85 if same_user else 0.6, s["ts"],
                                   "ip", ip, f"Successful login from {ip} after {len(c)} failures",
                                   f"{s['username']} authenticated successfully from {ip} {int(delta.total_seconds())}s after a burst of "
                                   f"{len(c)} failed logins from the same address. "
                                   + ("The account was among those previously failing, consistent with a guessed credential."
                                      if same_user else "The account was not among those failing; correlation is weaker."),
                                   [e["id"] for e in c] + [s["id"]],
                                   {"source_ip": ip, "account": s["username"], "host": s["hostname"], "failures_before": len(c),
                                    "seconds_after_last_failure": int(delta.total_seconds()), "account_was_targeted": same_user,
                                    "success_event": s["id"]},
                                   key=f"{ip}|{s['id']}"))
                break
    return out


# ---- HF-003 -------------------------------------------------------------------------
def multi_location(conn, p, ing):
    out = []
    rows = _fetch(conn, "event_type='authentication' AND outcome='success' AND country IS NOT NULL AND username IS NOT NULL", [], ing)
    by_user: dict[str, list[dict]] = {}
    for e in rows:
        by_user.setdefault(e["username"], []).append(e)
    for user in sorted(by_user):
        evs = by_user[user]
        for a, b in zip(evs, evs[1:]):
            if a["country"] != b["country"] and _dt(b["ts"]) - _dt(a["ts"]) <= timedelta(minutes=p["window_minutes"]):
                mins = int((_dt(b["ts"]) - _dt(a["ts"])).total_seconds() // 60)
                out.append(Finding("HF-003", "medium", 0.5, b["ts"], "user", user,
                                   f"{user} authenticated from {a['country']} and {b['country']} within {mins} min",
                                   f"Successful logins for {user} from {a['country']} ({a['src_ip']}) and then {b['country']} "
                                   f"({b['src_ip']}) {mins} minutes apart. Travel between these locations in that time is unlikely, "
                                   "but VPNs, proxies and mobile networks can produce the same pattern.",
                                   [a["id"], b["id"]],
                                   {"user": user, "first": {"country": a["country"], "ip": a["src_ip"], "ts": a["ts"]},
                                    "second": {"country": b["country"], "ip": b["src_ip"], "ts": b["ts"]}, "minutes_apart": mins},
                                   key=f"{user}|{a['id']}|{b['id']}"))
    return out


# ---- HF-004 -------------------------------------------------------------------------
def privileged_external(conn, p, ing):
    out = []
    priv = {u.lower() for u in p["privileged_users"]}
    rows = _fetch(conn, "event_type='authentication' AND outcome='success' AND username IS NOT NULL AND src_ip IS NOT NULL", [], ing)
    groups: dict[tuple, list[dict]] = {}
    for e in rows:
        if e["username"].lower() in priv and not is_internal(e["src_ip"]):
            groups.setdefault((e["username"], e["src_ip"], e["ts"][:10]), []).append(e)
    for (user, ip, day), evs in sorted(groups.items()):
        out.append(Finding("HF-004", "high", 0.65, evs[-1]["ts"], "user", user,
                           f"Privileged account {user} logged in from external address {ip}",
                           f"{len(evs)} successful login(s) for privileged account '{user}' from non-internal address {ip} "
                           f"({evs[0]['country'] or 'country unknown'}) on {day}. Privileged accounts are expected to authenticate from "
                           "managed internal networks or approved VPN ranges.",
                           [e["id"] for e in evs],
                           {"account": user, "source_ip": ip, "country": evs[0]["country"], "hosts": sorted({e["hostname"] for e in evs if e["hostname"]}),
                            "count": len(evs)},
                           key=f"{user}|{ip}|{day}"))
    return out


# ---- HF-005 -------------------------------------------------------------------------
def unusual_outbound(conn, p, ing):
    out = []
    rows = _fetch(conn, "event_type='network_connection' AND dst_ip IS NOT NULL", [], ing)
    allowed = set(p["allowed_ports"])
    groups: dict[tuple, list[dict]] = {}
    for e in rows:
        if is_internal(e["dst_ip"]) or e["hostname"] is None:
            continue
        groups.setdefault((e["hostname"], e["dst_ip"], e["dst_port"]), []).append(e)
    for (host, ip, port), evs in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2] or 0)):
        total = sum(e["bytes_out"] or 0 for e in evs)
        big = [e for e in evs if (e["bytes_out"] or 0) >= p["large_transfer_bytes"]]
        odd_port = port is not None and port not in allowed and len(evs) >= p["min_connections"]
        if not (odd_port or big):
            continue
        reasons = []
        if odd_port:
            reasons.append(f"{len(evs)} connections to non-standard port {port}")
        if big:
            reasons.append(f"{len(big)} transfer(s) >= {p['large_transfer_bytes']:,} bytes (max {max(e['bytes_out'] for e in big):,})")
        conf = 0.45 + (0.2 if odd_port else 0) + (0.2 if big else 0)
        out.append(Finding("HF-005", "high" if big and odd_port else "medium", round(min(conf, 0.85), 2), evs[-1]["ts"], "host", host,
                           f"Unusual outbound traffic from {host} to {ip}:{port}",
                           f"{host} made {len(evs)} outbound connection(s) to external address {ip} on port {port}: "
                           + "; ".join(reasons) + f". Total bytes sent: {total:,}. Regular intervals would suggest automated beaconing, "
                           "but this rule does not measure periodicity.",
                           [e["id"] for e in evs],
                           {"host": host, "destination_ip": ip, "destination_port": port, "connections": len(evs),
                            "total_bytes_out": total, "reasons": reasons, "first_seen": evs[0]["ts"], "last_seen": evs[-1]["ts"]},
                           key=f"{host}|{ip}|{port}"))
    return out


# ---- HF-006 -------------------------------------------------------------------------
PROC_INDICATORS = [
    ("encoded_powershell", re.compile(r"powershell(\.exe)?\b.*\s-(enc|encodedcommand|e)\s+\S{8,}", re.I)),
    ("download_cradle", re.compile(r"(invoke-expression|iex)\b.*(downloadstring|invoke-webrequest)|certutil.*-urlcache|bitsadmin.*/transfer", re.I)),
    ("lolbin_remote_exec", re.compile(r"(regsvr32.*/i:https?://|rundll32.*javascript:|mshta(\.exe)?\s+https?://)", re.I)),
    ("hidden_window", re.compile(r"-w(indowstyle)?\s+hidden", re.I)),
]
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
SHELLS = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "pwsh.exe"}


def command_execution(conn, p, ing):
    out = []
    rows = _fetch(conn, "event_type='process_create'", [], ing)
    for e in rows:
        hits = []
        cl = e["command_line"] or ""
        for name, rx in PROC_INDICATORS:
            if rx.search(cl):
                hits.append(name)
        if (e["parent_process"] or "").lower() in OFFICE and (e["process_name"] or "").lower() in SHELLS:
            hits.append("office_spawned_shell")
        if re.search(r"\\(temp|appdata\\local\\temp|downloads)\\.*\.(exe|dll|bin|ps1)", cl, re.I) and "certutil" not in cl.lower():
            hits.append("execution_from_staging_path")
        if not hits:
            continue
        conf = round(min(0.5 + 0.15 * len(hits), 0.9), 2)
        host = e["hostname"] or "unknown"
        out.append(Finding("HF-006", "high" if len(hits) > 1 else "medium", conf, e["ts"], "host", host,
                           f"Suspicious command execution on {host}: {', '.join(hits)}",
                           f"Process {e['process_name']} (parent {e['parent_process'] or 'unknown'}) matched {len(hits)} indicator(s): "
                           f"{', '.join(hits)}. These patterns are common in malware delivery but also in legitimate administration scripts.",
                           [e["id"]],
                           {"host": host, "user": e["username"], "process": e["process_name"], "parent": e["parent_process"],
                            "command_line": cl, "indicators": hits},
                           key=str(e["id"])))
    return out


# ---- HF-007 -------------------------------------------------------------------------
def account_changes(conn, p, ing):
    out = []
    priv_groups = {g.lower() for g in p["privileged_groups"]}
    rows = _fetch(conn, "event_type IN ('account_created','group_member_added')", [], ing)
    creates = {}
    for e in rows:
        r = _raw(e)
        target = r.get("target_user") or r.get("TargetUserName")
        if not target:
            continue
        if e["event_type"] == "account_created":
            creates[target] = e
        group = r.get("group") or r.get("TargetGroup")
        is_priv = e["event_type"] == "group_member_added" and (group or "").lower() in priv_groups
        created = creates.get(target) if e["event_type"] == "group_member_added" else None
        recent_create = created is not None and (_dt(e["ts"]) - _dt(created["ts"])) <= timedelta(minutes=p["window_minutes"])
        if e["event_type"] == "account_created":
            sev, conf, title = "low", 0.3, f"Account {target} created by {e['username']}"
            expl = f"Account '{target}' was created by '{e['username']}' on {e['hostname']}. Account creation is normal administration unless unexpected."
            ids = [e["id"]]
        else:
            sev = "high" if is_priv else "low"
            conf = 0.8 if (is_priv and recent_create) else (0.5 if is_priv else 0.25)
            title = f"{target} added to {group}" + (" shortly after account creation" if recent_create else "")
            expl = (f"'{target}' was added to group '{group}' by '{e['username']}'. "
                    + ("This is a privileged group. " if is_priv else "")
                    + (f"The account was created {int((_dt(e['ts']) - _dt(created['ts'])).total_seconds() // 60)} min earlier. " if recent_create else "")
                    + "Verify against change tickets.")
            ids = ([created["id"]] if recent_create else []) + [e["id"]]
        out.append(Finding("HF-007", sev, conf, e["ts"], "user", target, title, expl, ids,
                           {"target_account": target, "actor": e["username"], "host": e["hostname"], "group": group,
                            "privileged_group": is_priv, "created_recently": recent_create},
                           key=str(e["id"])))
    return out


# ---- HF-008 -------------------------------------------------------------------------
PERSIST = [
    ("scheduled_task", re.compile(r"schtasks(\.exe)?\s+.*/create", re.I)),
    ("run_key", re.compile(r"reg(\.exe)?\s+add\s+.*\\currentversion\\run(once)?\b", re.I)),
    ("service_install", re.compile(r"\bsc(\.exe)?\s+create\b", re.I)),
    ("startup_folder", re.compile(r"\\start menu\\programs\\startup\\", re.I)),
]


def persistence(conn, p, ing):
    out = []
    rows = _fetch(conn, "event_type IN ('process_create','persistence')", [], ing)
    for e in rows:
        hits = []
        if e["event_type"] == "persistence":
            hits.append("persistence_event")
        for name, rx in PERSIST:
            if rx.search(e["command_line"] or ""):
                hits.append(name)
        if not hits:
            continue
        host = e["hostname"] or "unknown"
        out.append(Finding("HF-008", "medium", 0.6 if len(hits) > 1 or "SYSTEM" in (e["command_line"] or e["message"] or "") else 0.45,
                           e["ts"], "host", host, f"Possible persistence on {host}: {', '.join(hits)}",
                           f"Event on {host} by {e['username'] or 'unknown user'} matches persistence mechanism(s): {', '.join(hits)}. "
                           f"Details: {(e['command_line'] or e['message'] or '')[:300]}",
                           [e["id"]],
                           {"host": host, "user": e["username"], "mechanisms": hits, "detail": e["command_line"] or e["message"]},
                           key=str(e["id"])))
    return out


CATALOG: list[RuleDef] = [
    RuleDef("HF-001", "Repeated failed logins from one source", "Many failed authentications from a single IP address in a short period.",
            "T1110 Brute Force", "medium",
            "Group failed authentication events by src_ip. Split into clusters where consecutive events are <= window_minutes apart. "
            "Alert when a cluster has >= threshold events.", ["Authentication logs with src_ip and outcome"],
            "Misconfigured services, users behind shared NAT, password-manager retries.",
            "Does not detect distributed (many-IP) attacks. Low-and-slow attempts spaced wider than the window are missed.",
            ["Check whether the source IP is internal, a known scanner or a corporate NAT.", "List all accounts targeted and any later successes (see HF-002).",
             "Review account lockout state and consider blocking the source."],
            {"threshold": 10, "window_minutes": 10}, brute_force),
    RuleDef("HF-002", "Successful login after repeated failures", "A successful authentication from the same IP shortly after a failed-login burst.",
            "T1110 Brute Force / T1078 Valid Accounts", "high",
            "Reuse HF-001 clusters. Alert if a successful authentication from the same src_ip occurs within success_window_minutes after the cluster ends. "
            "Confidence is higher when the successful account was among those failing.", ["Authentication logs with src_ip, username and outcome"],
            "A legitimate user who mistyped a password many times from one address.",
            "Requires the same source IP for failures and success; attackers rotating IPs evade correlation.",
            ["Confirm the login with the account owner via a separate channel.", "Review everything the account did after the success.",
             "Reset credentials and revoke active sessions if unconfirmed."],
            {"threshold": 10, "window_minutes": 10, "success_window_minutes": 30}, success_after_failures),
    RuleDef("HF-003", "Account used from multiple countries quickly", "One account authenticates successfully from different countries within a short window.",
            "T1078 Valid Accounts", "medium",
            "For each user, order successful authentications that carry a country. Alert when consecutive logins differ in country and are <= window_minutes apart.",
            ["Authentication logs with country (GeoIP-enriched)"],
            "VPNs, corporate proxies, mobile carriers, and GeoIP inaccuracy.",
            "Needs a country field; absent geo data means no detection. Not true impossible-travel (no distance model).",
            ["Compare IP ownership/ASN for each login.", "Ask the user whether a VPN was active.", "Check what each session accessed."],
            {"window_minutes": 60}, multi_location),
    RuleDef("HF-004", "Privileged account from external address", "A privileged account authenticates successfully from a non-internal IP.",
            "T1078.002 Domain Accounts / T1078.003 Local Accounts", "high",
            "Alert on successful authentication where username is in privileged_users and src_ip is outside RFC1918/loopback/link-local ranges. Grouped per user, IP and day.",
            ["Authentication logs with src_ip and username"], "Administrators using approved remote access or cloud-hosted jump boxes.",
            "Static account list; does not discover privileged accounts from group membership. Internal ranges are RFC1918 only.",
            ["Verify the source is an approved admin path.", "Review commands run in the session.", "Rotate the credential if unexplained."],
            {"privileged_users": ["admin", "administrator", "root"]}, privileged_external),
    RuleDef("HF-005", "Unusual outbound connections", "Repeated connections to external hosts on non-standard ports, or very large outbound transfers.",
            "T1071 Application Layer Protocol / T1041 Exfiltration Over C2 Channel", "medium",
            "For network_connection events to non-internal dst_ip, group by host+dst_ip+dst_port. Alert when port not in allowed_ports and count >= min_connections, "
            "or any single bytes_out >= large_transfer_bytes.", ["Network flow/firewall logs with dst_ip, dst_port, bytes_out"],
            "Backups, software updates, developer tooling, legitimate large uploads.",
            "No threat-intel lookup, no periodicity analysis; encrypted content cannot be inspected.",
            ["Identify the process that opened the connection.", "Check DNS history for the destination.", "Determine what data was sent."],
            {"allowed_ports": [80, 443, 53, 123, 22, 25, 587, 993], "min_connections": 3, "large_transfer_bytes": 10_000_000}, unusual_outbound),
    RuleDef("HF-006", "Suspicious command execution indicators", "Process creation with command lines or parent/child relationships associated with malware delivery.",
            "T1059 Command and Scripting Interpreter / T1204 User Execution", "high",
            "Match process_create events against regex indicators (encoded PowerShell, download cradles, LOLBin remote execution, hidden windows, execution from temp paths) "
            "and Office applications spawning shells.", ["Process creation telemetry with command_line and parent_process (EDR, Sysmon 1, Windows 4688)"],
            "Admin scripts, software installers and management tooling that use encoded commands.",
            "Signature-style regexes are easy to evade by obfuscation; absent command-line logging means no detection.",
            ["Decode and review the command line.", "Trace the parent process chain and the user.", "Look for follow-on network activity from the host."],
            {}, command_execution),
    RuleDef("HF-007", "Account creation and privilege changes", "New accounts and group membership additions, escalated when privileged groups are involved.",
            "T1136 Create Account / T1098 Account Manipulation", "medium",
            "Alert on account_created and group_member_added events (target_user and group read from the raw record). Severity rises for privileged_groups, "
            "and confidence rises when the account was created within window_minutes before being added.", ["Directory/OS audit logs (Windows 4720/4728/4732)"],
            "Routine onboarding and approved administrative changes.",
            "Cannot know whether a change was authorised; correlate with change records.",
            ["Verify a ticket exists for the change.", "Review actions by the creating account.", "Disable the new account if unexpected."],
            {"privileged_groups": ["administrators", "domain admins", "enterprise admins"], "window_minutes": 30}, account_changes),
    RuleDef("HF-008", "Possible persistence mechanisms", "Scheduled tasks, Run keys, new services or startup items created via command line or persistence telemetry.",
            "T1053 Scheduled Task / T1547 Boot or Logon Autostart / T1543 Create or Modify System Process", "medium",
            "Match process_create command lines against persistence patterns and any event typed 'persistence'.",
            ["Process creation telemetry; scheduled task/service creation events"],
            "Software installers and IT management tools create tasks and services routinely.",
            "Only observable techniques in the available telemetry are covered. WMI subscriptions, DLL hijacking and others are not.",
            ["Inspect the task/service binary path and hash.", "Check the creating user and parent process.", "Compare against approved software inventory."],
            {}, persistence),
]
BY_ID = {r.id: r for r in CATALOG}
