#!/usr/bin/env python3
"""
NetGuard - SmartBranch 360 Config Assurance Tool
--------------------------------------------------
Validates a branch office network build against its design plan.

It reads:
  1. plan.json            - the intended VLAN / IP / security design
  2. show_vlan.txt         - output of 'show vlan brief' from the switch
  3. show_ip_int_brief.txt - output of 'show ip interface brief' from the router
  4. show_run_acl.txt      - relevant 'show run | section access-list' output
  5. show_ip_nat_stats.txt - output of 'show ip nat statistics'

It reports PASS/FAIL findings such as: missing VLANs, VLANs pruned from the
trunk, wrong sub-interface gateway addresses, an ACL that does not block
Guest -> Server traffic, and NAT overload not active.

Usage:
    python3 netguard.py --plan plan.json --evidence ./evidence
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field


@dataclass
class Finding:
    check: str
    status: str          # "PASS" or "FAIL"
    detail: str


@dataclass
class Report:
    findings: list = field(default_factory=list)

    def add(self, check, ok, detail):
        self.findings.append(Finding(check, "PASS" if ok else "FAIL", detail))

    def print(self):
        print("=" * 72)
        print("NetGuard Assurance Report - SmartBranch 360")
        print("=" * 72)
        fails = 0
        for f in self.findings:
            marker = "[ OK ]" if f.status == "PASS" else "[FAIL]"
            if f.status == "FAIL":
                fails += 1
            print(f"{marker} {f.check:<38} {f.detail}")
        print("-" * 72)
        total = len(self.findings)
        print(f"Result: {total - fails}/{total} checks passed.")
        if fails:
            print("Action required: review the FAIL lines above before sign-off.")
        else:
            print("All configuration checks match the SmartBranch 360 design plan.")
        return fails


def load_text(path):
    try:
        with open(path) as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def check_vlans(plan, vlan_txt, report):
    """Every VLAN in the plan must exist and be active on the switch."""
    for vlan in plan["vlans"]:
        pattern = rf"^{vlan['id']}\s+{vlan['name']}\s+active"
        found = re.search(pattern, vlan_txt, re.MULTILINE | re.IGNORECASE)
        report.add(
            f"VLAN {vlan['id']} ({vlan['name']}) present",
            bool(found),
            "found and active" if found else "missing or inactive on switch",
        )


def check_trunk_allowed(plan, vlan_txt, trunk_txt, report):
    """All VLANs must be allowed on the uplink trunk (not pruned)."""
    allowed_line = re.search(r"Vlans allowed on trunk\s*\n?\s*Fa\S*\s+([\d,\s]+)", trunk_txt)
    allowed_ids = set()
    if allowed_line:
        allowed_ids = {v.strip() for v in allowed_line.group(1).split(",") if v.strip()}
    for vlan in plan["vlans"]:
        ok = str(vlan["id"]) in allowed_ids
        report.add(
            f"VLAN {vlan['id']} allowed on trunk",
            ok,
            "carried on uplink trunk" if ok else "PRUNED from trunk allowed list",
        )


def check_gateways(plan, ip_int_txt, report):
    """Each VLAN sub-interface must be up and hold the planned gateway IP."""
    for vlan in plan["vlans"]:
        subif = f"GigabitEthernet0/1.{vlan['id']}"
        pattern = rf"{re.escape(subif)}\s+(\S+)\s+YES\s+\S+\s+(up)\s+(up)"
        m = re.search(pattern, ip_int_txt)
        if not m:
            report.add(f"{subif} gateway", False, "sub-interface not found or down")
            continue
        actual_ip = m.group(1)
        ok = actual_ip == vlan["gateway"]
        report.add(
            f"{subif} gateway",
            ok,
            f"{actual_ip} matches plan" if ok else f"{actual_ip} != planned {vlan['gateway']}",
        )


def check_guest_to_server_block(plan, acl_txt, report):
    """The security plan requires Guest VLAN traffic to Server VLAN to be denied."""
    guest_net = next(v for v in plan["vlans"] if v["name"] == "GUEST")["network"]
    server_net = next(v for v in plan["vlans"] if v["name"] == "SERVER")["network"]
    pattern = rf"deny\s+ip\s+{re.escape(guest_net)}.*{re.escape(server_net)}"
    found = re.search(pattern, acl_txt)
    report.add(
        "ACL: Guest -> Server denied",
        bool(found),
        "deny rule present" if found else "no explicit deny rule found - guest can reach servers",
    )


def check_ssh_mgmt_only(plan, acl_txt, report):
    """SSH (VTY) access should only be permitted from the Management VLAN."""
    mgmt_net = next(v for v in plan["vlans"] if v["name"] == "MANAGEMENT")["network"]
    found = re.search(rf"permit\s+tcp\s+{re.escape(mgmt_net)}.*eq\s+22", acl_txt)
    report.add(
        "SSH restricted to Management VLAN",
        bool(found),
        "management-only permit found" if found else "no VTY ACL tying SSH to management subnet",
    )


def check_nat_overload(nat_txt, report):
    """NAT overload (PAT) must be active for internet-bound traffic."""
    low = nat_txt.lower()
    ok = "outside interfaces" in low and "inside interfaces" in low and "hits" in low
    report.add(
        "NAT overload active",
        ok,
        "NAT statistics show active translations" if ok  else "NAT statistics missing/empty - check overload config",
    )


def main():
    ap = argparse.ArgumentParser(description="NetGuard - SmartBranch 360 assurance tool")
    ap.add_argument("--plan", default="plan.json", help="Path to the design plan JSON")
    ap.add_argument("--evidence", default=".", help="Directory containing captured show-command text files")
    args = ap.parse_args()

    with open(args.plan) as fh:
        plan = json.load(fh)

    vlan_txt = load_text(f"{args.evidence}/show_vlan.txt")
    trunk_txt = load_text(f"{args.evidence}/show_trunk.txt")
    ip_int_txt = load_text(f"{args.evidence}/show_ip_int_brief.txt")
    acl_txt = load_text(f"{args.evidence}/show_run_acl.txt")
    nat_txt = load_text(f"{args.evidence}/show_ip_nat_stats.txt")

    report = Report()
    check_vlans(plan, vlan_txt, report)
    check_trunk_allowed(plan, vlan_txt, trunk_txt, report)
    check_gateways(plan, ip_int_txt, report)
    check_guest_to_server_block(plan, acl_txt, report)
    check_ssh_mgmt_only(plan, acl_txt, report)
    check_nat_overload(nat_txt, report)

    fails = report.print()
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
