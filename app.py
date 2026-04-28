#!/usr/bin/env python3
"""
Panorama NAT Audit Tool
=======================
Web application to audit Palo Alto Panorama NAT rules:
- Connect via XML API or SSH
- List device groups / firewalls
- Pull static NAT entries
- Correlate with security (firewall) policies
- Ping internal hosts to check if they're alive
- Generate a report with CHG/RITM references
"""

import os
import re
import json
import time
import subprocess
import platform
import threading
from functools import wraps
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, Response
)

import requests
import xmltodict
import paramiko
import urllib3

# Suppress SSL warnings for self-signed Panorama certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production-panorama-nat-audit")

# ---------------------------------------------------------------------------
# Configuration defaults (override via environment or .env file)
# ---------------------------------------------------------------------------
# Load .env file if present (simple key=value parser, no dependency needed)
# Checks for .env first, falls back to config_example.env
_app_dir = os.path.dirname(os.path.abspath(__file__))
_env_file = None
for _candidate in [".env", "config_example.env"]:
    _path = os.path.join(_app_dir, _candidate)
    if os.path.exists(_path):
        _env_file = _path
        break

if _env_file:
    with open(_env_file) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _key, _val = _line.split("=", 1)
                os.environ.setdefault(_key.strip(), _val.strip())

# Web app login (the login page for this tool)
APP_USER = os.environ.get("APP_USER", "admin")
APP_PASS = os.environ.get("APP_PASS", "admin")

# Panorama connection defaults (pre-fill the connect form)
PANORAMA_HOST = os.environ.get("PANORAMA_HOST", "")
PANORAMA_USER = os.environ.get("PANORAMA_USER", "")
PANORAMA_PASS = os.environ.get("PANORAMA_PASS", "")
PANORAMA_API_KEY = os.environ.get("PANORAMA_API_KEY", "")
PANORAMA_METHOD = os.environ.get("PANORAMA_METHOD", "api")  # 'api' or 'ssh'
AUTO_CONNECT = os.environ.get("AUTO_CONNECT", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Authentication decorator
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

# ---------------------------------------------------------------------------
# Panorama XML API helpers
# ---------------------------------------------------------------------------
class PanoramaAPI:
    """Interact with Panorama / PAN-OS via the XML API."""

    def __init__(self, host, api_key, verify_ssl=False):
        self.base_url = f"https://{host}/api/"
        self.api_key = api_key
        self.verify = verify_ssl

    @staticmethod
    def generate_api_key(host, username, password, verify_ssl=False):
        """Generate an API key from username/password."""
        url = f"https://{host}/api/"
        params = {
            "type": "keygen",
            "user": username,
            "password": password,
        }
        resp = requests.get(url, params=params, verify=verify_ssl, timeout=30)
        resp.raise_for_status()
        data = xmltodict.parse(resp.text)
        return data["response"]["result"]["key"]

    def _request(self, params):
        """Make an API request and return parsed XML as dict."""
        params["key"] = self.api_key
        resp = requests.get(self.base_url, params=params, verify=self.verify, timeout=60)
        resp.raise_for_status()
        return xmltodict.parse(resp.text)

    def op(self, cmd):
        """Run an operational command."""
        return self._request({"type": "op", "cmd": cmd})

    def config_get(self, xpath):
        """Get configuration at an xpath."""
        return self._request({"type": "config", "action": "get", "xpath": xpath})

    # ----- Device groups -----
    def get_device_groups(self):
        """Return list of device group names from Panorama."""
        # Use operational command for a clean list of device groups
        # (config xpath returns the full nested config tree which
        # causes xmltodict to pick up child entries incorrectly)
        try:
            cmd = "<show><devicegroups><name>all</name></devicegroups></show>"
            data = self.op(cmd)
            groups = set()
            self._extract_device_group_names(data, groups)
            if groups:
                return sorted(groups)
        except Exception:
            pass

        # Fallback: use xpath but only request entry names
        try:
            xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry/@name"
            data = self.config_get(xpath)
            # Try to parse the response for @name attributes
            result = data.get("response", {}).get("result", "")
            if isinstance(result, str):
                # Some PAN-OS versions return names as text
                names = [n.strip() for n in result.split("\n") if n.strip()]
                if names:
                    return sorted(names)
        except Exception:
            pass

        # Final fallback: xpath with entry parsing, filter out non-DG names
        try:
            xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group"
            data = self.config_get(xpath)
            entries = data["response"]["result"]["device-group"]["entry"]
            if isinstance(entries, dict):
                entries = [entries]
            # Filter: real device groups have nested config like 'pre-rulebase',
            # 'post-rulebase', 'address', etc. Skip entries that look like
            # serial numbers or system keywords.
            system_keywords = {
                "certificate", "connected", "custom", "device", "express",
                "last", "local", "maximum", "merged", "operational",
                "predefined", "serial", "vpn", "virtual", "wildfire",
            }
            names = []
            for e in entries:
                name = e.get("@name", "")
                if not name:
                    continue
                # Skip serial numbers (all digits)
                if re.match(r'^\d+$', name):
                    continue
                # Skip system keywords
                if name.lower() in system_keywords:
                    continue
                # Skip separator lines
                if name.startswith("=") or name.startswith("-"):
                    continue
                # Skip entries with @ or > (like admin@panorama>)
                if "@" in name or ">" in name:
                    continue
                # Real device groups typically have sub-config
                has_config = any(
                    k in e for k in [
                        "pre-rulebase", "post-rulebase", "address",
                        "address-group", "service", "service-group",
                        "tag", "devices",
                    ]
                )
                if has_config:
                    names.append(name)
                elif len(entries) <= 20:
                    # If small list and passes filters above, include it
                    names.append(name)
            return sorted(names) if names else [e["@name"] for e in entries if "@name" in e]
        except (KeyError, TypeError):
            return []

    def _extract_device_group_names(self, data, groups, depth=0):
        """Extract device group names from operational command response."""
        if depth > 3:
            return
        if isinstance(data, dict):
            # The <show><devicegroups> response nests DG names as keys
            # or as entry @name attributes at the top level
            if "@name" in data and depth <= 2:
                name = data["@name"]
                # Validate it looks like a real device group name
                if (name and not re.match(r'^\d+$', name)
                        and "@" not in name and ">" not in name
                        and not name.startswith("=")):
                    groups.add(name)
            # Look for 'devicegroups' or 'device-group' keys
            for key in ("devicegroups", "device-group", "groups", "entry"):
                if key in data:
                    self._extract_device_group_names(data[key], groups, depth + 1)
            # Also check result
            if "result" in data:
                self._extract_device_group_names(data["result"], groups, depth + 1)
        elif isinstance(data, list):
            for item in data:
                self._extract_device_group_names(item, groups, depth + 1)

    def get_managed_firewalls(self):
        """Return list of managed firewall serial/hostname pairs."""
        cmd = "<show><devices><all></all></devices></show>"
        data = self.op(cmd)
        try:
            devices = data["response"]["result"]["devices"]["entry"]
            if isinstance(devices, dict):
                devices = [devices]
            results = []
            for d in devices:
                results.append({
                    "serial": d.get("serial", ""),
                    "hostname": d.get("hostname", d.get("serial", "unknown")),
                    "ip": d.get("ip-address", ""),
                    "model": d.get("model", ""),
                    "connected": d.get("connected", "no"),
                })
            return results
        except (KeyError, TypeError):
            return []

    # ----- NAT rules -----
    def get_nat_rules_device_group(self, device_group):
        """Get static NAT rules from a Panorama device group (pre-rules + post-rules)."""
        rules = []
        for rulebase in ["pre-rulebase", "post-rulebase"]:
            xpath = (
                f"/config/devices/entry[@name='localhost.localdomain']"
                f"/device-group/entry[@name='{device_group}']"
                f"/{rulebase}/nat/rules"
            )
            data = self.config_get(xpath)
            try:
                entries = data["response"]["result"]["rules"]["entry"]
                if isinstance(entries, dict):
                    entries = [entries]
                for e in entries:
                    rule = self._parse_nat_entry(e, rulebase)
                    if rule:
                        rules.append(rule)
            except (KeyError, TypeError):
                continue
        return rules

    def get_nat_rules_firewall(self, serial):
        """Get NAT rules from a specific firewall's local rulebase."""
        rules = []
        # Query the firewall directly through Panorama
        xpath = (
            f"/config/devices/entry[@name='localhost.localdomain']"
            f"/vsys/entry[@name='vsys1']/rulebase/nat/rules"
        )
        # Use target parameter for specific firewall
        params = {
            "type": "config",
            "action": "get",
            "xpath": xpath,
            "key": self.api_key,
            "target": serial,
        }
        try:
            resp = requests.get(self.base_url, params=params, verify=self.verify, timeout=60)
            resp.raise_for_status()
            data = xmltodict.parse(resp.text)
            entries = data["response"]["result"]["rules"]["entry"]
            if isinstance(entries, dict):
                entries = [entries]
            for e in entries:
                rule = self._parse_nat_entry(e, "local")
                if rule:
                    rules.append(rule)
        except (KeyError, TypeError, requests.RequestException):
            pass
        return rules

    def _parse_nat_entry(self, entry, rulebase):
        """Parse a NAT rule entry dict into a clean structure."""
        # We focus on static NAT (destination or source static)
        nat_type = "unknown"
        translated_ip = ""
        original_ip = ""

        # Destination translation (DNAT / static inbound)
        dst_trans = entry.get("destination-translation")
        src_trans = entry.get("source-translation")

        bi_directional = "no"

        if dst_trans:
            if isinstance(dst_trans, dict):
                static = dst_trans.get("translated-address", "")
                port = dst_trans.get("translated-port", "")
                translated_ip = static
                nat_type = "dnat-static"
                if port:
                    nat_type = f"dnat-static (port {port})"
        if src_trans:
            if isinstance(src_trans, dict):
                static_ip = src_trans.get("static-ip")
                if static_ip and isinstance(static_ip, dict):
                    translated_ip = static_ip.get("translated-address", "")
                    nat_type = "snat-static"
                    bi_dir = static_ip.get("bi-directional", "no")
                    if bi_dir and str(bi_dir).lower() == "yes":
                        bi_directional = "yes"
                        nat_type = "snat-static (bi-dir)"
                # Also check for dynamic-ip-and-port, dynamic-ip, etc.
                if not translated_ip:
                    dip = src_trans.get("dynamic-ip-and-port")
                    if dip and isinstance(dip, dict):
                        nat_type = "snat-dynamic"
                    dip2 = src_trans.get("dynamic-ip")
                    if dip2 and isinstance(dip2, dict):
                        nat_type = "snat-dynamic-ip"

        # Skip non-static NAT (dynamic IP/port, etc.)
        if "static" not in nat_type and not translated_ip:
            if dst_trans and isinstance(dst_trans, dict):
                if dst_trans.get("translated-address"):
                    translated_ip = dst_trans["translated-address"]
                    nat_type = "dnat"
            if not translated_ip:
                return None

        # Extract source/destination zones and addresses
        def _list_or_str(val):
            if val is None:
                return []
            if isinstance(val, dict):
                m = val.get("member", [])
                return m if isinstance(m, list) else [m]
            return [val] if isinstance(val, str) else list(val)

        src_zones = _list_or_str(entry.get("from"))
        dst_zones = _list_or_str(entry.get("to"))
        src_addrs = _list_or_str(entry.get("source"))
        dst_addrs = _list_or_str(entry.get("destination"))
        service = entry.get("service", "any")

        disabled = entry.get("disabled", "no")
        if disabled is None:
            disabled = "no"

        description = entry.get("description", "")
        tag = entry.get("tag")
        tags = _list_or_str(tag) if tag else []

        return {
            "name": entry.get("@name", "unknown"),
            "rulebase": rulebase,
            "nat_type": nat_type,
            "disabled": str(disabled).lower(),
            "from_zone": src_zones,
            "to_zone": dst_zones,
            "source": src_addrs,
            "destination": dst_addrs,
            "translated_ip": translated_ip,
            "bi_directional": bi_directional,
            "service": service if isinstance(service, str) else str(service),
            "description": description or "",
            "tags": tags,
        }

    # ----- Security / Firewall rules -----
    def get_security_rules_device_group(self, device_group):
        """Get security (firewall) rules from a device group."""
        rules = []
        for rulebase in ["pre-rulebase", "post-rulebase"]:
            xpath = (
                f"/config/devices/entry[@name='localhost.localdomain']"
                f"/device-group/entry[@name='{device_group}']"
                f"/{rulebase}/security/rules"
            )
            data = self.config_get(xpath)
            try:
                entries = data["response"]["result"]["rules"]["entry"]
                if isinstance(entries, dict):
                    entries = [entries]
                for e in entries:
                    rules.append(self._parse_security_entry(e, rulebase))
            except (KeyError, TypeError):
                continue
        return rules

    def get_security_rules_firewall(self, serial):
        """Get security rules from a specific managed firewall."""
        rules = []
        xpath = (
            f"/config/devices/entry[@name='localhost.localdomain']"
            f"/vsys/entry[@name='vsys1']/rulebase/security/rules"
        )
        params = {
            "type": "config",
            "action": "get",
            "xpath": xpath,
            "key": self.api_key,
            "target": serial,
        }
        try:
            resp = requests.get(self.base_url, params=params, verify=self.verify, timeout=60)
            resp.raise_for_status()
            data = xmltodict.parse(resp.text)
            entries = data["response"]["result"]["rules"]["entry"]
            if isinstance(entries, dict):
                entries = [entries]
            for e in entries:
                rules.append(self._parse_security_entry(e, "local"))
        except (KeyError, TypeError, requests.RequestException):
            pass
        return rules

    def _parse_security_entry(self, entry, rulebase):
        def _list_or_str(val):
            if val is None:
                return []
            if isinstance(val, dict):
                m = val.get("member", [])
                return m if isinstance(m, list) else [m]
            return [val] if isinstance(val, str) else list(val)

        disabled = entry.get("disabled", "no")
        if disabled is None:
            disabled = "no"

        description = entry.get("description", "")
        return {
            "name": entry.get("@name", "unknown"),
            "rulebase": rulebase,
            "action": entry.get("action", ""),
            "disabled": str(disabled).lower(),
            "from_zone": _list_or_str(entry.get("from")),
            "to_zone": _list_or_str(entry.get("to")),
            "source": _list_or_str(entry.get("source")),
            "destination": _list_or_str(entry.get("destination")),
            "application": _list_or_str(entry.get("application")),
            "service": _list_or_str(entry.get("service")),
            "description": description or "",
        }

    # ----- Hit count (to detect unused rules) -----
    def get_nat_hit_counts(self, device_group=None, serial=None):
        """Retrieve NAT rule hit counts. Returns dict {rule_name: hit_count}."""
        hit_counts = {}

        if device_group:
            # Try multiple command formats for Panorama rule hit counts
            for rulebase in ["pre-rulebase", "post-rulebase"]:
                # Format 1: Standard Panorama device-group hit count
                cmd = (
                    f"<show><rule-hit-count><device-group>"
                    f"<entry name='{device_group}'><{rulebase}>"
                    f"<entry name='nat'><rules><all/></rules></entry>"
                    f"</{rulebase}></entry>"
                    f"</device-group></rule-hit-count></show>"
                )
                try:
                    data = self.op(cmd)
                    self._extract_hit_counts(data, hit_counts)
                except Exception:
                    pass

            # Format 2: If no results, try without rulebase nesting
            if not hit_counts:
                cmd2 = (
                    f"<show><rule-hit-count><device-group>"
                    f"<entry name='{device_group}'>"
                    f"<rules><all/></rules>"
                    f"</entry></device-group></rule-hit-count></show>"
                )
                try:
                    data = self.op(cmd2)
                    self._extract_hit_counts(data, hit_counts)
                except Exception:
                    pass

        elif serial:
            cmd = (
                "<show><rule-hit-count><vsys><vsys-name>"
                "<entry name='vsys1'><rule-base><entry name='nat'>"
                "<rules><all/></rules></entry></rule-base></entry>"
                "</vsys-name></vsys></rule-hit-count></show>"
            )
            try:
                params = {
                    "type": "op", "cmd": cmd,
                    "key": self.api_key, "target": serial,
                }
                resp = requests.get(self.base_url, params=params, verify=self.verify, timeout=60)
                resp.raise_for_status()
                data = xmltodict.parse(resp.text)
                self._extract_hit_counts(data, hit_counts)
            except Exception:
                pass

        return hit_counts

    def _extract_hit_counts(self, data, result_dict):
        """Recursively find rule-hit-count entries and populate result_dict."""
        if isinstance(data, dict):
            # Check for hit-count data - could be "hit-count" or "hit_count"
            name = data.get("@name", "")
            hc = data.get("hit-count", data.get("hit_count"))
            if name and hc is not None:
                try:
                    result_dict[name] = int(hc)
                except (ValueError, TypeError):
                    result_dict[name] = 0
            # Also check for "rule-count" style entries
            if name and "latest" in data:
                latest = data.get("latest", "")
                if latest == "yes":
                    # This entry has count info nearby
                    count = data.get("rule-count", data.get("count", data.get("hit-count")))
                    if count is not None:
                        try:
                            result_dict[name] = int(count)
                        except (ValueError, TypeError):
                            pass
            for v in data.values():
                self._extract_hit_counts(v, result_dict)
        elif isinstance(data, list):
            for item in data:
                self._extract_hit_counts(item, result_dict)


# ---------------------------------------------------------------------------
# SSH helper
# ---------------------------------------------------------------------------
class PanoramaSSH:
    """Interact with Panorama / PAN-OS via SSH CLI."""

    def __init__(self, host, username, password, port=22):
        self.host = host
        self.username = username
        self.password = password
        self.port = port

    def _run_command(self, command, timeout=30):
        """Open SSH, run command, return output."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                self.host, port=self.port,
                username=self.username, password=self.password,
                timeout=15, look_for_keys=False, allow_agent=False,
            )
            # Use invoke_shell for PAN-OS (it doesn't support exec_command well)
            shell = client.invoke_shell(width=512, height=1000)
            time.sleep(2)
            shell.recv(65535)  # clear banner

            # Turn off paging
            shell.send("set cli pager off\n")
            time.sleep(1)
            shell.recv(65535)

            # Send command
            shell.send(command + "\n")
            time.sleep(3)

            output = b""
            wait_cycles = 0
            while wait_cycles < timeout:
                if shell.recv_ready():
                    chunk = shell.recv(65535)
                    output += chunk
                    wait_cycles = 0
                else:
                    time.sleep(1)
                    wait_cycles += 1
                    if wait_cycles > 5 and len(output) > 0:
                        break
            return output.decode("utf-8", errors="replace")
        finally:
            client.close()

    def get_device_groups(self):
        """Parse device groups from CLI using set-format output."""
        # Use 'set' output format to get clean device group names
        # Output looks like: "set device-group benson ..."
        output = self._run_command(
            "configure\n"  # enter config mode briefly
        )
        time.sleep(1)
        # Request set-format device group listing
        output = self._run_command(
            "show | match \"^set device-group\" | except rulebase | except address | except service | except profile | except tag | except log"
        )
        groups = set()
        for line in output.split("\n"):
            line = line.strip()
            m = re.match(r'^set\s+device-group\s+(\S+)', line)
            if m:
                groups.add(m.group(1))

        if groups:
            return sorted(groups)

        # Fallback: try 'show devicegroups' and parse the tabular output
        # Device group names appear in the first column of the table
        output = self._run_command("show devicegroups")
        groups = set()
        in_table = False
        for line in output.split("\n"):
            # Skip empty lines and separators
            stripped = line.strip()
            if not stripped or stripped.startswith("-") or stripped.startswith("="):
                continue
            # Skip header line
            if "device-group" in stripped.lower() and ("devices" in stripped.lower() or "name" in stripped.lower()):
                in_table = True
                continue
            # In the show devicegroups output, device group names are NOT indented
            # while firewall entries underneath them ARE indented
            if line and not line[0].isspace() and not line[0] in ('-', '=', '+', '|', '*'):
                # First non-space field on an unindented line
                name = stripped.split()[0] if stripped.split() else ""
                if name and not re.match(r'^\d+$', name) and "@" not in name and ">" not in name:
                    groups.add(name)

        return sorted(groups)

    def get_managed_firewalls(self):
        """Parse managed devices from CLI."""
        output = self._run_command("show devices all")
        devices = []
        current = {}
        for line in output.split("\n"):
            if "serial" in line.lower() and ":" in line:
                if current.get("serial"):
                    devices.append(current)
                current = {}
                val = line.split(":", 1)[-1].strip()
                current["serial"] = val
            elif "hostname" in line.lower() and ":" in line:
                current["hostname"] = line.split(":", 1)[-1].strip()
            elif "ip-address" in line.lower() and ":" in line:
                current["ip"] = line.split(":", 1)[-1].strip()
        if current.get("serial"):
            devices.append(current)
        return devices

    def get_nat_rules_raw(self, device_group=None):
        """Get NAT config via CLI and return raw text for parsing."""
        if device_group:
            cmd = f"show devicegroups name {device_group}"
        else:
            cmd = "show running nat-policy"
        return self._run_command(cmd, timeout=20)


# ---------------------------------------------------------------------------
# Utility: RFC1918 check
# ---------------------------------------------------------------------------
def is_rfc1918(ip):
    """Return True if ip is in 10/8, 172.16/12, or 192.168/16."""
    try:
        ip = ip.strip().split("/")[0]
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        octets = [int(p) for p in parts]
        if octets[0] == 10:
            return True
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        if octets[0] == 192 and octets[1] == 168:
            return True
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Utility: ping host locally (from the server running this app)
# ---------------------------------------------------------------------------
def ping_host(ip, timeout=2):
    """Ping an RFC1918 host from this server. Returns True/False/None."""
    try:
        ip = ip.strip().split("/")[0]
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            return None
        if not is_rfc1918(ip):
            return None
        param = "-n" if platform.system().lower() == "windows" else "-c"
        timeout_flag = "-w" if platform.system().lower() == "windows" else "-W"
        timeout_val = str(timeout * 1000) if platform.system().lower() == "windows" else str(timeout)
        result = subprocess.run(
            ["ping", param, "1", timeout_flag, timeout_val, ip],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout + 5,
        )
        return result.returncode == 0
    except Exception:
        return None


def ping_hosts_parallel(ip_list, timeout=2, max_threads=20):
    """Ping multiple RFC1918 hosts concurrently from this server."""
    results = {}
    lock = threading.Lock()

    def _ping(ip):
        alive = ping_host(ip, timeout)
        with lock:
            results[ip] = alive

    threads = []
    for ip in ip_list:
        t = threading.Thread(target=_ping, args=(ip,))
        threads.append(t)
        t.start()
        if len(threads) >= max_threads:
            for t in threads:
                t.join()
            threads = []
    for t in threads:
        t.join()
    return results


# ---------------------------------------------------------------------------
# Business logic: correlate NAT → Security rules
# ---------------------------------------------------------------------------
CHG_RITM_PATTERN = re.compile(r'(CHG\d{5,}|RITM\d{5,}|INC\d{5,}|REQ\d{5,})', re.IGNORECASE)


def find_change_tickets(description):
    """Extract CHG/RITM/INC/REQ ticket numbers from a description."""
    if not description:
        return []
    return CHG_RITM_PATTERN.findall(description)


def correlate_nat_to_security(nat_rules, security_rules):
    """
    For each NAT rule, find security rules that allow traffic for that NAT.

    Matching strategy: find the public (non-RFC1918) IP from the NAT rule,
    then look for security rules whose source or destination references
    that public IP. Security rules use the public/translated address.
    """
    correlations = {}

    for nat in nat_rules:
        matching_sec_rules = []
        nat_translated = nat.get("translated_ip", "")
        nat_sources = set(nat.get("source", [])) - {"any"}
        nat_destinations = set(nat.get("destination", [])) - {"any"}

        # Build the set of public (non-RFC1918) IPs for this NAT rule
        public_ips = set()
        for addr in nat_sources:
            if re.match(r'^\d{1,3}\.', addr) and not is_rfc1918(addr):
                public_ips.add(addr.split("/")[0])
        for addr in nat_destinations:
            if re.match(r'^\d{1,3}\.', addr) and not is_rfc1918(addr):
                public_ips.add(addr.split("/")[0])
        if nat_translated and re.match(r'^\d{1,3}\.', nat_translated):
            if not is_rfc1918(nat_translated):
                public_ips.add(nat_translated.split("/")[0])

        # Also keep non-IP address objects (named objects like "WebServer-Public")
        named_addrs = set()
        for addr in nat_sources | nat_destinations:
            if not re.match(r'^\d{1,3}\.', addr):
                named_addrs.add(addr)
        if nat_translated and not re.match(r'^\d{1,3}\.', nat_translated):
            named_addrs.add(nat_translated)

        all_match_addrs = public_ips | named_addrs

        if not all_match_addrs:
            # No public IPs found; skip correlation
            correlations[nat["name"]] = []
            continue

        for sec in security_rules:
            if sec.get("action") not in ("allow", ""):
                continue

            sec_sources = set(sec.get("source", []))
            sec_destinations = set(sec.get("destination", []))
            sec_all_addrs = sec_sources | sec_destinations

            # Match if any public IP from the NAT appears in the
            # security rule's source or destination addresses
            if all_match_addrs & sec_destinations:
                matching_sec_rules.append(sec)
            elif all_match_addrs & sec_sources:
                matching_sec_rules.append(sec)
            elif "any" in sec_destinations:
                # "any" destination could match, but only if zones align
                nat_src_zones = set(nat.get("from_zone", []))
                nat_dst_zones = set(nat.get("to_zone", []))
                sec_src_zones = set(sec.get("from_zone", []))
                sec_dst_zones = set(sec.get("to_zone", []))
                # Check forward or reverse zone match
                fwd = nat_src_zones & sec_src_zones and nat_dst_zones & sec_dst_zones
                rev = nat_dst_zones & sec_src_zones and nat_src_zones & sec_dst_zones
                if fwd or rev:
                    matching_sec_rules.append(sec)

        correlations[nat["name"]] = matching_sec_rules

    return correlations


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == APP_USER and password == APP_PASS:
            session["logged_in"] = True
            return redirect(url_for("index"))
        flash("Invalid credentials", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html",
        panorama_host=PANORAMA_HOST,
        panorama_user=PANORAMA_USER,
        panorama_pass=PANORAMA_PASS,
        panorama_api_key=PANORAMA_API_KEY,
        panorama_method=PANORAMA_METHOD,
        auto_connect=AUTO_CONNECT,
    )


@app.route("/api/connect", methods=["POST"])
@login_required
def api_connect():
    """Store Panorama connection info in session and test connectivity."""
    data = request.json
    method = data.get("method", "api")  # 'api' or 'ssh'
    host = data.get("host", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    api_key = data.get("api_key", "").strip()

    if not host:
        return jsonify({"error": "Panorama host is required"}), 400

    if method == "api":
        try:
            if not api_key:
                if not username or not password:
                    return jsonify({"error": "Provide API key or username/password"}), 400
                api_key = PanoramaAPI.generate_api_key(host, username, password)

            pan = PanoramaAPI(host, api_key)
            # Test: get system info
            info = pan.op("<show><system><info></info></system></show>")
            hostname = "Panorama"
            try:
                hostname = info["response"]["result"]["system"]["hostname"]
            except (KeyError, TypeError):
                pass

            session["panorama"] = {
                "host": host,
                "method": "api",
                "api_key": api_key,
            }
            return jsonify({"success": True, "hostname": hostname, "method": "api"})

        except Exception as e:
            return jsonify({"error": f"API connection failed: {str(e)}"}), 400

    elif method == "ssh":
        if not username or not password:
            return jsonify({"error": "Username and password required for SSH"}), 400
        try:
            ssh = PanoramaSSH(host, username, password)
            output = ssh._run_command("show system info")
            if "hostname" not in output.lower():
                return jsonify({"error": "SSH connected but unexpected output"}), 400

            session["panorama"] = {
                "host": host,
                "method": "ssh",
                "username": username,
                "password": password,
            }
            hostname = "Panorama"
            for line in output.split("\n"):
                if "hostname:" in line.lower():
                    hostname = line.split(":", 1)[-1].strip()
                    break
            return jsonify({"success": True, "hostname": hostname, "method": "ssh"})

        except Exception as e:
            return jsonify({"error": f"SSH connection failed: {str(e)}"}), 400

    return jsonify({"error": "Invalid method"}), 400


@app.route("/api/targets", methods=["GET"])
@login_required
def api_targets():
    """Get available device groups and managed firewalls."""
    pano = session.get("panorama")
    if not pano:
        return jsonify({"error": "Not connected to Panorama"}), 400

    device_groups = []
    firewalls = []

    if pano["method"] == "api":
        pan = PanoramaAPI(pano["host"], pano["api_key"])
        device_groups = pan.get_device_groups()
        firewalls = pan.get_managed_firewalls()
    elif pano["method"] == "ssh":
        try:
            ak = PanoramaAPI.generate_api_key(pano["host"], pano["username"], pano["password"])
            pan = PanoramaAPI(pano["host"], ak)
            device_groups = pan.get_device_groups()
            firewalls = pan.get_managed_firewalls()
            pano["api_key"] = ak
            session["panorama"] = pano
        except Exception:
            ssh = PanoramaSSH(pano["host"], pano["username"], pano["password"])
            device_groups = ssh.get_device_groups()
            firewalls = ssh.get_managed_firewalls()

    return jsonify({"device_groups": device_groups, "firewalls": firewalls})


@app.route("/api/audit", methods=["POST"])
@login_required
def api_audit():
    """Run the NAT audit for a selected target."""
    pano = session.get("panorama")
    if not pano:
        return jsonify({"error": "Not connected to Panorama"}), 400

    data = request.json
    target_type = data.get("target_type", "device_group")
    target_name = data.get("target_name", "")
    do_ping = data.get("do_ping", True)

    if not target_name:
        return jsonify({"error": "No target selected"}), 400

    api_key = pano.get("api_key", "")
    if not api_key and pano["method"] == "ssh":
        try:
            api_key = PanoramaAPI.generate_api_key(pano["host"], pano["username"], pano["password"])
            pano["api_key"] = api_key
            session["panorama"] = pano
        except Exception:
            return jsonify({"error": "Could not generate API key from SSH credentials."}), 400

    if not api_key:
        return jsonify({"error": "No API key available."}), 400

    pan = PanoramaAPI(pano["host"], api_key)

    if target_type == "device_group":
        nat_rules = pan.get_nat_rules_device_group(target_name)
        sec_rules = pan.get_security_rules_device_group(target_name)
        hit_counts = pan.get_nat_hit_counts(device_group=target_name)
    else:
        nat_rules = pan.get_nat_rules_firewall(target_name)
        sec_rules = pan.get_security_rules_firewall(target_name)
        hit_counts = pan.get_nat_hit_counts(serial=target_name)

    if not nat_rules:
        return jsonify({"error": "No static NAT rules found for this target", "results": []}), 200

    correlations = correlate_nat_to_security(nat_rules, sec_rules)

    # Compute internal (RFC1918) IP for each NAT rule
    def get_internal_ip(nat):
        """For SNAT: internal host is in source. For DNAT: it's the translated IP."""
        nat_type = nat.get("nat_type", "")
        if "snat" in nat_type:
            # Internal server IP is the source address
            for addr in nat.get("source", []):
                if addr != "any" and re.match(r'^\d{1,3}\.', addr):
                    ip = addr.split("/")[0]
                    if is_rfc1918(ip):
                        return ip
        if "dnat" in nat_type:
            # Internal server IP is the translated destination
            tip = nat.get("translated_ip", "")
            if tip and re.match(r'^\d{1,3}\.', tip):
                ip = tip.split("/")[0]
                if is_rfc1918(ip):
                    return ip
        # Bi-directional: also check source for the internal IP
        if nat.get("bi_directional") == "yes":
            for addr in nat.get("source", []):
                if addr != "any" and re.match(r'^\d{1,3}\.', addr):
                    ip = addr.split("/")[0]
                    if is_rfc1918(ip):
                        return ip
        # Last resort: check destination and translated_ip for any RFC1918
        for addr in nat.get("destination", []):
            if addr != "any" and re.match(r'^\d{1,3}\.', addr):
                ip = addr.split("/")[0]
                if is_rfc1918(ip):
                    return ip
        tip = nat.get("translated_ip", "")
        if tip and re.match(r'^\d{1,3}\.', tip):
            ip = tip.split("/")[0]
            if is_rfc1918(ip):
                return ip
        return ""

    # Build internal IP map and ping only RFC1918 addresses
    internal_ip_map = {}
    for rule in nat_rules:
        internal_ip_map[rule["name"]] = get_internal_ip(rule)

    ping_results = {}
    if do_ping:
        ips_to_ping = set()
        for name, ip in internal_ip_map.items():
            if ip and is_rfc1918(ip):
                ips_to_ping.add(ip)
        if ips_to_ping:
            ping_results = ping_hosts_parallel(list(ips_to_ping))

    results = []
    for nat in nat_rules:
        translated_ip = nat.get("translated_ip", "")
        internal_ip = internal_ip_map.get(nat["name"], "")
        is_disabled = nat.get("disabled", "no") == "yes"
        hc = hit_counts.get(nat["name"])
        hit_count_str = str(hc) if hc is not None else "N/A"
        is_unused = hc == 0 if hc is not None else None
        host_alive = ping_results.get(internal_ip) if internal_ip else None

        matched_sec = correlations.get(nat["name"], [])
        sec_rule_info = []
        all_tickets = []
        for sr in matched_sec:
            tickets = find_change_tickets(sr.get("description", ""))
            all_tickets.extend(tickets)
            sec_rule_info.append({
                "name": sr["name"],
                "action": sr.get("action", ""),
                "disabled": sr.get("disabled", "no"),
                "description": sr.get("description", ""),
                "tickets": tickets,
            })

        nat_tickets = find_change_tickets(nat.get("description", ""))
        all_tickets.extend(nat_tickets)

        status_flags = []
        if is_disabled:
            status_flags.append("DISABLED")
        if is_unused:
            status_flags.append("UNUSED (0 hits)")
        if host_alive is False:
            status_flags.append("HOST DOWN")
        elif host_alive is None and internal_ip:
            status_flags.append("HOST UNKNOWN")
        if not matched_sec:
            status_flags.append("NO SECURITY RULE")

        results.append({
            "nat_rule": nat["name"],
            "nat_type": nat["nat_type"],
            "rulebase": nat["rulebase"],
            "status": "inactive" if is_disabled else "active",
            "disabled": is_disabled,
            "from_zone": ", ".join(nat.get("from_zone", [])),
            "to_zone": ", ".join(nat.get("to_zone", [])),
            "original_src": ", ".join(nat.get("source", [])),
            "original_dst": ", ".join(nat.get("destination", [])),
            "translated_ip": translated_ip,
            "bi_directional": nat.get("bi_directional", "no"),
            "internal_ip": internal_ip,
            "service": nat.get("service", ""),
            "nat_description": nat.get("description", ""),
            "hit_count": hit_count_str,
            "is_unused": is_unused,
            "host_alive": host_alive,
            "host_status": "Up" if host_alive else ("Down" if host_alive is False else "Unknown"),
            "security_rules": sec_rule_info,
            "tickets": list(set(all_tickets)),
            "flags": status_flags,
        })

    results.sort(key=lambda r: (0 if r["flags"] else 1, r["nat_rule"]))


    summary = {
        "total_nat_rules": len(results),
        "disabled": sum(1 for r in results if r["disabled"]),
        "unused": sum(1 for r in results if r["is_unused"]),
        "host_down": sum(1 for r in results if r["host_alive"] is False),
        "no_security_rule": sum(1 for r in results if not r["security_rules"]),
        "clean": sum(1 for r in results if not r["flags"]),
    }

    return jsonify({"results": results, "summary": summary})


@app.route("/api/export", methods=["POST"])
@login_required
def api_export():
    """Export results as CSV."""
    data = request.json
    results = data.get("results", [])

    csv_lines = [
        "NAT Rule,Type,Rulebase,Status,From Zone,To Zone,Original Source,"
        "Original Destination,Translated IP,Internal IP,Bi-Directional,"
        "Service,Hit Count,Host Status,Security Rule(s),"
        "Tickets (CHG/RITM),Flags,NAT Description"
    ]

    for r in results:
        sec_names = "; ".join(s["name"] for s in r.get("security_rules", []))
        tickets = "; ".join(r.get("tickets", []))
        flags = "; ".join(r.get("flags", []))
        row = [
            r.get("nat_rule", ""), r.get("nat_type", ""), r.get("rulebase", ""),
            r.get("status", ""), r.get("from_zone", ""), r.get("to_zone", ""),
            r.get("original_src", ""), r.get("original_dst", ""),
            r.get("translated_ip", ""), r.get("internal_ip", ""),
            r.get("bi_directional", ""), r.get("service", ""),
            r.get("hit_count", ""), r.get("host_status", ""),
            sec_names, tickets, flags, r.get("nat_description", ""),
        ]
        csv_lines.append(",".join('"' + str(c) + '"' for c in row))

    csv_content = "\n".join(csv_lines)
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=nat_audit_export.csv"},
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
