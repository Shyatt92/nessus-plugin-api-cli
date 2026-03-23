#!/usr/bin/env python3
"""
fetch_matched_nessus_plugins.py

Modes:
  1) Expression mode:
     --expr '("Windows Server" AND 2016) AND NOT 2019'
  2) Direct plugin ID mode:
     --plugin-id 298556,283466

Authentication:
  - CLI:
      --access-key / --secret-key
      or
      --token
  - Environment variables:
      nessus_access_key
      nessus_secret_key
      nessus_api_token

Outputs:
  --out / -o   Comma-separated output types: json,csv,txt
  --filename/-f Single base filename used for all requested outputs
  -k / --insecure  Suppress TLS verification warnings

Examples:
  python fetch_matched_nessus_plugins.py \
    --plugin-id 298556,283466 \
    --access-key ACCESS --secret-key SECRET \
    --out json,csv,txt --filename results -k

  python fetch_matched_nessus_plugins.py \
    --expr 'KB5075999 OR KB5073722' \
    --token TOKEN \
    --out csv --filename results -k
"""

import argparse
import csv
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# -------------------------
# Expression parsing & eval
# -------------------------

def tokenize_expr(expr: str) -> List[str]:
    tokens = []
    i = 0
    n = len(expr)
    while i < n:
        c = expr[i]
        if c.isspace():
            i += 1
            continue
        if c in "()":
            tokens.append(c)
            i += 1
            continue
        if c in ("'", '"'):
            q = c
            i += 1
            start = i
            while i < n and expr[i] != q:
                i += 1
            tokens.append(expr[start:i])
            i += 1
            continue
        start = i
        while i < n and not expr[i].isspace() and expr[i] not in "()":
            i += 1
        tokens.append(expr[start:i])

    norm = []
    for t in tokens:
        ut = t.upper()
        norm.append(ut if ut in ("AND", "OR", "NOT") else t)
    return norm


def shunting_yard(tokens: List[str]) -> List[str]:
    prec = {"NOT": 3, "AND": 2, "OR": 1}
    output = []
    stack = []
    for tok in tokens:
        if tok in ("AND", "OR", "NOT"):
            while stack and stack[-1] != "(" and prec.get(stack[-1], 0) >= prec[tok]:
                output.append(stack.pop())
            stack.append(tok)
        elif tok == "(":
            stack.append(tok)
        elif tok == ")":
            while stack and stack[-1] != "(":
                output.append(stack.pop())
            if stack and stack[-1] == "(":
                stack.pop()
        else:
            output.append(tok)
    while stack:
        output.append(stack.pop())
    return output


def build_match_function(expr: str):
    tokens = tokenize_expr(expr)
    if not tokens:
        return lambda s: False
    rpn = shunting_yard(tokens)

    def matcher(s: str) -> bool:
        stack = []
        s_low = (s or "").lower()
        for tok in rpn:
            if tok == "NOT":
                if not stack:
                    return False
                a = stack.pop()
                stack.append(not a)
            elif tok == "AND":
                if len(stack) < 2:
                    return False
                b = stack.pop()
                a = stack.pop()
                stack.append(a and b)
            elif tok == "OR":
                if len(stack) < 2:
                    return False
                b = stack.pop()
                a = stack.pop()
                stack.append(a or b)
            else:
                stack.append(tok.lower() in s_low)
        return bool(stack) and stack[-1]

    return matcher


# -------------------------
# HTTP helpers
# -------------------------

def build_session(access_key: Optional[str], secret_key: Optional[str], token: Optional[str]) -> requests.Session:
    s = requests.Session()
    retries = Retry(total=3, backoff_factor=0.3, status_forcelist=(429, 500, 502, 503, 504))
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.mount("http://", HTTPAdapter(max_retries=retries))
    headers = {"Accept": "application/json"}
    if token:
        headers["X-Cookie"] = f"token={token}"
    elif access_key and secret_key:
        headers["X-ApiKeys"] = f"accessKey={access_key}; secretKey={secret_key}"
    else:
        raise ValueError("Either API keys or a session token must be provided.")
    s.headers.update(headers)
    return s


def request_json(session: requests.Session, method: str, url: str, json_body: Any = None, verify: bool = True, timeout: int = 20) -> Optional[Dict[str, Any]]:
    try:
        if method.upper() == "GET":
            resp = session.get(url, verify=verify, timeout=timeout)
        elif method.upper() == "POST":
            resp = session.post(url, json=json_body, verify=verify, timeout=timeout)
        else:
            resp = session.request(method, url, json=json_body, verify=verify, timeout=timeout)

        if 200 <= resp.status_code < 300:
            if not resp.content:
                return None
            try:
                return resp.json()
            except ValueError:
                return None
        return None
    except requests.RequestException:
        return None


# -------------------------
# Family parsing helpers
# -------------------------

def find_plugin_entries_in_family_json(family_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    candidates = []
    for key in ("plugins", "plugin_list", "pluginids", "pluginIDs", "plugin_ids", "plugin_ids_list", "pluginList"):
        if key in family_json and isinstance(family_json[key], list):
            candidates.extend(family_json[key])

    if "family" in family_json and isinstance(family_json["family"], dict):
        for key in ("plugins", "plugin_list", "pluginList"):
            if key in family_json["family"] and isinstance(family_json["family"][key], list):
                candidates.extend(family_json["family"][key])

    def _recursive_search(obj):
        if isinstance(obj, dict):
            if "id" in obj and any(k in obj for k in ("name", "plugin_name", "title")):
                candidates.append(obj)
            for v in obj.values():
                _recursive_search(v)
        elif isinstance(obj, list):
            for item in obj:
                _recursive_search(item)

    _recursive_search(family_json)

    normalized = []
    seen = set()
    for entry in candidates:
        if not isinstance(entry, dict):
            continue
        pid = None
        for pk in ("id", "plugin_id", "pluginID", "pluginId"):
            if pk in entry:
                pid = entry[pk]
                break
        name = None
        for nk in ("name", "plugin_name", "title"):
            if nk in entry:
                name = entry[nk]
                break
        if pid is None:
            continue
        try:
            pid_int = int(pid)
        except Exception:
            continue
        if pid_int in seen:
            continue
        seen.add(pid_int)
        normalized.append({"id": pid_int, "name": name or ""})
    return normalized


# -------------------------
# Fetch plugin details
# -------------------------

def fetch_plugin_detail_threadsafe(
    pid: int,
    access_key: Optional[str],
    secret_key: Optional[str],
    token: Optional[str],
    base: str,
    verify: bool,
    sleep: float,
    verbose: bool,
) -> Optional[Dict[str, Any]]:
    sess = build_session(access_key, secret_key, token)

    plugin_json = request_json(sess, "GET", f"{base}/plugins/plugin/{pid}", verify=verify)
    time.sleep(sleep)

    if not plugin_json:
        plugin_json = request_json(sess, "POST", f"{base}/plugins/plugin", json_body={"plugin_id": pid}, verify=verify)
        time.sleep(sleep)

    if plugin_json:
        plugin_json["_requested_id"] = pid
    elif verbose:
        print(f"[WARN] failed to fetch plugin {pid}", file=sys.stderr)

    return plugin_json


# -------------------------
# Output helpers
# -------------------------

def parse_out_types(out_arg: Optional[str]) -> List[str]:
    supported = {"json", "csv", "txt"}
    if not out_arg:
        return []
    return [t.strip().lower() for t in out_arg.split(",") if t.strip().lower() in supported]


def derive_filenames_from_basename(basename: Optional[str], out_types: List[str]) -> Dict[str, str]:
    defaults = {
        "json": "matched_plugins_full.json",
        "csv": "matched_plugins.csv",
        "txt": "matched_plugins_cves.txt",
    }
    if not out_types:
        return {}

    result = {}
    if basename:
        base = os.path.splitext(basename)[0]
        for t in out_types:
            result[t] = f"{base}.{t}"
    else:
        for t in out_types:
            result[t] = defaults[t]
    return result


def extract_cves(plugin_obj: Dict[str, Any]) -> List[str]:
    cves = []
    if "attributes" in plugin_obj and isinstance(plugin_obj["attributes"], list):
        for a in plugin_obj["attributes"]:
            if isinstance(a, dict) and a.get("attribute_name") == "cve":
                v = a.get("attribute_value")
                if v:
                    cves.append(str(v))

    if "plugin" in plugin_obj and isinstance(plugin_obj["plugin"], dict) and "cve" in plugin_obj["plugin"]:
        pcve = plugin_obj["plugin"]["cve"]
        if isinstance(pcve, list):
            cves.extend([str(x) for x in pcve if x])
        elif pcve:
            cves.append(str(pcve))

    dedup = []
    seen = set()
    for c in cves:
        if c not in seen:
            seen.add(c)
            dedup.append(c)
    return dedup


def collect_attr_values(plugin_obj: Dict[str, Any]) -> Dict[str, List[str]]:
    attr_values: Dict[str, List[str]] = {}
    if "attributes" in plugin_obj and isinstance(plugin_obj["attributes"], list):
        for a in plugin_obj["attributes"]:
            if not isinstance(a, dict):
                continue
            k = a.get("attribute_name")
            v = a.get("attribute_value")
            if not k:
                continue
            attr_values.setdefault(k, [])
            if v is not None and str(v) != "":
                val = str(v)
                if val not in attr_values[k]:
                    attr_values[k].append(val)
    return attr_values


# -------------------------
# Main
# -------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Query a local Nessus instance for plugin details by search expression or by explicit plugin IDs."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--expr", "-e",
        help='Boolean expression to match plugin names (supports AND, OR, NOT, parentheses). Terms may be quoted.'
    )
    group.add_argument(
        "--plugin-id", "-p",
        help="Single plugin ID or comma-separated list of plugin IDs. Skips family scanning and expr matching."
    )

    parser.add_argument("--host", "-H", default="https://127.0.0.1:8834", help="Nessus host (default https://127.0.0.1:8834)")
    parser.add_argument("--access-key", help="Nessus API Access Key (CLI). Falls back to env var 'nessus_access_key'.")
    parser.add_argument("--secret-key", help="Nessus API Secret Key (CLI). Falls back to env var 'nessus_secret_key'.")
    parser.add_argument("--token", help="Nessus session token (CLI). Falls back to env var 'nessus_api_token'.")
    parser.add_argument("--out", "-o", help="Comma-separated output types: json,csv,txt. If omitted, no files are written.")
    parser.add_argument("--filename", "-f", help="Single base filename used across all outputs. Extensions are added automatically.")
    parser.add_argument("--insecure", "-k", action="store_true", help="Skip TLS verification and suppress InsecureRequestWarning.")
    parser.add_argument("--sleep", type=float, default=0.12, help="Seconds to sleep between API calls (default 0.12).")
    parser.add_argument("--workers", type=int, default=6, help="Number of worker threads for fetching plugin details (default 6).")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output to stderr.")
    args = parser.parse_args()

    access_key = args.access_key or os.environ.get("nessus_access_key")
    secret_key = args.secret_key or os.environ.get("nessus_secret_key")
    token = args.token or os.environ.get("nessus_api_token")

    if not token and not (access_key and secret_key):
        parser.error(
            "Provide either --token or both --access-key and --secret-key, or set "
            "nessus_access_key / nessus_secret_key / nessus_api_token."
        )

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    verify = not args.insecure
    base = args.host.rstrip("/")
    out_types = parse_out_types(args.out)
    filenames = derive_filenames_from_basename(args.filename, out_types)

    if args.verbose:
        print(f"[INFO] out_types={out_types}", file=sys.stderr)
        print(f"[INFO] filenames={filenames}", file=sys.stderr)

    sess = build_session(access_key, secret_key, token)

    # Build requested plugin id set
    matched_plugin_ids: Dict[int, str] = {}

    if args.plugin_id:
        for raw in args.plugin_id.split(","):
            raw = raw.strip()
            if not raw:
                continue
            try:
                pid = int(raw)
            except ValueError:
                raise SystemExit(f"Invalid plugin id: {raw}")
            matched_plugin_ids[pid] = f"PLUGIN_{pid}"
    else:
        matcher = build_match_function(args.expr)
        if args.verbose:
            tokens = tokenize_expr(args.expr)
            print(f"[INFO] expression tokens: {tokens}", file=sys.stderr)
            print(f"[INFO] RPN: {shunting_yard(tokens)}", file=sys.stderr)

        families_endpoint = f"{base}/plugins/families"
        if args.verbose:
            print(f"[INFO] querying families endpoint: {families_endpoint}", file=sys.stderr)
        families_json = request_json(sess, "GET", families_endpoint, verify=verify)

        if not families_json:
            print("[ERROR] families endpoint returned no data. Exiting.", file=sys.stderr)
            sys.exit(1)

        families = []
        if isinstance(families_json, dict):
            if "families" in families_json and isinstance(families_json["families"], list):
                families = families_json["families"]
            else:
                for v in families_json.values():
                    if isinstance(v, list):
                        families = v
                        break
        elif isinstance(families_json, list):
            families = families_json

        family_list = []
        for f in families:
            if isinstance(f, dict):
                fid = f.get("id") or f.get("family") or f.get("family_id")
                fname = f.get("name") or f.get("family_name") or f.get("title") or ""
                try:
                    fid_int = int(fid)
                except Exception:
                    continue
                family_list.append({"id": fid_int, "name": fname})

        if args.verbose:
            print(f"[INFO] discovered {len(family_list)} families", file=sys.stderr)

        family_endpoints_variants = [
            "/plugins/families/{id}",
            "/plugin/families/{id}",
            "/plugins/family/{id}",
            "/plugin/family/{id}",
        ]

        for fam in family_list:
            fid = fam["id"]
            if args.verbose:
                print(f"[INFO] querying family {fid} ({fam.get('name','')})", file=sys.stderr)

            family_json = None
            for ep in family_endpoints_variants:
                url = base + ep.format(id=fid)
                family_json = request_json(sess, "GET", url, verify=verify)
                time.sleep(args.sleep)
                if family_json:
                    break

            if not family_json:
                for ep in family_endpoints_variants:
                    url = base + ep.format(id=fid)
                    family_json = request_json(sess, "POST", url, json_body={"family_id": fid}, verify=verify)
                    time.sleep(args.sleep)
                    if family_json:
                        break

            if not family_json:
                if args.verbose:
                    print(f"[WARN] no data for family {fid}", file=sys.stderr)
                continue

            plugin_entries = find_plugin_entries_in_family_json(family_json)
            if args.verbose:
                print(f"[INFO] family {fid} returned {len(plugin_entries)} plugin candidates", file=sys.stderr)

            for p in plugin_entries:
                pname = p.get("name") or ""
                try:
                    pid = int(p["id"])
                except Exception:
                    continue
                if matcher(pname) and pid not in matched_plugin_ids:
                    matched_plugin_ids[pid] = pname
                    if args.verbose:
                        print(f"[MATCH] {pid} -> {pname}", file=sys.stderr)

    if not matched_plugin_ids:
        print("[INFO] No plugins matched the provided selection.", file=sys.stderr)
        if out_types:
            empty_payload = {"matched_plugins": [], "metadata": {"expr": args.expr, "plugin_id": args.plugin_id}}
            for t in out_types:
                fname = filenames.get(t)
                if t == "json":
                    with open(fname, "w", encoding="utf-8") as fh:
                        json.dump(empty_payload, fh, indent=2)
                elif t == "csv":
                    with open(fname, "w", newline="", encoding="utf-8") as cf:
                        writer = csv.writer(cf)
                        writer.writerow(["PluginID", "PluginName", "ReportedCVEs", "CVSSv3_RiskFactor", "CVSSv3_BaseScore", "CVSSv3_ScoreSource", "ReferenceURL"])
                elif t == "txt":
                    open(fname, "w", encoding="utf-8").close()
        return

    if args.verbose:
        print(f"[INFO] matched {len(matched_plugin_ids)} plugin(s). Fetching details with {args.workers} workers...", file=sys.stderr)

    matched_details = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        future_to_pid = {
            ex.submit(fetch_plugin_detail_threadsafe, pid, access_key, secret_key, token, base, verify, args.sleep, args.verbose): pid
            for pid in matched_plugin_ids.keys()
        }
        for fut in as_completed(future_to_pid):
            pid = future_to_pid[fut]
            try:
                plugin_json = fut.result()
            except Exception as e:
                plugin_json = None
                if args.verbose:
                    print(f"[ERROR] exception fetching plugin {pid}: {e}", file=sys.stderr)
            if plugin_json:
                plugin_json["_matched_name"] = matched_plugin_ids.get(pid)
                matched_details.append(plugin_json)
            elif args.verbose:
                print(f"[WARN] no plugin detail for {pid}", file=sys.stderr)

    # Write outputs
    if "json" in out_types:
        fname = filenames["json"]
        out_obj = {
            "metadata": {
                "expression": args.expr,
                "plugin_id": args.plugin_id,
                "host": base,
                "count_matched": len(matched_details),
                "timestamp": int(time.time()),
            },
            "matched_plugins": matched_details,
        }
        with open(fname, "w", encoding="utf-8") as fh:
            json.dump(out_obj, fh, indent=2)
        if args.verbose:
            print(f"[INFO] Wrote JSON to {fname}", file=sys.stderr)

    if "csv" in out_types:
        fname = filenames["csv"]
        attr_names = set()
        for p in matched_details:
            if isinstance(p, dict) and isinstance(p.get("attributes"), list):
                for a in p["attributes"]:
                    if isinstance(a, dict) and a.get("attribute_name"):
                        attr_names.add(a["attribute_name"])

        sorted_attrs = sorted(attr_names, key=str.lower)
        header = ["PluginID", "PluginName", "ReportedCVEs", "CVSSv3_RiskFactor", "CVSSv3_BaseScore", "CVSSv3_ScoreSource", "ReferenceURL"] + sorted_attrs

        with open(fname, "w", newline="", encoding="utf-8") as cf:
            writer = csv.writer(cf)
            writer.writerow(header)

            for p in matched_details:
                pid = p.get("_requested_id") or p.get("id") or ""

                name = ""
                if isinstance(p, dict):
                    if isinstance(p.get("plugin"), dict):
                        name = p["plugin"].get("name") or p["plugin"].get("title") or ""
                    name = name or p.get("name") or p.get("_matched_name") or ""

                cves_cell = ";".join(extract_cves(p))
                attr_values = collect_attr_values(p)

                risk = ";".join(attr_values.get("risk_factor", []))
                base_score = ";".join(attr_values.get("cvss3_base_score", []))
                src = ";".join(attr_values.get("cvss_score_source", []) or attr_values.get("cvss3_score_source", []))

                row = [
                    pid,
                    name.replace('"', "'"),
                    cves_cell,
                    risk,
                    base_score,
                    src,
                    f"https://www.tenable.com/plugins/nessus/{pid}",
                ]
                for attr_name in sorted_attrs:
                    row.append(";".join(attr_values.get(attr_name, [])))
                writer.writerow(row)

        if args.verbose:
            print(f"[INFO] Wrote CSV to {fname}", file=sys.stderr)

    if "txt" in out_types:
        fname = filenames["txt"]
        seen = set()
        ordered = []
        for p in matched_details:
            for cve in extract_cves(p):
                if cve not in seen:
                    seen.add(cve)
                    ordered.append(cve)
        with open(fname, "w", encoding="utf-8") as tf:
            for cve in ordered:
                tf.write(cve + "\n")
        if args.verbose:
            print(f"[INFO] Wrote TXT to {fname}", file=sys.stderr)

    # stdout summary
    for p in matched_details:
        rid = p.get("_requested_id")
        pname = None
        if isinstance(p, dict) and isinstance(p.get("plugin"), dict):
            pname = p["plugin"].get("name") or p["plugin"].get("title")
        pname = pname or p.get("name") or p.get("_matched_name") or ""
        print(f"{rid},{pname}")


if __name__ == "__main__":
    main()
