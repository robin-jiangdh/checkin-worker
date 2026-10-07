#!/usr/bin/env python3
"""Deploy checkin-worker via the Cloudflare v4 API.

Bundles nothing itself: run `npx esbuild src/index.ts --bundle ...` first.
Reads secrets from env (never prints them):

  ENCRYPTION_KEY  base64(32 random bytes)
  ADMIN_TOKEN      bearer token for /api/*

Usage:
  ENCRYPTION_KEY=... ADMIN_TOKEN=... python3 deploy/cf_deploy_checkin.py \
      --account <id> --script checkin-worker --worker dist/worker.js \
      --d1-id <database-uuid> --tz Asia/Shanghai --cron '*/15 * * * *'
"""
import json
import sys
import urllib.parse
import urllib.request
import uuid

sys.path.insert(0, "/opt/hatch/skills/skill-creator/bin")
import dynamic_credentials as dc

BASE = "https://api.cloudflare.com/client/v4"
ALLOWED = ["api.cloudflare.com"]


def call(method, path, data=None, ok=True):
    url = BASE + path
    body = None
    headers = {"Accept": "application/json"}
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    dc.add_surrogate_to_request(req, "custom.cloudflare", entry_name="access_token", allowed_hosts=ALLOWED)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            payload = dc.read_json_response(resp)
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", errors="replace")[:800]
        raise SystemExit(f"API {method} {path} failed {exc.code}: {text}")
    if ok and isinstance(payload, dict) and payload.get("success") is False:
        raise SystemExit(f"API {method} {path} failed: {json.dumps(payload.get('errors'))[:800]}")
    return payload


def main(argv):
    import os
    args = {"tz": "Asia/Shanghai", "cron": "*/15 * * * *"}
    i = 0
    while i < len(argv):
        if argv[i].startswith("--") and i + 1 < len(argv):
            args[argv[i][2:].replace("-", "_")] = argv[i + 1]
            i += 2
        else:
            i += 1
    for k in ("account", "script", "worker", "d1_id"):
        if k not in args:
            raise SystemExit(f"missing --{k.replace('_', '-')}")
    enc_key = os.environ.get("ENCRYPTION_KEY")
    admin_token = os.environ.get("ADMIN_TOKEN")
    if not enc_key or not admin_token:
        raise SystemExit("ENCRYPTION_KEY and ADMIN_TOKEN env vars are required")

    with open(args["worker"], "r", encoding="utf-8") as f:
        script = f.read()

    acct = urllib.parse.quote(args["account"], safe="")
    name = urllib.parse.quote(args["script"], safe="")

    # 1. upload script + bindings
    metadata = {
        "main_module": "worker.js",
        "compatibility_date": "2025-09-01",
        "bindings": [
            {"type": "d1", "name": "DB", "id": args["d1_id"]},
            {"type": "secret_text", "name": "ENCRYPTION_KEY", "text": enc_key},
            {"type": "secret_text", "name": "ADMIN_TOKEN", "text": admin_token},
            {"type": "plain_text", "name": "CHECKIN_TZ", "text": args["tz"]},
        ],
    }
    boundary = "----cfdeploy" + uuid.uuid4().hex
    body = b""
    body += f"--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="metadata"\r\nContent-Type: application/json\r\n\r\n'
    body += json.dumps(metadata).encode("utf-8") + b"\r\n"
    body += f"--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="worker.js"; filename="worker.js"\r\nContent-Type: application/javascript+module\r\n\r\n'
    body += script.encode("utf-8") + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    req = urllib.request.Request(
        f"{BASE}/accounts/{acct}/workers/scripts/{name}",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="PUT",
    )
    dc.add_surrogate_to_request(req, "custom.cloudflare", entry_name="access_token", allowed_hosts=ALLOWED)
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            payload = dc.read_json_response(resp)
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", errors="replace")[:800]
        raise SystemExit(f"script upload failed {exc.code}: {text}")
    if not payload.get("success"):
        raise SystemExit(f"script upload failed: {json.dumps(payload.get('errors'))[:800]}")
    print("script uploaded:", payload["result"].get("modified_on"))

    # 2. cron triggers (PUT body is a bare JSON array, not {"schedules": [...]})
    out = call("PUT", f"/accounts/{acct}/workers/scripts/{name}/schedules",
               [{"cron": args["cron"]}])
    print("schedules:", json.dumps(out.get("result", {}).get("schedules")))

    # 3. workers.dev subdomain (API-uploaded scripts need this enabled explicitly)
    out = call("POST", f"/accounts/{acct}/workers/scripts/{name}/subdomain", {"enabled": True})
    print("subdomain:", json.dumps(out.get("result"), ensure_ascii=False))


if __name__ == "__main__":
    main(sys.argv[1:])
