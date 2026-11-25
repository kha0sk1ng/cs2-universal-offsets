#!/usr/bin/env python3
"""Command-line client for cs2-live (the loopback memory reader on 127.0.0.1:13380).

Start `cs2-live` once as administrator (see live.bat), then:

    python -I tools/live.py health
    python -I tools/live.py bases
    python -I tools/live.py read "client+0xB1FB80" -n 16
    python -I tools/live.py read "[client+0x23B95F0]+0x688" -t u64
    python -I tools/live.py scan client.dll "48 89 5C 24 ? 57 48 83 EC 20" --limit 5 --ctx 32
    echo '[{"e":"client+0x10","n":4,"t":"u32"}]' | python -I tools/live.py batch

Output is JSON on stdout. Exit codes: 0 ok, 1 server reported an error,
2 server unreachable. Python standard library only.
"""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_PORT = 13380
UNREACHABLE_HINT = (
    "cs2-live is not reachable. Start cs2.exe, then run cs2-live once as "
    "administrator (live.bat) and retry."
)


def call(args, method, path, query=None, body=None):
    url = f"http://127.0.0.1:{args.port}{path}"
    if query:
        # quote(), not urlencode(): '+' must become %2B, it is an operator in expressions.
        url += "?" + "&".join(
            f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in query.items() if v is not None
        )
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "replace")
        try:
            return json.loads(text)
        except ValueError:
            return {"ok": False, "error": f"HTTP {e.code}: {text.strip()}"}
    except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
        print(json.dumps({"ok": False, "error": UNREACHABLE_HINT, "detail": str(e)}))
        sys.exit(2)


def emit(result):
    print(json.dumps(result, indent=2))
    bad = isinstance(result, dict) and (result.get("ok") is False or "error" in result)
    sys.exit(1 if bad else 0)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--timeout", type=float, default=15.0, help="seconds (default 15)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("health", help="pid and module bases")
    sub.add_parser("bases", help="module name -> base/size")

    r = sub.add_parser("read", help="read memory at an expression")
    r.add_argument("expr", help="e.g. client+0xB1FB80, [client+0x23B95F0]+0x688")
    r.add_argument("-n", type=int, default=None, help="element count (bytes for hex)")
    r.add_argument(
        "-t",
        "--type",
        default=None,
        help="hex (default) u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 ptr cstr utf16 vec3",
    )

    s = sub.add_parser("scan", help="live IDA-style pattern scan")
    s.add_argument("module", help="e.g. client.dll")
    s.add_argument("pattern", help='e.g. "48 89 5C 24 ? 57"')
    s.add_argument("--limit", type=int, default=None)
    s.add_argument("--ctx", type=int, default=None, help="bytes of context to read per hit")

    sub.add_parser("batch", help='read a JSON list [{"e":..,"n":..,"t":..}] from stdin')

    a = p.parse_args()
    if a.cmd == "health":
        emit(call(a, "GET", "/health"))
    elif a.cmd == "bases":
        emit(call(a, "GET", "/bases"))
    elif a.cmd == "read":
        emit(call(a, "GET", "/read", {"e": a.expr, "n": a.n, "t": a.type}))
    elif a.cmd == "scan":
        emit(call(a, "GET", "/scan", {"m": a.module, "p": a.pattern, "limit": a.limit, "ctx": a.ctx}))
    elif a.cmd == "batch":
        try:
            reads = json.load(sys.stdin)
        except ValueError as e:
            print(json.dumps({"ok": False, "error": f"stdin is not valid JSON: {e}"}))
            sys.exit(1)
        emit(call(a, "POST", "/read", body={"reads": reads}))


if __name__ == "__main__":
    main()
