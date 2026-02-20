"""
test_peerglass.py — Complete PeerGlass test suite
Tests: compile, branding, RDAP endpoints, MCP name, tool count,
       REST API runtime, README correctness.
"""

import py_compile
import re
import sys

errors = []

print("=" * 60)
print("PEERGLASS — COMPLETE TEST SUITE")
print("=" * 60)


# ── 1. COMPILE CHECK ─────────────────────────────────────────
print("\n1. COMPILE CHECK — all .py files")
files = [
    "server.py", "rir_client.py", "formatters.py",
    "models.py", "cache.py", "normalizer.py", "api.py",
]
for f in files:
    try:
        py_compile.compile(f, doraise=True)
        print(f"   ✅ {f}")
    except py_compile.PyCompileError as e:
        print(f"   ❌ {f}: {e}")
        errors.append(f"compile:{f}:{e}")


# ── 2. BRANDING AUDIT ────────────────────────────────────────
print("\n2. BRANDING AUDIT — no stale WHOIS in identity strings")

FORBIDDEN = [
    (r"Multi-RIR WHOIS",   "Old product name"),
    (r"rir_whois_mcp",     "Old MCP server ID"),
    (r"WHOIS MCP",         "Old product name variant"),
]

check_files = {
    "server.py":     open("server.py").read(),
    "rir_client.py": open("rir_client.py").read(),
    "cache.py":      open("cache.py").read(),
    "models.py":     open("models.py").read(),
    "api.py":        open("api.py").read(),
    "README.md":     open("README.md").read(),
    "pyproject.toml":open("pyproject.toml").read(),
}

for fname, content in check_files.items():
    file_errors = []
    for pattern, reason in FORBIDDEN:
        if re.search(pattern, content):
            file_errors.append(f'{pattern} ({reason})')
            errors.append(f"branding:{fname}:{pattern}")
    if file_errors:
        for e in file_errors:
            print(f"   ❌ {fname}: found \"{e}\"")
    else:
        print(f"   ✅ {fname}")


# ── 3. RDAP ENDPOINTS ────────────────────────────────────────
print("\n3. RDAP ENDPOINTS — all 5 RIRs present and correct")
client_src = open("rir_client.py").read()
rdap_urls = [
    ("AFRINIC", "https://rdap.afrinic.net/rdap"),
    ("APNIC",   "https://rdap.apnic.net"),
    ("ARIN",    "https://rdap.arin.net/registry"),
    ("LACNIC",  "https://rdap.lacnic.net/rdap"),
    ("RIPE",    "https://rdap.db.ripe.net"),
]
for rir, url in rdap_urls:
    if url in client_src:
        print(f"   ✅ {rir}: {url}")
    else:
        print(f"   ❌ {rir}: {url} NOT FOUND")
        errors.append(f"rdap:{rir}")


# ── 4. PROTOCOL HEADER ───────────────────────────────────────
print("\n4. PROTOCOL HEADER — Accept: application/rdap+json")
if "application/rdap+json" in client_src:
    print("   ✅ Accept header uses RDAP media type")
else:
    print("   ❌ RDAP Accept header missing")
    errors.append("accept_header")


# ── 5. USER-AGENT ────────────────────────────────────────────
print("\n5. USER-AGENT — updated to PeerGlass")
if "peerglass/1.0.0" in client_src and "PeerGlass RDAP" in client_src:
    print("   ✅ User-Agent: peerglass/1.0.0 (PeerGlass RDAP+BGP+RPKI client)")
else:
    print("   ❌ User-Agent not updated")
    errors.append("user_agent")


# ── 6. MCP SERVER NAME ───────────────────────────────────────
print("\n6. MCP SERVER NAME — updated to peerglass")
server_src = open("server.py").read()
if '"peerglass"' in server_src and "rir_whois_mcp" not in server_src:
    print('   ✅ MCP name = "peerglass"')
else:
    print("   ❌ MCP server name not updated")
    errors.append("mcp_name")


# ── 7. TOOL COUNT ────────────────────────────────────────────
print("\n7. TOOL COUNT — 17 @mcp.tool() decorators in server.py")
# Decorator is @mcp.tool( with description kwarg on next line
tools_found = re.findall(r"@mcp\.tool\(", server_src)
count = len(tools_found)
if count == 17:
    print(f"   ✅ {count} @mcp.tool() decorators found")
else:
    print(f"   ❌ Expected 17, found {count}")
    errors.append(f"tool_count:{count}")


# ── 8. REST ENDPOINTS ────────────────────────────────────────
print("\n8. REST API — all 15 endpoints present in api.py")
api_src = open("api.py").read()
routes = [
    "/v1/ip/{ip}",           "/v1/asn/{asn}",
    "/v1/abuse/{ip}",        "/v1/rpki",
    "/v1/bgp/{resource}",    "/v1/announced/{asn}",
    "/v1/org",               "/v1/history/{resource}",
    "/v1/transfers/{resource}", "/v1/stats/ipv4",
    "/v1/overview/{prefix}", "/v1/peering/{asn}",
    "/v1/ixp",               "/v1/health/{resource}",
    "/v1/monitor/{resource}",
]
for r in routes:
    if r in api_src:
        print(f"   ✅ {r}")
    else:
        print(f"   ❌ {r} MISSING")
        errors.append(f"route:{r}")


# ── 9. FASTAPI RUNTIME ───────────────────────────────────────
print("\n9. FASTAPI RUNTIME — routes resolve, OpenAI schema correct")
try:
    from fastapi.testclient import TestClient
    from api import app

    client = TestClient(app)

    r = client.get("/")
    assert r.status_code == 200, f"Root returned {r.status_code}"
    data = r.json()
    assert data["tools"] == 17, f"Root shows {data['tools']} tools not 17"
    assert data["name"] == "PeerGlass API", f"Name is {data['name']}"
    print(f"   ✅ GET /  → 200, name=PeerGlass API, tools=17")

    r = client.get("/v1/meta/cache")
    assert r.status_code == 200
    print("   ✅ GET /v1/meta/cache → 200")

    r = client.get("/v1/meta/openai-tools")
    assert r.status_code == 200
    tools_json = r.json()["tools"]
    names = [t["function"]["name"] for t in tools_json]
    required = [
        "peerglass_health", "peerglass_rpki",
        "peerglass_ixp", "peerglass_monitor", "peerglass_peering",
    ]
    for expected in required:
        assert expected in names, f"{expected} missing from OpenAI schema"
    print(f"   ✅ GET /v1/meta/openai-tools → {len(tools_json)} tools, all peerglass_*")

    # Confirm no stale branding in any response
    root_str = str(client.get("/").json()).lower()
    assert "whois_mcp" not in root_str
    assert "multi-rir whois" not in root_str
    print("   ✅ No stale branding in API responses")

except Exception as e:
    import traceback
    print(f"   ❌ FastAPI runtime error: {e}")
    traceback.print_exc()
    errors.append(f"fastapi:{e}")


# ── 10. README ───────────────────────────────────────────────
print("\n10. README — PeerGlass branding, 17 tools, RDAP note, historical-whois explained")
readme = open("README.md").read()

must_contain = [
    ("PeerGlass",              "Product name present"),
    ("17 tools",               "Correct tool count (17)"),
    ("RDAP (RFC 7480",         "RDAP RFC reference"),
    ("Protocol note",          "WHOIS→RDAP explanation block"),
    ("peerglass",              "MCP config uses peerglass"),
    ("RIPE Stat's own name",   "historical-whois explained as RIPE API naming"),
]
must_not_contain = [
    ("Multi-RIR WHOIS",        "Old product name must be absent"),
]

for term, desc in must_contain:
    if term in readme:
        print(f"   ✅ {desc}")
    else:
        print(f"   ❌ Missing: {desc}  (searched: \"{term}\")")
        errors.append(f"readme:missing:{term}")

for term, desc in must_not_contain:
    if term not in readme:
        print(f"   ✅ {desc}")
    else:
        print(f"   ❌ {desc}  (found \"{term}\")")
        errors.append(f"readme:found:{term}")


# ── SUMMARY ──────────────────────────────────────────────────
print()
print("=" * 60)
if not errors:
    print("✅ ALL TESTS PASSED — 0 errors")
    print()
    print("  Python files:         7  (all compile clean)")
    print("  MCP tools:            17")
    print("  REST endpoints:       15")
    print("  Protocol:             RDAP throughout (RFC 7480-7484)")
    print("  Branding:             PeerGlass throughout")
    print("  historical-whois:     correctly attributed to RIPE Stat API naming")
else:
    print(f"❌ {len(errors)} ERROR(S) FOUND:")
    for e in errors:
        print(f"   • {e}")
    sys.exit(1)
print("=" * 60)
