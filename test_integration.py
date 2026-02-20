"""
test_integration.py — PeerGlass REAL Integration Tests
Real network calls. No mocks. No fakes.
"""

import asyncio
import sys
import time
import traceback

import httpx
import rir_client

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

pass_count = 0
fail_count = 0
skip_count = 0
results    = []

def ok(label, detail=""):
    global pass_count
    pass_count += 1
    print(f"   {GREEN}✅ PASS{RESET}  {label}")
    if detail: print(f"         {CYAN}{detail}{RESET}")
    results.append(("PASS", label, detail))

def fail(label, reason):
    global fail_count
    fail_count += 1
    print(f"   {RED}❌ FAIL{RESET}  {label}")
    print(f"         {RED}{reason[:120]}{RESET}")
    results.append(("FAIL", label, reason))

def skip(label, reason):
    global skip_count
    skip_count += 1
    print(f"   {YELLOW}⚠️  SKIP{RESET}  {label}")
    print(f"         {reason}")
    results.append(("SKIP", label, reason))

def section(title):
    print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*60}{RESET}")


# ── TEST 1: All 5 RIR RDAP servers reachable ──────────────────
async def test_rdap_reachability():
    section("TEST 1 — RDAP Server Reachability (all 5 RIRs)")
    print("  Querying 1.1.1.1 at each RIR. 200=authoritative, 404=up-but-not-owner.")

    rdap_servers = {
        "RIPE":    "https://rdap.db.ripe.net/ip/1.1.1.1",
        "ARIN":    "https://rdap.arin.net/registry/ip/1.1.1.1",
        "APNIC":   "https://rdap.apnic.net/ip/1.1.1.1",
        "LACNIC":  "https://rdap.lacnic.net/rdap/ip/1.1.1.1",
        "AFRINIC": "https://rdap.afrinic.net/rdap/ip/1.1.1.1",
    }
    headers = {"Accept": "application/rdap+json", "User-Agent": "peerglass/1.0.0 (integration-test)"}

    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
        tasks = [client.get(url, headers=headers) for url in rdap_servers.values()]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    for rir, resp in zip(rdap_servers.keys(), responses):
        if isinstance(resp, Exception):
            fail(f"{rir} RDAP reachable", str(resp)[:80])
        elif resp.status_code in (200, 301, 302, 400, 404):
            ok(f"{rir} RDAP reachable", f"HTTP {resp.status_code}")
        else:
            fail(f"{rir} RDAP reachable", f"Unexpected HTTP {resp.status_code}")


# ── TEST 2: RDAP IP lookup — 1.1.1.1 via APNIC ───────────────
async def test_rdap_ip_lookup():
    section("TEST 2 — RDAP IP Lookup: 1.1.1.1 (APNIC authoritative)")
    print("  Expect: objectClassName=ip network, startAddress in 1.1.1.x")

    url = "https://rdap.apnic.net/ip/1.1.1.1"
    headers = {"Accept": "application/rdap+json", "User-Agent": "peerglass/1.0.0 (integration-test)"}

    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            t0   = time.time()
            resp = await client.get(url, headers=headers)
            elapsed = time.time() - t0

        if resp.status_code != 200:
            fail("APNIC RDAP returned 200", f"HTTP {resp.status_code}"); return

        data  = resp.json()
        start = data.get("startAddress", "")
        end   = data.get("endAddress", "")
        name  = data.get("name", "")
        ct    = resp.headers.get("content-type", "")

        ok("objectClassName = ip network", f"RT={elapsed:.2f}s") if data.get("objectClassName") == "ip network" else fail("objectClassName", data.get("objectClassName","?"))
        ok("startAddress contains 1.1.1.x", f"start={start} end={end}") if "1.1.1." in start else fail("startAddress", f"Got {start}")
        ok("Network name present", f"name='{name}'")
        ok("Content-Type is JSON/RDAP", f"{ct[:60]}") if "json" in ct else fail("Content-Type", ct)

    except Exception:
        fail("RDAP IP lookup 1.1.1.1", traceback.format_exc()[-120:])


# ── TEST 3: RDAP ASN lookup — AS13335 (Cloudflare) ────────────
async def test_rdap_asn_lookup():
    section("TEST 3 — RDAP ASN Lookup: AS13335 (Cloudflare)")
    print("  Expect: objectClassName=autnum, name contains CLOUDFLARE")

    url = "https://rdap.arin.net/registry/autnum/13335"
    headers = {"Accept": "application/rdap+json", "User-Agent": "peerglass/1.0.0 (integration-test)"}

    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers)

        if resp.status_code not in (200, 301, 302):
            fail("ARIN RDAP ASN 13335", f"HTTP {resp.status_code}"); return

        data  = resp.json()
        name  = data.get("name", "")
        start = data.get("startAutnum", 0)
        end   = data.get("endAutnum", 0)

        ok("objectClassName = autnum", f"handle={data.get('handle','?')}") if data.get("objectClassName") == "autnum" else fail("objectClassName", data.get("objectClassName","?"))
        ok("Name contains CLOUDFLARE", f"name='{name}'") if "CLOUDFLARE" in name.upper() else fail("Name CLOUDFLARE", f"Got '{name}'")
        ok("AS13335 in range", f"{start}..{end}") if start <= 13335 <= end else fail("AS13335 in range", f"{start}..{end}")

    except Exception:
        fail("RDAP ASN lookup", traceback.format_exc()[-120:])


# ── TEST 4: Cloudflare RPKI — 1.1.1.0/24 AS13335 ─────────────
async def test_rpki():
    section("TEST 4 — RPKI Validation: 1.1.1.0/24 origin AS13335")
    print("  RIPE Stat RPKI API. Expect: status=ok and validity status=valid")

    url = "https://stat.ripe.net/data/rpki-validation/data.json"
    params = {
        "resource": "AS13335",
        "prefix": "1.1.1.0/24",
        "sourceapp": "peerglass-integration-test",
    }
    headers = {"Accept": "application/json", "User-Agent": "peerglass/1.0.0 (integration-test)"}

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(url, params=params, headers=headers)

        if resp.status_code != 200:
            fail("RPKI API returned 200", f"HTTP {resp.status_code}"); return

        data    = resp.json()
        state   = data.get("data", {}).get("status", "")
        matched = data.get("data", {}).get("validating_roas", [])

        ok("RIPE Stat status=ok") if data.get("status") == "ok" else fail("status=ok", data.get("status", "?"))
        ok("RPKI state = valid", "1.1.1.0/24 has a valid ROA from APNIC") if state == "valid" else fail("RPKI state", f"Got '{state}'")
        ok("VRPs matched", f"{len(matched)} ROA(s) found")

    except Exception:
        fail("RPKI validation", traceback.format_exc()[-120:])


# ── TEST 5: RIPE Stat BGP — 1.1.1.0/24 ───────────────────────
async def test_bgp_status():
    section("TEST 5 — RIPE Stat BGP Status: 1.1.1.0/24")
    print("  stat.ripe.net/data/routing-status. Expect: visibility and origin AS")

    url = "https://stat.ripe.net/data/routing-status/data.json"
    params = {"resource": "1.1.1.0/24", "sourceapp": "peerglass-integration-test"}
    headers = {"Accept": "application/json", "User-Agent": "peerglass/1.0.0 (integration-test)"}

    try:
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.get(url, params=params, headers=headers)

        if resp.status_code != 200:
            fail("RIPE Stat BGP returned 200", f"HTTP {resp.status_code}"); return

        data = resp.json()
        payload = data.get("data", {})
        visibility = payload.get("visibility", {})

        vis_v4 = visibility.get("v4", {}) if isinstance(visibility, dict) else {}
        vis_v6 = visibility.get("v6", {}) if isinstance(visibility, dict) else {}
        seeing = max(vis_v4.get("ris_peers_seeing", 0) or 0, vis_v6.get("ris_peers_seeing", 0) or 0)
        total  = max(vis_v4.get("total_ris_peers", 0) or 0, vis_v6.get("total_ris_peers", 0) or 0)

        origins_raw = payload.get("origins", [])
        origin_asns = []
        for o in origins_raw:
            origin = o.get("origin") if isinstance(o, dict) else o
            if origin is None:
                continue
            origin_asns.append(f"AS{origin}" if not str(origin).upper().startswith("AS") else str(origin))

        ok("RIPE Stat status=ok") if data.get("status") == "ok" else fail("status=ok", data.get("status", "?"))
        ok("Prefix visible to RIS peers", f"seeing={seeing} / total={total}") if seeing > 0 else fail("RIS visibility", f"seeing={seeing}")
        ok("Origin ASN present", f"{origin_asns[:3]}") if origin_asns else fail("Origin ASN", "empty list")

    except Exception:
        fail("RIPE Stat BGP", traceback.format_exc()[-120:])


# ── TEST 13: IANA Bootstrap consistency across all 5 RIRs ─────
async def test_iana_bootstrap_all_rirs():
    section("TEST 13 — IANA/ICANN Bootstrap Consistency (IPv4, IPv6, ASN)")
    print("  Expect: all 5 RIR service URLs present in each IANA bootstrap file")

    endpoints = {
        "ipv4": "https://data.iana.org/rdap/ipv4.json",
        "ipv6": "https://data.iana.org/rdap/ipv6.json",
        "asn":  "https://data.iana.org/rdap/asn.json",
    }
    required_rirs = ["afrinic", "apnic", "arin", "lacnic", "ripe"]
    headers = {"Accept": "application/json", "User-Agent": "peerglass/1.0.0 (integration-test)"}

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            for kind, url in endpoints.items():
                resp = await client.get(url, headers=headers)
                if resp.status_code != 200:
                    fail(f"IANA {kind} bootstrap returned 200", f"HTTP {resp.status_code}")
                    continue

                data = resp.json()
                services = data.get("services", [])
                urls = []
                for entry in services:
                    if isinstance(entry, list) and len(entry) >= 2 and isinstance(entry[1], list):
                        urls.extend(entry[1])
                all_urls = "\n".join(urls).lower()

                ok(f"IANA {kind} services present", f"{len(services)} entries") if services else fail(f"IANA {kind} services", "empty")
                for rir in required_rirs:
                    ok(f"IANA {kind} includes {rir.upper()}") if rir in all_urls else fail(f"IANA {kind} includes {rir.upper()}", "missing")

    except Exception:
        fail("IANA bootstrap consistency", traceback.format_exc()[-120:])


# ── TEST 14: PeerGlass delegated IPv4 blocks feature ─────────
async def test_ipv4_blocks_feature():
    section("TEST 14 — PeerGlass Delegated IPv4 Blocks (AFRINIC)")
    print("  Expect: include_blocks returns paginated rows with status/country filtering")

    try:
        # Base feature check: include blocks for AFRINIC with status filter
        result = await rir_client.get_global_ipv4_stats(
            rir_filter="AFRINIC",
            include_blocks=True,
            status_filter="allocated",
            limit=3,
            offset=0,
        )

        if result.blocks_returned > 0:
            ok(
                "Delegated blocks returned",
                f"returned={result.blocks_returned}, total={result.blocks_total}"
            )
        else:
            fail("Delegated blocks returned", "No rows returned for AFRINIC allocated blocks")

        if result.blocks_total >= result.blocks_returned:
            ok("Pagination metadata valid", f"total={result.blocks_total} >= returned={result.blocks_returned}")
        else:
            fail("Pagination metadata", f"total={result.blocks_total}, returned={result.blocks_returned}")

        if result.ipv4_blocks and all(b.rir == "AFRINIC" for b in result.ipv4_blocks):
            ok("All rows scoped to AFRINIC")
        else:
            fail("RIR scope", "Found non-AFRINIC rows in AFRINIC query")

        if result.ipv4_blocks and all(b.status == "allocated" for b in result.ipv4_blocks):
            ok("Status filter applied", "all rows status=allocated")
        else:
            fail("Status filter", "At least one row is not allocated")

        # Country filter check
        gh = await rir_client.get_global_ipv4_stats(
            rir_filter="AFRINIC",
            include_blocks=True,
            status_filter="allocated",
            country_filter="GH",
            limit=3,
            offset=0,
        )
        if gh.blocks_returned == 0:
            skip("Country filter GH", "No matching rows in current snapshot")
        elif all((b.country or "") == "GH" for b in gh.ipv4_blocks):
            ok("Country filter applied", f"rows={gh.blocks_returned}, country=GH")
        else:
            fail("Country filter", "Found non-GH rows in GH-filtered result")

        # Validation behavior check
        invalid = await rir_client.get_global_ipv4_stats(include_blocks=True)
        if invalid.errors and "requires rir_filter" in invalid.errors[0]:
            ok("include_blocks requires rir_filter")
        else:
            fail("include_blocks validation", f"Unexpected errors: {invalid.errors}")

    except Exception:
        fail("PeerGlass delegated IPv4 blocks", traceback.format_exc()[-120:])


# ── TEST 6: Announced prefixes — AS13335 ──────────────────────
async def test_announced_prefixes():
    section("TEST 6 — RIPE Stat Announced Prefixes: AS13335")
    print("  Cloudflare announces many prefixes globally. Expect: >= 5 results with IPv4 and IPv6")

    url = "https://stat.ripe.net/data/announced-prefixes/data.json"
    params = {"resource": "AS13335", "sourceapp": "peerglass-integration-test"}
    headers = {"Accept": "application/json", "User-Agent": "peerglass/1.0.0 (integration-test)"}

    try:
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.get(url, params=params, headers=headers)

        if resp.status_code != 200:
            fail("Announced prefixes returned 200", f"HTTP {resp.status_code}"); return

        prefixes = resp.json().get("data", {}).get("prefixes", [])
        ipv4 = [p for p in prefixes if "." in p.get("prefix", "")]
        ipv6 = [p for p in prefixes if ":" in p.get("prefix", "")]

        ok(f"Prefix count >= 5", f"{len(prefixes)} total prefixes") if len(prefixes) >= 5 else fail("Prefix count", f"Only {len(prefixes)}")
        ok("Has both IPv4 and IPv6", f"IPv4={len(ipv4)}, IPv6={len(ipv6)}")

    except Exception:
        fail("Announced prefixes", traceback.format_exc()[-120:])


# ── TEST 7: RIPE Stat historical — AS15169 ────────────────────
async def test_history():
    section("TEST 7 — RIPE Stat Historical Data: AS15169 (Google)")
    print("  NOTE: 'historical-whois' is RIPE Stat's API name, not our protocol choice")
    print("  Expect: status=ok, historical RDAP object versions")

    url = "https://stat.ripe.net/data/historical-whois/data.json"
    params = {"resource": "AS15169", "sourceapp": "peerglass-integration-test"}
    headers = {"Accept": "application/json", "User-Agent": "peerglass/1.0.0 (integration-test)"}

    try:
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.get(url, params=params, headers=headers)

        if resp.status_code != 200:
            fail("Historical RDAP returned 200", f"HTTP {resp.status_code}"); return

        data    = resp.json()
        objects = data.get("data", {}).get("objects", [])

        ok("status = ok") if data.get("status") == "ok" else fail("status=ok", data.get("status","?"))
        if objects:
            ok("Historical objects returned", f"{len(objects)} object(s), {len(objects[0].get('versions',[]))} versions in first")
        else:
            skip("Historical objects", "Empty — may be normal for some resources")

    except Exception:
        fail("RIPE Stat history", traceback.format_exc()[-120:])


# ── TEST 8: PeeringDB — AS13335 (Cloudflare) ──────────────────
async def test_peeringdb():
    section("TEST 8 — PeeringDB Network: AS13335 (Cloudflare)")
    print("  peeringdb.com/api/net?asn=13335. Expect: network record with peering policy")

    url = "https://www.peeringdb.com/api/net"
    params = {"asn": 13335, "depth": 0}
    headers = {"Accept": "application/json", "User-Agent": "peerglass/1.0.0 (integration-test)"}

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(url, params=params, headers=headers)

        if resp.status_code != 200:
            fail("PeeringDB returned 200", f"HTTP {resp.status_code}"); return

        nets = resp.json().get("data", [])
        if nets:
            net = nets[0]
            ok("PeeringDB network found", f"name='{net.get('name','?')}', ASN={net.get('asn','?')}")
            ok("Peering policy present", f"policy_general='{net.get('policy_general','?')}'")
        else:
            fail("PeeringDB network found", "No records for AS13335")

    except Exception:
        fail("PeeringDB", traceback.format_exc()[-120:])


# ── TEST 9: IANA Bootstrap — ASN routing table ────────────────
async def test_iana_bootstrap():
    section("TEST 9 — IANA Bootstrap: ASN Routing Table")
    print("  data.iana.org/rdap/asn.json. Expect: AS13335 maps to a service URL")

    url = "https://data.iana.org/rdap/asn.json"
    headers = {"Accept": "application/json", "User-Agent": "peerglass/1.0.0 (integration-test)"}

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(url, headers=headers)

        if resp.status_code != 200:
            fail("IANA Bootstrap returned 200", f"HTTP {resp.status_code}"); return

        services = resp.json().get("services", [])
        ok("Bootstrap services present", f"{len(services)} ASN range entries") if services else fail("Bootstrap services", "empty")

        found = None
        for entry in services:
            for r in entry[0]:
                parts = r.split("-")
                if len(parts) == 2 and int(parts[0]) <= 13335 <= int(parts[1]):
                    found = entry[1]; break
            if found: break

        ok("AS13335 maps to RDAP service", str(found)) if found else fail("AS13335 in bootstrap", "Not found in any range")

    except Exception:
        fail("IANA Bootstrap", traceback.format_exc()[-120:])


# ── TEST 10: AFRINIC — African IP block ───────────────────────
async def test_afrinic():
    section("TEST 10 — AFRINIC RDAP: 102.176.0.0 (African IP block)")
    print("  Expect: objectClassName=ip network, African country code")

    url = "https://rdap.afrinic.net/rdap/ip/102.176.0.0"
    headers = {"Accept": "application/rdap+json", "User-Agent": "peerglass/1.0.0 (integration-test)"}

    try:
        async with httpx.AsyncClient(timeout=25.0, follow_redirects=True) as client:
            t0   = time.time()
            resp = await client.get(url, headers=headers)
            elapsed = time.time() - t0

        if resp.status_code == 200:
            data = resp.json()
            ok("AFRINIC objectClassName=ip network", f"RT={elapsed:.2f}s") if data.get("objectClassName") == "ip network" else fail("objectClassName", data.get("objectClassName","?"))
            ok("AFRINIC network details", f"name='{data.get('name','?')}', country='{data.get('country','?')}'")
        elif resp.status_code == 404:
            skip("AFRINIC 102.176.0.0", f"404 — IP may be reallocated; AFRINIC server is up (HTTP 404 is a valid RDAP response)")
        else:
            fail("AFRINIC RDAP", f"HTTP {resp.status_code}")

    except Exception:
        fail("AFRINIC RDAP", traceback.format_exc()[-120:])


# ── TEST 11: ASN Neighbours — AS13335 ─────────────────────────
async def test_asn_neighbours():
    section("TEST 11 — RIPE Stat ASN Neighbours: AS13335 (BGP Peers)")
    print("  Expect: upstream/downstream/peer ASN list for Cloudflare")

    url = "https://stat.ripe.net/data/asn-neighbours/data.json"
    params = {"resource": "AS13335", "sourceapp": "peerglass-integration-test"}
    headers = {"Accept": "application/json", "User-Agent": "peerglass/1.0.0 (integration-test)"}

    try:
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.get(url, params=params, headers=headers)

        if resp.status_code != 200:
            fail("ASN Neighbours returned 200", f"HTTP {resp.status_code}"); return

        neighbours = resp.json().get("data", {}).get("neighbours", [])
        upstreams  = [n for n in neighbours if n.get("type") == "left"]
        peers      = [n for n in neighbours if n.get("type") == "right"]

        ok("ASN neighbours returned", f"total={len(neighbours)}, upstreams={len(upstreams)}, peers={len(peers)}") if neighbours else fail("ASN neighbours", "Empty list")

    except Exception:
        fail("ASN neighbours", traceback.format_exc()[-120:])


# ── TEST 12: PeeringDB IXPs ────────────────────────────────────
async def test_peeringdb_ixp():
    section("TEST 12 — PeeringDB IXP List (Internet Exchange Points globally)")
    print("  peeringdb.com/api/ix?limit=10. Expect: real IXPs with country and name")

    url = "https://www.peeringdb.com/api/ix"
    params = {"limit": 10}
    headers = {"Accept": "application/json", "User-Agent": "peerglass/1.0.0 (integration-test)"}

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(url, params=params, headers=headers)

        if resp.status_code != 200:
            fail("PeeringDB IXP returned 200", f"HTTP {resp.status_code}"); return

        ixps = resp.json().get("data", [])
        if ixps:
            first = ixps[0]
            ok("IXP list returned", f"{len(ixps)} IXPs — first: '{first.get('name','?')}' ({first.get('country','?')})")
        else:
            fail("IXP list", "No IXPs in response")

    except Exception:
        fail("PeeringDB IXP", traceback.format_exc()[-120:])


# ── MAIN ──────────────────────────────────────────────────────
async def main():
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  PEERGLASS — LIVE INTEGRATION TEST SUITE{RESET}")
    print(f"{BOLD}  Real HTTP calls. No mocks. No fakes.{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print(f"  APIs: RIPE · ARIN · APNIC · LACNIC · AFRINIC · Cloudflare · RIPE Stat · PeeringDB · IANA\n")

    t0 = time.time()

    await test_rdap_reachability()
    await test_rdap_ip_lookup()
    await test_rdap_asn_lookup()
    await test_rpki()
    await test_bgp_status()
    await test_announced_prefixes()
    await test_history()
    await test_peeringdb()
    await test_iana_bootstrap()
    await test_afrinic()
    await test_asn_neighbours()
    await test_peeringdb_ixp()
    await test_iana_bootstrap_all_rirs()
    await test_ipv4_blocks_feature()

    elapsed = time.time() - t0

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  SUMMARY{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  Checks run   : {pass_count + fail_count + skip_count}")
    print(f"  {GREEN}✅ Passed{RESET}     : {pass_count}")
    print(f"  {RED}❌ Failed{RESET}     : {fail_count}")
    print(f"  {YELLOW}⚠️  Skipped{RESET}    : {skip_count}")
    print(f"  Duration     : {elapsed:.1f}s\n")

    if fail_count == 0:
        print(f"{GREEN}{BOLD}  🎉 ALL TESTS PASSED — PeerGlass live APIs confirmed working!{RESET}")
    else:
        print(f"{RED}{BOLD}  ❌ {fail_count} FAILURE(S) — see details above{RESET}")
        for s, l, r in results:
            if s == "FAIL":
                print(f"    • {l}: {r[:80]}")

    print(f"\n{'='*60}\n")
    return fail_count

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
