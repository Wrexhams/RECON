#!/usr/bin/env python3
# language: Python 3.11+, file: recon.py, runtime: Termux (Android)

import subprocess
import sys
import os
import json
import socket
import re
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

DEPS = ["requests", "phonenumbers", "tqdm"]

def install_deps():
    for pkg in DEPS:
        try:
            __import__(pkg.replace("-", "_"))
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])

install_deps()

import requests
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from tqdm import tqdm

# ─── API КЛЮЧИ — вставь сюда ───────────────────────────────────────────────
SHODAN_KEY     = ""   # https://account.shodan.io/          (бесплатно — 1 scan/сек)
IPINFO_TOKEN   = ""   # https://ipinfo.io/account/token     (бесплатно — 50k/мес)
LEAKCHECK_KEY  = ""   # https://leakcheck.io/api            (пусто = public 50/день)
VIRUSTOTAL_KEY = ""   # https://www.virustotal.com/gui/join-us (бесплатно — 500/день)
ABUSEIPDB_KEY  = ""   # https://www.abuseipdb.com/api       (бесплатно — 1000/день)
HUNTER_KEY     = ""   # https://hunter.io/api               (бесплатно — 25/мес)
# ───────────────────────────────────────────────────────────────────────────

OUT_DIR = os.path.expanduser("~/recon_out")
os.makedirs(OUT_DIR, exist_ok=True)

BANNER = r"""
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
       OSINT / DOX SUITE v4 — TERMUX
"""

HEADERS_UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}

def save(name: str, data: dict):
    path = os.path.join(OUT_DIR, f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[+] сохранено → {path}")
    return path

def pr(label: str, value):
    if value or value == 0:
        print(f"  {label:<26} {value}")

def fetch(url: str, headers: dict = None, timeout: int = 8, retries: int = 3) -> requests.Response | None:
    h = HEADERS_UA.copy()
    if headers:
        h.update(headers)
    for attempt in range(retries):
        try:
            return requests.get(url, headers=h, timeout=timeout)
        except requests.exceptions.Timeout:
            if attempt < retries - 1:
                time.sleep(1.5 * (attempt + 1))
        except Exception as e:
            print(f"  [!] fetch error: {e}")
            return None
    return None

# ──────────────────────────────────────────────────────────────────────────────
# HTML ОТЧЁТ
# ──────────────────────────────────────────────────────────────────────────────

def generate_html_report(results: dict, title: str = "Recon Report"):
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    path = os.path.join(OUT_DIR, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")

    rows = ""
    for module, data in results.items():
        rows += f"<tr><td colspan='2' class='module'>{module}</td></tr>\n"
        if isinstance(data, dict):
            for k, v in data.items():
                rows += f"<tr><td class='key'>{k}</td><td class='val'>{v}</td></tr>\n"
        else:
            rows += f"<tr><td colspan='2'>{data}</td></tr>\n"

    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  body {{ background:#0d0d0d; color:#e0e0e0; font-family:monospace; padding:20px }}
  h1   {{ color:#ff4444; border-bottom:1px solid #333; padding-bottom:8px }}
  .ts  {{ color:#666; font-size:.85em; margin-bottom:20px }}
  table {{ border-collapse:collapse; width:100% }}
  td   {{ padding:6px 10px; border:1px solid #222 }}
  .module {{ background:#1a1a1a; color:#ff8c00; font-weight:bold; font-size:1.05em }}
  .key    {{ color:#888; width:30% }}
  .val    {{ color:#e0e0e0; word-break:break-all }}
</style>
</head>
<body>
<h1>🔍 {title}</h1>
<div class="ts">сгенерировано: {ts}</div>
<table>{rows}</table>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] HTML отчёт → {path}")
    return path

# ──────────────────────────────────────────────────────────────────────────────
# МОДУЛИ
# ──────────────────────────────────────────────────────────────────────────────

def ip_lookup(ip: str) -> dict:
    print(f"\n[IP] {ip}")
    url = f"https://ipinfo.io/{ip}/json"
    if IPINFO_TOKEN:
        url += f"?token={IPINFO_TOKEN}"
    r = fetch(url)
    if not r:
        return {}
    data = r.json()

    result = {
        "ip":       data.get("ip"),
        "hostname": data.get("hostname"),
        "city":     data.get("city"),
        "region":   data.get("region"),
        "country":  data.get("country"),
        "org":      data.get("org"),
        "timezone": data.get("timezone"),
        "loc":      data.get("loc"),
    }
    for k, v in result.items():
        pr(k, v)

    # VirusTotal
    if VIRUSTOTAL_KEY:
        r2 = fetch(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_KEY}
        )
        if r2 and r2.status_code == 200:
            stats = r2.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result["vt_malicious"]  = stats.get("malicious", 0)
            result["vt_suspicious"] = stats.get("suspicious", 0)
            pr("vt_malicious",  result["vt_malicious"])
            pr("vt_suspicious", result["vt_suspicious"])

    # AbuseIPDB
    if ABUSEIPDB_KEY:
        r3 = fetch(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        )
        if r3 and r3.status_code == 200:
            d = r3.json().get("data", {})
            result["abuse_score"]    = d.get("abuseConfidenceScore")
            result["abuse_reports"]  = d.get("totalReports")
            result["abuse_domain"]   = d.get("domain")
            result["abuse_isp"]      = d.get("isp")
            pr("abuse_score",   result["abuse_score"])
            pr("abuse_reports", result["abuse_reports"])
            pr("abuse_domain",  result["abuse_domain"])

    # Shodan
    if SHODAN_KEY:
        try:
            import shodan
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "shodan", "-q"])
            import shodan
        try:
            info = shodan.Shodan(SHODAN_KEY).host(ip)
            result["open_ports"] = info.get("ports", [])
            result["vulns"]      = list(info.get("vulns", {}).keys())
            pr("open_ports", result["open_ports"])
            pr("vulns",      result["vulns"])
        except Exception as e:
            print(f"  [shodan] {e}")

    save(f"ip_{ip.replace('.','_')}", result)
    return result


def reverse_dns(ip: str) -> dict:
    print(f"\n[REVERSE DNS] {ip}")
    result = {"ip": ip}

    r = fetch(f"https://api.hackertarget.com/reversedns/?q={ip}")
    if r and r.status_code == 200 and "error" not in r.text.lower():
        domains = [line.split()[-1] for line in r.text.strip().splitlines() if line.strip()]
        result["domains"] = domains
        pr("domains", domains)

    r2 = fetch(f"https://api.hackertarget.com/hostsearch/?q={ip}")
    if r2 and r2.status_code == 200 and "error" not in r2.text.lower():
        hosts = [line.strip() for line in r2.text.strip().splitlines() if line.strip()]
        result["shared_hosts"] = hosts
        for h in hosts[:10]:
            print(f"  {h}")

    save(f"rdns_{ip.replace('.','_')}", result)
    return result


def subdomain_enum(domain: str) -> dict:
    print(f"\n[SUBDOMAINS] {domain}")
    result = {"domain": domain, "subdomains": []}
    found  = set()

    # crt.sh — certificate transparency
    r = fetch(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
    if r and r.status_code == 200:
        try:
            entries = r.json()
            for e in entries:
                for name in e.get("name_value", "").splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain):
                        found.add(name)
            print(f"  [crt.sh] найдено: {len(found)}")
        except Exception:
            pass

    # HackerTarget
    r2 = fetch(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
    if r2 and r2.status_code == 200 and "error" not in r2.text.lower():
        for line in r2.text.strip().splitlines():
            sub = line.split(",")[0].strip()
            if sub:
                found.add(sub)
        print(f"  [hackertarget] найдено: {len(found)}")

    result["subdomains"] = sorted(found)
    result["count"]      = len(found)

    for sub in sorted(found)[:30]:
        print(f"  {sub}")
    if len(found) > 30:
        print(f"  ... и ещё {len(found) - 30}")

    save(f"subdomains_{domain.replace('.','_')}", result)
    return result


def phone_lookup(number: str) -> dict:
    print(f"\n[PHONE] {number}")
    try:
        parsed = phonenumbers.parse(number)
        result = {
            "number":    number,
            "valid":     phonenumbers.is_valid_number(parsed),
            "country":   geocoder.description_for_number(parsed, "ru"),
            "carrier":   carrier.name_for_number(parsed, "ru"),
            "timezones": list(timezone.time_zones_for_number(parsed)),
            "type":      str(phonenumbers.number_type(parsed)),
            "intl_fmt":  phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        }
        for k, v in result.items():
            pr(k, v)
        save(f"phone_{re.sub(r'[^0-9]', '', number)}", result)
        return result
    except Exception as e:
        print(f"  [!] ошибка: {e}")
        return {}


def username_lookup(username: str) -> dict:
    print(f"\n[USERNAME] {username}")
    sites = {
        "GitHub":     f"https://github.com/{username}",
        "GitLab":     f"https://gitlab.com/{username}",
        "Twitter/X":  f"https://twitter.com/{username}",
        "Reddit":     f"https://www.reddit.com/user/{username}",
        "Instagram":  f"https://www.instagram.com/{username}",
        "TikTok":     f"https://www.tiktok.com/@{username}",
        "Telegram":   f"https://t.me/{username}",
        "VK":         f"https://vk.com/{username}",
        "Pinterest":  f"https://pinterest.com/{username}",
        "Twitch":     f"https://www.twitch.tv/{username}",
        "Steam":      f"https://steamcommunity.com/id/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "Pastebin":   f"https://pastebin.com/u/{username}",
        "Replit":     f"https://replit.com/@{username}",
        "Gravatar":   f"https://en.gravatar.com/{username}",
        "Keybase":    f"https://keybase.io/{username}",
        "Bitbucket":  f"https://bitbucket.org/{username}",
        "Codecademy": f"https://www.codecademy.com/profiles/{username}",
        "HackerNews": f"https://news.ycombinator.com/user?id={username}",
        "ProductHunt":f"https://www.producthunt.com/@{username}",
    }
    found = {}

    def check(item):
        site, url = item
        try:
            resp = requests.get(url, headers=HEADERS_UA, timeout=6, allow_redirects=True)
            hit  = resp.status_code == 200
            return site, url, hit, resp.status_code
        except Exception:
            return site, url, False, "timeout"

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(check, item): item for item in sites.items()}
        for future in tqdm(as_completed(futures), total=len(sites), desc="  проверка", ncols=60):
            site, url, hit, code = future.result()
            status = "✅ найден" if hit else f"❌ {code}"
            print(f"  {site:<18} {status}  {url}")
            if hit:
                found[site] = url

    # GitHub детали
    if "GitHub" in found:
        r = fetch(f"https://api.github.com/users/{username}")
        if r and r.status_code == 200:
            d = r.json()
            pr("gh_name",      d.get("name"))
            pr("gh_bio",       d.get("bio"))
            pr("gh_location",  d.get("location"))
            pr("gh_company",   d.get("company"))
            pr("gh_followers", d.get("followers"))
            pr("gh_repos",     d.get("public_repos"))
            pr("gh_created",   d.get("created_at"))
            found["github_details"] = {k: d.get(k) for k in
                ["name","bio","location","company","followers","public_repos","created_at"]}

    save(f"username_{username}", {"username": username, "found": found})
    return found


def email_lookup(email: str) -> dict:
    print(f"\n[EMAIL] {email}")
    result = {"email": email}

    # LeakCheck
    try:
        if LEAKCHECK_KEY:
            r = fetch(
                f"https://leakcheck.io/api/v2/query/{email}",
                headers={"X-API-Key": LEAKCHECK_KEY}
            )
            if r and r.status_code == 200:
                data    = r.json()
                sources = [e.get("source", {}).get("name", "?") for e in data.get("result", [])]
                result["leakcheck_found"]   = bool(sources)
                result["leakcheck_sources"] = sources
                result["leakcheck_count"]   = len(sources)
                pr("leak_found",   "ДА ⚠" if sources else "нет")
                pr("leak_count",   len(sources))
                pr("leak_sources", sources)
        else:
            r = fetch(f"https://leakcheck.io/api/public?check={email}")
            if r and r.status_code == 200:
                data    = r.json()
                sources = data.get("sources", [])
                result.update({
                    "leakcheck_found":   data.get("found", False),
                    "leakcheck_sources": sources,
                    "leakcheck_count":   len(sources),
                })
                pr("leak_found",   "ДА ⚠" if data.get("found") else "нет")
                pr("leak_count",   len(sources))
                pr("leak_sources", sources)
            elif r and r.status_code == 429:
                print("  [LeakCheck] лимит 50 req/день исчерпан")
    except Exception as e:
        print(f"  [LeakCheck] ошибка: {e}")

    # Hunter email verify
    if HUNTER_KEY:
        r2 = fetch(f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={HUNTER_KEY}")
        if r2 and r2.status_code == 200:
            d = r2.json().get("data", {})
            result["hunter_status"]     = d.get("status")
            result["hunter_score"]      = d.get("score")
            result["hunter_disposable"] = d.get("disposable")
            pr("hunter_status",     result["hunter_status"])
            pr("hunter_score",      result["hunter_score"])
            pr("hunter_disposable", result["hunter_disposable"])

    # MX
    domain = email.split("@")[-1]
    for cmd in [["nslookup", "-type=MX", domain], ["dig", "+short", "MX", domain]]:
        try:
            out = subprocess.check_output(cmd, text=True, timeout=5, stderr=subprocess.DEVNULL)
            mx  = [l.strip() for l in out.splitlines() if l.strip()]
            if mx:
                result["mx_records"] = mx
                pr("mx_records", mx)
                break
        except Exception:
            continue

    save(f"email_{re.sub(r'[^a-zA-Z0-9]', '_', email)}", result)
    return result


def domain_lookup(domain: str) -> dict:
    print(f"\n[DOMAIN] {domain}")
    result = {"domain": domain}

    try:
        ip = socket.gethostbyname(domain)
        result["resolved_ip"] = ip
        pr("resolved_ip", ip)
    except Exception:
        pass

    # WHOIS
    r = fetch(f"https://who.is/whois-json/{domain}")
    if r and r.status_code == 200:
        try:
            w = r.json()
            for field in ["registrar", "created", "updated", "expires", "nameservers"]:
                val = w.get(field) or w.get("whois", {}).get(field)
                if val:
                    result[field] = val
                    pr(field, val)
        except Exception:
            pass

    # HTTP headers
    for scheme in ("https", "http"):
        r2 = fetch(f"{scheme}://{domain}", timeout=6)
        if r2:
            keys = ["server", "x-powered-by", "x-frame-options",
                    "content-security-policy", "x-generator"]
            hdrs = {k: v for k, v in r2.headers.items() if k.lower() in keys}
            result["http_headers"] = hdrs
            pr("http_headers", hdrs)
            break

    # robots.txt
    r3 = fetch(f"https://{domain}/robots.txt", timeout=5)
    if r3 and r3.status_code == 200:
        dis = [l for l in r3.text.splitlines() if l.lower().startswith("disallow")]
        result["robots_disallow"] = dis
        pr("robots_disallow", dis[:15])

    # VirusTotal domain
    if VIRUSTOTAL_KEY:
        r4 = fetch(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_KEY}
        )
        if r4 and r4.status_code == 200:
            stats = r4.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result["vt_malicious"]  = stats.get("malicious", 0)
            result["vt_suspicious"] = stats.get("suspicious", 0)
            pr("vt_malicious",  result["vt_malicious"])
            pr("vt_suspicious", result["vt_suspicious"])

    # Hunter domain search
    if HUNTER_KEY:
        r5 = fetch(f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={HUNTER_KEY}")
        if r5 and r5.status_code == 200:
            d     = r5.json().get("data", {})
            emails = [e.get("value") for e in d.get("emails", [])]
            result["hunter_emails"] = emails
            result["hunter_org"]    = d.get("organization")
            pr("hunter_org",    result["hunter_org"])
            pr("hunter_emails", emails[:10])

    save(f"domain_{domain.replace('.','_')}", result)
    return result


def batch_mode(json_path: str):
    print(f"\n[BATCH] {json_path}")
    try:
        with open(json_path, encoding="utf-8") as f:
            targets = json.load(f)
    except Exception as e:
        print(f"  [!] ошибка чтения файла: {e}")
        return

    all_results = {}
    for target in targets:
        t_type = target.get("type", "").lower()
        value  = target.get("value", "")
        if not value:
            continue
        print(f"\n{'─'*50}")
        if t_type == "ip":
            all_results[f"ip:{value}"] = ip_lookup(value)
        elif t_type == "phone":
            all_results[f"phone:{value}"] = phone_lookup(value)
        elif t_type == "username":
            all_results[f"username:{value}"] = username_lookup(value)
        elif t_type == "email":
            all_results[f"email:{value}"] = email_lookup(value)
        elif t_type == "domain":
            all_results[f"domain:{value}"] = domain_lookup(value)
        else:
            print(f"  [!] неизвестный тип: {t_type}")

    generate_html_report(all_results, title=f"Batch Recon — {os.path.basename(json_path)}")


MENU = """
  [1]  IP lookup         геолокация + ASN + VirusTotal + AbuseIPDB
  [2]  Phone lookup      страна / оператор / тип / тайм-зона
  [3]  Username lookup   20 платформ (параллельно) + GitHub детали
  [4]  Email lookup      LeakCheck + Hunter verify + MX
  [5]  Domain lookup     WHOIS + заголовки + VirusTotal + Hunter emails
  [6]  Reverse DNS       PTR + shared hosts (HackerTarget)
  [7]  Subdomain enum    crt.sh + HackerTarget
  [8]  Full combo        IP + username + email + domain
  [9]  Batch mode        JSON файл с целями → HTML отчёт
  [0]  Выход
"""

def main():
    print(BANNER)
    keys = {
        "SHODAN":      SHODAN_KEY,
        "IPINFO":      IPINFO_TOKEN,
        "LEAKCHECK":   LEAKCHECK_KEY,
        "VIRUSTOTAL":  VIRUSTOTAL_KEY,
        "ABUSEIPDB":   ABUSEIPDB_KEY,
        "HUNTER":      HUNTER_KEY,
    }
    for name, val in keys.items():
        status = "✅" if val else "—"
        print(f"  {name:<14} {status}")

    while True:
        print(MENU)
        choice = input("  → ").strip()

        if choice == "1":
            ip_lookup(input("  IP: ").strip())
        elif choice == "2":
            phone_lookup(input("  Номер (+7...): ").strip())
        elif choice == "3":
            username_lookup(input("  Username: ").strip())
        elif choice == "4":
            email_lookup(input("  Email: ").strip())
        elif choice == "5":
            domain_lookup(input("  Домен (без https://): ").strip())
        elif choice == "6":
            reverse_dns(input("  IP: ").strip())
        elif choice == "7":
            subdomain_enum(input("  Домен (без https://): ").strip())
        elif choice == "8":
            ti = input("  IP (пусто = пропустить): ").strip()
            tu = input("  Username (пусто = пропустить): ").strip()
            te = input("  Email (пусто = пропустить): ").strip()
            td = input("  Домен (пусто = пропустить): ").strip()
            combo = {}
            if ti: combo[f"ip:{ti}"]         = ip_lookup(ti)
            if tu: combo[f"username:{tu}"]   = username_lookup(tu)
            if te: combo[f"email:{te}"]       = email_lookup(te)
            if td: combo[f"domain:{td}"]     = domain_lookup(td)
            generate_html_report(combo, title="Full Combo Recon")
        elif choice == "9":
            path = input("  Путь к JSON (~/targets.json): ").strip()
            batch_mode(os.path.expanduser(path))
        elif choice == "0":
            print("\n[*] fuelle off.\n")
            break
        else:
            print("  [!] неверный выбор")

if __name__ == "__main__":
    main()