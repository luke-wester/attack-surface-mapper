import requests
import tldextract
import subprocess
import json
import re
import socket
import shutil
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from threading import local


def env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


HTTP_TIMEOUT = env_int("HTTP_TIMEOUT", 10)
SCAN_WORKERS = env_int("SCAN_WORKERS", 8)
RISKY_PORTS = {21, 22, 23, 445, 3389}

THREAD_LOCAL = local()
TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

CLOUD_PATTERNS = {
    "aws": (
        r"s3\.amazonaws\.com",
        r"cloudfront\.net",
        r"elasticbeanstalk\.com",
    ),
    "gcp": (
        r"storage\.googleapis\.com",
        r"appspot\.com",
        r"googlehosted\.com",
    ),
    "azure": (
        r"blob\.core\.windows\.net",
        r"azurewebsites\.net",
        r"trafficmanager\.net",
    ),
    "cloudflare": (r"cloudflare\.net",),
    "github": (r"github\.io",),
    "heroku": (r"herokudns\.com", r"herokuapp\.com"),
    "netlify": (r"netlify\.app", r"netlifyglobalcdn\.com"),
}


def get_session():
    if not hasattr(THREAD_LOCAL, "session"):
        THREAD_LOCAL.session = requests.Session()
        THREAD_LOCAL.session.headers.update(
            {
                "Accept": "application/json,text/plain,*/*",
                "User-Agent": "AttackSurfaceMapper/1.0",
            }
        )
    return THREAD_LOCAL.session

# -------------------------------------------
def load_config():
    """Load API keys from environment variables (Render) or local config.json."""
    if os.environ.get("SHODAN_API_KEY") or os.environ.get("GITHUB_TOKEN"):
        return {
            "shodan_api_key": os.environ.get("SHODAN_API_KEY"),
            "github_token": os.environ.get("GITHUB_TOKEN"),
        }
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    if os.path.exists(config_path):
        with open(config_path) as f:
            return json.load(f)
    return {}

config = load_config()
SHODAN_API_KEY = config.get("shodan_api_key")
GITHUB_TOKEN = config.get("github_token")


def normalize_subdomain(value, domain):
    value = value.strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    if not value or value == domain or not value.endswith(f".{domain}"):
        return None
    if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}", value):
        return None
    return value


def get_subdomains(domain):
    result = []
    if shutil.which("subfinder"):
        try:
            result = subprocess.check_output(
                ["subfinder", "-d", domain, "-silent"],
                stderr=subprocess.DEVNULL,
                timeout=45,
            ).decode().splitlines()
        except Exception as e:
            print(f"subfinder error: {e}")
    result += get_subdomains_from_crtsh(domain)
    return deduplicate_subdomains(result, domain)


def get_subdomains_from_crtsh(domain):
    try:
        r = get_session().get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=HTTP_TIMEOUT + 10,
        )
        r.raise_for_status()
        names = list({entry["name_value"] for entry in r.json()})
        flattened = []
        for name in names:
            flattened += name.split("\n")
        return flattened
    except Exception:
        return []


def detect_cloud_provider(subdomain):
    try:
        r = get_session().get(
            "https://dns.google/resolve",
            params={"name": subdomain, "type": "CNAME"},
            timeout=5,
        ).json()
        answers = r.get("Answer", [])
        cnames = [
            answer.get("data", "").lower().rstrip(".")
            for answer in answers
            if answer.get("type") == 5 and answer.get("data")
        ]
        for cname in cnames:
            for provider, patterns in CLOUD_PATTERNS.items():
                if any(re.search(pattern, cname) for pattern in patterns):
                    return provider, cname
    except Exception:
        pass
    return "unknown", ""


def resolve_ip(subdomain):
    try:
        return socket.gethostbyname(subdomain)
    except Exception:
        return None


def shodan_lookup(ip):
    if not SHODAN_API_KEY:
        return None
    try:
        resp = get_session().get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_API_KEY},
            timeout=HTTP_TIMEOUT,
        )
        return resp.json() if resp.status_code == 200 else None
    except Exception:
        return None


def check_subdomain_takeover(subdomain, cname):
    takeover_targets = ["github.io", "herokudns.com", "netlify.app"]
    cname = cname.lower()
    for target in takeover_targets:
        if target in cname:
            try:
                r = get_session().get(f"http://{subdomain}", timeout=5)
                body = r.text.lower()
                if r.status_code in [404, 403] and (
                    "not found" in body or "no such app" in body
                ):
                    return True
            except Exception:
                return True
    return False


def check_s3_buckets(domain):
    common_names = [domain, f"{domain}-public", f"{domain}-assets", f"{domain}-files"]
    findings = []
    for name in common_names:
        url = f"http://{name}.s3.amazonaws.com"
        try:
            r = get_session().get(url, timeout=5)
            if r.status_code in [200, 403]:
                findings.append(
                    {
                        "url": url,
                        "status": r.status_code,
                        "access": "public" if r.status_code == 200 else "exists_forbidden",
                    }
                )
        except Exception:
            pass
    return findings


def mask_secret(value):
    if not value:
        return value
    if len(value) <= 12:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def extract_credentials_from_text(text):
    patterns = {
        "aws_access_key": r"AKIA[0-9A-Z]{16}",
        "aws_secret_key": r"(?i)aws_secret_access_key[\s:=\"']+([A-Za-z0-9/+=]{40})",
        "stripe_key": r"sk_live_[0-9a-zA-Z]{24,}",
        "github_token": r"gh[pousr]_[A-Za-z0-9]{36,}",
        "google_api": r"AIza[0-9A-Za-z\-_]{35}",
        "slack_token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    }
    found = []
    for name, pattern in patterns.items():
        matches = re.findall(pattern, text)
        for match in matches:
            found.append({"type": name, "value": mask_secret(match)})
    return found


def github_leak_scan(domain):
    if not GITHUB_TOKEN:
        return []
    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"}
    found = []
    try:
        r = get_session().get(
            "https://api.github.com/search/code",
            params={"q": f"{domain} AWS_SECRET_ACCESS_KEY", "per_page": 5},
            headers=headers,
            timeout=HTTP_TIMEOUT,
        )
        if r.status_code == 200:
            for item in r.json().get("items", []):
                raw_url = (
                    item["html_url"]
                    .replace("github.com", "raw.githubusercontent.com")
                    .replace("/blob/", "/")
                )
                try:
                    raw_text = get_session().get(raw_url, timeout=HTTP_TIMEOUT).text
                    creds = extract_credentials_from_text(raw_text)
                    if creds:
                        found.append({"url": item["html_url"], "credentials": creds})
                except Exception:
                    continue
    except Exception:
        pass
    return found


def analyze_single_subdomain(subdomain):
    ip = resolve_ip(subdomain)
    cloud, cname = detect_cloud_provider(subdomain)
    shodan_data = shodan_lookup(ip) if ip else None
    open_ports = sorted(shodan_data.get("ports", [])) if shodan_data else []
    risky_ports = [port for port in open_ports if port in RISKY_PORTS]

    return {
        "subdomain": subdomain,
        "ip": ip,
        "cloud_provider": cloud,
        "cname": cname,
        "takeover_candidate": check_subdomain_takeover(subdomain, cname),
        "risky_ports": risky_ports,
        "open_ports": open_ports,
        "org": shodan_data.get("org") if shodan_data else None,
    }


def analyze_subdomains(subdomains, domain, progress_callback=None, max_workers=SCAN_WORKERS):
    results = []
    exposed_buckets = check_s3_buckets(domain)
    github_leaks = github_leak_scan(domain)
    credentials = []
    for leak in github_leaks:
        credentials.extend(leak["credentials"])

    total = len(subdomains)
    workers = max(1, min(max_workers, total or 1))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(analyze_single_subdomain, subdomain): subdomain
            for subdomain in subdomains
        }
        for index, future in enumerate(as_completed(futures), start=1):
            subdomain = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:
                results.append(
                    {
                        "subdomain": subdomain,
                        "ip": None,
                        "cloud_provider": "unknown",
                        "cname": "",
                        "takeover_candidate": False,
                        "risky_ports": [],
                        "open_ports": [],
                        "org": None,
                        "error": str(exc),
                    }
                )
            if progress_callback:
                progress_callback(index, total, subdomain)

    return sorted(results, key=lambda item: item["subdomain"]), exposed_buckets, github_leaks, credentials


def score_risk(results, buckets, leaks, credentials):
    scores = {"aws": 0, "gcp": 0, "azure": 0, "cloudflare": 0, "github": 0, "heroku": 0, "netlify": 0}
    for entry in results:
        provider = entry["cloud_provider"]
        if provider in scores:
            scores[provider] += 10
            scores[provider] += len(entry["risky_ports"]) * 5
            if entry["takeover_candidate"]:
                scores[provider] += 20
    if buckets:
        scores["aws"] += len(buckets) * 15
    if leaks:
        scores["github"] += len(leaks) * 10
    if credentials:
        scores["aws"] += len(credentials) * 50
    return scores


def generate_report(domain, results, scores, buckets, leaks, credentials):
    return {
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "subdomains_analyzed": len(results),
            "bucket_findings": len(buckets),
            "github_leaks": len(leaks),
            "credentials_found": len(credentials),
        },
        "discovered_assets": results,
        "risk_score": scores,
        "exposed_buckets": buckets,
        "github_leaks": leaks,
        "credentials_found": credentials,
    }


def deduplicate_subdomains(subdomains, domain=None):
    seen = set()
    filtered = []
    for sub in subdomains:
        candidate = normalize_subdomain(sub, domain) if domain else sub.strip().lower().rstrip(".")
        if not candidate:
            continue
        ext = TLD_EXTRACT(candidate)
        if not ext.domain or not ext.suffix:
            continue
        root = ".".join(part for part in [ext.subdomain, ext.domain, ext.suffix] if part)
        if root and root not in seen:
            seen.add(root)
            filtered.append(candidate)
    return sorted(filtered)

# -------------------------------------------
if __name__ == "__main__":
    domain = input("Enter a company domain (e.g. acme.com): ").strip().lower()
    print(f"\n[+] Gathering subdomains for {domain}...")
    subdomains = get_subdomains(domain)
    limited = deduplicate_subdomains(subdomains)[:50]
    print(f"[+] Analyzing {len(limited)} subdomains...\n")

    results, buckets, leaks, credentials = analyze_subdomains(limited, domain)
    scores = score_risk(results, buckets, leaks, credentials)
    generate_report(domain, results, scores, buckets, leaks, credentials)
