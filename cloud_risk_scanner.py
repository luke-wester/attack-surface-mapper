import requests
import tldextract
import subprocess
import json
import re
import socket
import shutil
import time
import os

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

# -------------------------------------------
def get_subdomains(domain):
    result = []
    if shutil.which("subfinder"):
        try:
            result = subprocess.check_output(
                ["subfinder", "-d", domain, "-silent"],
                stderr=subprocess.DEVNULL,
            ).decode().splitlines()
        except Exception as e:
            print(f"subfinder error: {e}")
    result += get_subdomains_from_crtsh(domain)
    return list(set(result))

# -------------------------------------------
def get_subdomains_from_crtsh(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=10)
        names = list({entry['name_value'] for entry in r.json()})
        flattened = []
        for name in names:
            flattened += name.split('\n')
        return list(set(flattened))
    except:
        return []

# -------------------------------------------
def detect_cloud_provider(subdomain):
    patterns = {
        'aws': r's3\\.amazonaws\\.com',
        'gcp': r'storage\\.googleapis\\.com',
        'azure': r'blob\\.core\\.windows\\.net',
        'cloudflare': r'cdn\\.cloudflare\\.net',
        'github': r'github\\.io',
        'heroku': r'herokudns\\.com',
        'netlify': r'netlify\\.app'
    }
    try:
        r = requests.get(f"https://dns.google/resolve?name={subdomain}&type=CNAME", timeout=5).json()
        cname = r.get("Answer", [{}])[0].get("data", "")
        for provider, pattern in patterns.items():
            if re.search(pattern, cname):
                return provider, cname
    except:
        pass
    return 'unknown', ''

# -------------------------------------------
def resolve_ip(subdomain):
    try:
        return socket.gethostbyname(subdomain)
    except:
        return None

# -------------------------------------------
def shodan_lookup(ip):
    if not SHODAN_API_KEY:
        return None
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        resp = requests.get(url, timeout=10)
        return resp.json() if resp.status_code == 200 else None
    except Exception:
        return None

# -------------------------------------------
def check_subdomain_takeover(subdomain, cname):
    takeover_targets = ['github.io', 'herokudns.com', 'netlify.app']
    for target in takeover_targets:
        if target in cname:
            try:
                r = requests.get(f"http://{subdomain}", timeout=5)
                if r.status_code in [404, 403] and "not found" in r.text.lower():
                    return True
            except:
                return True
    return False

# -------------------------------------------
def check_s3_buckets(domain):
    common_names = [domain, f"{domain}-public", f"{domain}-assets", f"{domain}-files"]
    exposed = []
    for name in common_names:
        url = f"http://{name}.s3.amazonaws.com"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code in [200, 403]:
                exposed.append(url)
        except:
            pass
    return exposed

# -------------------------------------------
def extract_credentials_from_text(text):
    patterns = {
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret_key': r'(?i)aws_secret_access_key[\s:=\"\']+([A-Za-z0-9/+=]{40})',
        'stripe_key': r'sk_live_[0-9a-zA-Z]{24,}',
        'github_token': r'gh[pousr]_[A-Za-z0-9]{36,}',
        'google_api': r'AIza[0-9A-Za-z\-_]{35}',
        'slack_token': r'xox[baprs]-[0-9a-zA-Z]{10,48}'
    }
    found = []
    for name, pattern in patterns.items():
        matches = re.findall(pattern, text)
        for match in matches:
            found.append({'type': name, 'value': match})
    return found

# -------------------------------------------
def github_leak_scan(domain):
    if not GITHUB_TOKEN:
        return []
    url = f"https://api.github.com/search/code?q={domain}+AWS_SECRET_ACCESS_KEY&per_page=5"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    found = []
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            for item in r.json().get("items", []):
                raw_url = item['html_url'].replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                try:
                    raw_text = requests.get(raw_url, timeout=10).text
                    creds = extract_credentials_from_text(raw_text)
                    if creds:
                        found.extend([{'url': item['html_url'], 'credentials': creds}])
                except:
                    continue
    except:
        pass
    return found

# -------------------------------------------
def analyze_subdomains(subdomains, domain, progress_callback=None):
    results = []
    exposed_buckets = check_s3_buckets(domain)
    github_leaks = github_leak_scan(domain)
    credentials = []
    for leak in github_leaks:
        credentials.extend(leak['credentials'])

    total = len(subdomains)
    for index, sub in enumerate(subdomains):
        ip = resolve_ip(sub)
        cloud, cname = detect_cloud_provider(sub)
        shodan_data = shodan_lookup(ip) if ip else None
        risky_ports = [p for p in shodan_data.get('ports', []) if p in [21, 22, 23, 445, 3389]] if shodan_data else []

        results.append({
            'subdomain': sub,
            'ip': ip,
            'cloud_provider': cloud,
            'cname': cname,
            'takeover_candidate': check_subdomain_takeover(sub, cname),
            'risky_ports': risky_ports,
            'open_ports': shodan_data.get('ports') if shodan_data else [],
            'org': shodan_data.get('org') if shodan_data else None
        })

        if progress_callback:
            progress_callback(index + 1, total, sub)

        time.sleep(1.2)

    return results, exposed_buckets, github_leaks, credentials

# -------------------------------------------
def score_risk(results, buckets, leaks, credentials):
    scores = {'aws': 0, 'gcp': 0, 'azure': 0, 'cloudflare': 0, 'github': 0, 'heroku': 0, 'netlify': 0}
    for entry in results:
        provider = entry['cloud_provider']
        if provider in scores:
            scores[provider] += 10
            scores[provider] += len(entry['risky_ports']) * 5
            if entry['takeover_candidate']:
                scores[provider] += 20
    if buckets:
        scores['aws'] += len(buckets) * 15
    if leaks:
        scores['github'] += len(leaks) * 10
    if credentials:
        scores['aws'] += len(credentials) * 50  # HIGH impact
    return scores

# -------------------------------------------
def generate_report(domain, results, scores, buckets, leaks, credentials):
    report = {
        'domain': domain,
        'discovered_assets': results,
        'risk_score': scores,
        'exposed_buckets': buckets,
        'github_leaks': leaks,
        'credentials_found': credentials
    }
    print(json.dumps(report, indent=2))
    return report

# -------------------------------------------
def deduplicate_subdomains(subdomains):
    seen = set()
    filtered = []
    for sub in subdomains:
        ext = tldextract.extract(sub)
        root = f"{ext.subdomain}.{ext.domain}.{ext.suffix}"
        if root not in seen:
            seen.add(root)
            filtered.append(sub)
    return filtered

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
