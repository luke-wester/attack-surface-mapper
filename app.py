import hmac
import json
import os
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from cloud_risk_scanner import (
    GITHUB_TOKEN,
    SCAN_WORKERS,
    SHODAN_API_KEY,
    analyze_subdomains,
    deduplicate_subdomains,
    generate_report,
    get_subdomains,
    score_risk,
)

APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)
MAX_BODY_BYTES = 4096


def normalize_domain(value):
    value = (value or "").strip().lower()
    if "://" in value:
        value = urlparse(value).netloc
    value = value.split("/")[0].split(":")[0].strip(".")
    if value.startswith("www."):
        value = value[4:]
    return value


def bounded_int(value, default, minimum, maximum):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def password_ok(value):
    if not APP_PASSWORD:
        return True
    return hmac.compare_digest(value or "", APP_PASSWORD)


def build_scan(payload):
    if not payload.get("authorized"):
        raise ValueError("Confirm that you are authorized to scan this domain.")
    if not password_ok(payload.get("password")):
        raise PermissionError("Invalid password.")

    domain = normalize_domain(payload.get("domain"))
    if not DOMAIN_PATTERN.fullmatch(domain):
        raise ValueError("Enter a valid domain, for example example.com.")

    max_subdomains = bounded_int(payload.get("max_subdomains"), 50, 5, 100)
    scan_workers = bounded_int(payload.get("scan_workers"), SCAN_WORKERS, 1, 16)

    subdomains = get_subdomains(domain)
    limited = deduplicate_subdomains(subdomains, domain)[:max_subdomains]
    if not limited:
        return {
            "domain": domain,
            "summary": {
                "subdomains_analyzed": 0,
                "bucket_findings": 0,
                "github_leaks": 0,
                "credentials_found": 0,
            },
            "discovered_assets": [],
            "risk_score": {},
            "exposed_buckets": [],
            "github_leaks": [],
            "credentials_found": [],
            "message": "No subdomains found. Try another domain or check network access.",
        }

    results, buckets, leaks, credentials = analyze_subdomains(
        limited,
        domain,
        max_workers=scan_workers,
    )
    scores = score_risk(results, buckets, leaks, credentials)
    return generate_report(domain, results, scores, buckets, leaks, credentials)


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Attack Surface Mapper</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f8fa;
      --surface: #ffffff;
      --surface-strong: #eef3f5;
      --text: #172026;
      --muted: #5e6d77;
      --line: #d7dee3;
      --primary: #176b6b;
      --primary-dark: #0f5151;
      --warn: #a65313;
      --bad: #b3261e;
      --good: #277a42;
      --shadow: 0 16px 36px rgba(23, 32, 38, 0.09);
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    header {
      border-bottom: 1px solid var(--line);
      background: var(--surface);
    }
    .topbar {
      max-width: 1180px;
      margin: 0 auto;
      padding: 18px 22px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 18px;
    }
    h1 {
      margin: 0;
      font-size: 24px;
      letter-spacing: 0;
    }
    .status {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }
    .badge {
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 4px 9px;
      color: var(--muted);
      background: var(--surface-strong);
      font-size: 12px;
      white-space: nowrap;
    }
    .badge.ok { color: var(--good); }
    .badge.missing { color: var(--warn); }
    main {
      max-width: 1180px;
      margin: 0 auto;
      padding: 24px 22px 44px;
    }
    .workspace {
      display: grid;
      grid-template-columns: minmax(280px, 360px) minmax(0, 1fr);
      gap: 22px;
      align-items: start;
    }
    form, .results {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }
    form {
      padding: 18px;
      display: grid;
      gap: 14px;
      position: sticky;
      top: 16px;
    }
    label {
      display: grid;
      gap: 6px;
      font-weight: 650;
      color: var(--text);
    }
    .hint {
      color: var(--muted);
      font-size: 12px;
      font-weight: 400;
    }
    input[type="text"], input[type="password"], input[type="number"] {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 10px 11px;
      color: var(--text);
      font: inherit;
      background: #fff;
    }
    input:focus {
      outline: 3px solid rgba(23, 107, 107, 0.18);
      border-color: var(--primary);
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
    }
    .check {
      display: grid;
      grid-template-columns: 18px 1fr;
      gap: 9px;
      align-items: start;
      font-weight: 500;
    }
    .check input { margin-top: 4px; }
    button {
      border: 0;
      border-radius: 6px;
      background: var(--primary);
      color: #fff;
      padding: 11px 14px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
    }
    button:hover { background: var(--primary-dark); }
    button:disabled {
      opacity: 0.58;
      cursor: wait;
    }
    .results {
      min-height: 560px;
      overflow: hidden;
    }
    .results-head {
      padding: 18px;
      border-bottom: 1px solid var(--line);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
    }
    h2 {
      margin: 0;
      font-size: 18px;
      letter-spacing: 0;
    }
    .results-body {
      padding: 18px;
      display: grid;
      gap: 18px;
    }
    .empty, .message {
      color: var(--muted);
      padding: 34px 18px;
      text-align: center;
    }
    .message.error {
      color: var(--bad);
      text-align: left;
      background: #fff3f1;
      border: 1px solid #ffd4cf;
      border-radius: 6px;
      padding: 12px;
    }
    .metrics {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
    }
    .metric {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: var(--surface-strong);
    }
    .metric b {
      display: block;
      font-size: 24px;
      line-height: 1.15;
    }
    .metric span {
      color: var(--muted);
      font-size: 12px;
    }
    .section {
      display: grid;
      gap: 10px;
    }
    .bar {
      display: grid;
      grid-template-columns: 90px 1fr 38px;
      gap: 10px;
      align-items: center;
      margin: 8px 0;
    }
    .track {
      height: 10px;
      background: var(--surface-strong);
      border-radius: 999px;
      overflow: hidden;
    }
    .fill {
      height: 100%;
      background: var(--primary);
      border-radius: inherit;
    }
    .table-wrap {
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    table {
      width: 100%;
      min-width: 720px;
      border-collapse: collapse;
      background: #fff;
    }
    th, td {
      border-bottom: 1px solid var(--line);
      padding: 9px 10px;
      text-align: left;
      vertical-align: top;
      font-size: 13px;
    }
    th {
      color: var(--muted);
      background: var(--surface-strong);
      font-size: 12px;
      text-transform: uppercase;
    }
    tr:last-child td { border-bottom: 0; }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 12px;
    }
    .download {
      background: transparent;
      color: var(--primary);
      border: 1px solid var(--primary);
      padding: 8px 10px;
    }
    .download:hover {
      color: #fff;
    }
    .spinner {
      width: 16px;
      height: 16px;
      border: 2px solid var(--line);
      border-top-color: var(--primary);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      display: none;
    }
    .loading .spinner { display: inline-block; }
    @keyframes spin { to { transform: rotate(360deg); } }

    @media (max-width: 880px) {
      .topbar, main { padding-left: 16px; padding-right: 16px; }
      .workspace { grid-template-columns: 1fr; }
      form { position: static; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body data-password-required="__PASSWORD_REQUIRED__">
  <header>
    <div class="topbar">
      <h1>Attack Surface Mapper</h1>
      <div class="status">
        <span class="badge __SHODAN_CLASS__">Shodan __SHODAN_STATUS__</span>
        <span class="badge __GITHUB_CLASS__">GitHub __GITHUB_STATUS__</span>
        <span class="badge __PASSWORD_CLASS__">Password __PASSWORD_STATUS__</span>
      </div>
    </div>
  </header>
  <main>
    <div class="workspace">
      <form id="scan-form">
        <label>
          Domain
          <input id="domain" name="domain" type="text" placeholder="example.com" autocomplete="off" required>
        </label>
        <label id="password-row">
          Password
          <input id="password" name="password" type="password" autocomplete="current-password">
        </label>
        <div class="grid">
          <label>
            Max subdomains
            <input id="max-subdomains" name="max_subdomains" type="number" min="5" max="100" step="5" value="50">
          </label>
          <label>
            Parallel checks
            <input id="scan-workers" name="scan_workers" type="number" min="1" max="16" step="1" value="8">
          </label>
        </div>
        <label class="check">
          <input id="authorized" name="authorized" type="checkbox">
          <span>I have permission to scan this domain.</span>
        </label>
        <button id="run-button" type="submit">Run scan</button>
        <span class="hint">Scans can take a few minutes for larger domains.</span>
      </form>

      <section class="results">
        <div class="results-head">
          <h2>Results</h2>
          <div class="spinner" aria-label="Loading"></div>
          <button class="download" id="download-button" type="button" hidden>Download JSON</button>
        </div>
        <div class="results-body" id="results-body">
          <div class="empty">Run an authorized scan to see discovered assets, risk scores, bucket findings, and credential hits.</div>
        </div>
      </section>
    </div>
  </main>

  <script>
    const body = document.body;
    const form = document.getElementById("scan-form");
    const resultsBody = document.getElementById("results-body");
    const runButton = document.getElementById("run-button");
    const downloadButton = document.getElementById("download-button");
    const passwordRow = document.getElementById("password-row");
    let latestReport = null;

    if (body.dataset.passwordRequired !== "true") {
      passwordRow.hidden = true;
    }

    const escapeHtml = (value) => String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");

    const renderList = (value) => Array.isArray(value) && value.length
      ? value.map((item) => `<code>${escapeHtml(item)}</code>`).join(", ")
      : "";

    const renderRisk = (scores = {}) => {
      const entries = Object.entries(scores).sort((a, b) => b[1] - a[1]);
      if (!entries.length) return "<p class='empty'>No risk scores yet.</p>";
      const max = Math.max(...entries.map(([, score]) => score), 1);
      return entries.map(([name, score]) => `
        <div class="bar">
          <code>${escapeHtml(name)}</code>
          <div class="track"><div class="fill" style="width:${Math.round((score / max) * 100)}%"></div></div>
          <strong>${score}</strong>
        </div>
      `).join("");
    };

    const renderAssets = (assets = []) => {
      if (!assets.length) return "<p class='empty'>No subdomains analyzed.</p>";
      return `
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Subdomain</th>
                <th>IP</th>
                <th>Provider</th>
                <th>CNAME</th>
                <th>Risky ports</th>
                <th>Takeover</th>
              </tr>
            </thead>
            <tbody>
              ${assets.map((asset) => `
                <tr>
                  <td><code>${escapeHtml(asset.subdomain)}</code></td>
                  <td>${escapeHtml(asset.ip || "")}</td>
                  <td>${escapeHtml(asset.cloud_provider || "unknown")}</td>
                  <td><code>${escapeHtml(asset.cname || "")}</code></td>
                  <td>${renderList(asset.risky_ports)}</td>
                  <td>${asset.takeover_candidate ? "Yes" : "No"}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      `;
    };

    const renderFindings = (title, rows, columns) => {
      if (!rows || !rows.length) return "";
      return `
        <section class="section">
          <h2>${escapeHtml(title)}</h2>
          <div class="table-wrap">
            <table>
              <thead><tr>${columns.map((column) => `<th>${escapeHtml(column.label)}</th>`).join("")}</tr></thead>
              <tbody>
                ${rows.map((row) => `
                  <tr>${columns.map((column) => `<td>${escapeHtml(column.value(row))}</td>`).join("")}</tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        </section>
      `;
    };

    const renderReport = (report) => {
      const summary = report.summary || {};
      resultsBody.innerHTML = `
        ${report.message ? `<div class="message">${escapeHtml(report.message)}</div>` : ""}
        <div class="metrics">
          <div class="metric"><b>${summary.subdomains_analyzed || 0}</b><span>Subdomains</span></div>
          <div class="metric"><b>${summary.bucket_findings || 0}</b><span>Bucket findings</span></div>
          <div class="metric"><b>${summary.github_leaks || 0}</b><span>GitHub leaks</span></div>
          <div class="metric"><b>${summary.credentials_found || 0}</b><span>Credential hits</span></div>
        </div>
        <section class="section">
          <h2>Risk scores</h2>
          ${renderRisk(report.risk_score)}
        </section>
        <section class="section">
          <h2>Discovered assets</h2>
          ${renderAssets(report.discovered_assets)}
        </section>
        ${renderFindings("Bucket findings", report.exposed_buckets, [
          { label: "URL", value: (row) => row.url },
          { label: "Status", value: (row) => row.status },
          { label: "Access", value: (row) => row.access },
        ])}
        ${renderFindings("Credential hits", report.credentials_found, [
          { label: "Type", value: (row) => row.type },
          { label: "Value", value: (row) => row.value },
        ])}
        ${renderFindings("GitHub links", report.github_leaks, [
          { label: "URL", value: (row) => row.url },
        ])}
      `;
      downloadButton.hidden = false;
    };

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      latestReport = null;
      downloadButton.hidden = true;
      runButton.disabled = true;
      document.querySelector(".results").classList.add("loading");
      resultsBody.innerHTML = "<div class='empty'>Scanning public records and configured APIs...</div>";

      const payload = {
        domain: document.getElementById("domain").value,
        password: document.getElementById("password").value,
        max_subdomains: document.getElementById("max-subdomains").value,
        scan_workers: document.getElementById("scan-workers").value,
        authorized: document.getElementById("authorized").checked,
      };

      try {
        const response = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Scan failed.");
        latestReport = data;
        renderReport(data);
      } catch (error) {
        resultsBody.innerHTML = `<div class="message error">${escapeHtml(error.message)}</div>`;
      } finally {
        runButton.disabled = false;
        document.querySelector(".results").classList.remove("loading");
      }
    });

    downloadButton.addEventListener("click", () => {
      if (!latestReport) return;
      const blob = new Blob([JSON.stringify(latestReport, null, 2)], { type: "application/json" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `${latestReport.domain || "attack-surface"}_scan.json`;
      link.click();
      URL.revokeObjectURL(link.href);
    });
  </script>
</body>
</html>
"""


def render_index():
    return (
        INDEX_HTML.replace("__PASSWORD_REQUIRED__", "true" if APP_PASSWORD else "false")
        .replace("__SHODAN_CLASS__", "ok" if SHODAN_API_KEY else "missing")
        .replace("__SHODAN_STATUS__", "ready" if SHODAN_API_KEY else "missing")
        .replace("__GITHUB_CLASS__", "ok" if GITHUB_TOKEN else "missing")
        .replace("__GITHUB_STATUS__", "ready" if GITHUB_TOKEN else "missing")
        .replace("__PASSWORD_CLASS__", "ok" if APP_PASSWORD else "missing")
        .replace("__PASSWORD_STATUS__", "on" if APP_PASSWORD else "off")
    )


class AttackSurfaceHandler(BaseHTTPRequestHandler):
    server_version = "AttackSurfaceMapper/1.0"

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

    def send_body(self, status, body, content_type):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(encoded)

    def send_json(self, status, payload):
        self.send_body(status, json.dumps(payload), "application/json; charset=utf-8")

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            self.send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if path == "/":
            self.send_body(HTTPStatus.OK, render_index(), "text/html; charset=utf-8")
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/api/scan":
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
            return

        try:
            length = bounded_int(self.headers.get("Content-Length"), 0, 0, MAX_BODY_BYTES)
            payload = json.loads(self.rfile.read(length) or b"{}")
            report = build_scan(payload)
            self.send_json(HTTPStatus.OK, report)
        except PermissionError as exc:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
        except ValueError as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"Scan failed: {exc}"})


def main():
    port = bounded_int(os.environ.get("PORT"), 10000, 1, 65535)
    server = ThreadingHTTPServer(("0.0.0.0", port), AttackSurfaceHandler)
    print(f"Attack Surface Mapper running on port {port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
