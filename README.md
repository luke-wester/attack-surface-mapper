# Attack Surface Mapper

Web-based cloud attack surface scanner for authorized security review. It discovers subdomains, maps likely cloud providers, checks Shodan for risky open ports, probes common S3 bucket names, and searches GitHub for credential exposure.

The app uses a small built-in Python web server and is ready for Docker deployment on Render. Streamlit is not used.

## Local Development

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Optional: copy config template for local API keys
cp config.json.example config.json
# Edit config.json with your keys

python app.py
```

Open `http://localhost:10000`.

Install [subfinder](https://github.com/projectdiscovery/subfinder) locally for broader subdomain discovery. Without it, crt.sh is still used.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SHODAN_API_KEY` | Recommended | Enables Shodan host lookups for open ports and org data |
| `GITHUB_TOKEN` | Recommended | Enables GitHub code search for credential exposure |
| `APP_PASSWORD` | Recommended | Password required before visitors can run scans |
| `PORT` | Render sets this | Web server port; defaults to `10000` |
| `SCAN_WORKERS` | Optional | Parallel subdomain checks; defaults to `8` |
| `HTTP_TIMEOUT` | Optional | HTTP timeout in seconds; defaults to `10` |

## Deploy To Render

1. Push this repo to GitHub.
2. In Render, choose **New -> Blueprint**.
3. Select `luke-wester/attack-surface-mapper`.
4. Render will read `render.yaml` and build the Docker service.
5. Add `APP_PASSWORD`, `SHODAN_API_KEY`, and `GITHUB_TOKEN` in the Render dashboard.
6. Deploy.

The health check endpoint is `/health`.

## Security

- Never commit API keys or `config.json`.
- Use `APP_PASSWORD` so strangers cannot burn your API quotas.
- Only scan domains you own or have written permission to test.
- Credential matches are masked before being returned in the UI or JSON report.
