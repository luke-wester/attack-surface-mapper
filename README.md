# Attack Surface Mapper

Web-based cloud attack surface scanner with a Streamlit UI. Discovers subdomains, maps cloud providers, checks Shodan for open ports, probes S3 buckets, and searches GitHub for leaked credentials.

## Local development

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Optional: copy config template for local API keys
cp config.json.example config.json
# Edit config.json with your keys

streamlit run streamlit_app.py
```

Install [subfinder](https://github.com/projectdiscovery/subfinder) locally for broader subdomain discovery. Without it, crt.sh is still used.

## Deploy to Render

Render is recommended over Streamlit Community Cloud because you can run Docker (subfinder), keep secrets in env vars, and gate access with a password.

### 1. Prepare the repo

```bash
git init
git add .
git commit -m "Add Render deployment"
```

Push to GitHub. **Do not commit `config.json`** — it is listed in `.gitignore`.

Rotate any API keys that were previously stored in `config.json` if that file was ever shared or committed.

### 2. Create the Render service

1. Go to [render.com](https://render.com) and sign in.
2. **New → Blueprint** (if using `render.yaml`) or **New → Web Service**.
3. Connect your GitHub repository.
4. If not using Blueprint:
   - **Environment:** Docker
   - **Branch:** `main`
   - Dockerfile path: `Dockerfile`
5. Add environment variables in the Render dashboard:

| Variable | Required | Description |
|----------|----------|-------------|
| `SHODAN_API_KEY` | Recommended | Shodan API key for port/org lookups |
| `GITHUB_TOKEN` | Recommended | GitHub PAT for code search (needs `public_repo` scope) |
| `APP_PASSWORD` | Recommended | Password visitors must enter before using the app |

6. Deploy. Render assigns a URL like `https://attack-surface-mapper.onrender.com`.

Share that URL and `APP_PASSWORD` only with people you trust.

### Render free tier notes

- Services **spin down after ~15 minutes** of no traffic; the first visit after sleep can take 30–60 seconds to wake up.
- Free tier has CPU/memory limits; scans of 50 subdomains can take a few minutes.

## Why not Streamlit Community Cloud?

Common limitations that push security tools toward Render:

- Hard to install CLI tools like **subfinder**
- Free apps are **public** unless you pay for private/team hosting
- Free tier historically required a **public** GitHub repo
- Less control over Docker, env vars, and runtime compared to Render

## Security

- Never commit API keys or `config.json`.
- Use `APP_PASSWORD` so strangers cannot abuse your Shodan/GitHub quotas.
- Only scan domains you are authorized to test.
