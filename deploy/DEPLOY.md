# Deploying Pleroma (Phase 1)

Target: `pleroma-aicds.duckdns.org` on Ubuntu 26.04, alongside an existing
`bible-pointer` service on the same VPS. Nginx + certbot + systemd, no Docker.

All commands run as user `opt` on the VPS, with `sudo` where indicated. Local
commands run from your Windows machine in Git Bash.

---

## 0. Prereqs (already done — verified during planning)

- nginx running ✓
- certbot installed at `/usr/bin/certbot` ✓
- Python 3.14 at `/usr/bin/python3` ✓
- `pleroma-aicds.duckdns.org` → `157.250.205.174` (DuckDNS) ✓
- Ports 80/443 reachable ✓

---

## 1. Copy the repo to the VPS

From your **local Git Bash**, in the pleroma directory:

```bash
cd "/c/Users/BRAHIOM BASHIR/Downloads/pleroma"

# Ship code (excludes node_modules and any local venv)
rsync -avz --delete \
    --exclude '.git' \
    --exclude 'node_modules' \
    --exclude '.venv' \
    --exclude 'frontend/dist' \
    ./ opt@157.250.205.174:/tmp/pleroma-staging/
```

If you don't have `rsync` in Git Bash, use `scp -r ./ opt@157.250.205.174:/tmp/pleroma-staging/` — slower but works.

Then on the **VPS**:

```bash
sudo mkdir -p /opt/pleroma
sudo chown -R opt:opt /opt/pleroma
rsync -a --delete /tmp/pleroma-staging/ /opt/pleroma/
rm -rf /tmp/pleroma-staging
```

---

## 2. Backend: Python venv + dependencies

On the **VPS**:

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip libpq-dev build-essential

python3 -m venv /opt/pleroma/.venv
/opt/pleroma/.venv/bin/pip install --upgrade pip
/opt/pleroma/.venv/bin/pip install -r /opt/pleroma/backend/requirements.txt
```

If `psycopg2-binary` fails to build on Python 3.14, swap to `psycopg2` (compiled
against the libpq-dev we just installed):

```bash
/opt/pleroma/.venv/bin/pip install psycopg2
```

---

## 3. Backend: configure secrets

Create `/opt/pleroma/backend/.env`:

```bash
nano /opt/pleroma/backend/.env
```

Fill in (copy your existing values from the old backend repo's `.env`):

```env
DATABASE_URL=postgresql://...your Neon URL...
SECRET_KEY=...long random string for JWT...
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Optional but recommended
GROQ_API_KEY=...
SERPER_API_KEY=...
HF_API_KEY=...

# Webhook (optional)
WEBHOOK_URL=
ALERTS_ENABLED=false

# CORS — same-origin in production so this can stay default, but include
# localhost for dev sessions if you SSH-tunnel
ALLOWED_ORIGINS=https://pleroma-aicds.duckdns.org,http://localhost:5173
```

Lock it down:

```bash
chmod 600 /opt/pleroma/backend/.env
```

---

## 4. Backend: systemd service

```bash
sudo cp /opt/pleroma/deploy/pleroma-backend.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pleroma-backend
sudo systemctl status pleroma-backend --no-pager
```

Quick sanity check from the VPS:

```bash
curl -s http://127.0.0.1:8000/
# Expected: {"status":"online","message":"AICDS System Active"}
```

If it fails, check logs:

```bash
sudo journalctl -u pleroma-backend -n 50 --no-pager
```

---

## 5. Frontend: build locally, ship dist to VPS

On your **local machine** (Git Bash, in pleroma):

```bash
cd "/c/Users/BRAHIOM BASHIR/Downloads/pleroma/frontend"
npm install
npm run build
```

This produces `frontend/dist/`. Ship it:

```bash
rsync -avz --delete dist/ opt@157.250.205.174:/tmp/pleroma-dist/
```

On the **VPS**:

```bash
sudo mkdir -p /opt/pleroma/frontend-dist
sudo rsync -a --delete /tmp/pleroma-dist/ /opt/pleroma/frontend-dist/
sudo chown -R www-data:www-data /opt/pleroma/frontend-dist
rm -rf /tmp/pleroma-dist
```

---

## 6. Nginx vhost

```bash
sudo cp /opt/pleroma/deploy/nginx-pleroma.conf /etc/nginx/sites-available/pleroma-aicds
sudo ln -sf /etc/nginx/sites-available/pleroma-aicds /etc/nginx/sites-enabled/pleroma-aicds
sudo nginx -t                    # syntax check — must say "ok" and "successful"
sudo systemctl reload nginx
```

Verify bible-pointer is still alive:

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://157.250.205.174.nip.io
# Expected: 200 (or whatever bible-pointer normally returns)
```

Pleroma should answer over HTTP for now:

```bash
curl -s -H "Host: pleroma-aicds.duckdns.org" http://127.0.0.1/
# Expected: the index.html of the built frontend
```

---

## 7. TLS via certbot

```bash
sudo certbot --nginx -d pleroma-aicds.duckdns.org
```

When prompted:
- Email: any address you check (Let's Encrypt expiry warnings go here)
- Agree to ToS
- Redirect HTTP → HTTPS: **yes** (option 2)

Certbot patches the vhost in place, adds the `listen 443 ssl` block, and
sets up an http→https redirect.

Verify:

```bash
curl -sI https://pleroma-aicds.duckdns.org/
# Expected: HTTP/2 200
```

---

## 8. DuckDNS keep-alive cron

Store the token (the one in the DuckDNS dashboard, **not** committed):

```bash
echo 'DUCKDNS_TOKEN=YOUR-TOKEN-HERE' | sudo tee /opt/pleroma/.duckdns-token >/dev/null
sudo chmod 600 /opt/pleroma/.duckdns-token
sudo chown opt:opt /opt/pleroma/.duckdns-token
chmod +x /opt/pleroma/deploy/duckdns-update.sh
```

Add to `opt`'s crontab (`crontab -e`):

```cron
*/5 * * * * /opt/pleroma/deploy/duckdns-update.sh >> /var/log/duckdns.log 2>&1
```

Create the log file with permissions:

```bash
sudo touch /var/log/duckdns.log
sudo chown opt:opt /var/log/duckdns.log
```

Test once manually:

```bash
/opt/pleroma/deploy/duckdns-update.sh
cat /var/log/duckdns.log
# Expected: "<timestamp> duckdns update OK"
```

**Then regenerate the token in the DuckDNS dashboard** (your previous one
was shared in a screenshot — treat it as compromised) and replace it in
`/opt/pleroma/.duckdns-token`.

---

## 9. Smoke test the URL scanner end-to-end

In a browser:

1. Open `https://pleroma-aicds.duckdns.org`
2. Register a new account
3. Log in
4. Go to URL Scan
5. Submit a known-bad-looking URL (e.g. one from the OpenPhish feed) and a
   known-good one (e.g. https://wikipedia.org)
6. Verify both return verdicts within ~20s

If anything 500s, the most useful log is:

```bash
sudo journalctl -u pleroma-backend -f
```

---

## Update workflow (for later iteration)

Once you've pushed pleroma to a GitHub repo:

```bash
# On VPS, after each push:
cd /opt/pleroma && git pull
/opt/pleroma/.venv/bin/pip install -r backend/requirements.txt   # if deps changed
sudo systemctl restart pleroma-backend

# Locally, when frontend changes:
cd frontend && npm run build
rsync -avz --delete dist/ opt@157.250.205.174:/opt/pleroma/frontend-dist/
```

That's the whole loop.
