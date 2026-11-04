# Baitcheck

Phishing link checker.

## Two ways to run it

1. Simple: double-click `index.html`. Everything works except certificate details.
2. With certificate checks: install Python 3.8+ (no extra packages), then in this folder run

       python server.py

   and open http://127.0.0.1:8000 . On Windows you can also try `py server.py`.
   Stop it with Ctrl+C.

## What the helper does
`server.py` serves the page and adds one endpoint, `/api/cert`, which connects to the
site you are checking and reads its TLS certificate (issuer, dates, names covered,
whether your computer trusts it). It listens on 127.0.0.1 only and refuses private
and local addresses unless started with `--allow-private`.
Domain age is not checked.

## Data
- `data/phishing-domains-snapshot.txt`: snapshot (4 Nov 2026) of active phishing domains from
  Phishing.Database (https://github.com/mitchellkrogza/Phishing.Database), also embedded in index.html.
- The India National Cyber Crime Reporting Portal publishes no list, so nothing here comes from it.
  Use the Report fraud page to file a complaint.

## Updating the blocklist
`build_data.py` and `index.src.html` are included. Download the latest
phishing-domains-ACTIVE.txt, then run
    python3 build_data.py phishing-domains-ACTIVE.txt data
and replace __BL__ / __STATS__ in index.src.html with data.b64 / data.json.
