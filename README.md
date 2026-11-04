# Baitcheck

A phishing link checker that runs entirely in your browser. Paste a link and
Baitcheck gives a 0-100 risk score, explains each reason, and checks the domain
against a snapshot of 392,000 reported phishing domains.

## Features
- Risk score with a reason for every warning sign
- Checks against the Phishing.Database snapshot (4 Nov 2026), packed into the page so it works offline
- Brand lookalike and typo detection, raw IPs, `@` tricks, punycode lookalikes,
  long subdomain chains, shorteners, free hosting, high-abuse endings, pressure wording
- Optional TLS certificate check (issuer, dates, trust, age) through a local helper
- Report fraud page: 1930 helpline, cybercrime.gov.in steps, evidence checklist,
  and a complaint-text writer
- Light and dark themes, no tracking, nothing leaves your browser

## Run it
**Simple:** open `index.html` in a browser. Everything works except certificate checks.

**With certificate checks:** requires Python 3.8+ and no other packages.

    python server.py

Then open http://127.0.0.1:8000. The helper listens on localhost only and
refuses private and local addresses.

## Limits
Baitcheck judges the address, not the page behind it. It does not check domain
age or page content. The blocklist is a snapshot, so new scams will not be in it.
A clean result means "nothing obvious", not "safe".

## Updating the blocklist
    python build_data.py phishing-domains-ACTIVE.txt data
Then replace `__BL__` and `__STATS__` in `index.src.html` with the generated
`data.b64` and `data.json`.

## Data and credits
Blocklist from [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database)
by Mitchell Krogza. Check that project's licence before redistributing the list.
The National Cyber Crime Reporting Portal publishes no list of fraud sites, so no
data comes from it.
