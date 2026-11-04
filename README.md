# Baitcheck

Phishing link checker. Open `index.html` in any browser. No server or install needed.

- Pages: Home, Threat list, Safety tips, About (hash routing)
- Blocklist: snapshot of active domains from Phishing.Database (github.com/mitchellkrogza/Phishing.Database), taken 4 Nov 2026, embedded in index.html as a compact fingerprint index
- All analysis runs in the browser; nothing is sent anywhere
- Fonts load from Google Fonts when online and fall back to system fonts offline

## Updating the blocklist
build_data.py and index.src.html are included. Download the latest
phishing-domains-ACTIVE.txt, then run:
  python3 build_data.py phishing-domains-ACTIVE.txt data
and re-inject data.b64 / data.json into index.src.html (replace __BL__ and __STATS__).
