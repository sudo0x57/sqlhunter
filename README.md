# SQLHunter v3.3

**SQLHunter** is a fast, multi-threaded SQL Injection scanner for URLs and HTML forms. It supports error-, boolean-, and time-based detection with caching, WAF awareness, and flexible reporting.

> For educational and authorized penetration testing only.

## ✨ Features

- **GET and POST scanning**: URL parameters and HTML forms
- **Boolean- and Time-based checks** with baseline timing to reduce false positives
- **Error-based detection** through common DBMS signatures
- **Concurrency**: Tunable threads for targets and per-parameter testing
- **Rate limiting and delays** to be gentle on targets
- **Session reuse with retries** for reliability
- **WAF awareness and simple bypass variants**
- **Crawling (optional)**: Discover URLs from a starting page
- **Caching**: Response caching for faster rescans
- **Reporting**: HTML, JSON, CSV
- **Config persistence** in `~/.config/sqlhunter/`

## 📦 Requirements

- Python 3.8+ and pip
- Git (recommended)

## 🛠️ Installation

- Quick setup:
```bash
pip install -r requirements.txt
# Optional (for JS crawling)
playwright install
```

- From scratch:

1) Clone the repository
```bash
git clone https://github.com/sudo0x57/sqlhunter
cd sqlhunter
```

2) Create a virtual environment
- Windows (PowerShell):
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```
- Linux/macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

3) Install dependencies
```bash
pip install -r requirements.txt
```

4) Install Playwright browsers (optional, for JavaScript-heavy crawling)
```bash
playwright install
```

## 🚀 Quick Start

1) Scan a single URL (scheme optional):
```bash
python sqlhunter.py -u "testphp.vulnweb.com/listproducts.php?cat=1"
```

2) Scan a domain (scheme optional):
```bash
python sqlhunter.py -ud "google.com"
```

3) Scan a list of URLs from a file:
```bash
python sqlhunter.py -l urls.txt
```

4) Update payloads (URL or domain-only is accepted):
```bash
# With full URL
python sqlhunter.py update -u "https://example.com/payloads.json"

# Or with domain/relative path
python sqlhunter.py update -uP "example.com/payloads.txt" --merge
```

## 🔧 Common Options

- **Targets**
  - `-u, --url`            Single URL (scheme optional)
  - `-ud, --domain`        Domain to scan (scheme optional)
  - `-l, --list`           File containing URLs (one per line)

- **Concurrency / Timing**
  - `-t, --threads`        Worker threads for targets (default 20)
  - `-pt, --param-threads` Threads per-parameter (default 6)
  - `-T, --timeout`        Request timeout (seconds)
  - `-d, --delay`          Delay between requests
  - `-R, --rate-limit`     Requests per second limit

- **HTTP / Transport**
  - `-P, --proxy`          HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)
  - `--no-verify`          Disable SSL verification
  - `--rotate-ua`          Rotate User-Agent per request
  - `-H, --header`         Custom header (key:value), repeatable

- **Detection / Behavior**
  - `-w, --waf`            Enable WAF bypass variants
  - `-E, --exploit`        Try exploitation helpers (limited, opt-in)
  - `--blind-timeout`      Time-based delay threshold (default ~8s)
  - `--include-params`     Only test these params (comma-separated)
  - `--exclude-params`     Skip these params (comma-separated)
  - `--max-params-per-url` Cap tested params per URL
  - Default: stop on first finding per parameter (faster scans)

- **Crawling**
  - `-c, --crawl`          Crawl starting page
  - `--max-pages`          Max crawl pages (default 50)
  - `--same-domain-only`   Restrict crawling to same domain

- **Output / Reporting**
  - `-f, --format`         Report format(s) comma-separated (html,json,csv)
  - `--save-responses`     Save responses for analysis
  - `-x, --export-curl`    Print cURL for tested requests
  - `-s, --silent`         Suppress console output (logs still saved)

## 🧭 Examples

- Crawl and scan with WAF bypass through proxy:
```bash
python sqlhunter.py -u "testphp.vulnweb.com/" -c -w -P "http://127.0.0.1:8080" --no-verify
```

- Increase threads and output JSON only:
```bash
python sqlhunter.py -u "https://target/page.php?id=1" -t 40 -f json
```

- Scan a form-heavy target with saved responses:
```bash
python sqlhunter.py -u "https://target/submit.php" --save-responses
```

## 📝 Notes

- When a scheme is omitted (e.g., `example.com`), `http://` is assumed.
- Logs, caches, and reports are stored under `~/.config/sqlhunter/` by default.
- Use `-s/--silent` for CI environments to reduce console noise.

## ⚠️ Legal

Use only on systems you own or have explicit permission to test. Misuse may violate laws and policies.

## 🤝 Contributing

Issues and PRs are welcome. Please describe changes clearly and include reproducible steps.

## 📄 License

Specify your license (e.g., MIT). If a `LICENSE` file is added, reference it here.






