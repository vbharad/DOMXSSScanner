# DOM XSS Scanner & PoC Generator

**Developed by Vishal Bharad**

A comprehensive DOM-based vulnerability scanner that performs both static analysis and dynamic testing to detect Cross-Site Scripting (XSS) vulnerabilities in web applications. When XSS is **confirmed** (dynamically verified), it automatically generates Proof-of-Concept (PoC) HTML files.

---

## Features

- **Static Analysis** — Scans JavaScript files for dangerous source-to-sink data flows (innerHTML, eval, document.write, etc.)
- **Dynamic Testing** — Uses Selenium to load pages and inject payloads, confirming real XSS with alert() detection
- **javascript: Protocol Injection** — Detects and tests URL parameters used as navigation targets without protocol filtering
- **postMessage XSS Testing** — Dynamically sends payloads via postMessage to test handlers for XSS
- **Prototype Pollution Detection** — Identifies potential prototype pollution vectors
- **Sensitive Data Exposure** — Finds hardcoded API keys, tokens, and internal URLs in JS files
- **Framework-Specific Scanning** — Angular (bypassSecurityTrust), React (dangerouslySetInnerHTML), jQuery (.html(), .append())
- **PoC Generation** — Generates ready-to-use PoC HTML files **only for confirmed vulnerabilities**
- **Multi-Format Reports** — HTML, JSON, and TXT reports with severity filtering
- **Crawling** — Recursive page crawling to discover and analyze all JavaScript on a target

---

## Requirements

### Python Version
- Python 3.8 or higher

### Required Packages

```
requests
tldextract
jsbeautifier
beautifulsoup4
colorama
```

### Optional (for Dynamic Testing)

```
selenium
```

> **Note:** Dynamic testing (actual XSS confirmation via browser) requires Selenium + Chrome/ChromeDriver. Without it, the tool still performs heuristic detection and full static analysis.

---

## Installation

### 1. Clone or copy the tool

```powershell
cd C:\TFS\Tools\XSS
```

### 2. Install required dependencies

```powershell
pip install requests tldextract jsbeautifier beautifulsoup4 colorama
```

### 3. Install Selenium (recommended, for dynamic XSS confirmation)

```powershell
pip install selenium
```

### 4. Install ChromeDriver

- Download from: https://googlechromelabs.github.io/chrome-for-testing/
- Ensure `chromedriver.exe` is in your system PATH, or in the same directory as the script
- ChromeDriver version must match your installed Chrome browser version

Alternatively, install `webdriver-manager` for automatic driver management:

```powershell
pip install webdriver-manager
```

---

## Usage

### Basic Scan (Single URL)

```powershell
python dom.py -u https://example.com
```

### Scan with PoC Generation

```powershell
python dom.py -u https://example.com --generate-pocs
```

### Scan with Specific URL Parameter Testing

```powershell
python dom.py -u "https://target.com/login.html?loginUrl=" --extra-params loginUrl --generate-pocs -v
```

### Scan Multiple URLs from File

```powershell
python dom.py -l urls.txt --generate-pocs --report-format all
```

### Analyze Local JavaScript Files

```powershell
python dom.py --js-file app.js utils.js
python dom.py --js-file ./js-directory/
```

### Full Scan with All Options

```powershell
python dom.py -u https://target.com --depth 3 --threads 10 --all-origins --generate-pocs --report-format all -v
```

### With Authentication (Cookies/Headers)

```powershell
python dom.py -u https://target.com --cookies "session=abc123; token=xyz" --headers "Authorization: Bearer mytoken"
```

### With Proxy (e.g., Burp Suite)

```powershell
python dom.py -u https://target.com --proxy http://127.0.0.1:8080
```

### Disable Dynamic Testing

```powershell
python dom.py -u https://target.com --no-dynamic
```

### Confirmed XSS Finding
https://github.com/vbharad/DOMXSSScanner/blob/main/Confirmed%20XSS.png

---

## Command-Line Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Target URL to scan |
| `-l, --url-list` | File containing list of URLs (one per line) |
| `--js-file` | Local JavaScript file(s) or directory to analyze |
| `--depth` | Maximum crawl depth (default: 2) |
| `--threads` | Concurrent threads for fetching JS files (default: 5) |
| `--all-origins` | Include JS files from all origins (not just same-origin) |
| `--no-beautify` | Skip JS beautification (faster but less accurate) |
| `--dynamic` | Enable dynamic URL parameter testing (default: enabled) |
| `--no-dynamic` | Disable dynamic URL parameter testing |
| `--extra-params` | Additional URL parameter names to test |
| `--min-severity` | Minimum severity to report: critical, high, medium, low, info |
| `--cookies` | Cookies to send (format: "name1=val1; name2=val2") |
| `--headers` | Custom headers (format: "Header-Name: value") |
| `--proxy` | HTTP/HTTPS proxy (e.g., http://127.0.0.1:8080) |
| `-o, --output-dir` | Output directory for reports/PoCs (default: dom_xss_reports) |
| `--report-format` | Report format(s): json, html, txt, all |
| `--generate-pocs` | Generate PoC HTML files for confirmed findings |
| `-v, --verbose` | Enable verbose/debug output |

---

## How It Works

### Scan Phases

1. **Phase 1: JavaScript Collection**
   - Crawls target pages recursively (up to `--depth`)
   - Collects external JS file URLs and inline `<script>` content
   - Extracts JS from event handler attributes and `javascript:` hrefs

2. **Phase 2: Static Analysis of External JS**
   - Fetches all discovered JS files
   - Beautifies code for accurate line numbers
   - Scans for dangerous sinks (innerHTML, eval, location, jQuery methods, etc.)
   - Traces source-to-sink data flows
   - Calculates confidence based on proximity, variable tracing, and sanitization detection

3. **Phase 3: Static Analysis of Inline Scripts**
   - Same analysis as Phase 2 but on inline `<script>` content

4. **Phase 3.5: Dynamic Testing**
   - **URL Parameter Testing:** Detects URL params, injects `javascript:` protocol payloads, checks for reflection and alert execution
   - **postMessage Testing:** Detects message handlers, sends XSS payloads via `postMessage()`, confirms alert execution
   - Findings are marked as **CONFIRMED** only when alert() actually fires

5. **Phase 4: PoC Generation (Confirmed Only)**
   - Generates tailored PoC HTML files **only** for dynamically confirmed XSS
   - PoCs include test payloads, attack description, and copy-to-clipboard reports

6. **Phase 5: Report Generation**
   - All findings (static + dynamic) appear in the final report
   - Reports available in HTML, JSON, and TXT formats

---

## Output Structure

```
dom_xss_reports/
├── pocs/
│   ├── poc_CONFIRMED_1_javascript_protocol_injection_critical.html
│   ├── poc_CONFIRMED_2_postmessage_xss_critical.html
│   └── ...
├── report_https___target_com_20260429_143000.html
├── report_https___target_com_20260429_143000.json
└── report_https___target_com_20260429_143000.txt
```

---

## Vulnerability Categories Detected

### Critical
- DOM XSS via innerHTML/outerHTML/document.write
- JavaScript execution via eval()/Function()/setTimeout with strings
- javascript: protocol injection via URL parameters
- postMessage XSS (no origin validation + unsafe data handling)
- Angular bypassSecurityTrust*
- Hardcoded cloud credentials (AWS, GitHub, Stripe, etc.)
- iframe srcdoc injection

### High
- jQuery XSS sinks (.html(), .append(), $() with user input)
- URL/attribute manipulation (.src=, .href=, .action=)
- Prototype Pollution vectors
- postMessage handlers without origin checks
- React dangerouslySetInnerHTML
- Client-side template injection

### Medium
- Open Redirect via DOM
- Cookie manipulation
- WebSocket injection
- DOM Clobbering
- Dangerous APIs (createContextualFragment, DOMParser, etc.)

### Low/Info
- Debug information exposure
- Sensitive comments in code

---

## Examples

### Detecting javascript: Protocol XSS (like your loginUrl case)

```powershell
python dom.py -u "https://app.example.com/login.html?isiclogin=false&loginUrl=" --generate-pocs -v
```

The tool will:
1. Detect `loginUrl` as a potential redirect parameter
2. Inject `javascript:alert(1337)` and other payloads
3. If Selenium is available, open the page and confirm if alert fires
4. Generate a PoC HTML file only if confirmed

### Detecting postMessage XSS

```powershell
python dom.py -u "https://app.example.com/dashboard" --generate-pocs
```

The tool will:
1. Load the page in headless Chrome
2. Detect if message event listeners exist
3. Send XSS payloads via `window.postMessage()`
4. If alert fires → confirmed, PoC generated

---

## Limitations

1. **Dynamic testing requires Selenium + Chrome** — Without it, only static analysis and heuristic detection are performed (no confirmed PoCs generated)

2. **Single-page application (SPA) challenges** — Pages that require complex user interaction or authentication flows before revealing vulnerable code may need `--cookies` or manual exploration

3. **Rate limiting** — Aggressive crawling may trigger WAF/rate limits. Use `--proxy` with Burp Suite for throttling

4. **False positives in static analysis** — Source-to-sink tracing is heuristic-based. Not all reported sinks are exploitable. Only `[CONFIRMED]` findings are verified

5. **Client-side rendering** — If JavaScript is loaded dynamically (lazy loading, code splitting), the crawler may not discover all JS files. Increase `--depth` or use `--js-file` for local analysis

6. **CSP/frame-ancestors** — Targets with strict Content Security Policy may block PoC payloads from executing even if the vulnerability exists

7. **Obfuscated/minified code** — While `jsbeautifier` handles most minified code, heavily obfuscated JS (webpack chunks, custom obfuscation) may reduce detection accuracy

8. **Authentication-gated pages** — Use `--cookies` and `--headers` to provide valid session tokens for authenticated scanning

9. **No CSRF token handling** — The tool does not automatically handle CSRF-protected forms

10. **Browser version dependency** — ChromeDriver version must match installed Chrome version exactly

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical or high findings |
| 1 | High severity findings detected |
| 2 | Critical severity findings detected |
| 130 | Scan interrupted by user (Ctrl+C) |

---

## Tips

- Always use `--generate-pocs` to get PoC files for confirmed findings
- Use `-v` (verbose) for debugging when the tool doesn't detect expected issues
- Use `--extra-params paramName` if you know a specific parameter is vulnerable but not in the built-in list
- Combine with Burp Suite: `--proxy http://127.0.0.1:8080` to capture all traffic
- For large applications, scan specific pages rather than the root URL
- Check the HTML report for a visual summary with severity filtering

---

## Disclaimer

This tool is intended for authorized security testing, bug bounty programs, and internal security assessments. Always obtain proper authorization before scanning any target. Unauthorized scanning is illegal and unethical.

---

**Developed by Vishal Bharad**
