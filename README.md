# Lyseis v0.1

> **JavaScript Reconnaissance Tool for Offensive Security Research**

```
         / \__
        (  ^-^)    sniff sniff...
        /|  🔍|\
       (_|_/\_|_)

 ██╗  ██╗   ██╗███████╗███████╗██╗███████╗
 ██║  ╚██╗ ██╔╝██╔════╝██╔════╝██║██╔════╝
 ██║   ╚████╔╝ ███████╗█████╗  ██║███████╗
 ██║    ╚██╔╝  ╚════██║██╔══╝  ██║╚════██║
 ███████╗██║   ███████║███████╗██║███████║
 ╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝╚══════╝
```

⚠ **For authorized security testing and educational purposes only.**

---

## What It Does

Lyseis accepts a target URL, discovers all JavaScript files, analyzes them, and extracts:

| Category | Examples |
|---|---|
| **API keys & tokens** | AWS, Stripe, GitHub, Google, JWT, Twilio, SendGrid, Slack |
| **Hardcoded credentials** | `password = "..."`, `apiKey = "..."` |
| **High-entropy strings** | Keyword-gated Shannon entropy detection |
| **API endpoints** | REST paths, versioned APIs, GraphQL refs |
| **WebSocket URLs** | `ws://` / `wss://` endpoints |
| **Infrastructure leaks** | Internal IPs (RFC 1918), S3/GCS/Azure buckets, sourcemaps |
| **Staging URLs** | `staging.`, `dev.`, `uat.` subdomains |
| **Developer comments** | TODO/FIXME/HACK containing sensitive keywords |
| **Debug flags** | `console.log`, `DEBUG=true`, `process.env.*` |
| **DOM sinks** | `postMessage`, CORS wildcards, feature flag blobs |

---

## Install (Kali Linux / Debian)

```bash
# Clone
git clone https://github.com/yourhandle/lyseis.git
cd lyseis

# Install (editable, in a venv)
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Or just install dependencies
pip install -r requirements.txt
pip install -e .
```

Requires **Python 3.11+**.

---

## Usage

```bash
# Basic scan
lyseis -u https://target.com

# Allow cross-origin JS files too
lyseis -u https://target.com --allow-external

# JSON output to stdout (pipe-friendly)
lyseis -u https://target.com --json

# Save JSON report to file
lyseis -u https://target.com --output report.json

# Silent mode (suppress banner + status, ideal for scripting)
lyseis -u https://target.com --silent --json | jq '.findings[] | select(.severity == "CRITICAL")'

# Verbose debug output
lyseis -u https://target.com -v

# Custom headers / rate limiting
lyseis -u https://target.com --user-agent "Mozilla/5.0" --delay 1.0 --timeout 15
```

---

## All Options

```
  -u, --url URL         Target URL (required)
  --allow-external      Fetch JS from cross-origin domains
  --json                Output findings as JSON to stdout
  --output PATH         Write JSON report to file
  --delay SEC           Delay between requests (default: 0.5)
  --timeout SEC         HTTP request timeout (default: 10)
  --user-agent UA       Custom User-Agent string
  --no-color            Disable ANSI colour output
  --silent              Suppress banner and status messages
  -v, --verbose         Debug logging to stderr
  -h, --help            Show help
```

---

## Example Output

```
  [*] Target :  https://example.com
  [*] Crawling for JavaScript sources...
  [*] Found 6 JS source(s).
  [*] Running analysis engines...
  [*] Analysis complete — 14 unique finding(s).

╭─────────────────── Lyseis — 14 Finding(s) ──────────────────────────────────────╮
│ SEV │ TYPE                  │ VALUE                  │ SOURCE      │ LINE │
├─────┼───────────────────────┼────────────────────────┼─────────────┼──────┤
│ 💀  │ AWS_ACCESS_KEY        │ AKIAIOSFODNN7EXAMPLE   │ app.js      │ 12   │
│ 💀  │ STRIPE_LIVE_KEY       │ sk_live_4eC39Hq...     │ payment.js  │ 3    │
│ 💀  │ GITHUB_TOKEN          │ ghp_16C7e42F292c...    │ app.js      │ 14   │
│ 🔴  │ JWT_TOKEN             │ eyJhbGciOiJIUzI...     │ app.js      │ 16   │
│ 🔴  │ GRAPHQL_REFERENCE     │ IntrospectionQuery     │ graphql.js  │ 22   │
│ 🔴  │ INTERNAL_IP           │ 10.0.0.42              │ config.js   │ 8    │
│ 🔴  │ SOURCEMAP_REF         │ app.chunk.js.map       │ app.js      │ 89   │
│ 🟡  │ API_ENDPOINT          │ /api/v1/users          │ routes.js   │ 45   │
│ 🟡  │ WEBSOCKET_ENDPOINT    │ wss://...              │ ws.js       │ 7    │
│ 🟡  │ S3_BUCKET_URL         │ https://bucket.s3...   │ upload.js   │ 12   │
│ 🟡  │ POST_MESSAGE_SINK     │ addEventListener(...)  │ ui.js       │ 33   │
│ 🔵  │ INTERESTING_COMMENT   │ // FIXME: remove key   │ auth.js     │ 4    │
│ 🔵  │ DEBUG_FLAG            │ console.log(...)       │ app.js      │ 99   │
│ 🔵  │ HIGH_ENTROPY_STRING   │ zXcVbNm...             │ bundle.js   │ 1    │
╰─────────────────────────────────────────────────────────────────────────────────╯

  JS Sources:   6
  💀 CRITICAL:  3   🔴 HIGH: 4   🟡 MEDIUM: 4   🔵 INFO: 3
```

### JSON output (`--json`)

```json
{
  "meta": { "tool": "Lyseis", "version": "0.1.0", "target": "https://example.com" },
  "stats": { "js_sources": 6, "total": 14, "critical": 3, "high": 4, "medium": 4, "info": 3 },
  "findings": [
    {
      "type": "AWS_ACCESS_KEY",
      "value": "AKIAIOSFODNN7EXAMPLE",
      "severity": "CRITICAL",
      "source_url": "https://example.com/static/app.js",
      "source_type": "external",
      "line": 12,
      "context": "const config = {\n    awsKey: \"AKIAIOSFODNN7EXAMPLE\",\n    ..."
    }
  ]
}
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan complete, no HIGH/CRITICAL findings |
| `1` | Fatal error (invalid URL, connection failure) |
| `2` | Scan complete, HIGH or CRITICAL findings present |

This makes Lyseis scriptable:
```bash
lyseis -u https://target.com --silent && echo "Clean" || echo "Findings found"
```

---

## Tests

```bash
pytest tests/ -v
```

---

## Project Structure

```
lyseis/
├── lyseis/
│   ├── cli.py          # Entry point, banner, argparse, pipeline
│   ├── config.py       # Config dataclass
│   ├── models.py       # JSSource, Finding, ScanResult
│   ├── crawler.py      # Fetch HTML, extract + download JS
│   ├── reporter.py     # Terminal (rich) + JSON output
│   ├── utils.py        # Logger (stderr), rate limiter
│   └── analyzer/
│       ├── engine.py   # Analyzer registry + fan-out
│       ├── patterns.py # All compiled regexes
│       ├── secrets.py  # API keys and tokens
│       ├── endpoints.py# Routes, GraphQL, WebSocket
│       ├── entropy.py  # Shannon entropy detection
│       ├── comments.py # Developer comments + debug flags
│       ├── infrared.py # IPs, buckets, sourcemaps
│       └── dom.py      # postMessage, CORS, feature flags
├── tests/
│   ├── fixtures/       # Sample JS files for testing
│   └── unit/           # pytest unit tests
├── requirements.txt
└── pyproject.toml
```

---

## Severity Classification

| Level | Icon | Criteria |
|---|---|---|
| CRITICAL | 💀 | Confirmed secret with known provider pattern (AWS, Stripe, GitHub) |
| HIGH | 🔴 | JWT, entropy+keyword, GraphQL introspection, internal IP, sourcemap, CORS wildcard |
| MEDIUM | 🟡 | API endpoints, WebSocket, cloud storage, staging URL, feature flags |
| INFO | 🔵 | Comments, debug flags, unconfirmed high-entropy strings |

---

## v0.2 Roadmap

- Headless JS execution (Playwright) for SPA support
- Multi-target input (`-l targets.txt`)
- HTTP/SOCKS5 proxy support
- Async fetching (`httpx`)
- AST-based analysis for minified/obfuscated JS
- Authenticated sessions (cookie jar, bearer injection)
