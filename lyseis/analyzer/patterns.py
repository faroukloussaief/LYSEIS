"""
lyseis.analyzer.patterns
~~~~~~~~~~~~~~~~~~~~~~~~
Single source of truth for ALL compiled regular expressions.
Grouped by domain. Import from here only — never define re.compile() elsewhere.

v0.1-r2: Extended with DOM sinks, additional secrets, SSR hydration,
         infra patterns, storage leaks, minification detection.
"""

import re

# ======================================================================= #
# SECRETS — API keys, tokens, hardcoded credentials
# ======================================================================= #

# AWS
AWS_ACCESS_KEY = re.compile(r'\b(AKIA[0-9A-Z]{16})\b')
AWS_SECRET_KEY = re.compile(
    r'(?i)(aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key)\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']'
)

# Stripe
STRIPE_LIVE_KEY       = re.compile(r'\bsk_live_[0-9a-zA-Z]{24,}\b')
STRIPE_TEST_KEY       = re.compile(r'\bsk_test_[0-9a-zA-Z]{24,}\b')
STRIPE_RESTRICTED_KEY = re.compile(r'\brk_live_[0-9a-zA-Z]{24,}\b')

# GitHub
GITHUB_TOKEN = re.compile(
    r'\b(ghp_[0-9a-zA-Z]{36}'           # classic PAT
    r'|github_pat_[0-9a-zA-Z_]{82}'     # fine-grained PAT
    r'|gho_[0-9a-zA-Z]{36}'             # OAuth token
    r'|ghs_[0-9a-zA-Z]{36}'             # installation token
    r')\b'
)

# Google / Firebase — same prefix; Firebase config is a separate block pattern
GOOGLE_API_KEY = re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b')

# Firebase initialisation config block (multi-field object)
FIREBASE_CONFIG = re.compile(
    r'(?i)(?:firebaseConfig|initializeApp)\s*[=(,]\s*\{'
    r'[^}]{30,600}'
    r'\}',
    re.MULTILINE | re.DOTALL,
)

# JSON Web Token
JWT_TOKEN = re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b')

# SendGrid
SENDGRID_KEY = re.compile(r'\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b')

# Slack
SLACK_TOKEN = re.compile(r'\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b')

# Twilio
TWILIO_KEY = re.compile(r'\bSK[0-9a-fA-F]{32}\b')

# Mailgun
MAILGUN_KEY = re.compile(r'\bkey-[0-9a-zA-Z]{32}\b')

# Sentry DSN
SENTRY_DSN = re.compile(
    r'https://[a-f0-9]{32}@o\d+\.ingest(?:\.us|\.eu)?\.sentry\.io/\d+'
)

# Mapbox
MAPBOX_TOKEN = re.compile(r'\bpk\.[A-Za-z0-9]{60,}\b')

# NPM
NPM_TOKEN = re.compile(r'\bnpm_[A-Za-z0-9]{36}\b')

# Square
SQUARE_TOKEN = re.compile(r'\bsq0[a-z]{3}-[A-Za-z0-9]{22,43}\b')

# Discord bot token
DISCORD_TOKEN = re.compile(
    r'\b[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b'
)

# Telegram bot token
TELEGRAM_TOKEN = re.compile(r'\b\d{8,11}:[A-Za-z0-9_-]{35}\b')

# Shopify
SHOPIFY_TOKEN = re.compile(r'\bshpat_[A-Za-z0-9]{32}\b')

# HuggingFace
HUGGINGFACE_TOKEN = re.compile(r'\bhf_[A-Za-z0-9]{34}\b')

# PEM private key block (critical — most severe credential type)
PEM_PRIVATE_KEY = re.compile(
    r'-----BEGIN\s(?:RSA|EC|DSA|OPENSSH|ENCRYPTED\s)?PRIVATE\sKEY-----'
    r'[\s\S]{40,3000}'
    r'-----END\s(?:RSA|EC|DSA|OPENSSH|ENCRYPTED\s)?PRIVATE\sKEY-----',
    re.MULTILINE,
)

# Database/broker connection strings (contain credentials)
DB_CONNECTION_STRING = re.compile(
    r'(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp(?:s)?|mssql)'
    r'://[A-Za-z0-9_\-\.%]+:[^@\s"\'`<>]{3,100}@[^\s"\'`<>]{4,100}'
)

# SMTP connection strings
SMTP_CONNECTION = re.compile(
    r'smtps?://[A-Za-z0-9_%\-\.]+:[^@\s"\'`<>]{3,100}@[^\s"\'`<>]{4,100}'
)

# WebRTC TURN / STUN server credentials
TURN_CREDENTIAL = re.compile(
    r'(?i)(?:credential|password)\s*:\s*["\']([^"\']{6,64})["\']'
    r'(?=[^}]{0,300}(?:turn:|stun:))'
)

# Generic API key / secret assignment (captures the value)
GENERIC_API_KEY = re.compile(
    r'(?i)(api[_\-]?key|apikey|api[_\-]?secret|access[_\-]?token|auth[_\-]?token'
    r'|secret[_\-]?key|client[_\-]?secret)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{16,128})["\']'
)

# Hardcoded credential variable assignment
HARDCODED_CRED = re.compile(
    r'(?i)\b(password|passwd|pwd|secret|credential|api_key|apikey)'
    r'\s*[=:]\s*["\']([^"\']{12,128})["\']'  # min 12 chars to reduce FPs
)

# ======================================================================= #
# ENDPOINTS — routes, APIs, protocols
# ======================================================================= #

REST_PATH = re.compile(
    r'''(?x)
    ["'`]
    (
      /(?:api|v\d+|rest|graphql|service|backend|admin|auth|oauth|internal|
         user|account|pay(?:ment)?|webhook|token|upload|download|public|private|
         health|status|search|data|resource|rpc|endpoint|management|portal|
         dashboard|config|settings|profile|login|register|logout|refresh|debug)
      [^\s"'`<>{}]{0,200}
    )
    ["'`]
    '''
)

VERSIONED_API = re.compile(r'["\'`](/v?\d+/[^\s"\'`<>]{4,150})["\']')

GRAPHQL_REF = re.compile(
    r'(?i)\b(graphql|__schema|IntrospectionQuery|gql\s*`|query\s+\w+\s*\{)',
    re.MULTILINE,
)

WEBSOCKET_URL = re.compile(r'\bwss?://[^\s"\'`<>\{\}]{4,200}')

# ======================================================================= #
# DOM SINKS — XSS, code execution, open redirect
# ======================================================================= #

# eval() and new Function() — direct code execution
EVAL_SINK = re.compile(r'\beval\s*\(')
NEW_FUNCTION_SINK = re.compile(r'\bnew\s+Function\s*\(')

# document.write / writeln — potential DOM XSS
DOCUMENT_WRITE_SINK = re.compile(r'\bdocument\.write(?:ln)?\s*\(')

# innerHTML / outerHTML assignment — most common DOM XSS sink
INNER_HTML_SINK = re.compile(r'\.innerHTML\s*=(?!=)')
OUTER_HTML_SINK = re.compile(r'\.outerHTML\s*=(?!=)')

# insertAdjacentHTML — equivalent to innerHTML
INSERT_ADJACENT_HTML = re.compile(r'\.insertAdjacentHTML\s*\(')

# setTimeout / setInterval with a string argument (not a function ref)
SETTIMEOUT_STRING  = re.compile(r'\bsetTimeout\s*\(\s*(?:["\']|`)')
SETINTERVAL_STRING = re.compile(r'\bsetInterval\s*\(\s*(?:["\']|`)')

# Open redirect sinks
OPEN_REDIRECT = re.compile(
    r'(?i)('
    r'window\.location(?:\.href)?\s*=(?!=)'
    r'|location\.replace\s*\('
    r'|location\.assign\s*\('
    r')'
)

# document.domain reassignment (privilege escalation)
DOCUMENT_DOMAIN = re.compile(r'\bdocument\.domain\s*=(?!=)')

# atob() call — base64 decode, may reveal a hidden secret
ATOB_CALL = re.compile(r'\batob\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\']')

# ======================================================================= #
# STORAGE — insecure credential storage
# ======================================================================= #

# localStorage / sessionStorage storing credential-like keys
STORAGE_CREDS = re.compile(
    r'(?i)(localStorage|sessionStorage)\.setItem\s*\(\s*'
    r'["\'](?:token|jwt|auth|password|secret|key|credential|session|access_token)["\']'
)

# document.cookie assignment (check for missing Secure/HttpOnly flags)
COOKIE_SET = re.compile(r'document\.cookie\s*=(?!=)')

# ======================================================================= #
# SERVER-SIDE RENDERING LEAKS
# ======================================================================= #

# SSR hydration blobs (Next.js, Nuxt, Redux, Angular Universal, etc.)
SSR_HYDRATION = re.compile(
    r'window\.__('
    r'NEXT_DATA__'
    r'|PRELOADED_STATE__'
    r'|INITIAL_STATE__'
    r'|NUXT__'
    r'|REDUX_STATE__'
    r'|APP_STATE__'
    r'|APOLLO_STATE__'
    r'|SERVER_DATA__'
    r')\s*='
)

# ======================================================================= #
# JSONP — callback injection
# ======================================================================= #

JSONP_CALLBACK = re.compile(
    r'(?i)('
    r'[?&]callback\s*='
    r'|[?&]jsonp\s*='
    r'|document\.createElement\s*\(\s*["\']script["\']'
    r')'
)

# ======================================================================= #
# INFRASTRUCTURE — internal addresses, cloud storage, source maps
# ======================================================================= #

# RFC 1918 private IP addresses
INTERNAL_IP = re.compile(
    r'\b('
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3}'
    r')\b'
)

# Loopback / localhost
LOCALHOST_URL = re.compile(
    r'https?://(localhost|127\.0\.0\.1)(:\d{1,5})?[^\s"\'`<>{}\[\]]{0,150}'
)

# Non-standard ports in URLs (internal services, debug servers)
NON_STANDARD_PORT = re.compile(
    r'https?://[^\s"\'`<>{}\[\]]{3,80}'
    r':(8080|8443|8888|9000|9090|9092|9200|9300|3000|3001|4000|4200|5000|5001|5432|6379|27017|6443|8001|8081|8000)'
    r'[^\s"\'`<>{}\[\]]{0,100}'
)

# AWS IMDSv1 / IMDSv2 — cloud metadata SSRF
CLOUD_METADATA = re.compile(r'\b169\.254\.169\.254\b')

# Node.js inspector port (9229) — remote code execution if exposed
NODE_DEBUGGER = re.compile(r'(localhost|127\.0\.0\.1):9229')

# Amazon S3 buckets
S3_BUCKET = re.compile(
    r'https?://[a-zA-Z0-9][a-zA-Z0-9\-\.]{1,61}[a-zA-Z0-9]'
    r'\.s3(?:\.[a-zA-Z0-9\-]+)?\.amazonaws\.com[^\s"\'`<>\{\}]{0,200}'
)

# Google Cloud Storage
GCS_BUCKET = re.compile(r'https?://storage\.googleapis\.com/[^\s"\'`<>\{\}]{4,200}')

# Azure Blob Storage
AZURE_BLOB = re.compile(
    r'https?://[a-zA-Z0-9\-]{3,24}\.blob\.core\.windows\.net/[^\s"\'`<>\{\}]{4,200}'
)

# Source map references
SOURCEMAP = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*([^\s\r\n]+)')

# Staging / development hostnames
STAGING_SUBDOMAIN = re.compile(
    r'https?://(staging|dev|test|uat|qa|preprod|sandbox)\.[^\s"\'`<>\{\}]{6,200}'
)

# ======================================================================= #
# DOM / CLIENT-SIDE — original patterns
# ======================================================================= #

POST_MESSAGE = re.compile(
    r'(?i)(window\.addEventListener\s*\(\s*["\']message["\']|\.postMessage\s*\()',
    re.MULTILINE,
)

CORS_WILDCARD = re.compile(
    r'(?i)(allowedOrigins|corsOrigins|Access-Control-Allow-Origin)\s*[=:]\s*["\']?\*["\']?'
)

FEATURE_FLAG = re.compile(
    r'(?i)(featureFlag|feature_flags?|enabledFeatures?|featureToggles?)\s*[=:]\s*\{[^}]{10,800}\}',
    re.MULTILINE,
)

# ======================================================================= #
# COMMENTS — interesting developer notes
# ======================================================================= #

INTERESTING_COMMENT = re.compile(
    r'(?:'
    r'//[^\r\n]*\b(?:todo|fixme|hack|bug|password|secret|key|credential|token|'
    r'admin|debug|internal|remove|staging|temp|bypass|backdoor|hardcoded|vuln|'
    r'broken|insecure|unsafe|deprecated|disable|disable[_-]?auth)\b[^\r\n]*'
    r'|/\*[\s\S]{0,5000}?\b(?:todo|fixme|hack|bug|password|secret|key|credential|token|'
    r'admin|debug|internal|remove|staging|temp|bypass|backdoor|hardcoded|vuln|'
    r'broken|insecure|unsafe|deprecated|disable|disable[_-]?auth)\b[\s\S]{0,5000}?\*/'
    r')',
    re.IGNORECASE,
)

# Debug flags — keyword-gated console.log (reduces FP flood)
DEBUG_FLAG = re.compile(
    r'(?i)\b('
    r'__DEV__'
    r'|DEBUG\s*[=:]\s*true'
    r'|process\.env\.[A-Z][A-Z0-9_]{2,}'
    r'|debugMode\s*[=:]\s*true'
    r'|verbose\s*[=:]\s*true'
    r'|import\.meta\.env\.[A-Z][A-Z_0-9]{2,}'  # Vite env vars
    r')\b'
)

# console.log ONLY when a credential keyword is in the same call
CONSOLE_CREDENTIAL_LEAK = re.compile(
    r'(?i)console\.\w+\s*\([^)]*\b(token|password|secret|key|auth|api_?key|jwt|credential)[^)]*\)'
)

# ======================================================================= #
# ENTROPY — high-entropy string detection
# ======================================================================= #

LONG_STRING = re.compile(r'["\'`]([A-Za-z0-9+/=_\-\.]{20,500})["\']')

ENTROPY_CONTEXT_KEYWORDS = re.compile(
    r'(?i)\b(key|token|secret|password|auth|api|credential|pass|signature|cert|hash|seed|private)\b'
)

# Base64 data URI — exclude from entropy analysis (images/fonts, not secrets)
DATA_URI_PREFIX = re.compile(r'^data:[a-zA-Z]+/[a-zA-Z0-9+\-]+;base64,', re.IGNORECASE)

# ======================================================================= #
# MINIFICATION DETECTION
# ======================================================================= #

# A line longer than 500 chars is a strong minification indicator
MINIFIED_LINE_THRESHOLD = 500
