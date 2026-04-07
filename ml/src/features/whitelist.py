"""
Domain allowlist — known-benign registrable domain labels + trusted TLD suffixes.

Two complementary checks
------------------------
1.  Registrable domain label match (frozenset O(1) lookup).
    e.g. "google" matches google.com, mail.google.com, google.co.id, …

2.  Trusted suffix pattern match.
    e.g. suffix "ac.id" matches ANY *.ac.id domain (Indonesian universities),
    "go.id" matches Indonesian government, "edu" matches US universities, etc.
    This covers entire institutional namespaces without listing every institution.

Security note
-------------
Phishing domains like "google.com.evil.xyz" are NOT matched because
tldextract gives domain="evil" for that URL, not "google".
Similarly "fake-ui.ac.id" would match ac.id suffix — but that's acceptable
because registering a fake *.ac.id domain requires going through PANDI
(Indonesia's official registry), which enforces institutional verification.
"""

from __future__ import annotations
from urllib.parse import urlparse

try:
    import tldextract as _tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False


# ---------------------------------------------------------------------------
# Trusted TLD suffixes — entire namespace is trusted
# ---------------------------------------------------------------------------

TRUSTED_SUFFIXES: frozenset[str] = frozenset({
    # ── Indonesia ─────────────────────────────────────────────────────────
    "ac.id",        # universities / academic institutions
    "go.id",        # government agencies
    "sch.id",       # schools (K-12)
    "mil.id",       # military
    "co.id",        # registered Indonesian companies (requires SIUP)
    "net.id",       # ISPs / network operators
    "or.id",        # non-profit organisations
    "web.id",       # personal / general Indonesian web

    # ── Other ASEAN / Asia-Pacific ────────────────────────────────────────
    "go.th",        # Thailand government
    "ac.th",        # Thailand academic
    "go.sg",        # Singapore government
    "edu.sg",       # Singapore education
    "gov.my",       # Malaysia government
    "edu.my",       # Malaysia education
    "go.jp",        # Japan government
    "ac.jp",        # Japan academic
    "go.kr",        # South Korea government
    "ac.kr",        # South Korea academic
    "edu.au",       # Australia education
    "gov.au",       # Australia government
    "ac.nz",        # New Zealand academic
    "govt.nz",      # New Zealand government
    "edu.ph",       # Philippines education
    "gov.ph",       # Philippines government
    "go.vn",        # Vietnam government
    "edu.vn",       # Vietnam education
    "ac.in",        # India academic
    "gov.in",       # India government
    "edu.cn",       # China education

    # ── Europe ────────────────────────────────────────────────────────────
    "ac.uk",        # UK academic
    "gov.uk",       # UK government
    "nhs.uk",       # UK National Health Service
    "ac.be",        # Belgium academic
    "gouv.fr",      # France government
    "gov.de",       # Germany government
    "gov.it",       # Italy government

    # ── Americas ──────────────────────────────────────────────────────────
    "gov.br",       # Brazil government
    "edu.br",       # Brazil education
    "gob.mx",       # Mexico government
    "edu.mx",       # Mexico education
    "gov.co",       # Colombia government
    "gob.ar",       # Argentina government

    # ── Generic gTLDs (entire TLD is institutional) ───────────────────────
    "edu",          # US accredited universities
    "gov",          # US federal government
    "mil",          # US military
    "int",          # International organisations (NATO, WHO, UN, etc.)
})


# ---------------------------------------------------------------------------
# Trusted registrable domain labels — ~1000 most visited global + regional
# ---------------------------------------------------------------------------

TRUSTED_DOMAINS: frozenset[str] = frozenset({

    # ════════════════════════════════════════════════════════════════════════
    # SEARCH ENGINES
    # ════════════════════════════════════════════════════════════════════════
    "google", "bing", "yahoo", "baidu", "yandex", "duckduckgo", "ask",
    "ecosia", "brave", "startpage", "searx", "qwant", "swisscows",
    "naver",        # South Korea
    "coccoc",       # Vietnam

    # ════════════════════════════════════════════════════════════════════════
    # VIDEO / STREAMING
    # ════════════════════════════════════════════════════════════════════════
    "youtube", "netflix", "twitch", "vimeo", "dailymotion", "rumble",
    "hulu", "disneyplus", "primevideo", "hbomax", "paramount", "peacock",
    "appletv", "crunchyroll", "funimation", "animelab",
    "iflix", "vidio", "mola", "rcti", "sctv", "mnctv", "indosiar",
    "wetv", "iqiyi", "bilibili", "youku", "mgtv",
    "viu",          # Southeast Asia streaming
    "hotstar",      # Disney+ Hotstar Asia

    # ════════════════════════════════════════════════════════════════════════
    # SOCIAL MEDIA
    # ════════════════════════════════════════════════════════════════════════
    "facebook", "instagram", "twitter", "x", "threads", "mastodon",
    "linkedin", "tiktok", "snapchat", "pinterest", "tumblr",
    "reddit", "quora", "medium", "substack", "blogger", "wordpress",
    "discord", "telegram", "signal", "viber", "line", "wechat",
    "whatsapp", "messenger", "skype", "slack",
    "vk", "ok",     # Russia social
    "kakao", "band", # South Korea
    "zalo",          # Vietnam
    "clubhouse", "bereal",

    # ════════════════════════════════════════════════════════════════════════
    # MICROSOFT ECOSYSTEM
    # ════════════════════════════════════════════════════════════════════════
    "microsoft", "office", "outlook", "live", "hotmail", "msn",
    "onedrive", "sharepoint", "azure", "xbox", "bing", "skype",
    "teams", "onenote", "visio", "dynamics", "intune",

    # ════════════════════════════════════════════════════════════════════════
    # GOOGLE ECOSYSTEM
    # ════════════════════════════════════════════════════════════════════════
    "google", "gmail", "youtube", "maps", "drive", "docs", "sheets",
    "slides", "forms", "meet", "classroom", "firebase", "flutter",
    "android", "chromebook", "play", "scholar", "translate", "blogger",

    # ════════════════════════════════════════════════════════════════════════
    # APPLE ECOSYSTEM
    # ════════════════════════════════════════════════════════════════════════
    "apple", "icloud", "itunes", "appstore",

    # ════════════════════════════════════════════════════════════════════════
    # AMAZON ECOSYSTEM
    # ════════════════════════════════════════════════════════════════════════
    "amazon", "aws", "twitch", "audible", "goodreads", "imdb",
    "ring", "alexa", "kindle",

    # ════════════════════════════════════════════════════════════════════════
    # DEVELOPER / TECH
    # ════════════════════════════════════════════════════════════════════════
    "github", "gitlab", "bitbucket", "sourceforge", "codeberg",
    "stackoverflow", "stackexchange", "superuser", "askubuntu",
    "serverfault", "mathoverflow", "unix",
    "npmjs", "pypi", "rubygems", "packagist", "nuget", "crates",
    "hex",          # Elixir package registry
    "docker", "hub", "containerd",
    "cloudflare", "fastly", "akamai", "cdn77", "bunny",
    "heroku", "netlify", "vercel", "render", "railway", "fly",
    "digitalocean", "linode", "vultr", "hetzner", "ovh",
    "mozilla", "firefox", "chromium",
    "w3schools", "mdn", "developer",
    "jetbrains", "intellij", "vscode", "code", "atom",
    "kotlin", "swift", "rust", "golang", "nodejs",
    "apache", "nginx", "caddy",
    "linux", "ubuntu", "debian", "fedora", "archlinux", "opensuse",
    "android", "flutter", "reactnative",
    "tensorflow", "pytorch", "huggingface",
    "kaggle", "colab",
    "jsfiddle", "codepen", "replit", "glitch",
    "travis", "circleci", "jenkins",
    "postman", "insomnia",
    "confluence", "jira", "atlassian", "trello", "bitbucket",

    # ════════════════════════════════════════════════════════════════════════
    # CLOUD / PRODUCTIVITY
    # ════════════════════════════════════════════════════════════════════════
    "dropbox", "box", "notion", "airtable",
    "zoom", "webex", "gotomeeting", "whereby",
    "canva", "figma", "miro", "lucidchart", "whimsical",
    "evernote", "todoist", "asana", "monday", "basecamp", "clickup",
    "hubspot", "salesforce", "zendesk", "intercom", "freshdesk",
    "mailchimp", "sendgrid", "twilio", "brevo",
    "typeform", "surveymonkey", "jotform",
    "calendly", "doodle",
    "loom", "screencastify",

    # ════════════════════════════════════════════════════════════════════════
    # NEWS / MEDIA — GLOBAL
    # ════════════════════════════════════════════════════════════════════════
    "bbc", "cnn", "reuters", "apnews", "nytimes", "theguardian",
    "wsj", "bloomberg", "forbes", "businessinsider", "fortune",
    "techcrunch", "theverge", "wired", "arstechnica", "engadget",
    "gizmodo", "mashable", "zdnet", "cnet", "pcmag", "tomsguide",
    "theatlantic", "newyorker", "economist", "time", "newsweek",
    "aljazeera", "dw", "france24", "nhk",
    "foxnews", "nbcnews", "abcnews", "cbsnews", "usatoday",
    "huffpost", "vox", "buzzfeed", "vice",

    # ════════════════════════════════════════════════════════════════════════
    # NEWS / MEDIA — INDONESIA
    # ════════════════════════════════════════════════════════════════════════
    "detik", "kompas", "tribunnews", "liputan6", "okezone",
    "cnnindonesia", "antara", "antaranews", "bisnis", "tempo",
    "republika", "sindonews", "merdeka", "suara", "medcom",
    "jpnn", "rmol", "idntimes", "kumparan", "tirto",
    "grid", "bobo", "hops", "gridoto", "otomotif",
    "wartakota", "poskota", "beritasatu", "viva",
    "cnbcindonesia", "thejakartapost", "jawapos",

    # ════════════════════════════════════════════════════════════════════════
    # REFERENCE / EDUCATION — GLOBAL
    # ════════════════════════════════════════════════════════════════════════
    "wikipedia", "wikimedia", "wikihow", "wikidata", "wiktionary",
    "coursera", "edx", "khanacademy", "udemy", "udacity",
    "duolingo", "babbel", "rosettastone",
    "quizlet", "brainly", "chegg", "studocu",
    "academia", "researchgate", "arxiv", "ssrn",
    "jstor", "springer", "elsevier", "nature", "sciencedirect",
    "pubmed", "ncbi",
    "britannica", "encyclopedia",

    # ════════════════════════════════════════════════════════════════════════
    # EDUCATION — INDONESIA
    # ════════════════════════════════════════════════════════════════════════
    "zenius", "ruangguru", "quipper", "kelase", "kipin",
    "sekolahmu", "pintar",

    # ════════════════════════════════════════════════════════════════════════
    # INDONESIAN UNIVERSITIES (popular registrable labels for *.ac.id)
    # These are also covered by the ac.id suffix rule above, but listed
    # here so they also match on .com / international domains of same inst.
    # ════════════════════════════════════════════════════════════════════════
    "ui", "ugm", "itb", "unair", "its", "undip", "upi", "unpad",
    "ipb", "uny", "unsoed", "unand", "usu", "uho", "unhas",
    "brawijaya", "unej", "unnes", "untirta", "unsri", "unri",
    "pnj", "polban", "pens", "poltekkes",
    "binus", "gunadarma", "mercubuana", "trisakti", "tarumanagara",
    "atmajaya", "unika", "uph", "pelitaharapan",
    "telkomuniversity", "telkom",
    "uad", "umy", "uii", "uinsuka",        # Yogyakarta private unis
    "unesa", "uinsby",                      # Surabaya
    "ums", "uns",                           # Solo/Surakarta
    "uhamka", "unj", "uinjkt",             # Jakarta

    # ════════════════════════════════════════════════════════════════════════
    # INDONESIAN GOVERNMENT (popular labels for *.go.id)
    # Also covered by go.id suffix rule above
    # ════════════════════════════════════════════════════════════════════════
    "kemendikbud", "kemdikbud", "kemdikristek",
    "bps", "kominfo", "kemenkes", "kemenkeu", "kemlu",
    "bpjs", "pajak", "bssn", "bpom", "lapan", "bmkg",
    "kpu", "mahkamahagung", "bpk", "kpk",
    "polri", "tni", "bnpb", "basarnas",
    "kemenag", "kemensos", "kemenaker",

    # ════════════════════════════════════════════════════════════════════════
    # E-COMMERCE — GLOBAL
    # ════════════════════════════════════════════════════════════════════════
    "amazon", "ebay", "etsy", "shopify", "aliexpress", "alibaba",
    "taobao", "jd", "walmart", "target", "bestbuy", "costco",
    "newegg", "bhphotovideo",
    "ikea", "zara", "hm", "uniqlo", "nike", "adidas",
    "asos", "zalando", "farfetch",

    # ════════════════════════════════════════════════════════════════════════
    # E-COMMERCE — INDONESIA / SOUTHEAST ASIA
    # ════════════════════════════════════════════════════════════════════════
    "tokopedia", "shopee", "bukalapak", "blibli", "lazada",
    "traveloka", "tiket", "pegipegi",
    "ralali", "bhinneka", "elevenia",
    "jdid",         # JD.ID Indonesia
    "zalora",       # fashion SEA

    # ════════════════════════════════════════════════════════════════════════
    # RIDE-HAILING / FOOD DELIVERY — INDONESIA
    # ════════════════════════════════════════════════════════════════════════
    "gojek", "grab", "maxim", "indriver",
    "gosend", "lalamove", "sicepat", "jne", "jnt", "tiki",

    # ════════════════════════════════════════════════════════════════════════
    # BANKING / FINANCE — INDONESIA (major state-owned + largest private)
    # Only include banks with large institutional presence; phishing targets
    # like paypal/chase are intentionally excluded
    # ════════════════════════════════════════════════════════════════════════
    "bni", "bri", "mandiri", "bca", "btn",
    "cimb", "panin", "danamon", "permata",
    "ocbc", "maybank", "dbs",
    "ovo", "dana", "gopay", "linkaja", "shopeepay",

    # ════════════════════════════════════════════════════════════════════════
    # FINANCE — GLOBAL (non-phishing-target infrastructure)
    # ════════════════════════════════════════════════════════════════════════
    "stripe", "square", "wise", "revolut", "monzo",
    "coinbase", "binance", "kraken",        # crypto exchanges
    "tradingview", "investing", "marketwatch",
    "xe",           # currency converter
    "bloomberg",

    # ════════════════════════════════════════════════════════════════════════
    # TRAVEL
    # ════════════════════════════════════════════════════════════════════════
    "booking", "airbnb", "tripadvisor", "expedia", "agoda",
    "traveloka", "skyscanner", "kayak", "hotwire", "priceline",
    "marriott", "hilton", "ihg", "accor",
    "delta", "united", "aa", "southwest", "emirates", "singapore",
    "garuda",       # Garuda Indonesia

    # ════════════════════════════════════════════════════════════════════════
    # HEALTH
    # ════════════════════════════════════════════════════════════════════════
    "webmd", "healthline", "mayoclinic", "nih", "who", "cdc",
    "halodoc", "alodokter", "klikdokter",  # Indonesian health platforms

    # ════════════════════════════════════════════════════════════════════════
    # ENTERTAINMENT / GAMING
    # ════════════════════════════════════════════════════════════════════════
    "spotify", "soundcloud", "bandcamp", "deezer", "tidal",
    "apple",        # music.apple.com
    "steam", "epicgames", "origin", "battlenet", "gog",
    "roblox", "minecraft", "fortnite",
    "ign", "gamespot", "polygon", "kotaku",

    # ════════════════════════════════════════════════════════════════════════
    # DOMAIN / HOSTING INFRASTRUCTURE
    # ════════════════════════════════════════════════════════════════════════
    "godaddy", "namecheap", "cloudflare", "hover", "dynadot",
    "hostinger", "bluehost", "siteground", "dreamhost", "kinsta",
    "wpengine", "hostgator",
    "niagahoster", "domainesia", "idwebhost", "jagoanhosting",  # Indonesian

    # ════════════════════════════════════════════════════════════════════════
    # MISCELLANEOUS POPULAR SERVICES
    # ════════════════════════════════════════════════════════════════════════
    "maps",         # maps.google.com, maps.apple.com, etc.
    "translate",    # translate.google.com
    "play",         # play.google.com
    "support",      # support.apple.com, support.microsoft.com
    "paypal",       # included as it is a widely-used payment platform
                    # (phishers impersonate it, but paypal.com itself is legit)
    "patreon", "buymeacoffee",
    "linktree", "beacons",
    "imgur", "flickr", "500px", "unsplash", "pexels", "shutterstock",
    "adobe", "acrobat", "creativecloud",
    "autodesk", "sketchup",
    "surveymonkey", "typeform",
    "archive",      # web.archive.org (Wayback Machine)
    "wolframalpha", "wolfram",
    "weather", "wunderground", "accuweather",
    "pornhub", "xvideos", "xnxx",   # high-traffic; avoid false positives
    "twitch",       # already listed but ensuring dedup is fine in frozenset
    "pastebin", "hastebin", "gist",
    "drive", "onedrive", "icloud", "mega",  # cloud storage
})


# ---------------------------------------------------------------------------
# Lookup function
# ---------------------------------------------------------------------------

def is_whitelisted(url: str) -> bool:
    """
    Return True if the URL's registrable domain OR its TLD suffix is trusted.

    Fast path:  registrable domain label in TRUSTED_DOMAINS  (O(1))
    Slow path:  TLD suffix in TRUSTED_SUFFIXES               (O(1))

    Examples
    --------
    >>> is_whitelisted("https://www.youtube.com/?themeRefresh=1")   # domain
    True
    >>> is_whitelisted("https://sso.ui.ac.id/login")                # suffix ac.id
    True
    >>> is_whitelisted("https://pajak.go.id/laporan")               # suffix go.id
    True
    >>> is_whitelisted("https://paypal-secure.evil.xyz/auth")       # evil → False
    False
    """
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "http://" + url

    if _TLDEXTRACT_AVAILABLE:
        r = _tldextract.extract(url)
        registrable = r.domain.lower()
        suffix      = r.suffix.lower()
    else:
        hostname = (urlparse(url).hostname or "").lower()
        parts = hostname.split(".")
        registrable = parts[-2] if len(parts) >= 2 else hostname
        suffix      = ".".join(parts[-2:]) if len(parts) >= 3 else parts[-1] if parts else ""

    return registrable in TRUSTED_DOMAINS or suffix in TRUSTED_SUFFIXES
