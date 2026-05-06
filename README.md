<div align="center">

```
 ███████╗ ██████╗ ██████╗
 ██╔════╝██╔═══██╗██╔══██╗
 █████╗  ██║   ██║██║  ██║
 ██╔══╝  ██║   ██║██║  ██║
 ███████╗╚██████╔╝██████╔╝
 ╚══════╝ ╚═════╝ ╚═════╝
 Evil Origin Detection
```

*Find the malicious origins of Indicators of Compromise*

[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green?style=flat-square)](https://fastapi.tiangolo.com)
[![Render](https://img.shields.io/badge/Deploy-Render-purple?style=flat-square)](https://render.com)

</div>

---

## What is EOD?

**Evil Origin Detection** is an open-source threat intelligence correlation platform.
Paste an IP, domain, hash, URL or email — EOD queries multiple intelligence sources in parallel, extracts related indicators, computes a risk score, and presents everything in a single analysis view with a correlation graph, activity timeline, and geolocation map.

---

## Features

- **Multiple sources queried in parallel** via `asyncio.gather()`
- **Token rotation** — 2 API keys per source, random selection with fallback
- **24h result cache** in SQLite with rescan button
- **Risk scoring** — weighted composite score 0–100
- **Correlation engine** — 7 heuristics (shared ASN, subnet, malware family, domain-in-URL, tags, PTR)
- **Standalone correlation graph** — `/graph` explorer with multi-IOC loading
- **Related IOC extraction** — normalizes emails, domains, IPs, URLs, hashes, networks and usernames into `related_iocs`
- **Graph pivoting** — expand a related node as a new IOC without leaving the graph
- **Cross-IOC graph correlation** — links loaded IOCs when they share related artifacts
- **Activity timeline** with direct links to source reports
- **Geolocation** via Leaflet.js + ip-api.com (no API key needed)
- **Screenshots** via URLScan.io for URLs and domains
- **Two themes** — Dark cosmos starfield + Light forensic
- **Structured query logging** — origin IP, user-agent, verdict, latency (backend only)

---

## Supported IOC Types

| Prefix | Type | Example |
|--------|------|---------|
| `ip=` | IPv4 / IPv6 | `ip=185.220.101.47` |
| `domain=` | Domain | `domain=evil-update.net` |
| `hash=` | MD5 / SHA1 / SHA256 / SHA512 | `hash=d41d8cd98f00b204e9800998ecf8427e` |
| `url=` | Full URL | `url=https://malicious.site/payload.exe` |
| `mail=` | Email address | `mail=phish@spoofed-domain.com` |
| `red=` | CIDR network | `red=192.168.0.0/24` |

Prefixes are optional — type is auto-detected when omitted.

---

## Intelligence Sources

| Source | Types | Free Tier |
|--------|-------|-----------|
| [VirusTotal](https://virustotal.com) | IP · Domain · Hash · URL | 500 req/day |
| [AbuseIPDB](https://abuseipdb.com) | IP | 1,000 req/day |
| [GreyNoise](https://greynoise.io) | IP | 1,000 req/month |
| [Shodan](https://shodan.io) | IP | 100 req/month |
| [Pulsedive](https://pulsedive.com) | IP · Domain · Hash · URL | 30 req/day |
| [Criminal IP](https://criminalip.io) | IP · Domain · URL | 100 credits/day |
| [MalwareBazaar](https://bazaar.abuse.ch) | Hash | Unlimited · no key |
| [URLScan.io](https://urlscan.io) | URL · Domain | 100 scans/day |
| [SecurityTrails](https://securitytrails.com) | IP · Domain | 50 req/month |
| [StopForumSpam](https://stopforumspam.com) | IP · Email | Unlimited · no key |

---

## Local Development

```bash
git clone https://github.com/starydarkz/EvilOriginDetection
cd EvilOriginDetection

pip install -r requirements.txt

cp .env.example .env
# Edit .env — add your API keys

uvicorn main:app --reload
# → http://localhost:8000
```

---

## Using the Correlation Graph

EOD includes a standalone graph explorer at:

```
/graph
```

You can open it from the home page using **Open Correlation Graph**.

### Analyze directly in the graph

From the home page, type an IOC and click **Analyze in Graph**. This opens:

```
/graph?ioc=185.220.101.47
```

The graph page will auto-load the IOC, call the JSON analyze API, then fetch its graph data.

### Expand related artifacts

When a graph node represents a related IOC, click it and use:

```
Expand artifacts
```

This analyzes that node as a new IOC inside the same graph. If that IOC already existed as a related artifact, the graph adds a dashed correlation edge such as:

```
expanded as IOC: block2.mmms.eu
```

### Cross-IOC correlations

When multiple IOCs are loaded in `/graph`, the frontend compares their related artifacts by:

```
type + normalized label
```

If two loaded IOCs share a domain, hash, email, URL, IP, username or network, the graph adds a dashed correlation edge between the central IOC nodes.

---

## Deploy to Render

### 1. Push to GitHub

```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/starydarkz/EvilOriginDetection
git push -u origin main
```

### 2. Create Web Service on Render

1. Go to [render.com](https://render.com) → **New → Web Service**
2. Connect your GitHub repository
3. Render detects `render.yaml` automatically — settings are pre-configured
4. Click **Create Web Service**

### 3. Set API Keys in Render

Go to your service → **Environment → Environment Variables** and add:

```
VT_KEY_1          your_virustotal_key
VT_KEY_2          your_second_virustotal_key (optional)
ABUSEIPDB_KEY_1   your_abuseipdb_key
GREYNOISE_KEY_1   your_greynoise_key
SHODAN_KEY_1      your_shodan_key
PULSEDIVE_KEY_1   your_pulsedive_key
CRIMINALIP_KEY_1  your_criminalip_key
URLSCAN_KEY_1     your_urlscan_key
SECURITYTRAILS_KEY_1  your_securitytrails_key
```

> **Never commit API keys to git.** The `.gitignore` excludes `.env`.
> All configuration in production is done via Render environment variables only.

### 4. Free Tier Notes

- The service **sleeps after 15 minutes** of inactivity — first request after sleep takes ~30s to wake up
- SQLite database is **ephemeral** — cache resets on each deploy or restart (expected behavior)
- Logs are written to `/tmp/eod.log` on Render

---

## Project Structure

```
EvilOriginDetection/
├── main.py                  # FastAPI app + startup
├── config.py                # Settings from environment variables
├── render.yaml              # Render deployment config
├── requirements.txt
├── .env.example             # API key template (no real values)
├── .gitignore
│
├── app/
│   ├── models.py            # SQLAlchemy ORM (5 tables)
│   ├── database.py          # Async SQLite engine
│   ├── parser.py            # IOC input parser + type detection
│   ├── scoring.py           # Weighted risk score engine
│   ├── correlator.py        # Cross-IOC correlation heuristics
│   ├── ioc_relations.py     # Central related IOC extractor
│   ├── logger.py            # Structured JSON query logging
│   │
│   ├── connectors/          # One connector per intelligence source
│   │   ├── base.py          # Abstract BaseConnector
│   │   ├── virustotal.py
│   │   ├── abuseipdb.py
│   │   ├── greynoise.py
│   │   ├── shodan.py
│   │   ├── pulsedive.py
│   │   ├── criminalip.py
│   │   ├── malwarebazaar.py
│   │   ├── urlscan.py
│   │   ├── securitytrails.py
│   │   ├── stopforumspam.py
│   │   └── whatsmyname.py
│   │
│   └── routers/
│       ├── analyze.py       # POST /analyze · POST /api/analyze
│       └── results.py       # GET /results/{id} · GET /results/{id}/graph · GET /graph
│
├── templates/               # Jinja2 HTML
│   ├── base.html            # Layout, nav, themes, cosmos
│   ├── index.html           # Search page
│   ├── results.html         # Analysis page (7 sections)
│   └── graph.html           # Correlation graph explorer
│
├── static/
│   ├── css/themes.css       # Dark/light CSS variables
│   ├── css/main.css         # All components
│   └── js/                  # theme.js, cosmos.js, app.js, graph.js
│
└── tests/
    ├── test_parser.py
    ├── test_scoring.py
    ├── test_correlator.py
    └── test_connectors.py
```

---

## Routes

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Search page |
| `POST` | `/analyze` | Submit IOC for analysis and redirect to `/results/{id}` |
| `POST` | `/api/analyze` | Submit IOC and return JSON with `ioc_id`, `result_url` and `graph_url` |
| `GET` | `/results/{id}` | Full analysis page |
| `GET` | `/results/{id}/graph` | Graph data (JSON for Cytoscape) |
| `POST` | `/results/{id}/rescan` | Force fresh analysis |
| `GET` | `/graph` | Correlation graph explorer |

---

## API Usage

Analyze an IOC and receive JSON:

```bash
curl -X POST http://localhost:8000/api/analyze \
  -F "ioc_input=185.220.101.47"
```

Example response:

```json
{
  "ioc_id": 1,
  "value": "185.220.101.47",
  "type": "ip",
  "verdict": "malicious",
  "score": 59,
  "result_url": "/results/1",
  "graph_url": "/results/1/graph"
}
```

Fetch graph data:

```bash
curl http://localhost:8000/results/1/graph
```

The graph endpoint returns Cytoscape-compatible JSON:

```json
{
  "nodes": [],
  "edges": [],
  "debug": {
    "ioc": "185.220.101.47",
    "relation_candidates": {}
  }
}
```

---

## Related IOC Extraction

Connector responses are normalized and enriched through:

```
app/ioc_relations.py
```

The extractor reads both:

```
SourceResult.normalized
SourceResult.raw_json
```

and stores extracted artifacts in:

```json
normalized["related_iocs"]
```

Supported related IOC types:

- **IP** — IPv4 / IPv6
- **Domain** — passive DNS, resolutions, contacted domains
- **URL** — URLScan, WhatsMyName and linked indicators
- **Email** — StopForumSpam evidence and associated submissions
- **Hash** — communicating/dropped files and malware artifacts
- **Network** — CIDR ranges
- **Username** — spam usernames and account hits

The graph consumes this unified `related_iocs` JSON to create nodes and edges consistently across APIs.

---

## Adding a New Intelligence Source

1. Create `app/connectors/mysource.py` extending `BaseConnector`
2. Set `SOURCE_NAME`, `SUPPORTED_TYPES`, implement `_fetch()` and `normalize()`
3. Add `MYSOURCE_KEY_1` / `MYSOURCE_KEY_2` to `config.py` and `.env.example`
4. Import and instantiate in `app/routers/analyze.py` → `build_connectors()`
5. Add to `render.yaml` env vars (value set in Render Dashboard)
6. If the source returns linked indicators, add extraction rules in `app/ioc_relations.py`

---

## Running Tests

```bash
pip install pytest pytest-asyncio
pytest tests/ -v
```

---

## Contributing

Open an issue or pull request on [GitHub](https://github.com/starydarkz/EvilOriginDetection).

Future ideas: MISP integration · bulk CSV import · campaign tagging · Docker · PostgreSQL support

---

<div align="center">
<sub>Built for threat analysts. Find the evil.</sub>
</div>
