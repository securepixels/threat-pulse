# Threat Pulse

A threat intelligence feed aggregator that consolidates IP, domain, and file hash lookups across multiple open intel sources into a single SOC-style interface.

## What it does

Search an indicator and Threat Pulse auto-detects the type (IP, domain, or hash) and returns consolidated results from:

- **AbuseIPDB** - IP reputation scoring and abuse report counts
- **AlienVault OTX** - pulse data, community indicators, and tagging
- **VirusTotal** - multi-engine detection ratios

Results include a verdict (malicious, suspicious, clean, unknown), confidence percentage, report count, first/last seen dates, categories, and a per-source breakdown.

The Threat Feed tab shows a timeline of recent threat intelligence items formatted for quick scanning during triage.

## How it works

The layout is built like a SOC monitoring panel:

- **Sidebar** with persistent search, sample indicators, and a running history of every lookup
- **Status bar** tracking live lookup count and malicious hits
- **Data table** for dense, scannable results (click a row to expand full details)
- **Threat Feed** with timestamped intel items and severity tags

Currently runs on demo data with realistic indicators (Tor exit nodes, known C2 domains, EICAR test hashes). The Next.js production build routes API calls through server-side functions to keep keys secure.

## Tech stack

- Next.js (React)
- Supabase (persistent history in production)
- AbuseIPDB, AlienVault OTX, VirusTotal free-tier APIs
- Deployed on Vercel

## Run locally

```bash
git clone https://github.com/securepixels/threat-pulse.git
cd threat-pulse
# Open index.html in your browser, or:
npx serve .
```

