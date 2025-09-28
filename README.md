# recon_subdomains

**`recon_subdomains.sh`** — Passive-first subdomain enumeration & enrichment automation script.
Safe by default (passive only). Active/bruteforce steps are optional and must only be used with explicit permission.

---

## What it does

This script automates collection, normalization, filtering, and basic enrichment of subdomains for a target domain by combining multiple sources:

- Passive sources: `amass (passive)`, `subfinder`, `assetfinder`, `crt.sh`, `waybackurls`, `gau`
- Optional GitHub code search expansion (requires a token)
- Combine, dedupe, wildcard detection
- Resolve candidates (using `dnsx` or fallback `dig`)
- HTTP probing (using `httpx`)
- Optional active bruteforce resolution and takeover checks (`dnsx` bruteforce + `subjack`) when `--active` is specified
- Outputs CSV and JSON summary files

---

## Table of Contents

- [Prerequisites](#prerequisites)  
- [Installation / Tool Setup](#installation--tool-setup)  
- [Usage](#usage)  
- [Options / Flags](#options--flags)  
- [Outputs](#outputs)  
- [How it works (high level)](#how-it-works-high-level)  
- [Examples](#examples)  
- [Troubleshooting & Notes](#troubleshooting--notes)  
- [Legal & Ethics](#legal--ethics)  
- [Possible Improvements](#possible-improvements)

---

## Prerequisites

Recommended (best experience):

- Linux / macOS with Bash
- `curl`, `jq`, `openssl`, `dig`
- Python 3 (for final JSON creation)
- Recommended Go-based tools (optional but strongly recommended):
  - `amass`
  - `subfinder`
  - `assetfinder`
  - `waybackurls`
  - `gau`
  - `dnsx`
  - `httpx`
  - `subjack` (for takeover checks)

> The script will gracefully warn and skip missing tools, but output quality improves with more tools installed.

---

## Installation / Tool Setup

If you have Go installed, run (example):
```bash
# Ensure your PATH includes $GOPATH/bin or $HOME/go/bin
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OWASP/Amass/v3/...@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/haccer/subjack@latest
```

Make the script executable:
```bash
chmod +x recon_subdomains.sh
```

---

## Usage

```bash
./recon_subdomains.sh --target example.com [--active] [--wordlist /path/to/wordlist] [--github-token TOKEN] [--outdir results]
```

### Options / Flags

- `--target` (required) — target domain (e.g., `example.com`)
- `--active` — enable active steps (bruteforce + takeover checks). **Use only with permission**
- `--wordlist` — wordlist path for bruteforce (required if you want bruteforce)
- `--github-token` — GitHub token for limited code search expansion (optional)
- `--outdir` — base output directory (default: `results`)

---

## Outputs

Script creates a work directory at `results/<target>/` and produces:

- `results/<target>/<target>_<timestamp>.csv` — main CSV (subdomain, resolved IP, HTTP status/title, source)
- `results/<target>/<timestamp>.json` — JSON summary
- intermediate files:
  - `amass_passive.txt`, `subfinder.txt`, `assetfinder.txt`, `crtsh.txt`, `waybackurls.txt`, `gau.txt`, `github.txt`
  - `all_candidates.txt`, `combined.txt`, `resolved.txt`, `http_probe.jsonl`
  - optional: `bruteforce_resolved.txt`, `subjack_results.txt`

CSV columns:  
`subdomain, resolved_ips, http_status, http_title, source`

---

## How it works (high level)

1. Run passive collectors and pull outputs into `workdir/`
2. Combine, normalize, and dedupe candidates
3. Detect wildcard DNS (skip or filter wildcard hits)
4. Optionally run active bruteforce using a wordlist (if `--active`)
5. Resolve hostnames (`dnsx` preferred; `dig` fallback)
6. Probe HTTP(S) using `httpx` (status, title, IP)
7. Optionally check for subdomain takeover with `subjack` (if `--active`)
8. Produce CSV + JSON outputs

---

## Examples

**Passive-only (safe, default):**
```bash
./recon_subdomains.sh --target example.com
```

**Active (bruteforce + takeover checks) — use only with permission:**
```bash
./recon_subdomains.sh --target example.com --active --wordlist ~/wordlists/subdomains.txt
```

**With GitHub code search expansion (may be slow / rate-limited):**
```bash
./recon_subdomains.sh --target example.com --github-token ghp_xxx
```

---

## Troubleshooting & Notes

- `command not found` warnings: install the missing tool or proceed; script will skip that source.
- GitHub search: rate-limited; use a token and limit large-scale queries.
- Wildcard DNS: script attempts a basic detection by querying random subdomains. Manually verify suspicious results.
- Slow fallback: if `dnsx`/`httpx` are missing, the fallback (`dig`) is much slower; consider installing `massdns` or `dnsx` for speed.
- For extensive runs, use API keys for enrichment services to reduce scraping/rate-limit issues.

---

## Legal & Ethics

- **Always have explicit permission** before running active scans (bruteforce, takeover checks, or any intrusive activity).
- Passive enumeration is typically low-risk but still check the target program’s rules/TOS.
- Keep API keys and tokens secure (don’t commit them to public repos).
- Use the tool responsibly — this repository is provided for lawful security research and authorized bug bounty testing only.

---

## Possible Improvements

- Track per-host provenance (which tool discovered each host)
- Enrichment via SecurityTrails / VirusTotal / Shodan / Censys (API keys required)
- Post-probing actions: automatically generate `targets.txt` for Burp; run `nuclei` templates on live hosts
- Faster resolution with `massdns`, more robust wildcard detection heuristics
- Web UI or dashboard for team triage and integration with JIRA/Slack

---

## License

Use as you like. No warranty. If you improve it, consider submitting changes or open an issue.

---

If you want, I can:
- add `per-host source` tracking to the CSV,
- add SecurityTrails / VirusTotal enrichment (you provide API keys), or
- convert outputs into Burp `targets.txt`/scope format.

Which would you like next?
