#!/usr/bin/env bash
# recon_subdomains.sh
# Passive-first subdomain enumeration + optional active enrichment.
# Usage:
#   ./recon_subdomains.sh --target example.com [--active] [--wordlist /path/to/wordlist] [--github-token TOKEN] [--outdir results]
#
# Defaults:
#  - Passive sources only unless --active provided.
#  - Outputs CSV + JSON in outdir/<target>_*.*
#
set -euo pipefail
IFS=$'\n\t'

usage(){
  cat <<EOF
Usage: $0 --target example.com [--active] [--wordlist wordlist.txt] [--github-token TOKEN] [--outdir results]
Options:
  --target        Target domain (required)
  --active        Enable active steps: bruteforce (dnsx/massdns), takeover checks (subjack)
  --wordlist      Wordlist for bruteforce (required if --active and you want bruteforce)
  --github-token  Optional GitHub token to expand code search (slower, optional)
  --outdir        Output directory (default: results)
  --help
EOF
  exit 1
}

# --------------------
# Parse args
# --------------------
TARGET=""
ACTIVE=false
WORDLIST=""
GITHUB_TOKEN=""
OUTDIR="results"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2;;
    --active) ACTIVE=true; shift;;
    --wordlist) WORDLIST="$2"; shift 2;;
    --github-token) GITHUB_TOKEN="$2"; shift 2;;
    --outdir) OUTDIR="$2"; shift 2;;
    --help) usage;;
    *) echo "Unknown arg: $1"; usage;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "[!] --target is required"
  usage
fi

mkdir -p "$OUTDIR"
WORKDIR="$OUTDIR/$TARGET"
mkdir -p "$WORKDIR"
echo "[*] Workdir: $WORKDIR"

TIMESTAMP=$(date +%s)
OUT_JSON="$WORKDIR/${TARGET}_$TIMESTAMP.json"
OUT_CSV="$WORKDIR/${TARGET}_$TIMESTAMP.csv"
TMP_ALL="$WORKDIR/all_candidates.txt"
TMP_COMBINED="$WORKDIR/combined.txt"

# --------------------
# Helper: check command
# --------------------
check_cmd(){
  if ! command -v "$1" >/dev/null 2>&1 ; then
    echo "[WARN] $1 not found in PATH. Some functionality may be skipped."
    return 1
  fi
  return 0
}

# --------------------
# Passive collectors
# --------------------
echo "[*] Starting passive collection for $TARGET"

# 1) amass passive
if check_cmd amass; then
  echo "[+][amass] running passive..."
  amass enum -passive -d "$TARGET" -o "$WORKDIR/amass_passive.txt" || true
else
  touch "$WORKDIR/amass_passive.txt"
fi

# 2) subfinder
if check_cmd subfinder; then
  echo "[+][subfinder] running..."
  subfinder -d "$TARGET" -silent -o "$WORKDIR/subfinder.txt" || true
else
  touch "$WORKDIR/subfinder.txt"
fi

# 3) assetfinder
if check_cmd assetfinder; then
  echo "[+][assetfinder] running..."
  assetfinder "$TARGET" | tee "$WORKDIR/assetfinder.txt" >/dev/null || true
else
  touch "$WORKDIR/assetfinder.txt"
fi

# 4) crt.sh (public CT)
echo "[+][crt.sh] querying certificate transparency..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
  jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | tr '\r' '\n' | sort -u > "$WORKDIR/crtsh.txt" || true

# 5) waybackurls + gau (archived URLs -> extract hostnames)
if check_cmd waybackurls; then
  echo "[+][waybackurls] running..."
  echo "$TARGET" | waybackurls | awk -F/ '{print $3}' | sed 's/:[0-9]*$//' | sort -u > "$WORKDIR/waybackurls.txt" || true
else
  touch "$WORKDIR/waybackurls.txt"
fi

if check_cmd gau; then
  echo "[+][gau] running..."
  gau --subs "$TARGET" 2>/dev/null | awk -F/ '{print $3}' | sed 's/:[0-9]*$//' | sort -u > "$WORKDIR/gau.txt" || true
else
  touch "$WORKDIR/gau.txt"
fi

# 6) optional GitHub code search (requires token - may be rate-limited)
if [[ -n "$GITHUB_TOKEN" ]]; then
  echo "[+][github] Searching code for references to $TARGET (this may take time)..."
  # simple search for occurrences in file contents; limited results per query
  GH_QUERY="${TARGET} in:file"
  # GitHub search API (search/code) - page through up to 2 pages to avoid complexity
  for page in 1 2; do
    resp=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
      "https://api.github.com/search/code?q=$(printf %s "$GH_QUERY" | jq -sRr @uri)&per_page=100&page=$page")
    echo "$resp" | jq -r '.items[]?.html_url' >> "$WORKDIR/github_urls_raw.txt" || true
  done
  # extract hostnames
  if [[ -f "$WORKDIR/github_urls_raw.txt" ]]; then
    cat "$WORKDIR/github_urls_raw.txt" | sed -E 's|https?://[^/]+/||' | sort -u > "$WORKDIR/github.txt" || true
  else
    touch "$WORKDIR/github.txt"
  fi
else
  touch "$WORKDIR/github.txt"
fi

# --------------------
# Combine results & clean
# --------------------
echo "[*] Combining sources..."
cat "$WORKDIR/"*.txt 2>/dev/null | grep -E "\.$TARGET$" -i || true \
  > "$TMP_ALL" || true

# Extra: include the root domain too
echo "$TARGET" >> "$TMP_ALL"
# normalize and dedupe
cat "$TMP_ALL" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | tr '[:upper:]' '[:lower:]' | sort -u > "$TMP_COMBINED"

echo "[*] Candidates collected: $(wc -l < "$TMP_COMBINED")"

# --------------------
# Wildcard detection
# --------------------
echo "[*] Checking for wildcard DNS (to reduce false positives)..."
R1=$(openssl rand -hex 8)
R2=$(openssl rand -hex 8)
test1="${R1}.${TARGET}"
test2="${R2}.${TARGET}"

RES1=$(dig +short "$test1" | tr '\n' ',' | sed 's/,$//')
RES2=$(dig +short "$test2" | tr '\n' ',' | sed 's/,$//')

WILDCARD=false
if [[ -n "$RES1" && -n "$RES2" && "$RES1" == "$RES2" ]]; then
  echo "[WARN] Wildcard DNS looks enabled (random subdomains resolve to same IPs): $RES1"
  WILDCARD=true
else
  echo "[OK] No obvious wildcard DNS detected."
fi

# --------------------
# Active steps (optional)
# --------------------
if $ACTIVE; then
  echo "[*] ACTIVE mode enabled — bruteforce (if wordlist) and takeover checks may run."
  if [[ -n "$WORDLIST" && -f "$WORDLIST" ]]; then
    if check_cmd dnsx; then
      echo "[+][dnsx] Running bruteforce wordlist..."
      cat "$WORDLIST" | sed "s/\$TARGET/$TARGET/g" | dnsx -a -resp -silent -t 50 -o "$WORKDIR/bruteforce_resolved.txt" || true
    else
      echo "[WARN] dnsx not found — skipping bruteforce resolution."
    fi
  else
    echo "[*] No valid wordlist supplied or file not found — skipping bruteforce step."
  fi
else
  echo "[*] ACTIVE mode disabled (default). To enable add flag --active"
fi

# --------------------
# Append bruteforce results (if any) and dedupe final list
# --------------------
if [[ -f "$WORKDIR/bruteforce_resolved.txt" ]]; then
  cat "$WORKDIR/bruteforce_resolved.txt" >> "$TMP_COMBINED"
fi
sort -u "$TMP_COMBINED" -o "$TMP_COMBINED"

# If wildcard detected, filter candidates that resolve to wildcard IPs (best-effort)
if $WILDCARD ; then
  echo "[*] Filtering results that resolve exactly to wildcard IPs to reduce noise..."
  WILDCARD_IPS="$RES1"
  # keep only entries that either don't resolve or resolve to something different
  touch "$WORKDIR/tmp_filtered.txt"
  while read -r host; do
    ips=$(dig +short "$host" | tr '\n' ',' | sed 's/,$//')
    if [[ -z "$ips" ]]; then
      # unresolved -> keep (might be valid future host)
      echo "$host" >> "$WORKDIR/tmp_filtered.txt"
    else
      if [[ "$ips" != "$WILDCARD_IPS" ]]; then
        echo "$host" >> "$WORKDIR/tmp_filtered.txt"
      fi
    fi
  done < "$TMP_COMBINED"
  mv "$WORKDIR/tmp_filtered.txt" "$TMP_COMBINED"
fi

echo "[*] Final candidates after filtering: $(wc -l < "$TMP_COMBINED")"

# --------------------
# Resolution + HTTP probing
# --------------------
echo "[*] Resolving and probing HTTP(S) with dnsx + httpx (if available)..."

RESOLVED="$WORKDIR/resolved.txt"
HTTP_PROBE="$WORKDIR/http_probe.jsonl"

if check_cmd dnsx; then
  # dnsx accepts list of hosts on stdin
  cat "$TMP_COMBINED" | dnsx -a -resp -silent -o "$RESOLVED" || true
else
  # fallback: try dig per-host (slow)
  echo "[WARN] dnsx not found — falling back to dig for resolution (slow)..."
  > "$RESOLVED"
  while read -r host; do
    ips=$(dig +short "$host" | paste -s -d',' -)
    echo "$host,$ips" >> "$RESOLVED"
  done < "$TMP_COMBINED"
fi

if check_cmd httpx; then
  cat "$RESOLVED" | cut -d',' -f1 | httpx -silent -status-code -title -ip -jsonl > "$HTTP_PROBE" || true
else
  echo "[WARN] httpx not found — skipping HTTP probing."
fi

# --------------------
# Takeover checks (optional)
# --------------------
if $ACTIVE && check_cmd subjack; then
  echo "[*] Running subjack takeover checks..."
  cat "$TMP_COMBINED" | subjack -w - -t 50 -timeout 30 -v -output "$WORKDIR/subjack_results.txt" || true
else
  if $ACTIVE; then
    echo "[*] subjack not found — skipping takeover checks."
  fi
fi

# --------------------
# Scoring & CSV output
# --------------------
echo "[*] Creating CSV and JSON output..."

# Build CSV header
echo "subdomain,resolved_ips,http_status,http_title,source" > "$OUT_CSV"

# We'll try to combine data: prefer httpx JSONL if available, else fall back to dnsx file
if [[ -f "$HTTP_PROBE" && -s "$HTTP_PROBE" ]]; then
  # For each httpx jsonl line, extract fields
  jq -c -r '. | {host: .host, ip: .ips[0]?, status: .status_code?, title: .title?} | @base64' < "$HTTP_PROBE" | while read -r l; do
    json=$(echo "$l" | base64 --decode)
    host=$(echo "$json" | jq -r '.host // ""')
    ip=$(echo "$json" | jq -r '.ip // ""')
    status=$(echo "$json" | jq -r '.status // ""')
    title=$(echo "$json" | jq -r '.title // ""' | tr -d '\n' | sed 's/"/""/g')
    # source - best effort: if host was in crtsh/subfinder etc - mark multiple sources not tracked per-host in this simple script
    echo "\"$host\",\"$ip\",\"$status\",\"$title\",\"aggregated\"" >> "$OUT_CSV"
  done
else
  # fallback: use resolved.txt
  while IFS= read -r line; do
    host=$(echo "$line" | cut -d',' -f1)
    ips=$(echo "$line" | cut -d',' -f2-)
    echo "\"$host\",\"$ips\",\"\",\"\",\"aggregated\"" >> "$OUT_CSV"
  done < "$RESOLVED"
fi

# Create a simple JSON output (list of objects)
python3 - <<PY
import csv, json, sys
csvf = "$OUT_CSV"
outj = []
with open(csvf, newline='', encoding='utf-8') as f:
    r = csv.DictReader(f)
    for row in r:
        outj.append(row)
with open("$OUT_JSON", "w", encoding="utf-8") as o:
    json.dump({"domain":"$TARGET","results": outj}, o, indent=2)
print("[*] JSON saved to $OUT_JSON")
PY

echo "[+] CSV saved to $OUT_CSV"
echo "[+] Done. Workdir: $WORKDIR"

# Quick summary
echo "Summary:"
wc -l "$TMP_COMBINED" "$RESOLVED" || true
if [[ -f "$WORKDIR/subjack_results.txt" ]]; then
  echo "Potential takeovers: $(wc -l < "$WORKDIR/subjack_results.txt")"
fi
