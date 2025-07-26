#!/bin/bash

# Nuclei Blade The Tactical Orchestrator
# Made by DarkLegende
# Optimized for speed and modularity, crafted for elite pentesters

# Configuration
CONFIG_FILE="blade_config.yaml"
OUTPUT_DIR="./nuclei_blade_output"
mkdir -p "$OUTPUT_DIR" >/dev/null 2>&1
LOG_FILE="$OUTPUT_DIR/nuclei_blade.log"
exec 3>>"$LOG_FILE"
echo "[*] Nuclei Blade started at $(date)" >&3

# Banner
echo "========================================"
echo " Nuclei Blade - Tactical Recon Scanner"
echo " Made by DarkLegende"
echo "========================================" >&3

# Ensure dependencies
command -v nuclei >/dev/null 2>&1 || { echo "[-] Nuclei not found. Install it first!" >&3; exit 1; }
command -v parallel >/dev/null 2>&1 || { echo "[-] GNU Parallel not found. Install it first!" >&3; exit 1; }
command -v yara >/dev/null 2>&1 || { echo "[-] YARA not found. Install it first!" >&3; exit 1; }
[ -f "$CONFIG_FILE" ] || { echo "[-] $CONFIG_FILE not found!" >&3; exit 1; }
[ -d "$NUCLEI_TEMPLATES" ] || { echo "[-] Nuclei templates not found at $NUCLEI_TEMPLATES" >&3; exit 1; }

# Load config
mode="${1:-stealth}"
sync_mode="${2:-async}"
config=$(yq e ".modes.$mode" "$CONFIG_FILE" 2>/dev/null)
if [ -z "$config" ]; then
  echo "[-] Invalid mode '$mode'. Using 'stealth'." >&3
  mode="stealth"
  config=$(yq e ".modes.$mode" "$CONFIG_FILE")
fi
tags=$(echo "$config" | yq e '.tags' -r)
severity=$(echo "$config" | yq e '.severity' -r)
rate_limit=$(echo "$config" | yq e '.rate_limit' -r)
concurrency=$(echo "$config" | yq e '.concurrency' -r)
timeout=$(echo "$config" | yq e '.timeout' -r)
noise_filter=$(echo "$config" | yq e '.noise_filter' -r)

# Resource check
cpu_cores=$(nproc 2>/dev/null || echo 1)
mem_total=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 500000)
current_load=$(uptime | awk '{print $10}' | cut -d',' -f1)
if [ "$cpu_cores" -lt 2 ] || [ "$mem_total" -lt 1000000 ]; then
  rate_limit=$((rate_limit / 2))
  concurrency=$((concurrency / 2))
  echo "[*] Low resources detected, scaling down to rate $rate_limit, concurrency $concurrency" >&3
fi

# Lightweight loading screen
loading_animation() {
  local pid=$1
  local frames=("-" "\\" "|" "/")
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r[*] Scanning [%s]" "${frames[i++ % 4]}" >&2
    sleep 0.1
  done
  printf "\r[*] Scan batch completed        \n" >&2
}

scan_file() {
  local file=$1
  local label=$2
  local timestamp=$(date +%s)

  [ -s "$file" ] || { echo "[-] $file ($label) is empty or missing" >&3; return; }

  echo "[*] Scanning $file ($label) in $mode mode" >&3
  split -l "$BATCH_SIZE" "$file" "$OUTPUT_DIR/chunk_${label}_" >/dev/null 2>&1

  export NUCLEI_TEMPLATES OUTPUT_DIR
  find "$OUTPUT_DIR/chunk_${label}_"* -type f | parallel -j "$PARALLEL_JOBS" --no-notice '
    chunk={}
    label='"$label"'
    timestamp='"$timestamp"'
    echo "[*] Processing chunk: $(basename "$chunk")" >&3
    
    nuclei -l "$chunk" \
      -t "$NUCLEI_TEMPLATES" \
      -severity "$severity" \
      -tags "$tags" \
      -timeout '"$timeout"' \
      -rate-limit '"$rate_limit"' \
      -concurrency '"$concurrency"' \
      -retries '"$RETRIES"' \
      -bulk-size '"$BULK_SIZE"' \
      '"${PROXY:+ -proxy \"$PROXY\"}"' \
      '"${ADAPTIVE_RATE:+ -adaptive}"' \
      -silent \
      -no-meta \
      -no-color \
      -disable-update-check \
      -o "$OUTPUT_DIR/${label}_${timestamp}_$(basename "$chunk").txt" &
    
    loading_animation $! &
  '
  wait
}

# Target map
declare -a target_map=(
  "live-ips.txt:IPs"
  "live-paths.txt:Paths"
  "live-targets-idor.txt:IDOR"
  "live-targets-lfi.txt:LFI"
  "live-targets-rfi.txt:RFI"
  "live-targets-xss.txt:XSS"
  "upload.txt:Upload"
  "rce.txt:RCE"
  "sqli.txt:SQLi"
  "ssrf.txt:SSRF"
  "xxe.txt:XXE"
  "adnl_gau_urls.txt:GAU"
  "waymore-urls.txt:Waymore"
  "katana-sliced.txt:Katana"
  "hak_urls.txt:HAK"
  "subdomains.txt:Subs"
  "paths.txt:GeneralPaths"
  "jsfiles.txt:JS"
  "graphql-endpoints.txt:GraphQL"
  "api-endpoints.txt:API"
  "backup-files.txt:Backups"
  "config-files.txt:Configs"
)

# Check for missing files
missing_files=()
for entry in "${target_map[@]}"; do
  IFS=":" read -r file label <<< "$entry"
  [ -f "$file" ] || missing_files+=("$file:$label")
done

if [ ${#missing_files[@]} -gt 0 ]; then
  echo "[-] Missing target files detected!" >&3
  for entry in "${missing_files[@]}"; do
    IFS=":" read -r file label <<< "$entry"
    echo "[-] $file ($label) is missing. Provide the file path or press Enter to skip:" >&2
    read -r new_file
    if [ -n "$new_file" ] && [ -f "$new_file" ]; then
      for i in "${!target_map[@]}"; do
        if [[ "${target_map[$i]}" == "$file:$label" ]]; then
          target_map[$i]="$new_file:$label"
        fi
      done
      echo "[*] Updated $label to use $new_file" >&3
    else
      echo "[*] Skipping $label scan due to missing file" >&3
      for i in "${!target_map[@]}"; do
        if [[ "${target_map[$i]}" == "$file:$label" ]]; then
          unset 'target_map[$i]'
        fi
      done
    fi
  done
fi

# Execute scans
echo "[*] Engaging $mode mode scan..." >&3
for entry in "${target_map[@]}"; do
  [ -z "$entry" ] && continue
  IFS=":" read -r file label <<< "$entry"
  if [ "$sync_mode" = "sync" ]; then
    scan_file "$file" "$label"
  else
    scan_file "$file" "$label" &
  fi
done

# Wait for async jobs
[ "$sync_mode" != "sync" ] && wait

# Post-processing
if [ "$noise_filter" = "true" ]; then
  python3 noise_filter.py "$OUTPUT_DIR"/*.txt
  echo "[*] Noise filtering applied" >&3
fi

python3 blade_summary.py "$OUTPUT_DIR"/*.txt
echo "[*] Summary generated" >&3

yara loot_signature.yar "$OUTPUT_DIR"/*.txt > "$OUTPUT_DIR/loot_report.txt"
echo "[*] Loot scan completed, check $OUTPUT_DIR/loot_report.txt" >&3

# Cleanup
for label in $(echo "${target_map[*]}" | tr ' ' '\n' | cut -d':' -f2 | sort -u); do
  cat "$OUTPUT_DIR/${label}_"*".txt" 2>/dev/null > "$OUTPUT_DIR/${label}_final.txt"
  rm -f "$OUTPUT_DIR/${label}_"*".txt" "$OUTPUT_DIR/chunk_${label}_"* 2>/dev/null
done
find "$OUTPUT_DIR" -type f -empty -delete 2>/dev/null

echo "[*] All scans completed. Results saved to $OUTPUT_DIR" >&3
echo "[*] Stay legendary! - DarkLegende" >&3
exec 3>&-
