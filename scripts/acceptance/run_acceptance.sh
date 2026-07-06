#!/usr/bin/env bash
set -u

# DNS Relay acceptance helper for Linux/macOS/Git Bash.
# It assumes the DNS Relay program is already running and listening on UDP 53.
# The script records raw nslookup output and a lightweight CSV summary.

LOCAL_DNS="${LOCAL_DNS:-127.0.0.1}"
LOCAL_DNS_PORT="${LOCAL_DNS_PORT:-53}"
UPSTREAM_DNS="${UPSTREAM_DNS:-202.106.0.20}"
LOCAL_HIT_DOMAIN="${LOCAL_HIT_DOMAIN:-www.bupt.com.cn}"
LOCAL_HIT_IP="${LOCAL_HIT_IP:-114.255.40.66}"
BLACKLIST_DOMAIN="${BLACKLIST_DOMAIN:-www.666.com}"
MISS_DOMAIN="${MISS_DOMAIN:-www.baidu.com}"
REPEAT_COUNT="${REPEAT_COUNT:-100}"
OUT_DIR="${OUT_DIR:-evidence/nslookup}"

mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/bash_summary.csv"
RUN_LOG="$OUT_DIR/bash_run.log"

{
  echo "DNS Relay acceptance run"
  echo "date=$(date '+%Y-%m-%d %H:%M:%S %z')"
  echo "local_dns=$LOCAL_DNS"
  echo "local_dns_port=$LOCAL_DNS_PORT"
  echo "upstream_dns=$UPSTREAM_DNS"
  echo "local_hit_domain=$LOCAL_HIT_DOMAIN"
  echo "local_hit_ip=$LOCAL_HIT_IP"
  echo "blacklist_domain=$BLACKLIST_DOMAIN"
  echo "miss_domain=$MISS_DOMAIN"
  echo "repeat_count=$REPEAT_COUNT"
  echo
} > "$RUN_LOG"

echo "case,domain,type,server,iteration,exit_code,elapsed_ms,heuristic" > "$SUMMARY"

run_lookup() {
  local case_id="$1"
  local domain="$2"
  local qtype="$3"
  local server="$4"
  local iteration="$5"
  local outfile="$OUT_DIR/${case_id}_${qtype}_${iteration}.txt"
  local start end elapsed exit_code heuristic

  start=$(date +%s%N 2>/dev/null || date +%s000000000)
  if [ "$server" = "$LOCAL_DNS" ] && [ "$LOCAL_DNS_PORT" != "53" ]; then
    port_arg="-port=$LOCAL_DNS_PORT"
  else
    port_arg=""
  fi

  if [ "$qtype" = "DEFAULT" ]; then
    nslookup $port_arg "$domain" "$server" > "$outfile" 2>&1
  else
    nslookup $port_arg "-type=$qtype" "$domain" "$server" > "$outfile" 2>&1
  fi
  exit_code=$?
  end=$(date +%s%N 2>/dev/null || date +%s000000000)
  elapsed=$(((end - start) / 1000000))

  heuristic="manual_check"
  if [ "$case_id" = "TC02_local_hit" ]; then
    grep -q "$LOCAL_HIT_IP" "$outfile" && heuristic="contains_expected_ip" || heuristic="missing_expected_ip"
  elif [ "$case_id" = "TC03_blacklist" ]; then
    grep -Eiq "NXDOMAIN|Non-existent domain|can't find|not find|不存在|不存在的域" "$outfile" \
      && heuristic="looks_nxdomain_or_not_found" || heuristic="manual_check_blacklist"
  elif [ "$case_id" = "TC04_miss_relay" ] || [ "$case_id" = "TC04_miss_upstream" ]; then
    heuristic="output_saved_manual_compare"
  elif [ "$case_id" = "TC06_type_a" ]; then
    grep -q "$LOCAL_HIT_IP" "$outfile" && heuristic="contains_expected_a_ip" || heuristic="missing_expected_a_ip"
  elif [ "$case_id" = "TC06_type_aaaa" ]; then
    heuristic="aaaa_policy_requires_packet_or_output_review"
  fi

  printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$case_id" "$domain" "$qtype" "$server" "$iteration" "$exit_code" "$elapsed" "$heuristic" >> "$SUMMARY"
}

echo "[1/7] TC-02 local hit A lookup"
run_lookup "TC02_local_hit" "$LOCAL_HIT_DOMAIN" "DEFAULT" "$LOCAL_DNS" "001"

echo "[2/7] TC-03 blacklist lookup"
run_lookup "TC03_blacklist" "$BLACKLIST_DOMAIN" "DEFAULT" "$LOCAL_DNS" "001"

echo "[3/7] TC-04 relay miss lookup via local DNS"
run_lookup "TC04_miss_relay" "$MISS_DOMAIN" "DEFAULT" "$LOCAL_DNS" "001"

echo "[4/7] TC-04 direct upstream comparison"
run_lookup "TC04_miss_upstream" "$MISS_DOMAIN" "DEFAULT" "$UPSTREAM_DNS" "001"

echo "[5/7] TC-06 A and AAAA lookups"
run_lookup "TC06_type_a" "$LOCAL_HIT_DOMAIN" "A" "$LOCAL_DNS" "001"
run_lookup "TC06_type_aaaa" "$LOCAL_HIT_DOMAIN" "AAAA" "$LOCAL_DNS" "001"

echo "[6/7] TC-05 quick mixed sequence"
for domain in "$MISS_DOMAIN" "www.qq.com" "www.sina.com.cn" "$LOCAL_HIT_DOMAIN" "$BLACKLIST_DOMAIN"; do
  safe_name=$(printf '%s' "$domain" | tr -c 'A-Za-z0-9_' '_')
  run_lookup "TC05_mixed_${safe_name}" "$domain" "DEFAULT" "$LOCAL_DNS" "001"
done

echo "[7/7] TC-07 repeated local-hit lookup: $REPEAT_COUNT iterations"
i=1
while [ "$i" -le "$REPEAT_COUNT" ]; do
  iter=$(printf '%03d' "$i")
  run_lookup "TC07_100_loop" "$LOCAL_HIT_DOMAIN" "DEFAULT" "$LOCAL_DNS" "$iter"
  i=$((i + 1))
done

{
  echo
  echo "Output files:"
  echo "- raw nslookup output: $OUT_DIR"
  echo "- summary CSV: $SUMMARY"
  echo
  echo "Important: Wireshark evidence, UDP 53 listener evidence, administrator permissions, and screenshots must be collected manually on the acceptance machine."
} | tee -a "$RUN_LOG"

echo "Done. Review $SUMMARY and the raw files under $OUT_DIR."
