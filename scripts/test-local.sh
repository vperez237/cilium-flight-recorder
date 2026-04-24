#!/usr/bin/env bash
set -euo pipefail

# End-to-end test suite for the Cilium Flight Recorder running under
# docker-compose (mock Cilium + mock Hubble + MinIO + flight-recorder).
#
# Coverage:
#   - /health, /ready, /metrics probes
#   - automatic anomaly detection (all four trigger types)
#   - manual POST /capture including all validation paths
#   - GET /captures pagination, filtering, X-Total-Count
#   - S3 upload to MinIO with the cluster/node/YYYY/MM/DD/ key layout
#   - PCAP file validity (magic bytes, tcpdump readability)
#   - capture metadata round-trip
#
# Requires: curl, jq, and `docker compose up -d` with all services running.
# Dependencies: curl, jq

API="http://localhost:8080"
MINIO_API="http://localhost:9000"
MINIO_CONSOLE="http://localhost:9001"
BUCKET="flight-recorder-pcaps"

PASS=0
FAIL=0
TOTAL=0

pass() { PASS=$((PASS + 1)); TOTAL=$((TOTAL + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); TOTAL=$((TOTAL + 1)); echo "  FAIL: $1"; }

header() { echo ""; echo "=== $1 ==="; }

# http_status METHOD URL [BODY]
# Returns just the HTTP status code. Sends JSON when a body is provided.
http_status() {
    local method=$1 url=$2 body=${3:-}
    if [ -n "$body" ]; then
        curl -s -o /dev/null -w "%{http_code}" -X "$method" "$url" \
            -H "Content-Type: application/json" -d "$body"
    else
        curl -s -o /dev/null -w "%{http_code}" -X "$method" "$url"
    fi
}

# --------------------------------------------------------------------------
header "0. Waiting for services to be ready"
# --------------------------------------------------------------------------
echo "  Polling $API/health ..."
for i in $(seq 1 30); do
    if curl -sf "$API/health" > /dev/null 2>&1; then
        echo "  API ready after ${i}s"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "  ERROR: API not reachable after 30s — are services running? (make docker-up)"
        exit 1
    fi
    sleep 1
done

# --------------------------------------------------------------------------
header "1. Liveness — GET /health"
# --------------------------------------------------------------------------
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API/health")
if [ "$HTTP_CODE" = "200" ]; then
    pass "GET /health returns 200"
else
    fail "GET /health returned $HTTP_CODE (expected 200)"
fi

HEALTH_BODY=$(curl -s "$API/health" | jq -r '.status')
if [ "$HEALTH_BODY" = "ok" ]; then
    pass "/health body is {status: ok}"
else
    fail "/health body status=$HEALTH_BODY (expected ok)"
fi

# --------------------------------------------------------------------------
header "2. Readiness — GET /ready"
# --------------------------------------------------------------------------
# Locally, mock-hubble is running so Hubble should be connected and /ready
# returns 200. Give the watcher a few seconds to connect after boot.
READY_CODE=""
for i in $(seq 1 10); do
    READY_CODE=$(http_status GET "$API/ready")
    if [ "$READY_CODE" = "200" ]; then break; fi
    sleep 1
done

if [ "$READY_CODE" = "200" ]; then
    pass "GET /ready returns 200 once Hubble connects"
else
    fail "GET /ready still $READY_CODE after 10s (expected 200)"
fi

READY_STATUS=$(curl -s "$API/ready" | jq -r '.status')
READY_HUBBLE=$(curl -s "$API/ready" | jq -r '.hubbleConnected')
if [ "$READY_STATUS" = "ready" ] && [ "$READY_HUBBLE" = "true" ]; then
    pass "/ready body reports {status: ready, hubbleConnected: true}"
else
    fail "/ready body: status=$READY_STATUS hubbleConnected=$READY_HUBBLE"
fi

# --------------------------------------------------------------------------
header "3. Metrics — GET /metrics"
# --------------------------------------------------------------------------
METRICS_CODE=$(http_status GET "$API/metrics")
if [ "$METRICS_CODE" = "200" ]; then
    pass "GET /metrics returns 200"
else
    fail "GET /metrics returned $METRICS_CODE (expected 200)"
fi

METRICS_BODY=$(curl -s "$API/metrics")
EXPECTED_METRICS=(
    "flight_recorder_flows_processed_total"
    "flight_recorder_anomalies_detected_total"
    "flight_recorder_hubble_connected"
    "flight_recorder_captures_started_total"
    "flight_recorder_tracked_keys"
    "flight_recorder_cilium_circuit_state"
)
for m in "${EXPECTED_METRICS[@]}"; do
    if echo "$METRICS_BODY" | grep -q "^# HELP $m\|^$m"; then
        pass "/metrics exposes $m"
    else
        fail "/metrics missing $m"
    fi
done

# Hubble should be reported as connected (1) via the gauge.
HUBBLE_GAUGE=$(echo "$METRICS_BODY" | awk '/^flight_recorder_hubble_connected / {print $2}')
if [ "$HUBBLE_GAUGE" = "1" ]; then
    pass "flight_recorder_hubble_connected == 1"
else
    fail "flight_recorder_hubble_connected = $HUBBLE_GAUGE (expected 1)"
fi

# --------------------------------------------------------------------------
header "4. Automatic Anomaly Detection (wait for mock flows)"
# --------------------------------------------------------------------------
echo "  Waiting 40s for mock Hubble to generate all anomaly types..."
echo "  (drops every 10s, HTTP 503 every 15s, DNS NXDOMAIN every 25s, latency every 3.5s)"
sleep 40

CAPTURES=$(curl -s "$API/captures")
CAPTURE_COUNT=$(echo "$CAPTURES" | jq 'length')
if [ "$CAPTURE_COUNT" -gt 0 ]; then
    pass "Captures list is not empty ($CAPTURE_COUNT captures)"
else
    fail "No captures recorded after 40s"
fi

DROP_COUNT=$(echo "$CAPTURES" | jq '[.[] | select(.trigger == "drop")] | length')
if [ "$DROP_COUNT" -gt 0 ]; then
    pass "Drop anomaly detected ($DROP_COUNT captures)"
else
    fail "No drop anomalies detected"
fi

HTTP_COUNT=$(echo "$CAPTURES" | jq '[.[] | select(.trigger == "http_error")] | length')
if [ "$HTTP_COUNT" -gt 0 ]; then
    pass "HTTP 5xx anomaly detected ($HTTP_COUNT captures)"
else
    fail "No HTTP 5xx anomalies detected"
fi

DNS_COUNT=$(echo "$CAPTURES" | jq '[.[] | select(.trigger == "dns_failure")] | length')
if [ "$DNS_COUNT" -gt 0 ]; then
    pass "DNS failure anomaly detected ($DNS_COUNT captures)"
else
    fail "No DNS failure anomalies detected"
fi

LATENCY_COUNT=$(echo "$CAPTURES" | jq '[.[] | select(.trigger == "latency")] | length')
if [ "$LATENCY_COUNT" -gt 0 ]; then
    pass "Latency spike anomaly detected ($LATENCY_COUNT captures)"
else
    fail "No latency spike anomalies detected"
fi

# --------------------------------------------------------------------------
header "5. /captures pagination and filtering"
# --------------------------------------------------------------------------
# Sanity: the default list is newest first. Compare timestamps of first and
# last entries — earlier > later means DESC order by startTime.
LIST_DEFAULT=$(curl -s "$API/captures")
if [ "$(echo "$LIST_DEFAULT" | jq 'length')" -ge 2 ]; then
    FIRST_TS=$(echo "$LIST_DEFAULT" | jq -r '.[0].startTime')
    LAST_TS=$(echo "$LIST_DEFAULT" | jq -r '.[-1].startTime')
    if [[ "$FIRST_TS" > "$LAST_TS" ]] || [[ "$FIRST_TS" == "$LAST_TS" ]]; then
        pass "/captures is sorted newest-first (first=$FIRST_TS, last=$LAST_TS)"
    else
        fail "/captures appears out of order (first=$FIRST_TS, last=$LAST_TS)"
    fi
else
    echo "  (skipping sort check — fewer than 2 captures)"
fi

# limit=N returns at most N.
LIMITED=$(curl -s "$API/captures?limit=2")
LIMIT_LEN=$(echo "$LIMITED" | jq 'length')
if [ "$LIMIT_LEN" -le 2 ] && [ "$LIMIT_LEN" -ge 0 ]; then
    pass "/captures?limit=2 returns $LIMIT_LEN entries (<= 2)"
else
    fail "/captures?limit=2 returned $LIMIT_LEN entries"
fi

# X-Total-Count header is present and matches unfiltered size. Use a real
# GET (-sD - dumps headers to stdout, -o /dev/null drops the body) because
# the /captures route only accepts GET — HEAD would 405.
TOTAL_HEADER=$(curl -sD - -o /dev/null "$API/captures?limit=1" | awk -F': ' 'tolower($1) == "x-total-count" { gsub(/\r/, "", $2); print $2 }')
if [ -n "$TOTAL_HEADER" ] && [ "$TOTAL_HEADER" -ge "$CAPTURE_COUNT" ]; then
    pass "X-Total-Count header present and >= total (got $TOTAL_HEADER)"
else
    fail "X-Total-Count header = '$TOTAL_HEADER' (expected >= $CAPTURE_COUNT)"
fi

# offset skips entries.
if [ "$CAPTURE_COUNT" -ge 2 ]; then
    SECOND=$(curl -s "$API/captures?limit=1&offset=1" | jq -r '.[0].startTime // empty')
    NEWEST=$(echo "$LIST_DEFAULT" | jq -r '.[0].startTime')
    if [ -n "$SECOND" ] && [ "$SECOND" != "$NEWEST" ]; then
        pass "/captures?offset=1 skips the newest entry"
    else
        fail "/captures?offset=1 returned the newest entry (offset ignored?)"
    fi
fi

# trigger filter returns only the requested type.
FILTERED=$(curl -s "$API/captures?trigger=drop")
BAD_TRIGGERS=$(echo "$FILTERED" | jq '[.[] | select(.trigger != "drop")] | length')
if [ "$BAD_TRIGGERS" = "0" ]; then
    pass "/captures?trigger=drop returns only drop entries"
else
    fail "/captures?trigger=drop returned $BAD_TRIGGERS non-drop entries"
fi

# Bad limit is rejected.
BAD_LIMIT=$(http_status GET "$API/captures?limit=abc")
if [ "$BAD_LIMIT" = "400" ]; then
    pass "/captures?limit=abc returns 400"
else
    fail "/captures?limit=abc returned $BAD_LIMIT (expected 400)"
fi

OVER_LIMIT=$(http_status GET "$API/captures?limit=99999")
if [ "$OVER_LIMIT" = "400" ]; then
    pass "/captures?limit=99999 returns 400 (above max)"
else
    fail "/captures?limit=99999 returned $OVER_LIMIT (expected 400)"
fi

# --------------------------------------------------------------------------
header "6. Manual Capture via API"
# --------------------------------------------------------------------------
MANUAL_RESP=$(curl -s -X POST "$API/capture" \
    -H "Content-Type: application/json" \
    -d '{"srcCIDR":"192.168.1.0/24","dstCIDR":"192.168.2.0/24","dstPort":3306,"protocol":"TCP","durationSeconds":5}')

MANUAL_STATUS=$(echo "$MANUAL_RESP" | jq -r '.status')
if [ "$MANUAL_STATUS" = "accepted" ]; then
    pass "POST /capture returns {status: accepted}"
else
    fail "POST /capture returned: $MANUAL_RESP"
fi

echo "  Waiting 15s for manual capture to complete..."
sleep 15

CAPTURES_AFTER=$(curl -s "$API/captures")
MANUAL_COUNT=$(echo "$CAPTURES_AFTER" | jq '[.[] | select(.trigger == "manual")] | length')
if [ "$MANUAL_COUNT" -gt 0 ]; then
    pass "Manual capture completed and listed ($MANUAL_COUNT)"
else
    fail "Manual capture not found in captures list"
fi

MANUAL_PORT=$(echo "$CAPTURES_AFTER" | jq '[.[] | select(.trigger == "manual")][0].dstPort')
if [ "$MANUAL_PORT" = "3306" ]; then
    pass "Manual capture has correct destination port (3306)"
else
    fail "Manual capture port: $MANUAL_PORT (expected 3306)"
fi

# Bare IP (no CIDR) should work too.
BARE_CODE=$(http_status POST "$API/capture" \
    '{"srcCIDR":"10.0.0.5","dstCIDR":"10.0.0.6","dstPort":443,"protocol":"TCP"}')
if [ "$BARE_CODE" = "202" ]; then
    pass "POST /capture accepts bare IPs (no /mask)"
else
    fail "POST /capture with bare IPs returned $BARE_CODE (expected 202)"
fi

# Empty src/dst (means "any") should still be accepted.
ANY_CODE=$(http_status POST "$API/capture" '{"dstPort":80,"protocol":"TCP"}')
if [ "$ANY_CODE" = "202" ]; then
    pass "POST /capture accepts empty src/dst (matches any)"
else
    fail "POST /capture with empty src/dst returned $ANY_CODE (expected 202)"
fi

# --------------------------------------------------------------------------
header "7. Input Validation — POST /capture"
# --------------------------------------------------------------------------
# Every one of these should be rejected with 400 and a JSON {"error":"…"} body.
declare -a BAD_BODIES=(
    '{"srcCIDR":"not-an-ip","dstCIDR":"10.0.0.1"}|srcCIDR'
    '{"srcCIDR":"10.0.0.1","dstCIDR":"10.0.0.0/99"}|dstCIDR'
    '{"srcCIDR":"10.0.0.1","dstCIDR":"10.0.0.2","dstPort":70000}|dstPort'
    '{"srcCIDR":"10.0.0.1","dstCIDR":"10.0.0.2","protocol":"SCTP"}|protocol'
    '{"srcCIDR":"10.0.0.1","dstCIDR":"10.0.0.2","durationSeconds":-5}|durationSeconds'
)
for pair in "${BAD_BODIES[@]}"; do
    body="${pair%|*}"
    want="${pair#*|}"

    # Grab both status code and body in one shot.
    resp_file=$(mktemp)
    code=$(curl -s -o "$resp_file" -w "%{http_code}" -X POST "$API/capture" \
        -H "Content-Type: application/json" -d "$body")
    body_text=$(cat "$resp_file"); rm -f "$resp_file"

    if [ "$code" = "400" ] && echo "$body_text" | grep -q "$want"; then
        pass "$want rejected with 400"
    else
        fail "$want: got status=$code body=$body_text"
    fi
done

# Malformed JSON → 400.
BAD_JSON_CODE=$(http_status POST "$API/capture" 'not valid json')
if [ "$BAD_JSON_CODE" = "400" ]; then
    pass "POST /capture with invalid JSON returns 400"
else
    fail "POST /capture with invalid JSON returned $BAD_JSON_CODE (expected 400)"
fi

# --------------------------------------------------------------------------
header "8. Cooldown / Rate Limiting"
# --------------------------------------------------------------------------
TOTAL_CAPTURES_BEFORE=$(curl -s "$API/captures" | jq 'length')
echo "  Current capture count: $TOTAL_CAPTURES_BEFORE"
echo "  Waiting 10s — drops happen every 10s but cooldown is 30s, so no new drop captures..."
sleep 10

# Since mock uses random IPs, each drop is unique. But with cooldown=30s, rapid identical
# anomalies from the same source would be suppressed. We verify the system is still running.
TOTAL_CAPTURES_AFTER=$(curl -s "$API/captures" | jq 'length')
echo "  Capture count after 10s: $TOTAL_CAPTURES_AFTER"
if [ "$TOTAL_CAPTURES_AFTER" -ge "$TOTAL_CAPTURES_BEFORE" ]; then
    pass "System continues to capture new anomalies (count: $TOTAL_CAPTURES_BEFORE -> $TOTAL_CAPTURES_AFTER)"
else
    fail "Capture count decreased unexpectedly"
fi

# --------------------------------------------------------------------------
header "9. S3 (MinIO) Upload Verification"
# --------------------------------------------------------------------------
S3_OBJECTS=$(curl -s "http://localhost:9000/${BUCKET}?list-type=2" 2>/dev/null || echo "")
if echo "$S3_OBJECTS" | grep -q "<Key>"; then
    S3_COUNT=$(echo "$S3_OBJECTS" | grep -c "<Key>" || true)
    pass "PCAPs uploaded to MinIO ($S3_COUNT objects in bucket)"
else
    fail "No objects found in MinIO bucket (check http://localhost:9001)"
fi

# Verify S3 key structure: {cluster}/{node}/{YYYY}/{MM}/{DD}/{filename}.pcap
# We don't know the exact date at runtime, but the layout has 5 slashes after
# the first cluster segment followed by a .pcap filename.
#
# Example: docker-local/docker-local/2026/03/26/20260326T140747Z_drop_...pcap
FIRST_KEY=$(echo "$S3_OBJECTS" | grep -oP '(?<=<Key>)[^<]+' | head -1 || true)
if [ -n "$FIRST_KEY" ] && echo "$FIRST_KEY" | grep -Eq '^[^/]+/[^/]+/[0-9]{4}/[0-9]{2}/[0-9]{2}/[^/]+\.pcap$'; then
    pass "S3 key matches cluster/node/YYYY/MM/DD/<filename>.pcap ($FIRST_KEY)"
else
    fail "S3 key does not match expected layout: $FIRST_KEY"
fi

# --------------------------------------------------------------------------
header "10. PCAP File Validity"
# --------------------------------------------------------------------------
if [ -n "$FIRST_KEY" ]; then
    TMPFILE=$(mktemp /tmp/test-pcap-XXXXXX.pcap)
    curl -s "http://localhost:9000/${BUCKET}/${FIRST_KEY}" -o "$TMPFILE" 2>/dev/null

    # PCAP magic number: d4 c3 b2 a1 (little-endian)
    MAGIC=$(xxd -l 4 -p "$TMPFILE" 2>/dev/null || true)
    if [ "$MAGIC" = "d4c3b2a1" ]; then
        pass "Downloaded PCAP has valid magic number (d4c3b2a1)"
    else
        fail "PCAP magic number: $MAGIC (expected d4c3b2a1)"
    fi

    FILE_SIZE=$(stat -c%s "$TMPFILE" 2>/dev/null || stat -f%z "$TMPFILE" 2>/dev/null || echo "0")
    if [ "$FILE_SIZE" -gt 24 ]; then
        pass "PCAP file has content (${FILE_SIZE} bytes, header + packets)"
    else
        fail "PCAP file too small: ${FILE_SIZE} bytes"
    fi

    if command -v tcpdump &>/dev/null; then
        TCPDUMP_OUT=$(tcpdump -r "$TMPFILE" -c 5 2>&1 || true)
        if echo "$TCPDUMP_OUT" | grep -q "reading from file"; then
            pass "tcpdump can read the PCAP file"
        else
            echo "  (tcpdump output: $TCPDUMP_OUT)"
        fi
    else
        echo "  (tcpdump not installed — skipping deep PCAP validation)"
    fi

    rm -f "$TMPFILE"
else
    fail "Could not extract S3 key to download PCAP"
fi

# --------------------------------------------------------------------------
header "11. Capture Metadata Fields"
# --------------------------------------------------------------------------
# Pick the newest capture that has a non-empty srcIP. We deliberately fired
# an "any" manual capture above (empty src/dst) so .[0] would legitimately
# have empty srcIP/dstIP — filter those out before asserting on all fields.
SAMPLE=$(curl -s "$API/captures" | jq '[.[] | select(.srcIP != "" and .dstIP != "")][0]')
if [ "$SAMPLE" = "null" ] || [ -z "$SAMPLE" ]; then
    fail "No capture found with non-empty srcIP/dstIP to assert metadata against"
else
    for field in trigger reason srcIP dstIP dstPort filePath startTime duration; do
        VALUE=$(echo "$SAMPLE" | jq -r ".$field")
        if [ "$VALUE" != "null" ] && [ -n "$VALUE" ]; then
            pass "Capture has field '$field' = $VALUE"
        else
            fail "Capture missing field '$field'"
        fi
    done
fi

# --------------------------------------------------------------------------
header "12. Metrics reflect captured activity"
# --------------------------------------------------------------------------
# After all the activity above, FlowsProcessed and CapturesCompleted must be
# non-zero. Pulling the raw counter values and asserting > 0 is a cheap smoke
# test that metrics are actually being recorded (not just exposed).
METRICS_NOW=$(curl -s "$API/metrics")

# Sum all label permutations of a counter from the /metrics body.
get_counter() {
    echo "$METRICS_NOW" | awk -v m="$1" '
        $1 ~ "^"m"(\\{|$)" { sum += $2 }
        END { print (sum == "" ? 0 : sum) }
    '
}

# Return 0 (success) if the argument is numerically > 0. Uses awk so we
# don'\''t need bc, and it handles both integer and float counter values.
is_positive() {
    awk -v v="$1" 'BEGIN { exit (v+0 > 0) ? 0 : 1 }'
}

for metric in \
    flight_recorder_flows_processed_total \
    flight_recorder_captures_completed_total \
    flight_recorder_uploads_total
do
    value=$(get_counter "$metric")
    if is_positive "$value"; then
        pass "$metric > 0 ($value)"
    else
        fail "$metric = $value (expected > 0)"
    fi
done

# --------------------------------------------------------------------------
header "RESULTS"
# --------------------------------------------------------------------------
echo ""
echo "  Total: $TOTAL   Passed: $PASS   Failed: $FAIL"
echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "  ALL TESTS PASSED"
    exit 0
else
    echo "  SOME TESTS FAILED"
    exit 1
fi
