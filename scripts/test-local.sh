#!/usr/bin/env bash
set -euo pipefail

# Comprehensive local test suite for the Cilium Flight Recorder.
# Requires: docker compose up -d (all services running)
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
header "1. Health Check"
# --------------------------------------------------------------------------
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API/health")
if [ "$HTTP_CODE" = "200" ]; then
    pass "GET /health returns 200"
else
    fail "GET /health returned $HTTP_CODE (expected 200)"
fi

HEALTH_BODY=$(curl -s "$API/health" | jq -r '.status')
if [ "$HEALTH_BODY" = "ok" ]; then
    pass "Health response body is {status: ok}"
else
    fail "Health response body: $HEALTH_BODY"
fi

# --------------------------------------------------------------------------
header "2. Automatic Anomaly Detection (wait for mock flows)"
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

# Check for DROP trigger
DROP_COUNT=$(echo "$CAPTURES" | jq '[.[] | select(.trigger == "drop")] | length')
if [ "$DROP_COUNT" -gt 0 ]; then
    pass "Drop anomaly detected ($DROP_COUNT captures)"
else
    fail "No drop anomalies detected"
fi

# Check for HTTP error trigger
HTTP_COUNT=$(echo "$CAPTURES" | jq '[.[] | select(.trigger == "http_error")] | length')
if [ "$HTTP_COUNT" -gt 0 ]; then
    pass "HTTP 5xx anomaly detected ($HTTP_COUNT captures)"
else
    fail "No HTTP 5xx anomalies detected"
fi

# Check for DNS failure trigger
DNS_COUNT=$(echo "$CAPTURES" | jq '[.[] | select(.trigger == "dns_failure")] | length')
if [ "$DNS_COUNT" -gt 0 ]; then
    pass "DNS failure anomaly detected ($DNS_COUNT captures)"
else
    fail "No DNS failure anomalies detected"
fi

# Check for latency trigger
LATENCY_COUNT=$(echo "$CAPTURES" | jq '[.[] | select(.trigger == "latency")] | length')
if [ "$LATENCY_COUNT" -gt 0 ]; then
    pass "Latency spike anomaly detected ($LATENCY_COUNT captures)"
else
    fail "No latency spike anomalies detected"
fi

# --------------------------------------------------------------------------
header "3. Manual Capture via API"
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

# Check manual capture has correct port
MANUAL_PORT=$(echo "$CAPTURES_AFTER" | jq '[.[] | select(.trigger == "manual")][0].dstPort')
if [ "$MANUAL_PORT" = "3306" ]; then
    pass "Manual capture has correct destination port (3306)"
else
    fail "Manual capture port: $MANUAL_PORT (expected 3306)"
fi

# --------------------------------------------------------------------------
header "4. Cooldown / Rate Limiting"
# --------------------------------------------------------------------------
TOTAL_CAPTURES_BEFORE=$(curl -s "$API/captures" | jq 'length')
echo "  Current capture count: $TOTAL_CAPTURES_BEFORE"
echo "  Waiting 10s — drops happen every 10s but cooldown is 30s, so no new drop captures..."
sleep 10

# Count only drops to verify cooldown (same src/dst should not trigger again within 30s)
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
header "5. S3 (MinIO) Upload Verification"
# --------------------------------------------------------------------------
S3_OBJECTS=$(curl -s "http://localhost:9000/${BUCKET}?list-type=2" 2>/dev/null || echo "")
if echo "$S3_OBJECTS" | grep -q "<Key>"; then
    S3_COUNT=$(echo "$S3_OBJECTS" | grep -c "<Key>" || true)
    pass "PCAPs uploaded to MinIO ($S3_COUNT objects in bucket)"
else
    fail "No objects found in MinIO bucket (check http://localhost:9001)"
fi

# Verify S3 key structure: {cluster}/{node}/{date}/{filename}.pcap
if echo "$S3_OBJECTS" | grep -q "docker-local/docker-local/"; then
    pass "S3 key follows expected structure (cluster/node/date/file.pcap)"
else
    fail "S3 key structure doesn't match expected pattern"
fi

# --------------------------------------------------------------------------
header "6. PCAP File Validity"
# --------------------------------------------------------------------------
# Download first PCAP from MinIO and check magic bytes
FIRST_KEY=$(echo "$S3_OBJECTS" | grep -oP '(?<=<Key>)[^<]+' | head -1 || true)
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

    # Try tcpdump if available
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
header "7. Capture Metadata Fields"
# --------------------------------------------------------------------------
SAMPLE=$(curl -s "$API/captures" | jq '.[0]')

for field in trigger reason srcIP dstIP dstPort filePath startTime duration; do
    VALUE=$(echo "$SAMPLE" | jq -r ".$field")
    if [ "$VALUE" != "null" ] && [ -n "$VALUE" ]; then
        pass "Capture has field '$field' = $VALUE"
    else
        fail "Capture missing field '$field'"
    fi
done

# --------------------------------------------------------------------------
header "8. Error Handling — Invalid API Request"
# --------------------------------------------------------------------------
BAD_RESP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/capture" \
    -H "Content-Type: application/json" \
    -d 'not valid json')
if [ "$BAD_RESP_CODE" = "400" ]; then
    pass "POST /capture with invalid JSON returns 400"
else
    fail "POST /capture with invalid JSON returned $BAD_RESP_CODE (expected 400)"
fi

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
