#!/bin/bash

# ANSI color codes
RED='\033[91m'
GREEN='\033[92m'
RESET='\033[0m'

# ASCII art banner
echo -e "${RED}"
echo -e "${RESET}"

# Ensure required tools are installed
REQUIRED_TOOLS=("gau" "waybackurls" "uro" "httpx" "nuclei" "xsstrike" "dalfox")
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        echo -e "${RED}[ERROR] $tool is not installed. Please install it and try again.${RESET}"
        exit 1
    fi
done

# Check if URL argument is provided
if [ -z "$1" ]; then
    echo -e "${RED}[ERROR] Please provide a target URL as an argument.${RESET}"
    echo -e "${RED}[USAGE] $0 <target_url>${RESET}"
    exit 1
fi

TARGET_URL="$1"

# Remove protocols (http/https) if present
TARGET=$(echo "$TARGET_URL" | sed 's|https\?://||g')

# Create temporary files
GAU_FILE=$(mktemp)
WAYBACK_FILE=$(mktemp)
FILTERED_URLS_FILE="filtered_urls.txt"
NUCLEI_RESULTS="nuclei_results.txt"
XSSTRIKE_RESULTS="xsstrike_results.txt"
DALFOX_RESULTS="dalfox_results.txt"

# Step 1: Fetch URLs using multiple sources
echo -e "${GREEN}[INFO] Fetching URLs using gau...${RESET}"
echo "$TARGET" | xargs -P10 -I{} sh -c 'gau "{}" >> "'$GAU_FILE'"' -- {}

GAU_COUNT=$(wc -l < "$GAU_FILE" 2>/dev/null || echo "0")
echo -e "${GREEN}[INFO] Gau found: $GAU_COUNT URLs${RESET}"

# Fallback to waybackurls if gau found nothing
if [ ! -s "$GAU_FILE" ]; then
    echo -e "${GREEN}[INFO] Gau found nothing, trying waybackurls...${RESET}"
    echo "$TARGET" | waybackurls >> "$WAYBACK_FILE"
    # Combine results if waybackurls found something
    if [ -s "$WAYBACK_FILE" ]; then
        cat "$WAYBACK_FILE" > "$GAU_FILE"
        WAYBACK_COUNT=$(wc -l < "$GAU_FILE")
        echo -e "${GREEN}[INFO] Waybackurls found: $WAYBACK_COUNT URLs${RESET}"
    fi
fi

# Step 2: Filter URLs with query parameters
echo -e "${GREEN}[INFO] Filtering URLs with query parameters...${RESET}"
# First filter URLs with query parameters, then use uro safely
grep -E '\?[^=]+=.+$' "$GAU_FILE" > temp_urls.txt
if [ -s "temp_urls.txt" ]; then
    # Try uro first, fallback to simple filtering if it fails
    cat temp_urls.txt | uro > "$FILTERED_URLS_FILE" 2>/dev/null || {
        echo -e "${GREEN}[INFO] uro failed, using simple filtering...${RESET}"
        # Simple filtering: remove duplicates and basic cleaning
        cat temp_urls.txt | sort -u | grep -v '^\s*$' > "$FILTERED_URLS_FILE"
    }
else
    echo "No URLs with query parameters found"
    touch "$FILTERED_URLS_FILE"
fi
rm -f temp_urls.txt

# Step 3: XSS Testing with XSStrike and Dalfox
echo -e "${GREEN}[INFO] Running XSStrike for XSS testing...${RESET}"
if [ -s "$FILTERED_URLS_FILE" ]; then
    echo -e "${GREEN}[INFO] XSStrike: Testing URLs with advanced XSS payloads...${RESET}"
    URL_COUNT=$(wc -l < "$FILTERED_URLS_FILE")
    echo -e "${GREEN}[INFO] Total URLs to test: $URL_COUNT${RESET}"

    # Run XSStrike with single instance to avoid multiple banners
    echo -e "${GREEN}[INFO] XSStrike: Starting XSS scan...${RESET}"
    xsstrike --fuzzer --delay 1 --threads 3 --skip-dom --quiet --seeds "$FILTERED_URLS_FILE" >> "$XSSTRIKE_RESULTS" 2>&1 || {
        echo -e "${GREEN}[INFO] XSStrike failed, trying alternative method...${RESET}"
        xargs -a "$FILTERED_URLS_FILE" -I@ bash -c 'xsstrike -u "@" --fuzzer --delay 2 --threads 1 --skip-dom --quiet' >> "$XSSTRIKE_RESULTS" 2>/dev/null || true
    }
fi

echo -e "${GREEN}[INFO] Running Dalfox for XSS testing...${RESET}"
if [ -s "$FILTERED_URLS_FILE" ]; then
    echo -e "${GREEN}[INFO] Dalfox: Advanced XSS scanning with context awareness...${RESET}"
    dalfox file "$FILTERED_URLS_FILE" \
        --no-color \
        -S \
        --deep-domxss \
        --context-aware \
        --waf-evasion \
        --worker 30 \
        --delay 1500 \
        --only-poc 'g,v' \
        --format plain \
        --ignore-return '404,403' \
        --skip-bav \
        --skip-mining-all \
        --report >> "$DALFOX_RESULTS" 2>/dev/null || {
        echo -e "${GREEN}[INFO] Dalfox advanced options failed, trying basic scan...${RESET}"
        dalfox file "$FILTERED_URLS_FILE" --no-color -S --worker 20 >> "$DALFOX_RESULTS" 2>/dev/null || true
    }
fi

# Step 4: Check live URLs using httpx
echo -e "${GREEN}[INFO] Checking for live URLs using httpx...${RESET}"
httpx -silent -t 300 -rl 200 < "$FILTERED_URLS_FILE" > "$FILTERED_URLS_FILE.tmp"
mv "$FILTERED_URLS_FILE.tmp" "$FILTERED_URLS_FILE"

LIVE_COUNT=$(wc -l < "$FILTERED_URLS_FILE" 2>/dev/null || echo "0")
echo -e "${GREEN}[INFO] Live URLs after httpx: $LIVE_COUNT${RESET}"

# Step 5: Run nuclei for comprehensive scanning
echo -e "${GREEN}[INFO] Running nuclei for comprehensive scanning...${RESET}"
echo -e "${GREEN}[INFO] Nuclei: Scanning for vulnerabilities...${RESET}"
nuclei -t xss,ssrf,sqli,injection,redirect,exposure,misconfiguration,informational -severity low,medium,high,critical -retries 2 -silent -o "$NUCLEI_RESULTS" < "$FILTERED_URLS_FILE"

NUCLEI_COUNT=$(wc -l < "$NUCLEI_RESULTS" 2>/dev/null || echo "0")
echo -e "${GREEN}[INFO] Nuclei found: $NUCLEI_COUNT potential issues${RESET}"

# Step 6: Show detailed results summary
echo -e "${GREEN}[INFO] =================================${RESET}"
echo -e "${GREEN}[INFO] SCAN SUMMARY${RESET}"
echo -e "${GREEN}[INFO] =================================${RESET}"

echo -e "${GREEN}[INFO] Target: $TARGET_URL${RESET}"
echo -e "${GREEN}[INFO] Gau URLs: $GAU_COUNT${RESET}"
if [ ! -s "$GAU_FILE" ] && [ -s "$WAYBACK_FILE" ]; then
    echo -e "${GREEN}[INFO] Wayback URLs: $(wc -l < "$WAYBACK_FILE" 2>/dev/null || echo "0")${RESET}"
fi
echo -e "${GREEN}[INFO] URLs with parameters: $(wc -l < "$FILTERED_URLS_FILE" 2>/dev/null || echo "0")${RESET}"
echo -e "${GREEN}[INFO] Live URLs: $LIVE_COUNT${RESET}"

# Show results file sizes
echo -e "${GREEN}[INFO] =================================${RESET}"
echo -e "${GREEN}[INFO] RESULTS${RESET}"
echo -e "${GREEN}[INFO] =================================${RESET}"

NUCLEI_COUNT=$(wc -l < "$NUCLEI_RESULTS" 2>/dev/null || echo "0")
XSSTRIKE_COUNT=$(wc -l < "$XSSTRIKE_RESULTS" 2>/dev/null || echo "0")
DALFOX_COUNT=$(wc -l < "$DALFOX_RESULTS" 2>/dev/null || echo "0")

echo -e "${GREEN}[INFO] Nuclei findings: $NUCLEI_COUNT${RESET}"
echo -e "${GREEN}[INFO] XSStrike findings: $XSSTRIKE_COUNT${RESET}"
echo -e "${GREEN}[INFO] Dalfox findings: $DALFOX_COUNT${RESET}"

echo -e "${GREEN}[INFO] =================================${RESET}"
echo -e "${GREEN}[INFO] FILES CREATED${RESET}"
echo -e "${GREEN}[INFO] =================================${RESET}"
echo -e "${GREEN}[INFO] Nuclei results: $NUCLEI_RESULTS${RESET}"
echo -e "${GREEN}[INFO] XSStrike results: $XSSTRIKE_RESULTS${RESET}"
echo -e "${GREEN}[INFO] Dalfox results: $DALFOX_RESULTS${RESET}"
echo -e "${GREEN}[INFO] Filtered URLs: $FILTERED_URLS_FILE${RESET}"
echo -e "${GREEN}[INFO] Automation completed successfully!${RESET}"

# Check if any tool found vulnerabilities
if [ ! -s "$NUCLEI_RESULTS" ] && [ ! -s "$XSSTRIKE_RESULTS" ] && [ ! -s "$DALFOX_RESULTS" ]; then
    echo -e "${GREEN}[INFO] =================================${RESET}"
    echo -e "${GREEN}[INFO] STATUS: No vulnerabilities found${RESET}"
else
    echo -e "${GREEN}[INFO] =================================${RESET}"
    echo -e "${GREEN}[INFO] STATUS: Vulnerabilities detected!${RESET}"
fi

# Cleanup temporary files
rm -f "$GAU_FILE" "$WAYBACK_FILE"
