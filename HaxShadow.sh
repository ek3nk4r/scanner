#!/bin/bash

# ANSI color codes
RED='\033[91m'
GREEN='\033[92m'
RESET='\033[0m'

# ASCII art banner
echo -e "${RED}"
echo -e "${RESET}"

# Ensure required tools are installed
REQUIRED_TOOLS=("gau" "uro" "httpx" "nuclei")
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
FILTERED_URLS_FILE="filtered_urls.txt"
NUCLEI_RESULTS="nuclei_results.txt"

# Step 1: Fetch URLs in Parallel using xargs
echo -e "${GREEN}[INFO] Fetching URLs using gau in parallel...${RESET}"
echo "$TARGET" | xargs -P10 -I{} sh -c 'gau "{}" >> "$1"' _ "$GAU_FILE"

# Step 2: Filter URLs with query parameters
echo -e "${GREEN}[INFO] Filtering URLs with query parameters...${RESET}"
grep -E '\?[^=]+=.+$' "$GAU_FILE" | uro | sort -u > "$FILTERED_URLS_FILE"

# Step 3: Check live URLs using httpx
echo -e "${GREEN}[INFO] Checking for live URLs using httpx...${RESET}"
httpx -silent -t 300 -rl 200 < "$FILTERED_URLS_FILE" > "$FILTERED_URLS_FILE.tmp"
mv "$FILTERED_URLS_FILE.tmp" "$FILTERED_URLS_FILE"

# Step 4: Run nuclei for DAST scanning
echo -e "${GREEN}[INFO] Running nuclei for DAST scanning...${RESET}"
nuclei -dast -retries 2 -silent -o "$NUCLEI_RESULTS" < "$FILTERED_URLS_FILE"

# Step 5: Show saved results
echo -e "${GREEN}[INFO] Nuclei results saved to $NUCLEI_RESULTS${RESET}"
echo -e "${GREEN}[INFO] Filtered URLs saved to $FILTERED_URLS_FILE for manual testing.${RESET}"
echo -e "${GREEN}[INFO] Automation completed successfully!${RESET}"

# Check if Nuclei found any vulnerabilities
if [ ! -s "$NUCLEI_RESULTS" ]; then
    echo -e "${GREEN}[INFO] No vulnerable URLs found.${RESET}"
else
    echo -e "${GREEN}[INFO] Vulnerabilities were detected. Check $NUCLEI_RESULTS for details.${RESET}"
fi
