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

# Function to show usage
show_usage() {
    echo -e "${GREEN}[USAGE]${RESET}"
    echo -e "  $0 <target_url>                    # Run full scan (default)"
    echo -e "  $0 -x <target_url>                 # Run XSS scan only"
    echo -e "  $0 -n <target_url>                 # Run nuclei scan only"
    echo -e "  $0 -f <target_url>                 # Run URL finding only"
    echo -e "  $0 -s <target_url>                 # Run fast XSS scan (unlimited speed)"
    echo -e "  $0 -f -x <target_url>              # Run URL finding + XSS scan"
    echo -e "  $0 -f -n <target_url>              # Run URL finding + nuclei scan"
    echo -e "  $0 -x -n <target_url>              # Run XSS + nuclei scan"
    echo -e "  $0 -f -x -n <target_url>           # Run all (same as default)"
    echo -e ""
    echo -e "${GREEN}[OPTIONS]${RESET}"
    echo -e "  -f    Run URL finding (gau/waybackurls)"
    echo -e "  -x    Run XSS tests (XSStrike + Dalfox)"
    echo -e "  -n    Run nuclei scan"
    echo -e "  -s    Run fast XSS scan (no limits, maximum speed)"
    echo -e ""
    echo -e "${GREEN}[NOTES]${RESET}"
    echo -e "  • Multiple options can be combined (e.g., -f -x)"
    echo -e "  • -s can only be used with -x (fast XSS mode)"
    echo -e "  • Without options: runs full scan (equivalent to -f -x -n)"
    echo -e ""
    echo -e "${GREEN}[EXAMPLES]${RESET}"
    echo -e "  $0 https://example.com"
    echo -e "  $0 -x https://example.com"
    echo -e "  $0 -f -x https://example.com"
    echo -e "  $0 -s https://example.com"
}

# Parse arguments with multiple options support
RUN_FINDING=false
RUN_XSS=false
RUN_NUCLEI=false
FAST_MODE=false
TARGET_URL=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--finding)
            RUN_FINDING=true
            shift
            ;;
        -x|--xss)
            RUN_XSS=true
            shift
            ;;
        -n|--nuclei)
            RUN_NUCLEI=true
            shift
            ;;
        -s|--speed)
            FAST_MODE=true
            RUN_XSS=true  # Fast mode implies XSS
            shift
            ;;
        -*)
            echo -e "${RED}[ERROR] Unknown option: $1${RESET}"
            show_usage
            exit 1
            ;;
        *)
            if [ -z "$TARGET_URL" ]; then
                TARGET_URL="$1"
            else
                echo -e "${RED}[ERROR] Multiple target URLs not supported${RESET}"
                show_usage
                exit 1
            fi
            shift
            ;;
    esac
done

# Check if target URL is provided
if [ -z "$TARGET_URL" ]; then
    echo -e "${RED}[ERROR] Please provide a target URL${RESET}"
    show_usage
    exit 1
fi

# If no options specified, run all (default behavior)
if [ "$RUN_FINDING" = false ] && [ "$RUN_XSS" = false ] && [ "$RUN_NUCLEI" = false ]; then
    RUN_FINDING=true
    RUN_XSS=true
    RUN_NUCLEI=true
fi

# Validate fast mode is only used with XSS
if [ "$FAST_MODE" = true ] && [ "$RUN_XSS" = false ]; then
    echo -e "${RED}[ERROR] Fast mode (-s) can only be used with XSS scanning${RESET}"
    show_usage
    exit 1
fi

# Show selected modes
echo -e "${GREEN}[MODE] Selected:${RESET}"
echo -e "  Finding: $RUN_FINDING, XSS: $RUN_XSS, Nuclei: $RUN_NUCLEI, Fast: $FAST_MODE"

# Remove protocols (http/https) if present
TARGET=$(echo "$TARGET_URL" | sed 's|https\?://||g')

# Create temporary files
GAU_FILE=$(mktemp)
WAYBACK_FILE=$(mktemp)
FILTERED_URLS_FILE="filtered_urls.txt"
NUCLEI_RESULTS="nuclei_results.txt"
XSSTRIKE_RESULTS="xsstrike_results.txt"
DALFOX_RESULTS="dalfox_results.txt"

# Show execution plan
echo -e "${GREEN}[INFO] Execution plan:${RESET}"
if [ "$RUN_FINDING" = true ]; then
    echo -e "  ✓ URL Finding (gau/waybackurls)"
fi
if [ "$RUN_XSS" = true ]; then
    if [ "$FAST_MODE" = true ]; then
        echo -e "  ✓ Fast XSS Testing (XSStrike + Dalfox)"
    else
        echo -e "  ✓ XSS Testing (XSStrike + Dalfox)"
    fi
fi
if [ "$RUN_NUCLEI" = true ]; then
    echo -e "  ✓ Nuclei Scanning"
fi

# Step 1: Fetch URLs using multiple sources (if finding mode enabled)
if [ "$RUN_FINDING" = true ]; then
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
fi

# Step 3: XSS Testing with XSStrike and Dalfox (if XSS mode enabled)
if [ "$RUN_XSS" = true ]; then
    echo -e "${GREEN}[INFO] Running XSStrike for XSS testing...${RESET}"
    if [ -s "$FILTERED_URLS_FILE" ]; then
        echo -e "${GREEN}[INFO] XSStrike: Testing URLs with advanced XSS payloads...${RESET}"
        URL_COUNT=$(wc -l < "$FILTERED_URLS_FILE")
        echo -e "${GREEN}[INFO] Total URLs to test: $URL_COUNT${RESET}"

        # Set speed settings based on fast mode
        if [ "$FAST_MODE" = true ]; then
            XSS_DELAY=0
            XSS_THREADS=10
            DALFOX_WORKER=100
            DALFOX_DELAY=500
            echo -e "${GREEN}[INFO] Fast mode: Unlimited speed enabled${RESET}"
        else
            XSS_DELAY=1
            XSS_THREADS=3
            DALFOX_WORKER=30
            DALFOX_DELAY=1500
        fi

        # Run XSStrike with single instance to avoid multiple banners
        echo -e "${GREEN}[INFO] XSStrike: Starting XSS scan...${RESET}"
        # Suppress XSStrike banners and run scan
        {
            xsstrike --fuzzer --delay $XSS_DELAY --threads $XSS_THREADS --skip-dom --skip --console-log-level ERROR --seeds "$FILTERED_URLS_FILE" 2>/dev/null
        } | grep -v "XSStrike" | grep -v "v3.1.5" >> "$XSSTRIKE_RESULTS" 2>/dev/null || {
            echo -e "${GREEN}[INFO] XSStrike failed, trying alternative method...${RESET}"
            # Alternative method: test URLs one by one with banner suppression
            echo "# XSStrike Results" > "$XSSTRIKE_RESULTS"
            while IFS= read -r url; do
                if [ ! -z "$url" ]; then
                    echo -e "\n[Testing] $url" >> "$XSSTRIKE_RESULTS"
                    {
                        xsstrike -u "$url" --fuzzer --delay $XSS_DELAY --threads $XSS_THREADS --skip-dom --skip --console-log-level ERROR 2>/dev/null
                    } | grep -v "XSStrike" | grep -v "v3.1.5" | head -10 >> "$XSSTRIKE_RESULTS" 2>/dev/null || true
                fi
            done < "$FILTERED_URLS_FILE"
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
            --worker $DALFOX_WORKER \
            --delay $DALFOX_DELAY \
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
fi

# Step 4: Check live URLs using httpx (if not URL finding only mode)
if [ "$RUN_FINDING" = false ] || [ "$RUN_XSS" = true ] || [ "$RUN_NUCLEI" = true ]; then
    echo -e "${GREEN}[INFO] Checking for live URLs using httpx...${RESET}"
    httpx -silent -t 300 -rl 200 < "$FILTERED_URLS_FILE" > "$FILTERED_URLS_FILE.tmp"
    mv "$FILTERED_URLS_FILE.tmp" "$FILTERED_URLS_FILE"

    LIVE_COUNT=$(wc -l < "$FILTERED_URLS_FILE" 2>/dev/null || echo "0")
    echo -e "${GREEN}[INFO] Live URLs after httpx: $LIVE_COUNT${RESET}"
fi

# Step 5: Run nuclei for comprehensive scanning (if nuclei mode enabled)
if [ "$RUN_NUCLEI" = true ]; then
    echo -e "${GREEN}[INFO] Running nuclei for comprehensive scanning...${RESET}"
    echo -e "${GREEN}[INFO] Nuclei: Scanning for vulnerabilities...${RESET}"
    nuclei -t xss,ssrf,sqli,injection,redirect,exposure,misconfiguration,informational -severity low,medium,high,critical -retries 2 -silent -o "$NUCLEI_RESULTS" < "$FILTERED_URLS_FILE"

    NUCLEI_COUNT=$(wc -l < "$NUCLEI_RESULTS" 2>/dev/null || echo "0")
    echo -e "${GREEN}[INFO] Nuclei found: $NUCLEI_COUNT potential issues${RESET}"
fi

# Step 6: Show results summary based on mode
echo -e "${GREEN}[INFO] =================================${RESET}"
echo -e "${GREEN}[INFO] SCAN SUMMARY${RESET}"
echo -e "${GREEN}[INFO] =================================${RESET}"

echo -e "${GREEN}[INFO] Target: $TARGET_URL${RESET}"
# Show combined mode description
MODE_DESC=""
if [ "$RUN_FINDING" = true ] && [ "$RUN_XSS" = true ] && [ "$RUN_NUCLEI" = true ]; then
    MODE_DESC="complete scan"
elif [ "$RUN_FINDING" = true ] && [ "$RUN_XSS" = true ]; then
    MODE_DESC="finding + xss"
elif [ "$RUN_FINDING" = true ] && [ "$RUN_NUCLEI" = true ]; then
    MODE_DESC="finding + nuclei"
elif [ "$RUN_XSS" = true ] && [ "$RUN_NUCLEI" = true ]; then
    MODE_DESC="xss + nuclei"
elif [ "$RUN_FINDING" = true ]; then
    MODE_DESC="finding only"
elif [ "$RUN_XSS" = true ]; then
    MODE_DESC="xss only"
elif [ "$RUN_NUCLEI" = true ]; then
    MODE_DESC="nuclei only"
fi
echo -e "${GREEN}[INFO] Mode: $MODE_DESC${RESET}"

# Show URL finding results if applicable
if [ "$RUN_FINDING" = true ]; then
    echo -e "${GREEN}[INFO] =================================${RESET}"
    echo -e "${GREEN}[INFO] URL FINDING RESULTS${RESET}"
    echo -e "${GREEN}[INFO] =================================${RESET}"
    echo -e "${GREEN}[INFO] Gau URLs: $GAU_COUNT${RESET}"
    if [ ! -s "$GAU_FILE" ] && [ -s "$WAYBACK_FILE" ]; then
        echo -e "${GREEN}[INFO] Wayback URLs: $(wc -l < "$WAYBACK_FILE" 2>/dev/null || echo "0")${RESET}"
    fi
    echo -e "${GREEN}[INFO] URLs with parameters: $(wc -l < "$FILTERED_URLS_FILE" 2>/dev/null || echo "0")${RESET}"
fi

# Show XSS results if applicable
if [ "$RUN_XSS" = true ]; then
    echo -e "${GREEN}[INFO] =================================${RESET}"
    echo -e "${GREEN}[INFO] XSS SCAN RESULTS${RESET}"
    echo -e "${GREEN}[INFO] =================================${RESET}"
    if [ "$FAST_MODE" = true ]; then
        echo -e "${GREEN}[INFO] Speed Mode: Unlimited${RESET}"
    fi
    XSSTRIKE_COUNT=$(wc -l < "$XSSTRIKE_RESULTS" 2>/dev/null || echo "0")
    DALFOX_COUNT=$(wc -l < "$DALFOX_RESULTS" 2>/dev/null || echo "0")
    echo -e "${GREEN}[INFO] XSStrike findings: $XSSTRIKE_COUNT${RESET}"
    echo -e "${GREEN}[INFO] Dalfox findings: $DALFOX_COUNT${RESET}"
fi

# Show nuclei results if applicable
if [ "$RUN_NUCLEI" = true ]; then
    echo -e "${GREEN}[INFO] =================================${RESET}"
    echo -e "${GREEN}[INFO] NUCLEI SCAN RESULTS${RESET}"
    echo -e "${GREEN}[INFO] =================================${RESET}"
    NUCLEI_COUNT=$(wc -l < "$NUCLEI_RESULTS" 2>/dev/null || echo "0")
    echo -e "${GREEN}[INFO] Nuclei findings: $NUCLEI_COUNT${RESET}"
    if [ "$RUN_FINDING" = false ]; then
        echo -e "${GREEN}[INFO] Live URLs: $LIVE_COUNT${RESET}"
    fi
fi

# Show files created
echo -e "${GREEN}[INFO] =================================${RESET}"
echo -e "${GREEN}[INFO] FILES CREATED${RESET}"
echo -e "${GREEN}[INFO] =================================${RESET}"

if [ "$RUN_FINDING" = true ]; then
    echo -e "${GREEN}[INFO] Filtered URLs: $FILTERED_URLS_FILE${RESET}"
fi

if [ "$RUN_XSS" = true ]; then
    echo -e "${GREEN}[INFO] XSStrike results: $XSSTRIKE_RESULTS${RESET}"
    echo -e "${GREEN}[INFO] Dalfox results: $DALFOX_RESULTS${RESET}"
fi

if [ "$RUN_NUCLEI" = true ]; then
    echo -e "${GREEN}[INFO] Nuclei results: $NUCLEI_RESULTS${RESET}"
fi

echo -e "${GREEN}[INFO] Automation completed successfully!${RESET}"

# Check if any tool found vulnerabilities (only for relevant modes)
STATUS_FOUND=false
if [ "$RUN_XSS" = true ]; then
    if [ -s "$XSSTRIKE_RESULTS" ] || [ -s "$DALFOX_RESULTS" ]; then
        STATUS_FOUND=true
    fi
fi

if [ "$RUN_NUCLEI" = true ]; then
    if [ -s "$NUCLEI_RESULTS" ]; then
        STATUS_FOUND=true
    fi
fi

if [ "$STATUS_FOUND" = true ]; then
    echo -e "${GREEN}[INFO] =================================${RESET}"
    echo -e "${GREEN}[INFO] STATUS: Vulnerabilities detected!${RESET}"
else
    echo -e "${GREEN}[INFO] =================================${RESET}"
    echo -e "${GREEN}[INFO] STATUS: No vulnerabilities found${RESET}"
fi

# Cleanup temporary files
rm -f "$GAU_FILE" "$WAYBACK_FILE"
