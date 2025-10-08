#!/bin/bash

#=============================================================================
# HakerPher - Advanced Web Security Scanner (FIXED)
# Version: 2.3
# Author: ~/.TEAM_DH049
#=============================================================================

set -eo pipefail

# ANSI Color Codes
readonly RED='\033[91m'
readonly GREEN='\033[92m'
readonly YELLOW='\033[93m'
readonly BLUE='\033[94m'
readonly CYAN='\033[96m'
readonly BOLD='\033[1m'
readonly RESET='\033[0m'

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly OUTPUT_DIR="${SCRIPT_DIR}/out_$(date +%s)"
readonly LOG_FILE="${OUTPUT_DIR}/scan.log"
readonly HTTPX_THREADS=300
readonly HTTPX_RATE_LIMIT=200
readonly NUCLEI_RETRIES=2

# Required Tools
declare -A REQUIRED_TOOLS=(
    ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
    ["uro"]="github.com/s0md3v/uro@latest"
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
)

#=============================================================================
# Helper Functions
#=============================================================================

print_banner() {
    echo -e "${RED}${BOLD}"
    cat << "EOF" 
    ╔═══════════════════════════════════════════════════╗
    ║   HakerPher - Web Security Scanner v2.3          ║
    ║   Advanced DAST with Nuclei Integration          ║
    ║   by ~/.TEAM_DH049                               ║
    ╚═══════════════════════════════════════════════════╝
EOF
    echo -e "${RESET}"
}

log_msg() {
    local color=$1
    local level=$2
    shift 2
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    printf "%b[%s]%b %s\n" "$color" "$level" "$RESET" "$message"
    
    if [ -f "$LOG_FILE" ]; then
        printf "[%s] [%s] %s\n" "$timestamp" "$level" "$message" >> "$LOG_FILE"
    fi
}

log_info() { log_msg "$GREEN" "INFO" "$@"; }
log_warn() { log_msg "$YELLOW" "WARN" "$@"; }
log_error() { log_msg "$RED" "ERROR" "$@"; }
log_success() { log_msg "$CYAN" "SUCCESS" "$@"; }

check_dependencies() {
    log_info "Checking required tools..."
    local missing_tools=()
    
    for tool in "${!REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        echo ""
        log_info "Install missing tools with:"
        for tool in "${missing_tools[@]}"; do
            printf "%b  go install %s%b\n" "$BLUE" "${REQUIRED_TOOLS[$tool]}" "$RESET"
        done
        exit 1
    fi
    
    log_success "All required tools are installed"
}

validate_domain() {
    local domain=$1
    domain=$(echo "$domain" | sed -e 's|^https\?://||' -e 's|/.*||' -e 's|:.*||')
    
    if echo "$domain" | grep -qE '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'; then
        echo "$domain"
        return 0
    fi
    return 1
}

get_user_input() {
    if [ $# -gt 0 ]; then
        echo "$1"
        return 0
    fi
    
    echo ""
    printf "%b%b━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%b\n" "$BOLD" "$CYAN" "$RESET"
    printf "%b%b           Target Configuration%b\n" "$BOLD" "$CYAN" "$RESET"
    printf "%b%b━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%b\n" "$BOLD" "$CYAN" "$RESET"
    echo ""
    
    read -p "$(printf '%bEnter target domain or file path:%b ' "$YELLOW" "$RESET")" INPUT
    
    if [ -z "$INPUT" ]; then
        log_error "Input cannot be empty"
        exit 1
    fi
    
    echo "$INPUT"
}

prepare_targets() {
    local input=$1
    local targets_file="${OUTPUT_DIR}/targets.txt"
    
    if [ -f "$input" ]; then
        log_info "Reading targets from file: $input"
        while IFS= read -r line || [ -n "$line" ]; do
            [ -z "$line" ] && continue
            local cleaned
            if cleaned=$(validate_domain "$line"); then
                echo "$cleaned"
            fi
        done < "$input" | sort -u > "$targets_file"
    else
        local cleaned
        if cleaned=$(validate_domain "$input"); then
            log_info "Using single target: $cleaned"
            echo "$cleaned" > "$targets_file"
        else
            log_error "Invalid domain format: $input"
            exit 1
        fi
    fi
    
    local count=$(wc -l < "$targets_file" 2>/dev/null || echo 0)
    if [ "$count" -eq 0 ]; then
        log_error "No valid targets found"
        exit 1
    fi
    
    log_success "Prepared ${count} target(s) for scanning"
    echo "$targets_file"
}

fetch_urls() {
    local targets_file=$1
    local gau_output="${OUTPUT_DIR}/gau_urls.txt"
    
    log_info "Fetching URLs using gau (this may take a while)..."
    : > "$gau_output"
    
    local target_count=0
    while IFS= read -r target; do
        [ -z "$target" ] && continue
        target_count=$((target_count + 1))
        
        printf "  %b[%d]%b Scanning: %s\r" "$CYAN" "$target_count" "$RESET" "$target"
        
        {
            gau "$target" 2>/dev/null || true
            gau --providers wayback,commoncrawl,otx,urlscan "$target" 2>/dev/null || true
        } | grep -v '^$' >> "$gau_output" || true
        
    done < "$targets_file"
    
    echo ""
    
    if [ -f "$gau_output" ]; then
        sort -u "$gau_output" -o "$gau_output"
    fi
    
    local count=$(wc -l < "$gau_output" 2>/dev/null || echo 0)
    
    if [ "$count" -eq 0 ]; then
        log_warn "No URLs found by gau, creating fallback URLs..."
        while IFS= read -r target; do
            [ -z "$target" ] && continue
            echo "https://$target" >> "$gau_output"
            echo "http://$target" >> "$gau_output"
        done < "$targets_file"
        
        count=$(wc -l < "$gau_output" 2>/dev/null || echo 0)
    fi
    
    log_success "Collected ${count} URLs"
    echo "$gau_output"
}

filter_urls() {
    local gau_output=$1
    local filtered_urls="${OUTPUT_DIR}/filtered_urls.txt"
    
    log_info "Filtering URLs with query parameters..."
    
    # Filter URLs with parameters: must have ?key=value format
    grep -E '\?[^=&]+=[^&]+' "$gau_output" 2>/dev/null | \
        uro 2>/dev/null | \
        sort -u > "$filtered_urls" 2>/dev/null || true
    
    local count=$(wc -l < "$filtered_urls" 2>/dev/null || echo 0)
    
    if [ "$count" -eq 0 ]; then
        log_warn "No URLs with parameters found, using all URLs"
        cp "$gau_output" "$filtered_urls"
        count=$(wc -l < "$filtered_urls" 2>/dev/null || echo 0)
    fi
    
    log_success "Filtered to ${count} URLs"
    echo "$filtered_urls"
}

check_live_urls() {
    local filtered_urls=$1
    local live_urls="${OUTPUT_DIR}/live_urls.txt"
    
    log_info "Checking for live URLs using httpx..."
    
    httpx -silent \
        -t "$HTTPX_THREADS" \
        -rl "$HTTPX_RATE_LIMIT" \
        -mc 200,201,301,302,307,308,401,403 \
        -follow-redirects \
        -no-color \
        -l "$filtered_urls" \
        -o "$live_urls" 2>/dev/null || true
    
    local count=$(wc -l < "$live_urls" 2>/dev/null || echo 0)
    
    if [ "$count" -eq 0 ]; then
        log_warn "No live URLs found, using filtered URLs for scan"
        cp "$filtered_urls" "$live_urls"
        count=$(wc -l < "$live_urls" 2>/dev/null || echo 0)
    fi
    
    log_success "Found ${count} live URLs"
    echo "$live_urls"
}

run_nuclei_scan() {
    local live_urls=$1
    local nuclei_output="${OUTPUT_DIR}/nuclei_results.txt"
    local nuclei_json="${OUTPUT_DIR}/nuclei_results.json"
    
    log_info "Running Nuclei DAST scan (this may take several minutes)..."
    
    nuclei -l "$live_urls" \
        -dast \
        -retries "$NUCLEI_RETRIES" \
        -silent \
        -o "$nuclei_output" \
        -json \
        -jsonl \
        -je "$nuclei_json" 2>/dev/null || true
    
    local count=$(wc -l < "$nuclei_output" 2>/dev/null || echo 0)
    
    if [ "$count" -gt 0 ]; then
        log_warn "Found ${count} potential vulnerabilities"
    else
        log_success "No vulnerabilities detected"
    fi
    
    echo "$nuclei_output"
}

generate_report() {
    local nuclei_output=$1
    local report_file="${OUTPUT_DIR}/report.txt"
    
    log_info "Generating scan report..."
    
    {
        echo "╔═══════════════════════════════════════════════════╗"
        echo "║       HakerPher Security Scan Report              ║"
        echo "╚═══════════════════════════════════════════════════╝"
        echo ""
        echo "Scan Date: $(date)"
        echo "Output Directory: $OUTPUT_DIR"
        echo ""
        echo "═══════════════════════════════════════════════════"
        echo "SUMMARY"
        echo "═══════════════════════════════════════════════════"
        echo "  • Total URLs Found:        $(wc -l < "${OUTPUT_DIR}/gau_urls.txt" 2>/dev/null || echo 0)"
        echo "  • URLs with Parameters:    $(wc -l < "${OUTPUT_DIR}/filtered_urls.txt" 2>/dev/null || echo 0)"
        echo "  • Live URLs:               $(wc -l < "${OUTPUT_DIR}/live_urls.txt" 2>/dev/null || echo 0)"
        
        if [ -s "$nuclei_output" ]; then
            local vuln_count=$(wc -l < "$nuclei_output")
            echo "  • Vulnerabilities Found:   $vuln_count"
            echo ""
            echo "═══════════════════════════════════════════════════"
            echo "VULNERABILITY DETAILS"
            echo "═══════════════════════════════════════════════════"
            cat "$nuclei_output"
        else
            echo "  • Vulnerabilities Found:   0"
            echo ""
            echo "✓ No vulnerabilities detected."
        fi
        
        echo ""
        echo "═══════════════════════════════════════════════════"
    } > "$report_file"
    
    echo "$report_file"
}

#=============================================================================
# Main Execution
#=============================================================================

main() {
    print_banner
    
    mkdir -p "$OUTPUT_DIR"
    touch "$LOG_FILE"
    
    log_info "Starting HakerPher security scan..."
    log_info "Output directory: $OUTPUT_DIR"
    echo ""
    
    check_dependencies
    echo ""
    
    local input=$(get_user_input "$@")
    local targets_file=$(prepare_targets "$input")
    echo ""
    
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_info "PHASE 1: URL Collection"
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    local gau_output=$(fetch_urls "$targets_file")
    echo ""
    
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_info "PHASE 2: URL Filtering"
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    local filtered_urls=$(filter_urls "$gau_output")
    echo ""
    
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_info "PHASE 3: Live URL Detection"
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    local live_urls=$(check_live_urls "$filtered_urls")
    echo ""
    
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_info "PHASE 4: Nuclei DAST Scanning"
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    local nuclei_output=$(run_nuclei_scan "$live_urls")
    echo ""
    
    local report_file=$(generate_report "$nuclei_output")
    
    echo ""
    printf "%b%b╔═══════════════════════════════════════════════════╗%b\n" "$BOLD" "$GREEN" "$RESET"
    printf "%b%b║            Scan Complete!                         ║%b\n" "$BOLD" "$CYAN" "$RESET"
    printf "%b%b╚═══════════════════════════════════════════════════╝%b\n" "$BOLD" "$GREEN" "$RESET"
    echo ""
    
    log_success "Results directory: $OUTPUT_DIR"
    log_success "Detailed report: $report_file"
    echo ""
    
    if [ -s "$nuclei_output" ]; then
        local vuln_count=$(wc -l < "$nuclei_output")
        printf "%b%b⚠ WARNING: %d vulnerabilities detected!%b\n" "$RED" "$BOLD" "$vuln_count" "$RESET"
        printf "%bReview: %s%b\n" "$YELLOW" "$nuclei_output" "$RESET"
    else
        printf "%b✓ No vulnerabilities found. All scanned URLs appear secure.%b\n" "$GREEN" "$RESET"
    fi
    
    echo ""
    printf "%b%bFiles Generated:%b\n" "$BLUE" "$BOLD" "$RESET"
    echo "  • Targets:           ${OUTPUT_DIR}/targets.txt"
    echo "  • All URLs:          ${OUTPUT_DIR}/gau_urls.txt"
    echo "  • Filtered URLs:     ${OUTPUT_DIR}/filtered_urls.txt"
    echo "  • Live URLs:         ${OUTPUT_DIR}/live_urls.txt"
    echo "  • Vulnerabilities:   ${OUTPUT_DIR}/nuclei_results.txt"
    echo "  • JSON Report:       ${OUTPUT_DIR}/nuclei_results.json"
    echo "  • Full Report:       ${OUTPUT_DIR}/report.txt"
    echo "  • Log File:          ${OUTPUT_DIR}/scan.log"
    echo ""
}

main "$@"
