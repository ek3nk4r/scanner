#!/bin/bash

#=============================================================================
# HakerPher - Advanced Web Security Scanner
# Version: 2.0
# Author: ~/.TEAM_DH049
#=============================================================================

set -euo pipefail

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
readonly OUTPUT_DIR="${SCRIPT_DIR}/hakerpher_results_$(date +%Y%m%d_%H%M%S)"
readonly LOG_FILE="${OUTPUT_DIR}/scan.log"
readonly MAX_PARALLEL=10
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
██╗  ██╗ █████╗ ██╗  ██╗███████╗██████╗ ██████╗ ██╗  ██╗███████╗██████╗ 
██║  ██║██╔══██╗██║ ██╔╝██╔════╝██╔══██╗██╔══██╗██║  ██║██╔════╝██╔══██╗
███████║███████║█████╔╝ █████╗  ██████╔╝██████╔╝███████║█████╗  ██████╔╝
██╔══██║██╔══██║██╔═██╗ ██╔══╝  ██╔══██╗██╔══██╗██╔══██║██╔══╝  ██╔══██╗
██║  ██║██║  ██║██║  ██╗███████╗██║  ██║██║  ██║██║  ██║███████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                                                                          
                        Advanced Web Security Scanner v2.0
                              by ~/.TEAM_DH049
EOF
    echo -e "${RESET}"
}

log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[${timestamp}] [${level}] ${message}" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${GREEN}[INFO]${RESET} $*" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${RESET} $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${RESET} $*" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${CYAN}[SUCCESS]${RESET} $*" | tee -a "$LOG_FILE"
}

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
        log_info "Install missing tools with the following commands:"
        for tool in "${missing_tools[@]}"; do
            echo -e "${BLUE}  go install ${REQUIRED_TOOLS[$tool]}${RESET}"
        done
        echo ""
        exit 1
    fi
    
    log_success "All required tools are installed"
}

get_user_input() {
    echo ""
    echo -e "${BOLD}${CYAN}Target Configuration${RESET}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    
    read -p "$(echo -e ${YELLOW}Enter target domain or subdomains list file:${RESET} )" INPUT
    
    if [ -z "$INPUT" ]; then
        log_error "Input cannot be empty"
        exit 1
    fi
    
    if [ ! -f "$INPUT" ] && [[ ! "$INPUT" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        log_error "Invalid domain format or file not found"
        exit 1
    fi
    
    echo "$INPUT"
}

prepare_targets() {
    local input=$1
    local targets_file="${OUTPUT_DIR}/targets.txt"
    
    if [ -f "$input" ]; then
        log_info "Reading targets from file: $input"
        cat "$input" | sed 's|https\?://||g' | sed 's|/.*||' | sort -u > "$targets_file"
    else
        log_info "Using single target: $input"
        echo "$input" | sed 's|https\?://||g' | sed 's|/.*||' > "$targets_file"
    fi
    
    local count=$(wc -l < "$targets_file")
    log_info "Prepared ${count} target(s) for scanning"
    echo "$targets_file"
}

fetch_urls() {
    local targets_file=$1
    local gau_output="${OUTPUT_DIR}/gau_urls.txt"
    
    log_info "Fetching URLs using gau (parallel processing)..."
    
    cat "$targets_file" | xargs -P"$MAX_PARALLEL" -I{} sh -c \
        'gau "{}" 2>/dev/null || true' | sort -u > "$gau_output"
    
    local count=$(wc -l < "$gau_output")
    log_success "Collected ${count} URLs"
    echo "$gau_output"
}

filter_urls() {
    local gau_output=$1
    local filtered_urls="${OUTPUT_DIR}/filtered_urls.txt"
    
    log_info "Filtering URLs with query parameters and removing duplicates..."
    
    grep -E '\?[^=]+=.+$' "$gau_output" 2>/dev/null | \
        uro | \
        sort -u > "$filtered_urls"
    
    local count=$(wc -l < "$filtered_urls")
    log_success "Filtered to ${count} unique URLs with parameters"
    echo "$filtered_urls"
}

check_live_urls() {
    local filtered_urls=$1
    local live_urls="${OUTPUT_DIR}/live_urls.txt"
    
    log_info "Checking for live URLs using httpx..."
    
    httpx -silent \
        -t "$HTTPX_THREADS" \
        -rl "$HTTPX_RATE_LIMIT" \
        -mc 200,201,202,203,204,301,302,307,308,401,403,405,500 \
        -follow-redirects \
        -no-color \
        -l "$filtered_urls" \
        -o "$live_urls" 2>/dev/null || true
    
    local count=$(wc -l < "$live_urls" 2>/dev/null || echo 0)
    log_success "Found ${count} live URLs"
    echo "$live_urls"
}

run_nuclei_scan() {
    local live_urls=$1
    local nuclei_output="${OUTPUT_DIR}/nuclei_results.txt"
    local nuclei_json="${OUTPUT_DIR}/nuclei_results.json"
    
    log_info "Running Nuclei DAST scan..."
    
    nuclei -l "$live_urls" \
        -dast \
        -retries "$NUCLEI_RETRIES" \
        -silent \
        -o "$nuclei_output" \
        -json \
        -jsonl \
        -je "$nuclei_json" 2>/dev/null || true
    
    echo "$nuclei_output"
}

generate_report() {
    local nuclei_output=$1
    local report_file="${OUTPUT_DIR}/scan_report.txt"
    
    log_info "Generating scan report..."
    
    {
        echo "=============================================="
        echo "HakerPher Security Scan Report"
        echo "=============================================="
        echo "Scan Date: $(date)"
        echo "Output Directory: $OUTPUT_DIR"
        echo ""
        echo "Summary:"
        echo "  - Total URLs Found: $(wc -l < "${OUTPUT_DIR}/gau_urls.txt" 2>/dev/null || echo 0)"
        echo "  - URLs with Parameters: $(wc -l < "${OUTPUT_DIR}/filtered_urls.txt" 2>/dev/null || echo 0)"
        echo "  - Live URLs: $(wc -l < "${OUTPUT_DIR}/live_urls.txt" 2>/dev/null || echo 0)"
        
        if [ -s "$nuclei_output" ]; then
            local vuln_count=$(wc -l < "$nuclei_output")
            echo "  - Vulnerabilities Found: $vuln_count"
            echo ""
            echo "Vulnerability Details:"
            echo "---------------------------------------------"
            cat "$nuclei_output"
        else
            echo "  - Vulnerabilities Found: 0"
            echo ""
            echo "No vulnerabilities detected."
        fi
        
        echo ""
        echo "=============================================="
    } > "$report_file"
    
    echo "$report_file"
}

cleanup() {
    log_info "Cleaning up temporary files..."
    # Add any cleanup tasks here if needed
}

#=============================================================================
# Main Execution
#=============================================================================

main() {
    print_banner
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    touch "$LOG_FILE"
    
    log_info "Starting HakerPher security scan..."
    log_info "Output directory: $OUTPUT_DIR"
    
    # Check dependencies
    check_dependencies
    
    # Get user input
    local input=$(get_user_input)
    
    # Prepare targets
    local targets_file=$(prepare_targets "$input")
    
    # Fetch URLs
    local gau_output=$(fetch_urls "$targets_file")
    
    # Filter URLs
    local filtered_urls=$(filter_urls "$gau_output")
    
    # Check if we have any URLs to scan
    if [ ! -s "$filtered_urls" ]; then
        log_warn "No URLs with parameters found. Exiting."
        exit 0
    fi
    
    # Check live URLs
    local live_urls=$(check_live_urls "$filtered_urls")
    
    # Check if we have any live URLs
    if [ ! -s "$live_urls" ]; then
        log_warn "No live URLs found. Exiting."
        exit 0
    fi
    
    # Run Nuclei scan
    local nuclei_output=$(run_nuclei_scan "$live_urls")
    
    # Generate report
    local report_file=$(generate_report "$nuclei_output")
    
    # Display results
    echo ""
    echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}${CYAN}Scan Complete!${RESET}"
    echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
    log_success "All results saved to: $OUTPUT_DIR"
    log_success "Detailed report: $report_file"
    echo ""
    
    if [ -s "$nuclei_output" ]; then
        log_warn "Vulnerabilities detected! Check the report for details."
        echo -e "${YELLOW}Review: $nuclei_output${RESET}"
    else
        log_info "No vulnerabilities found. All scanned URLs appear secure."
    fi
    
    echo ""
    cleanup
}

# Trap errors and cleanup
trap cleanup EXIT

# Run main function
main "$@"
