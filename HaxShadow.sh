#!/bin/bash

#=============================================================================
# HakerPher - Advanced Web Security Scanner
# Version: 2.2
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
                                                                          
                        Advanced Web Security Scanner v2.2
                              by ~/.TEAM_DH049
EOF
    echo -e "${RESET}"
}

log_msg() {
    local color=$1
    local level=$2
    shift 2
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Print to console
    printf "%b[%s]%b %s\n" "$color" "$level" "$RESET" "$message"
    
    # Write to log file
    if [ -f "$LOG_FILE" ]; then
        printf "[%s] [%s] %s\n" "$timestamp" "$level" "$message" >> "$LOG_FILE"
    fi
}

log_info() {
    log_msg "$GREEN" "INFO" "$@"
}

log_warn() {
    log_msg "$YELLOW" "WARN" "$@"
}

log_error() {
    log_msg "$RED" "ERROR" "$@"
}

log_success() {
    log_msg "$CYAN" "SUCCESS" "$@"
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
        log_info "Install missing tools with:"
        for tool in "${missing_tools[@]}"; do
            printf "%b  go install %s%b\n" "$BLUE" "${REQUIRED_TOOLS[$tool]}" "$RESET"
        done
        echo ""
        exit 1
    fi
    
    log_success "All required tools are installed"
}

validate_domain() {
    local domain=$1
    # Remove protocol and path
    domain=$(echo "$domain" | sed -e 's|^https\?://||' -e 's|/.*||')
    
    # Validate domain format
    if [[ "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        echo "$domain"
        return 0
    else
        return 1
    fi
}

get_user_input() {
    if [ $# -gt 0 ]; then
        INPUT="$1"
    else
        echo ""
        printf "%b%b━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%b\n" "$BOLD" "$CYAN" "$RESET"
        printf "%b%b           Target Configuration%b\n" "$BOLD" "$CYAN" "$RESET"
        printf "%b%b━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%b\n" "$BOLD" "$CYAN" "$RESET"
        echo ""

        read -p "$(printf '%bEnter target domain or file path:%b ' "$YELLOW" "$RESET")" INPUT
    fi

    if [ -z "$INPUT" ]; then
        log_error "Input cannot be empty"
        exit 1
    fi

    # Check if it's a file
    if [ -f "$INPUT" ]; then
        echo "$INPUT"
        return 0
    fi

    # Validate as domain
    local cleaned_domain
    if cleaned_domain=$(validate_domain "$INPUT"); then
        echo "$cleaned_domain"
        return 0
    else
        log_error "Invalid domain format: $INPUT"
        log_info "Expected: example.com or https://example.com"
        exit 1
    fi
}

prepare_targets() {
    local input=$1
    local targets_file="${OUTPUT_DIR}/targets.txt"

    if [ -f "$input" ]; then
        log_info "Reading targets from file: $input"
        while IFS= read -r line || [ -n "$line" ]; do
            if [ -n "$line" ]; then
                local cleaned
                if cleaned=$(validate_domain "$line"); then
                    echo "$cleaned"
                fi
            fi
        done < "$input" | sort -u > "$targets_file"
    else
        log_info "Using single target: $input"
        echo "$input" > "$targets_file"
    fi

    if [ ! -f "$targets_file" ]; then
        log_error "Failed to create targets file: $targets_file"
        exit 1
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
    local temp_file="${OUTPUT_DIR}/temp_gau.txt"

    if [ ! -f "$targets_file" ]; then
        log_error "Targets file not found: $targets_file"
        return 1
    fi

    log_info "Fetching URLs using gau..."
    
    # Create empty files
    : > "$gau_output"
    : > "$temp_file"
    
    # Process each target
    local target_count=0
    while IFS= read -r target || [ -n "$target" ]; do
        if [ -n "$target" ]; then
            target_count=$((target_count + 1))
            printf "  Scanning: %s\r" "$target"
            gau "$target" 2>/dev/null >> "$temp_file" || true
        fi
    done < "$targets_file"
    
    echo ""
    
    # Remove duplicates and save
    if [ -f "$temp_file" ]; then
        sort -u "$temp_file" > "$gau_output"
        rm -f "$temp_file"
    fi
    
    local count=$(wc -l < "$gau_output" 2>/dev/null || echo 0)
    if [ "$count" -eq 0 ]; then
        log_warn "No URLs found by gau"
        return 1
    fi
    
    log_success "Collected ${count} URLs from ${target_count} target(s)"
    echo "$gau_output"
}

filter_urls() {
    local gau_output=$1
    local filtered_urls="${OUTPUT_DIR}/filtered_urls.txt"
    
    log_info "Filtering URLs with query parameters..."
    
    if [ ! -f "$gau_output" ]; then
        log_error "GAU output file not found"
        return 1
    fi
    
    grep -E '\?[^=]+=.+$' "$gau_output" 2>/dev/null | \
        uro 2>/dev/null | \
        sort -u > "$filtered_urls" || true
    
    local count=$(wc -l < "$filtered_urls" 2>/dev/null || echo 0)
    if [ "$count" -eq 0 ]; then
        log_warn "No URLs with parameters found"
        return 1
    fi
    
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
    if [ "$count" -eq 0 ]; then
        log_warn "No live URLs found"
        return 1
    fi
    
    log_success "Found ${count} live URLs"
    echo "$live_urls"
}

run_nuclei_scan() {
    local live_urls=$1
    local nuclei_output="${OUTPUT_DIR}/nuclei_results.txt"
    local nuclei_json="${OUTPUT_DIR}/nuclei_results.json"
    
    log_info "Running Nuclei DAST scan (this may take a while)..."
    
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
    local report_file="${OUTPUT_DIR}/report.txt"
    
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
    echo ""
    
    # Check dependencies
    check_dependencies
    
    # Get user input
    local input=$(get_user_input "$@")
    
    # Prepare targets
    local targets_file=$(prepare_targets "$input")
    
    echo ""
    log_info "Starting URL collection..."
    echo ""
    
    # Fetch URLs
    local gau_output
    if ! gau_output=$(fetch_urls "$targets_file"); then
        log_error "Failed to collect URLs. Exiting."
        exit 1
    fi
    
    # Filter URLs
    local filtered_urls
    if ! filtered_urls=$(filter_urls "$gau_output"); then
        log_error "No URLs with parameters found. Exiting."
        exit 1
    fi
    
    # Check live URLs
    local live_urls
    if ! live_urls=$(check_live_urls "$filtered_urls"); then
        log_error "No live URLs found. Exiting."
        exit 1
    fi
    
    # Run Nuclei scan
    local nuclei_output=$(run_nuclei_scan "$live_urls")
    
    # Generate report
    local report_file=$(generate_report "$nuclei_output")
    
    # Display results
    echo ""
    printf "%b%b━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%b\n" "$BOLD" "$GREEN" "$RESET"
    printf "%b%b            Scan Complete!%b\n" "$BOLD" "$CYAN" "$RESET"
    printf "%b%b━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%b\n" "$BOLD" "$GREEN" "$RESET"
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
    printf "%bFiles generated:%b\n" "$BLUE" "$RESET"
    echo "  • Targets: ${OUTPUT_DIR}/targets.txt"
    echo "  • All URLs: ${OUTPUT_DIR}/gau_urls.txt"
    echo "  • Filtered URLs: ${OUTPUT_DIR}/filtered_urls.txt"
    echo "  • Live URLs: ${OUTPUT_DIR}/live_urls.txt"
    echo "  • Vulnerabilities: ${OUTPUT_DIR}/nuclei_results.txt"
    echo "  • JSON Report: ${OUTPUT_DIR}/nuclei_results.json"
    echo "  • Full Report: ${OUTPUT_DIR}/report.txt"
    echo "  • Log File: ${OUTPUT_DIR}/scan.log"
    echo ""
}

# Run main function
main "$@"
