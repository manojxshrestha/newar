#!/bin/bash

# Vuln Hunter v1.0
# by ~/.manojxshrestha

set -euo pipefail

# ANSI color codes
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
RESET='\033[0m'

# ASCII art banner
echo -e "${YELLOW}"
cat << "EOF"
____   ______  _  _______ _______ 
 /    \_/ __ \ \/ \/ /\__  \\_  __ \
|   |  \  ___/\     /  / __ \|  | \/
|___|  /\___  >\/\_/  (____  /__|   
     \/     \/             \/         
                                                                
   Vuln Hunter v1.0
         by ~/.manojxshrestha
EOF
echo -e "${RESET}"

# Configuration
CONFIG_FILE="${HOME}/.elite_recon.conf"
OUTPUT_BASE="${HOME}/Recon"
THREADS="${THREADS:-10}"
EXT_PORTS="80,443,403,8080,8443,8000,8888,8081,8181,3306,5432,6379,27017,15672,10000,9090,5900"
NUCLEI_TEMPLATES="${NUCLEI_TEMPLATES:-/home/pwn/wordlists/nuclei-templates}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Required tools
REQUIRED_TOOLS=(
    "gau" "uro" "httpx" "nuclei" "waymore" "subfinder" "ffuf" "gf" "qsreplace" "jq"
    "dalfox" "getJS" "unfurl" "tok" "gron" "xmllint" "parallel" "httprobe" "anew" "curl"
    "dig" "whois" "assetfinder" "waybackurls" "sqlmap" "subjack" "paramspider" "jwt_tool"
    "nikto" "eyewitness" "trufflehog" "arjun" "kxss" "xsrfprobe"
)

# Temporary files
GAU_FILE=$(mktemp)
JS_FILE=$(mktemp)
WAYBACK_FILE=$(mktemp)
TEMP_SUBDOMAINS=$(mktemp)

# Logging function
log() {
    local msg="$1"
    if [[ -n "${LOG_FILE:-}" ]]; then
        mkdir -p "$(dirname "$LOG_FILE")"
        echo -e "$msg" | tee -a "$LOG_FILE"
    else
        echo -e "$msg"
    fi
}

# Error handling for API calls with retries
curl_with_retry() {
    local url=$1 output=$2 retries=3
    for ((i=1; i<=retries; i++)); do
        if curl -s --retry 3 --retry-delay 2 "$url" > "$output"; then
            return 0
        fi
        log "${YELLOW}[WARN] Failed to fetch $url (attempt $i/$retries). Retrying...${RESET}"
        sleep 2
    done
    log "${RED}[ERROR] Failed to fetch $url after $retries attempts.${RESET}"
    return 1
}

# Validate domain input
validate_domain() {
    local domain=$1
    if [[ ! "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$ ]]; then
        log "${RED}[ERROR] Invalid domain: $domain${RESET}"
        return 1
    fi
    return 0
}

# Check for required tools
check_tools() {
    log "${GREEN}[INFO] Checking for required tools...${RESET}"
    local missing_required=()

    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_required+=("$tool")
        fi
    done

    for tool in "${missing_required[@]}"; do
        log "${RED}[ERROR] Required tool $tool not installed. Please install it.${RESET}"
        case $tool in
            waymore) log "${RED}[INFO] Install: pip install waymore${RESET}" ;;
            subfinder) log "${RED}[INFO] Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest${RESET}" ;;
            ffuf) log "${RED}[INFO] Install: go install github.com/ffuf/ffuf/v2@latest${RESET}" ;;
            gf) log "${RED}[INFO] Install: go install github.com/tomnomnom/gf@latest${RESET}" ;;
            qsreplace) log "${RED}[INFO] Install: go install github.com/tomnomnom/qsreplace@latest${RESET}" ;;
            jq) log "${RED}[INFO] Install: sudo apt install jq${RESET}" ;;
            dalfox) log "${RED}[INFO] Install: go install github.com/hahwul/dalfox/v2@latest${RESET}" ;;
            getJS) log "${RED}[INFO] Install: go install github.com/003random/getJS@latest${RESET}" ;;
            unfurl) log "${RED}[INFO] Install: go install github.com/tomnomnom/unfurl@latest${RESET}" ;;
            tok) log "${RED}[INFO] Install: go install github.com/tomnomnom/hacks/tok@latest${RESET}" ;;
            gron) log "${RED}[INFO] Install: go install github.com/tomnomnom/gron@latest${RESET}" ;;
            xmllint) log "${RED}[INFO] Install: sudo apt install libxml2-utils${RESET}" ;;
            parallel) log "${RED}[INFO] Install: sudo apt install parallel${RESET}" ;;
            httprobe) log "${RED}[INFO] Install: go install github.com/tomnomnom/httprobe@latest${RESET}" ;;
            anew) log "${RED}[INFO] Install: go install github.com/tomnomnom/anew@latest${RESET}" ;;
            curl) log "${RED}[INFO] Install: sudo apt install curl${RESET}" ;;
            dig) log "${RED}[INFO] Install: sudo apt install dnsutils${RESET}" ;;
            whois) log "${RED}[INFO] Install: sudo apt install whois${RESET}" ;;
            assetfinder) log "${RED}[INFO] Install: go install github.com/tomnomnom/assetfinder@latest${RESET}" ;;
            waybackurls) log "${RED}[INFO] Install: go install github.com/tomnomnom/waybackurls@latest${RESET}" ;;
            sqlmap) log "${RED}[INFO] Install: sudo apt install sqlmap${RESET}" ;;
            subjack) log "${RED}[INFO] Install: go install github.com/haccer/subjack@latest${RESET}" ;;
            paramspider) log "${RED}[INFO] Install: pip install paramspider${RESET}" ;;
            jwt_tool) log "${RED}[INFO] Install: pip install jwt_tool${RESET}" ;;
            nikto) log "${RED}[INFO] Install: sudo apt install nikto${RESET}" ;;
            eyewitness) log "${RED}[INFO] Install: pip install eyewitness${RESET}" ;;
            trufflehog) log "${RED}[INFO] Install: pip install trufflehog${RESET}" ;;
            arjun) log "${RED}[INFO] Install: pip install arjun${RESET}" ;;
            kxss) log "${RED}[INFO] Install: go install github.com/Emoe/kxss@latest${RESET}" ;;
            xsrfprobe) log "${RED}[INFO] Install: pip install xsrfprobe${RESET}" ;;
            *) log "${RED}[INFO] Install $tool using your package manager or refer to its documentation.${RESET}" ;;
        esac
    done

    if [ ${#missing_required[@]} -gt 0 ]; then
        log "${RED}[ERROR] Missing required tools. Aborting.${RESET}"
        exit 1
    fi
}

# Check for wordlists
check_wordlists() {
    log "${GREEN}[INFO] Checking for wordlists...${RESET}"
    for wordlist in "$DIR_WORDLIST" "$API_WORDLIST" "$PARAMS_WORDLIST" "$SSRF_PAYLOADS"; do
        if [ ! -f "$wordlist" ]; then
            log "${RED}[ERROR] Wordlist $wordlist not found in $WORDLIST_DIR.${RESET}"
            exit 1
        fi
    done
}

# Check for nuclei templates
check_nuclei_templates() {
    log "${GREEN}[INFO] Checking for nuclei templates...${RESET}"
    if [ ! -d "$NUCLEI_TEMPLATES" ]; then
        log "${RED}[ERROR] Nuclei templates not found at $NUCLEI_TEMPLATES. Ensure templates are in place.${RESET}"
        exit 1
    fi
    for template in "http-smuggling.yaml" "basic-cors.yaml" "cors.yaml"; do
        if [ ! -f "$NUCLEI_TEMPLATES/$template" ]; then
            log "${YELLOW}[WARN] Nuclei template $template not found. Related scans may be skipped.${RESET}"
        fi
    done
}

# Initialize output directory
init_output() {
    local domain=$1
    local domain_dir="$OUTPUT_BASE/$domain/$TIMESTAMP"
    LOG_FILE="$domain_dir/scan.log"
    
    mkdir -p "$domain_dir" "$domain_dir/waymore_responses" "$domain_dir/eyewitness"
    touch "$LOG_FILE"
    log "${GREEN}[INFO] Output directory initialized at $domain_dir${RESET}"
}

# Subdomain enumeration
enumerate_subdomains() {
    local domain=$1
    local domain_dir=$2
    local temp_subs="$domain_dir/temp_subdomains.txt"
    local subs_file="$domain_dir/subdomains.txt"
    > "$temp_subs"

    log "${GREEN}[INFO] Enumerating subdomains for $domain...${RESET}"
    subfinder -d "$domain" -silent -t "$THREADS" | tee -a "$temp_subs" &
    assetfinder --subs-only "$domain" | tee -a "$temp_subs" &
    curl_with_retry "https://crt.sh/?q=%25.$domain&output=json" "$domain_dir/crtsh.json" &
    wait

    if [ -s "$domain_dir/crtsh.json" ] && jq -e '.[].name_value' "$domain_dir/crtsh.json" >/dev/null 2>&1; then
        jq -r '.[].name_value' "$domain_dir/crtsh.json" | sed 's/\*\.//g' | tee -a "$temp_subs" &
    else
        log "${YELLOW}[WARN] Failed to parse crt.sh JSON for $domain${RESET}"
    fi
    curl_with_retry "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns" "$domain_dir/otx.json" &
    wait

    if [ -s "$domain_dir/otx.json" ] && jq -e '.passive_dns[].hostname' "$domain_dir/otx.json" >/dev/null 2>&1; then
        jq -r '.passive_dns[].hostname' "$domain_dir/otx.json" | tee -a "$temp_subs" &
    else
        log "${YELLOW}[WARN] Failed to parse OTX JSON for $domain${RESET}"
    fi
    wait

    if [ -s "$temp_subs" ]; then
        sort -u "$temp_subs" -o "$subs_file"
        log "${GREEN}[INFO] Found $(wc -l < "$subs_file") unique subdomains for $domain.${RESET}"
    else
        log "${YELLOW}[WARN] No subdomains found for $domain.${RESET}"
    fi
}

# Probe live hosts
probe_live_hosts() {
    local domain_dir=$1
    local subs_file="$domain_dir/subdomains.txt"
    local live_hosts_file="$domain_dir/live_hosts.txt"

    log "${GREEN}[INFO] Probing live hosts with httpx...${RESET}"
    if [ -s "$subs_file" ]; then
        cat "$subs_file" | httpx -silent -threads "$THREADS" -ports "$EXT_PORTS" -o "$live_hosts_file" 2>"$domain_dir/httpx_error.log"
        if [ -s "$live_hosts_file" ]; then
            log "${GREEN}[INFO] Found $(wc -l < "$live_hosts_file") live hosts.${RESET}"
        else
            log "${YELLOW}[WARN] No live hosts found. Check $domain_dir/httpx_error.log.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] No subdomains found for probing.${RESET}"
    fi
}

# Gather URLs
gather_urls() {
    local domain=$1
    local domain_dir=$2
    local live_hosts_file="$domain_dir/live_hosts.txt"
    local urls_file="$domain_dir/urls.txt"
    > "$urls_file"

    log "${GREEN}[INFO] Gathering URLs for $domain...${RESET}"
    if [ -s "$live_hosts_file" ]; then
        cat "$live_hosts_file" | gau --threads "$THREADS" | tee -a "$urls_file" &
        cat "$live_hosts_file" | waybackurls | tee -a "$urls_file" &
        waymore -d "$domain" -oU "$domain_dir/waymore_urls.txt" -oR "$domain_dir/waymore_responses" -t "$THREADS" >"$domain_dir/waymore.log" 2>&1 &
        wait
        if [ -s "$domain_dir/waymore_urls.txt" ]; then
            cat "$domain_dir/waymore_urls.txt" >> "$urls_file"
        fi
        if [ -s "$urls_file" ]; then
            sort -u "$urls_file" -o "$urls_file"
            log "${GREEN}[INFO] Collected $(wc -l < "$urls_file") URLs.${RESET}"
        else
            log "${YELLOW}[WARN] No URLs collected. Check $domain_dir/waymore.log.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] No live hosts found for URL gathering.${RESET}"
    fi
}

# Filter alive URLs
filter_alive_urls() {
    local domain_dir=$1
    local urls_file="$domain_dir/urls.txt"
    local alive_urls_file="$domain_dir/alive_urls.txt"

    log "${GREEN}[INFO] Filtering alive URLs with httpx...${RESET}"
    if [ -s "$urls_file" ]; then
        httpx -l "$urls_file" -ports "$EXT_PORTS" -threads "$THREADS" -sc -ct -fc 404,403 -mr 'content-type:.*text/html' -o "$alive_urls_file" 2>"$domain_dir/httpx_alive_error.log"
        if [ -s "$alive_urls_file" ]; then
            log "${GREEN}[INFO] Found $(wc -l < "$alive_urls_file") alive URLs.${RESET}"
        else
            log "${YELLOW}[WARN] No alive URLs found. Check $domain_dir/httpx_alive_error.log.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] No URLs found for alive filtering.${RESET}"
    fi
}

# Extract JS files and endpoints
extract_js() {
    local domain_dir=$1
    local urls_file="$domain_dir/urls.txt"
    local js_files_file="$domain_dir/js_files.txt"
    local js_endpoints_file="$domain_dir/js_endpoints.txt"

    log "${GREEN}[INFO] Extracting JS files and endpoints with getJS...${RESET}"
    if [ -s "$urls_file" ]; then
        grep -Eo 'https?://[^ ]+\.js' "$urls_file" | sort -u > "$js_files_file"
        if [ -s "$js_files_file" ]; then
            getJS --input "$js_files_file" --output "$js_endpoints_file" --resolve --insecure --verbose >"$domain_dir/getjs.log" 2>&1 &
            wait
            if [ -s "$js_endpoints_file" ]; then
                log "${GREEN}[INFO] Extracted $(wc -l < "$js_files_file") JS files and endpoints.${RESET}"
            else
                log "${YELLOW}[WARN] getJS failed to extract endpoints. Check $domain_dir/getjs.log.${RESET}"
            fi
        else
            log "${YELLOW}[WARN] No JS files found in $urls_file.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] No URLs found for JS extraction.${RESET}"
    fi
}

# Parameter discovery
discover_parameters() {
    local domain=$1
    local domain_dir=$2
    local params_file="$domain_dir/parameters.txt"

    log "${GREEN}[INFO] Running ParamSpider for parameter discovery...${RESET}"
    mkdir -p "$domain_dir/paramspider"
    paramspider_out="$domain_dir/paramspider/$domain.txt"
    if command -v paramspider >/dev/null; then
        paramspider -d "$domain" -s >"$paramspider_out" 2>"$domain_dir/paramspider_error.log" &
        wait
        if [ -s "$paramspider_out" ]; then
            cat "$paramspider_out" > "$params_file"
            log "${GREEN}[INFO] Found $(wc -l < "$params_file") parameters.${RESET}"
        else
            log "${YELLOW}[WARN] ParamSpider found no parameters or failed. Check $domain_dir/paramspider_error.log.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] ParamSpider not installed.${RESET}"
    fi
}

# Extract secrets
extract_secrets() {
    local domain=$1
    local domain_dir=$2
    local secrets_file="$domain_dir/secrets.txt"

    log "${GREEN}[INFO] Extracting secrets with waymore...${RESET}"
    if command -v waymore >/dev/null; then
        waymore -d "$domain" -s -oU "$secrets_file" -oR "$domain_dir/waymore_responses" -t "$THREADS" >"$domain_dir/waymore_secrets.log" 2>&1 &
        wait
        if [ -s "$secrets_file" ]; then
            log "${GREEN}[INFO] Secrets extraction completed. Results in $secrets_file.${RESET}"
        else
            log "${YELLOW}[WARN] No secrets extracted. Check $domain_dir/waymore_secrets.log.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] Waymore not installed.${RESET}"
    fi
}

# Nuclei scans
run_nuclei() {
    local domain_dir=$1
    local live_hosts_file="$domain_dir/live_hosts.txt"
    local alive_urls_file="$domain_dir/alive_urls.txt"
    local nuclei_results="$domain_dir/nuclei_results.txt"
    local nuclei_dast_results="$domain_dir/nuclei_dast_results.txt"

    log "${GREEN}[INFO] Running nuclei scans with custom templates...${RESET}"
    if [ -s "$live_hosts_file" ] && command -v nuclei >/dev/null; then
        nuclei -l "$live_hosts_file" -t "$NUCLEI_TEMPLATES" -o "$nuclei_results" -silent -retries 3 -rl 100 -severity low,medium,high,critical >"$domain_dir/nuclei.log" 2>&1 &
        wait
        log "${GREEN}[INFO] General nuclei scan completed. Results in $nuclei_results.${RESET}"
    else
        log "${YELLOW}[WARN] No live hosts found or nuclei not installed.${RESET}"
    fi

    log "${GREEN}[INFO] Running nuclei DAST scan on filtered URLs...${RESET}"
    if [ -s "$alive_urls_file" ] && command -v nuclei >/dev/null; then
        nuclei -dast -l "$alive_urls_file" -t "$NUCLEI_TEMPLATES" -o "$nuclei_dast_results" -silent -retries 3 -rl 100 -severity low,medium,high,critical >"$domain_dir/nuclei_dast.log" 2>&1 &
        wait
        log "${GREEN}[INFO] Nuclei DAST scan completed. Results in $nuclei_dast_results.${RESET}"
    else
        log "${YELLOW}[WARN] No alive URLs found or nuclei not installed.${RESET}"
    fi
}

# Fuzz directories and APIs
fuzz_endpoints() {
    local domain_dir=$1
    local live_hosts_file="$domain_dir/live_hosts.txt"

    log "${GREEN}[INFO] Fuzzing directories and APIs with ffuf...${RESET}"
    if [ -s "$live_hosts_file" ] && command -v ffuf >/dev/null; then
        while IFS= read -r host; do
            host_clean=$(echo "$host" | sed 's|https\?://||')
            log "${GREEN}[INFO] Fuzzing directories for $host_clean...${RESET}"
            ffuf -w "$DIR_WORDLIST" -u "https://$host_clean/FUZZ" -t "$THREADS" -p 0.1 -timeout 15 -r -mc 200,201,204,301,302,307,401,403,500 -fs 0 -o "$domain_dir/ffuf_dirs.$host_clean.csv" -of csv -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" >"$domain_dir/ffuf_dirs_$host_clean.log" 2>&1 &
            log "${GREEN}[INFO] Fuzzing APIs for $host_clean...${RESET}"
            ffuf -w "$API_WORDLIST" -u "https://$host_clean/FUZZ" -t "$THREADS" -p 0.1 -timeout 15 -r -mc 200,201,204,301,302,307,401,403,500 -fs 0 -o "$domain_dir/ffuf_api.$host_clean.csv" -of csv -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" >"$domain_dir/ffuf_api_$host_clean.log" 2>&1 &
        done < "$live_hosts_file"
        wait
        log "${GREEN}[INFO] Fuzzing completed for all hosts.${RESET}"
    else
        log "${YELLOW}[WARN] No live hosts found or ffuf not installed.${RESET}"
    fi
}

# Nikto scan
run_nikto() {
    local domain_dir=$1
    local alive_urls_file="$domain_dir/alive_urls.txt"

    log "${GREEN}[INFO] Running Nikto scans...${RESET}"
    if command -v nikto >/dev/null && [ -s "$alive_urls_file" ]; then
        while read -r url; do
            host=$(echo "$url" | sed -E 's|https?://([^/]+).*|\1|')
            nikto -host "$host" -output "$domain_dir/nikto_$(echo "$host" | sed 's/[:\/]/_/g').txt" >"$domain_dir/nikto_$host.log" 2>&1 &
        done < "$alive_urls_file"
        wait
        log "${GREEN}[INFO] Nikto scans completed.${RESET}"
    else
        log "${YELLOW}[WARN] Nikto not installed or no alive URLs found.${RESET}"
    fi
}

# Eyewitness screenshots
run_eyewitness() {
    local domain_dir=$1
    local alive_urls_file="$domain_dir/alive_urls.txt"
    local ew_out="$domain_dir/eyewitness"

    log "${GREEN}[INFO] Running Eyewitness for screenshots...${RESET}"
    if command -v eyewitness >/dev/null && [ -s "$alive_urls_file" ]; then
        eyewitness --web -f "$alive_urls_file" -d "$ew_out" >"$ew_out/eyewitness.log" 2>&1 &
        wait
        if [ -d "$ew_out/report" ]; then
            log "${GREEN}[INFO] Eyewitness screenshots saved to $ew_out.${RESET}"
        else
            log "${YELLOW}[WARN] Eyewitness failed. Check $ew_out/eyewitness.log.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] Eyewitness not installed or no alive URLs found.${RESET}"
    fi
}

# TruffleHog scan
run_trufflehog() {
    local domain_dir=$1
    local th_out="$domain_dir/trufflehog_results.txt"

    log "${GREEN}[INFO] Running TruffleHog for leaked keys and creds...${RESET}"
    if command -v trufflehog >/dev/null && [ -d "$domain_dir/waymore_responses" ]; then
        trufflehog filesystem --directory "$domain_dir/waymore_responses" > "$th_out" 2>"$domain_dir/trufflehog_error.log" &
        wait
        if [ -s "$th_out" ]; then
            log "${GREEN}[INFO] TruffleHog scan completed. Results in $th_out.${RESET}"
        else
            log "${YELLOW}[WARN] No secrets found by TruffleHog. Check $domain_dir/trufflehog_error.log.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] TruffleHog not installed or no waymore responses found.${RESET}"
    fi
}

# Arjun + KXSS for parameter fuzzing and XSS
run_arjun_kxss() {
    local domain_dir=$1
    local alive_urls_file="$domain_dir/alive_urls.txt"
    local arjun_out="$domain_dir/arjun.txt"
    local kxss_out="$domain_dir/kxss.txt"

    log "${GREEN}[INFO] Running Arjun + KXSS...${RESET}"
    if command -v arjun >/dev/null && command -v kxss >/dev/null && [ -s "$alive_urls_file" ]; then
        arjun -q -i "$alive_urls_file" -oT "$arjun_out" >"$domain_dir/arjun.log" 2>&1 &
        wait
        if [ -s "$arjun_out" ]; then
            awk -F'[?&]' '{if (NF > 1) {baseUrl=$1; for(i=2; i<=NF; i++) {split($i, param, "="); if (param[1]) print baseUrl "?" param[1] "="}}}' "$arjun_out" | sort -u > "$domain_dir/kxss_input.txt"
            if [ -s "$domain_dir/kxss_input.txt" ]; then
                kxss < "$domain_dir/kxss_input.txt" > "$kxss_out" 2>"$domain_dir/kxss_error.log"
                if [ -s "$kxss_out" ]; then
                    log "${GREEN}[INFO] Arjun + KXSS results saved to $kxss_out.${RESET}"
                else
                    log "${YELLOW}[WARN] KXSS found no vulnerabilities. Check $domain_dir/kxss_error.log.${RESET}"
                fi
            else
                log "${YELLOW}[WARN] No valid parameters for KXSS from Arjun output.${RESET}"
            fi
        else
            log "${YELLOW}[WARN] No parameters found by Arjun. Check $domain_dir/arjun.log.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] Arjun or KXSS not installed, or no alive URLs found.${RESET}"
    fi
}

# HTTP Smuggling scan
run_http_smuggling() {
    local domain_dir=$1
    local alive_urls_file="$domain_dir/alive_urls.txt"
    local smuggling_out="$domain_dir/http_smuggling.txt"

    log "${GREEN}[INFO] Running HTTP Smuggling scan...${RESET}"
    if command -v nuclei >/dev/null && [ -s "$alive_urls_file" ] && [ -f "$NUCLEI_TEMPLATES/http-smuggling.yaml" ]; then
        nuclei -l "$alive_urls_file" -t "$NUCLEI_TEMPLATES/http-smuggling.yaml" -o "$smuggling_out" -silent -retries 3 -rl 100 >"$domain_dir/http_smuggling.log" 2>&1 &
        wait
        if [ -s "$smuggling_out" ]; then
            log "${GREEN}[INFO] HTTP Smuggling scan completed. Results in $smuggling_out.${RESET}"
        else
            log "${YELLOW}[WARN] No HTTP smuggling vulnerabilities found.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] Nuclei, template, or no alive URLs found for HTTP smuggling scan.${RESET}"
    fi
}

# XSRFProbe CSRF simulation
run_xsrfprobe() {
    local domain_dir=$1
    local alive_urls_file="$domain_dir/alive_urls.txt"
    local xsrf_out="$domain_dir/xsrfprobe_results.txt"

    log "${GREEN}[INFO] Running XSRFProbe...${RESET}"
    if command -v xsrfprobe >/dev/null && [ -s "$alive_urls_file" ]; then
        xsrfprobe -l "$alive_urls_file" -o "$xsrf_out" >"$domain_dir/xsrfprobe.log" 2>&1 &
        wait
        if [ -s "$xsrf_out" ]; then
            log "${GREEN}[INFO] XSRFProbe scan completed. Results in $xsrf_out.${RESET}"
        else
            log "${YELLOW}[WARN] No CSRF vulnerabilities found by XSRFProbe.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] XSRFProbe not installed or no alive URLs found.${RESET}"
    fi
}

# Extract Google Tag Manager subdomains
extract_gtm_subdomains() {
    local domain=$1
    local domain_dir=$2
    local gtm_file="$domain_dir/gtm_subdomains.txt"

    log "${GREEN}[INFO] Extracting Google Tag Manager subdomains for $domain...${RESET}"
    curl -s "https://$domain" | grep -oP '"key","[a-zA-Z0-9.-]+\.[a-z]{2,}"' | awk -F'"' '{print $4}' | sort -u > "$gtm_file" 2>"$domain_dir/gtm_error.log"
    if [ -s "$gtm_file" ]; then
        log "${GREEN}[INFO] Extracted $(wc -l < "$gtm_file") GTM subdomains.${RESET}"
    else
        log "${YELLOW}[WARN] No GTM subdomains found. Check $domain_dir/gtm_error.log.${RESET}"
    fi
}

# XSS detection
detect_xss() {
    local domain_dir=$1
    local params_file="$domain_dir/parameters.txt"
    local xss_dalfox_file="$domain_dir/xss_vuln_dalfox.txt"
    local js_files_file="$domain_dir/js_files.txt"
    local xss_js_file="$domain_dir/xss_js_vuln.txt"

    log "${GREEN}[INFO] Detecting XSS vulnerabilities with dalfox...${RESET}"
    if command -v dalfox >/dev/null && [ -s "$params_file" ]; then
        cat "$params_file" | grep -E 'http[s]?://' | dalfox pipe -o "$xss_dalfox_file" -w "$THREADS" --waf-evasion >"$domain_dir/dalfox_params.log" 2>&1 &
        wait
        if [ -s "$xss_dalfox_file" ]; then
            log "${GREEN}[INFO] Dalfox XSS scan completed. Results in $xss_dalfox_file.${RESET}"
        else
            log "${YELLOW}[WARN] No XSS vulnerabilities found in parameters. Check $domain_dir/dalfox_params.log.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] Dalfox not installed or no valid parameters found.${RESET}"
    fi

    log "${GREEN}[INFO] Detecting XSS in JS files with dalfox...${RESET}"
    if command -v dalfox >/dev/null && [ -s "$js_files_file" ]; then
        cat "$js_files_file" | dalfox file -o "$xss_js_file" >"$domain_dir/dalfox_js.log" 2>&1 &
        wait
        if [ -s "$xss_js_file" ]; then
            log "${GREEN}[INFO] Dalfox JS XSS scan completed. Results in $xss_js_file.${RESET}"
        else
            log "${YELLOW}[WARN] No XSS vulnerabilities found in JS files. Check $domain_dir/dalfox_js.log.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] Dalfox not installed or no JS files found.${RESET}"
    fi
}

# SQLi detection
detect_sqli() {
    local domain_dir=$1
    local urls_file="$domain_dir/urls.txt"
    local sqli_file="$domain_dir/sqli_vuln.txt"

    log "${GREEN}[INFO] Detecting SQLi vulnerabilities...${RESET}"
    if command -v gf >/dev/null && [ -s "$urls_file" ]; then
        cat "$urls_file" | gf sqli > "$sqli_file" 2>"$domain_dir/gf_sqli_error.log"
        if [ -s "$sqli_file" ]; then
            sqlmap -m "$sqli_file" --batch --threads="$THREADS" --output-dir="$domain_dir/sqlmap_output" >"$domain_dir/sqlmap.log" 2>&1 &
            wait
            log "${GREEN}[INFO] Sqlmap scan completed. Results in $domain_dir/sqlmap_output.${RESET}"
        else
            log "${YELLOW}[WARN] No SQLi URLs found for sqlmap. Check $domain_dir/gf_sqli_error.log.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] gf not installed or no URLs found for SQLi detection.${RESET}"
    fi
}

# LFI detection
detect_lfi() {
    local domain_dir=$1
    local urls_file="$domain_dir/urls.txt"
    local lfi_file="$domain_dir/lfi_vuln.txt"

    log "${GREEN}[INFO] Detecting LFI vulnerabilities...${RESET}"
    if command -v gf >/dev/null && command -v qsreplace >/dev/null && [ -s "$urls_file" ]; then
        cat "$urls_file" | gf lfi | qsreplace '.../../' > "$lfi_file" 2>"$domain_dir/lfi_error.log"
        if [ -s "$lfi_file" ]; then
            log "${GREEN}[INFO] LFI detection completed. Results in $lfi_file.${RESET}"
        else
            log "${YELLOW}[WARN] No LFI vulnerabilities found. Check $domain_dir/lfi_error.log.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] gf or qsreplace not installed, or no URLs found for LFI detection.${RESET}"
    fi
}

# Open redirect detection
detect_open_redirect() {
    local domain_dir=$1
    local urls_file="$domain_dir/urls.txt"
    local open_redirect_file="$domain_dir/open_redirect_vuln.txt"

    log "${GREEN}[INFO] Detecting open redirect vulnerabilities...${RESET}"
    if command -v gf >/dev/null && command -v qsreplace >/dev/null && [ -s "$urls_file" ]; then
        cat "$urls_file" | gf redirect | qsreplace 'https://evil.com' > "$open_redirect_file" 2>"$domain_dir/open_redirect_error.log"
        if [ -s "$open_redirect_file" ]; then
            log "${GREEN}[INFO] Open redirect detection completed. Results in $open_redirect_file.${RESET}"
        else
            log "${YELLOW}[WARN] No open redirect vulnerabilities found. Check $domain_dir/open_redirect_error.log.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] gf or qsreplace not installed, or no URLs found for open redirect detection.${RESET}"
    fi
}

# Prototype pollution detection
detect_prototype_pollution() {
    local domain_dir=$1
    local urls_file="$domain_dir/urls.txt"
    local proto_file="$domain_dir/prototype_vuln.txt"

    log "${GREEN}[INFO] Detecting prototype pollution vulnerabilities...${RESET}"
    if command -v gf >/dev/null && command -v qsreplace >/dev/null && [ -s "$urls_file" ]; then
        cat "$urls_file" | gf prototype | qsreplace '__proto__=polluted' > "$proto_file" 2>"$domain_dir/prototype_error.log"
        if [ -s "$proto_file" ]; then
            log "${GREEN}[INFO] Prototype pollution detection completed. Results in $proto_file.${RESET}"
        else
            log "${YELLOW}[WARN] No prototype pollution vulnerabilities found. Check $domain_dir/prototype_error.log.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] gf or qsreplace not installed, or no URLs found for prototype pollution detection.${RESET}"
    fi
}

# Sitemap extraction
extract_sitemap() {
    local domain_dir=$1
    local live_hosts_file="$domain_dir/live_hosts.txt"
    local sitemap_file="$domain_dir/sitemap_urls.txt"

    log "${GREEN}[INFO] Extracting sitemap URLs...${RESET}"
    > "$sitemap_file"
    if [ -s "$live_hosts_file" ]; then
        while IFS= read -r host; do
            sitemap_content=$(curl -s "https://$host/sitemap.xml")
            if echo "$sitemap_content" | xmllint --noout - 2>/dev/null; then
                echo "$sitemap_content" | xmllint --xpath '//url/loc/text()' - 2>/dev/null >> "$sitemap_file" &
            else
                log "${YELLOW}[WARN] Invalid sitemap XML for $host${RESET}"
            fi
        done < "$live_hosts_file"
        wait
        if [ -s "$sitemap_file" ]; then
            log "${GREEN}[INFO] Sitemap extraction completed. Results in $sitemap_file.${RESET}"
        else
            log "${YELLOW}[WARN] No sitemap URLs extracted.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] No live hosts found for sitemap extraction.${RESET}"
    fi
}

# Swagger endpoints
extract_swagger() {
    local domain_dir=$1
    local live_hosts_file="$domain_dir/live_hosts.txt"
    local swagger_file="$domain_dir/swagger_endpoints.txt"

    log "${GREEN}[INFO] Extracting swagger.json endpoints...${RESET}"
    > "$swagger_file"
    if [ -s "$live_hosts_file" ]; then
        while IFS= read -r host; do
            curl -s "https://$host/swagger.json" | jq -r '.paths | keys[]' >> "$swagger_file" 2>"$domain_dir/swagger_error.log" &
        done < "$live_hosts_file"
        wait
        if [ -s "$swagger_file" ]; then
            log "${GREEN}[INFO] Swagger extraction completed. Results in $swagger_file.${RESET}"
        else
            log "${YELLOW}[WARN] No Swagger endpoints found. Check $domain_dir/swagger_error.log.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] No live hosts found for Swagger extraction.${RESET}"
    fi
}

# CORS misconfiguration
check_cors() {
    local domain_dir=$1
    local live_hosts_file="$domain_dir/live_hosts.txt"
    local cors_file="$domain_dir/cors_vuln.txt"

    log "${GREEN}[INFO] Detecting CORS misconfigurations...${RESET}"
    > "$cors_file"
    if [ -s "$live_hosts_file" ]; then
        while IFS= read -r host; do
            cors_header=$(curl -s -I "https://$host" | grep -i 'access-control-allow-origin')
            if [[ -n "$cors_header" ]]; then
                echo "$host - $cors_header" >> "$cors_file"
            fi
        done < "$live_hosts_file"
        if [ -s "$cors_file" ]; then
            log "${GREEN}[INFO] CORS check completed. Results in $cors_file.${RESET}"
        else
            log "${YELLOW}[WARN] No CORS misconfigurations found.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] No live hosts found for CORS check.${RESET}"
    fi
}

# CSP domains
check_csp() {
    local domain_dir=$1
    local live_hosts_file="$domain_dir/live_hosts.txt"
    local csp_file="$domain_dir/csp_domains.txt"

    log "${GREEN}[INFO] Extracting Content Security Policy (CSP) domains...${RESET}"
    > "$csp_file"
    if [ -s "$live_hosts_file" ]; then
        while IFS= read -r host; do
            csp_header=$(curl -s -I "https://$host" | grep -i 'content-security-policy')
            if [[ -n "$csp_header" ]]; then
                echo "$host - $csp_header" >> "$csp_file"
            fi
        done < "$live_hosts_file"
        if [ -s "$csp_file" ]; then
            log "${GREEN}[INFO] CSP check completed. Results in $csp_file.${RESET}"
        else
            log "${YELLOW}[WARN] No CSP domains found.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] No live hosts found for CSP check.${RESET}"
    fi
}

# Subdomain takeover
check_subdomain_takeover() {
    local domain_dir=$1
    local subs_file="$domain_dir/subdomains.txt"
    local takeover_file="$domain_dir/subdomain_takeover.txt"

    log "${GREEN}[INFO] Checking for subdomain takeover vulnerabilities...${RESET}"
    if command -v subjack >/dev/null && [ -s "$subs_file" ]; then
        subjack -w "$subs_file" -t 100 -timeout 30 -o "$takeover_file" -ssl >"$domain_dir/subjack.log" 2>&1 &
        wait
        if [ -s "$takeover_file" ]; then
            log "${GREEN}[INFO] Subdomain takeover check completed. Results in $takeover_file.${RESET}"
        else
            log "${YELLOW}[WARN] No subdomain takeover vulnerabilities found.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] subjack not installed or no subdomains found.${RESET}"
    fi
}

# GraphQL endpoint discovery
discover_graphql() {
    local domain_dir=$1
    local live_hosts_file="$domain_dir/live_hosts.txt"
    local graphql_file="$domain_dir/graphql_endpoints.txt"

    log "${GREEN}[INFO] Discovering GraphQL endpoints...${RESET}"
    > "$graphql_file"
    if [ -s "$live_hosts_file" ]; then
        for endpoint in "/graphql" "/api/graphql" "/graphiql" "/v1/graphql"; do
            while IFS= read -r host; do
                if curl -s "https://$host$endpoint" | grep -q "GraphQL"; then
                    echo "https://$host$endpoint" >> "$graphql_file"
                fi
            done < "$live_hosts_file"
        done
        if [ -s "$graphql_file" ]; then
            log "${GREEN}[INFO] GraphQL discovery completed. Results in $graphql_file.${RESET}"
        else
            log "${YELLOW}[WARN] No GraphQL endpoints found.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] No live hosts found for GraphQL discovery.${RESET}"
    fi
}

# SSRF testing
test_ssrf() {
    local domain_dir=$1
    local params_file="$domain_dir/parameters.txt"
    local ssrf_file="$domain_dir/ssrf_vuln.txt"

    log "${GREEN}[INFO] Testing for SSRF vulnerabilities...${RESET}"
    if [ -f "$SSRF_PAYLOADS" ] && [ -s "$params_file" ]; then
        while IFS= read -r payload; do
            cat "$params_file" | qsreplace -a "$payload" | httpx -silent -sc -threads "$THREADS" -o "$domain_dir/ssrf_temp_$$.txt" &
        done < "$SSRF_PAYLOADS"
        wait
        if [ -s "$domain_dir/ssrf_temp_$$.txt" ]; then
            cat "$domain_dir/ssrf_temp_$$.txt" | grep -E '200|301|302|500' > "$ssrf_file"
            log "${GREEN}[INFO] SSRF testing completed. Results in $ssrf_file.${RESET}"
        else
            log "${YELLOW}[WARN] No SSRF vulnerabilities found.${RESET}"
        fi
        rm -f "$domain_dir/ssrf_temp_$$.txt"
    else
        log "${YELLOW}[WARN] SSRF payloads or parameters not found.${RESET}"
    fi
}

# Cloud misconfiguration checks
check_cloud_misconfig() {
    local domain_dir=$1
    local subs_file="$domain_dir/subdomains.txt"
    local cloud_file="$domain_dir/cloud_misconfig.txt"

    log "${GREEN}[INFO] Checking for cloud misconfigurations (S3 buckets)...${RESET}"
    > "$cloud_file"
    if [ -s "$subs_file" ]; then
        while IFS= read -r subdomain; do
            s3_url="http://$subdomain.s3.amazonaws.com"
            if curl -s "$s3_url" | grep -q "ListBucketResult"; then
                echo "Potential open S3 bucket: $s3_url" >> "$cloud_file"
            fi
        done < "$subs_file"
        if [ -s "$cloud_file" ]; then
            log "${GREEN}[INFO] Cloud misconfiguration check completed. Results in $cloud_file.${RESET}"
        else
            log "${YELLOW}[WARN] No cloud misconfigurations found.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] No subdomains found for cloud misconfiguration check.${RESET}"
    fi
}

# JWT analysis
analyze_jwt() {
    local domain_dir=$1
    local js_files_file="$domain_dir/js_files.txt"
    local jwt_file="$domain_dir/jwt_vuln.txt"

    log "${GREEN}[INFO] Analyzing JWT tokens...${RESET}"
    > "$jwt_file"
    if command -v jwt_tool >/dev/null && [ -s "$js_files_file" ]; then
        while IFS= read -r js_file; do
            jwt_tokens=$(curl -s "$js_file" | grep -Eo 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
            if [ -n "$jwt_tokens" ]; then
                echo "$js_file contains JWTs:" >> "$jwt_file"
                echo "$jwt_tokens" | while read -r token; do
                    if echo "$token" | grep -q '^eyJ'; then
                        jwt_tool -M scan "$token" >> "$jwt_file" 2>"$domain_dir/jwt_error.log" || log "${YELLOW}[WARN] jwt_tool failed for token in $js_file${RESET}"
                    else
                        log "${YELLOW}[WARN] Invalid JWT format in $js_file${RESET}"
                    fi
                done
            fi
        done < "$js_files_file"
        if [ -s "$jwt_file" ]; then
            log "${GREEN}[INFO] JWT analysis completed. Results in $jwt_file.${RESET}"
        else
            log "${YELLOW}[WARN] No JWT tokens found. Check $domain_dir/jwt_error.log.${RESET}"
        fi
    else
        log "${YELLOW}[WARN] jwt_tool not installed or no JS files found.${RESET}"
    fi
}

# Process domain
process_domain() {
    local domain=$1
    local domain_dir="$OUTPUT_BASE/$domain/$TIMESTAMP"

    if ! validate_domain "$domain"; then
        return 1
    fi

    log "${GREEN}[INFO] Starting scan for domain: $domain${RESET}"

    init_output "$domain"
    enumerate_subdomains "$domain" "$domain_dir"
    probe_live_hosts "$domain_dir"
    gather_urls "$domain" "$domain_dir"
    filter_alive_urls "$domain_dir"
    extract_js "$domain_dir"
    discover_parameters "$domain" "$domain_dir"
    extract_secrets "$domain" "$domain_dir"
    run_nuclei "$domain_dir"
    fuzz_endpoints "$domain_dir"
    run_nikto "$domain_dir"
    run_eyewitness "$domain_dir"
    run_trufflehog "$domain_dir"
    run_arjun_kxss "$domain_dir"
    run_http_smuggling "$domain_dir"
    run_xsrfprobe "$domain_dir"
    extract_gtm_subdomains "$domain" "$domain_dir"
    detect_xss "$domain_dir"
    detect_sqli "$domain_dir"
    detect_lfi "$domain_dir"
    detect_open_redirect "$domain_dir"
    detect_prototype_pollution "$domain_dir"
    extract_sitemap "$domain_dir"
    extract_swagger "$domain_dir"
    check_cors "$domain_dir"
    check_csp "$domain_dir"
    check_subdomain_takeover "$domain_dir"
    discover_graphql "$domain_dir"
    test_ssrf "$domain_dir"
    check_cloud_misconfig "$domain_dir"
    analyze_jwt "$domain_dir"

    log "${GREEN}[INFO] Scan completed for domain: $domain${RESET}"
}

# Generate summary report
generate_report() {
    local domain=$1
    local domain_dir="$OUTPUT_BASE/$domain/$TIMESTAMP"
    local report_file="$domain_dir/summary_report.txt"

    {
        echo "[SUMMARY REPORT for $domain]"
        [ -f "$domain_dir/subdomains.txt" ] && echo "Subdomains found: $(wc -l < "$domain_dir/subdomains.txt")"
        [ -f "$domain_dir/live_hosts.txt" ] && echo "Live hosts: $(wc -l < "$domain_dir/live_hosts.txt")"
        [ -f "$domain_dir/urls.txt" ] && echo "URLs collected: $(wc -l < "$domain_dir/urls.txt")"
        [ -f "$domain_dir/xss_vuln_dalfox.txt" ] && echo "XSS vulnerabilities: $(wc -l < "$domain_dir/xss_vuln_dalfox.txt")"
        [ -f "$domain_dir/sqli_vuln.txt" ] && echo "SQLi vulnerabilities: $(wc -l < "$domain_dir/sqli_vuln.txt")"
        [ -f "$domain_dir/ssrf_vuln.txt" ] && echo "SSRF vulnerabilities: $(wc -l < "$domain_dir/ssrf_vuln.txt")"
        [ -f "$domain_dir/cloud_misconfig.txt" ] && echo "Cloud misconfigurations: $(wc -l < "$domain_dir/cloud_misconfig.txt")"
        echo "Results saved in: $domain_dir"
    } | tee "$report_file"
    log "${GREEN}[INFO] Summary report saved to $report_file${RESET}"
}

# Main execution
main() {
    trap 'rm -f "$GAU_FILE" "$JS_FILE" "$WAYBACK_FILE" "$TEMP_SUBDOMAINS"; log "${YELLOW}[INFO] Cleaned up temporary files.${RESET}"' EXIT INT TERM

    # Prompt for domain or subdomains list
    echo -n "Enter the domain or subdomains list: "
    read -r DOMAIN_INPUT
    if [[ -z "$DOMAIN_INPUT" ]]; then
        log "${RED}[ERROR] No domain or subdomains list provided.${RESET}"
        exit 1
    fi

    # Prompt for wordlist path
    echo -n "Enter path to wordlist: "
    read -r WORDLIST_DIR
    if [[ -z "$WORDLIST_DIR" ]] || [[ ! -d "$WORDLIST_DIR" ]]; then
        log "${RED}[ERROR] Invalid or missing wordlist directory: $WORDLIST_DIR${RESET}"
        exit 1
    fi

    # Set wordlist paths
    DIR_WORDLIST="$WORDLIST_DIR/directory-list-2.3-medium.txt"
    API_WORDLIST="$WORDLIST_DIR/httparchive_apiroutes_2024_05_28.txt"
    PARAMS_WORDLIST="$WORDLIST_DIR/parameters.txt"
    SSRF_PAYLOADS="$WORDLIST_DIR/ssrf_payloads.txt"

    # Check if input is a file or a single domain
    if [[ -f "$DOMAIN_INPUT" ]]; then
        DOMAINS_FILE="$DOMAIN_INPUT"
    else
        # Create a temporary file for a single domain
        DOMAINS_FILE=$(mktemp)
        echo "$DOMAIN_INPUT" > "$DOMAINS_FILE"
        trap 'rm -f "$DOMAINS_FILE"; rm -f "$GAU_FILE" "$JS_FILE" "$WAYBACK_FILE" "$TEMP_SUBDOMAINS"; log "${YELLOW}[INFO] Cleaned up temporary files.${RESET}"' EXIT INT TERM
    fi

    check_tools
    check_wordlists
    check_nuclei_templates

    if [ ! -f "$DOMAINS_FILE" ]; then
        log "${RED}[ERROR] Domains file $DOMAINS_FILE not found.${RESET}"
        exit 1
    fi

    local skipped_domains=0
    local processed_domains=0
    while read -r domain; do
        if [[ -n "$domain" ]]; then
            if process_domain "$domain"; then
                generate_report "$domain"
                ((processed_domains++))
            else
                ((skipped_domains++))
                log "${YELLOW}[INFO] Skipped processing for $domain due to validation failure.${RESET}"
            fi
        fi
    done < "$DOMAINS_FILE"

    log "${GREEN}[INFO] Scan completed. Processed $processed_domains domains, skipped $skipped_domains domains.${RESET}"
}

main
