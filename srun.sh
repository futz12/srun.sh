#!/usr/bin/env bash

# srun.sh - A command-line tool for the srun authentication system.
#
# Usage:
#   srun.sh login <server_address> <username> <password> [client_ip]
#   srun.sh logout <server_address> [client_ip]
#   srun.sh check <server_address>

# --- Global Settings ---
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36"
CUSTOM_BASE64_ALPHABET="LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
STANDARD_BASE64_ALPHABET="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# --- Core Functions ---

log() {
    echo >&2 "[$(date +'%Y-%m-%d %H:%M:%S')] - $1"
}

urlencode_shell() {
    local input_string="$1"
    local encoded_string=""
    local char

    local LC_ALL=C

    for (( i=0; i < ${#input_string}; i++ )); do
        char="${input_string:$i:1}"
        case "$char" in
            [a-zA-Z0-9-._~])
                encoded_string+="$char"
                ;;
            *)
                encoded_string+=$(printf '%%%02X' "'$char")
                ;;
        esac
    done
    echo "$encoded_string"
}

generate_param_i_shell() {
    local username="$1" password="$2" ip="$3" acid="$4" token="$5"

    local info_json
    info_json=$(printf '{"username":"%s","password":"%s","ip":"%s","acid":%s,"enc_ver":"srun_bx1"}' "$username" "$password" "$ip" "$acid")

    str_to_u32_array() {
        local str="$1"
        local -n arr_ref="$2"
        local include_len="$3"
        local len=${#str}

        local padded_str="$str"
        if (( len % 4 != 0 )); then
            local pad_len=$((4 - len % 4))
            for ((i=0; i<pad_len; i++)); do padded_str+='\0'; done
        fi

        mapfile -t arr_ref < <(echo -ne "$padded_str" | od -A n -t u4 | xargs -n1)

        if [[ "$include_len" == "1" ]]; then
            arr_ref+=("$len")
        fi
    }

    u32_array_to_bytes() {
        local -n arr_ref="$1"
        for val in "${arr_ref[@]}"; do
            local num_val=$((val & 0xFFFFFFFF))
            printf '\\x%02x\\x%02x\\x%02x\\x%02x' \
                $(( (num_val)       & 0xFF )) \
                $(( (num_val >> 8)  & 0xFF )) \
                $(( (num_val >> 16) & 0xFF )) \
                $(( (num_val >> 24) & 0xFF ))
        done
    }

    local msg_list key_list
    str_to_u32_array "$info_json" msg_list 1
    str_to_u32_array "$token" key_list 0
    if [ ${#key_list[@]} -eq 0 ]; then
        key_list=(0 0 0 0)
    fi

    local msg_len=${#msg_list[@]}
    local last_idx=$((msg_len - 1))
    local right=${msg_list[$last_idx]}
    local c=2654435769
    local d=0
    local MASK=4294967295

    local count=$((6 + 52 / msg_len))
    for ((i=0; i<count; i++)); do
        d=$(((d + c) & MASK))
        local e=$(((d >> 2) & 3))
        for ((p=0; p<=last_idx; p++)); do
            local left_idx=$(((p + 1) % msg_len))
            local left=${msg_list[$left_idx]}

            local term1=$(( ((right >> 5) ^ (left << 2)) & MASK ))
            local term2=$(( ((left >> 3) ^ (right << 4)) & MASK ))
            local term3=$(( (d ^ left) & MASK ))
            local key_idx=$(((p & 3) ^ e))
            local term4=$(( (key_list[key_idx] ^ right) & MASK ))

            right=$(( (msg_list[p] + (term1 + (term2 ^ term3) + term4)) & MASK ))
            msg_list[$p]=$right
        done
    done

    local encrypted_bytes
    encrypted_bytes=$(u32_array_to_bytes msg_list)
    local encoded_b64
    encoded_b64=$(echo -ne "$encrypted_bytes" | base64 -w 0 | tr "$STANDARD_BASE64_ALPHABET" "$CUSTOM_BASE64_ALPHABET")

    echo "{SRBX1}${encoded_b64}"
}

check_online_status() {
    local auth_server="$1"
    local info_url="http://${auth_server}/cgi-bin/rad_user_info"
    local response
    response=$(curl -s -A "$USER_AGENT" "$info_url")
    if ! echo "$response" | grep -q "not_online_error"; then
        echo "$response"
        return 0
    else
        return 1
    fi
}

generate_random_digits() {
    date +%s%N | head -c 16
}

do_login() {
    local auth_server="$1" username="$2" password="$3"
    local client_ip="${4:-""}"

    log "Checking current online status..."
    if online_info=$(check_online_status "$auth_server"); then
        log "You are already logged in."
        echo "User Info: $online_info"
        exit 0
    fi
    log "Proceeding with login..."

    log "Fetching ac_id and Referer..."
    local html_content
    html_content=$(curl -sSL -A "$USER_AGENT" "http://${auth_server}/index_1.html")
    local location_path_raw
    location_path_raw=$(echo "$html_content" | sed -n 's/.*content="0;url=\([^"]*\).*/\1/p')
    if [ -z "$location_path_raw" ]; then log "Error: Could not parse redirect URL." && exit 1; fi
    local location_path=${location_path_raw//'&amp;'/'&'}
    local referer_url="http://${auth_server}${location_path}"
    local ac_id
    ac_id=$(echo "$location_path" | grep -o 'ac_id=[0-9]*' | cut -d= -f2)
    log "Successfully obtained ac_id: ${ac_id}"

    log "Getting challenge token..."
    local timestamp
    timestamp=$(date +%s)
    local random_digits
    random_digits=$(generate_random_digits)
    local callback="jQuery11240${random_digits}_${timestamp}"
    local challenge_url="http://${auth_server}/cgi-bin/get_challenge?callback=${callback}&username=${username}&ip=${client_ip}&_=${timestamp}"
    local challenge_response
    challenge_response=$(curl -s -A "$USER_AGENT" --referer "$referer_url" "$challenge_url")
    local token
    token=$(echo "$challenge_response" | sed -n 's/.*"challenge":"\([^"]*\).*/\1/p')
    if [ -z "$client_ip" ]; then
        client_ip=$(echo "$challenge_response" | sed -n 's/.*"client_ip":"\([^"]*\).*/\1/p')
    fi
    if [ -z "$token" ]; then log "Error: Failed to get token." && exit 1; fi
    log "Client IP: ${client_ip}"

    log "Encrypting credentials..."
    local password_hmd5
    password_hmd5=$(echo -n "$password" | openssl dgst -md5 -hmac "$token" | cut -d' ' -f2)
    local param_i
    param_i=$(generate_param_i_shell "$username" "$password" "$client_ip" "$ac_id" "$token")
    local n=200 type=1
    local checksum_str="${token}${username}${token}${password_hmd5}${token}${ac_id}${token}${client_ip}${token}${n}${token}${type}${token}${param_i}"
    local checksum
    checksum=$(echo -n "$checksum_str" | sha1sum | cut -d' ' -f1)

    log "Sending final login request..."
    local final_timestamp
    final_timestamp=$(($(date +%s) + 2))
    local final_random_digits
    final_random_digits=$(generate_random_digits)
    local final_callback="jQuery11240${final_random_digits}_${final_timestamp}"

    local encoded_param_i
    encoded_param_i=$(urlencode_shell "$param_i")

    local login_url="http://${auth_server}/cgi-bin/srun_portal"
    login_url+="?callback=${final_callback}&action=login&username=${username}&password=\{MD5\}${password_hmd5}"
    login_url+="&ip=${client_ip}&ac_id=${ac_id}&n=${n}&type=${type}&os=Linux&name=Linux&double_stack=0"
    login_url+="&info=${encoded_param_i}&chksum=${checksum}&_=${final_timestamp}"
    local login_response
    login_response=$(curl -s -A "$USER_AGENT" --referer "$referer_url" "$login_url")

    log "Analyzing server response..."
    echo >&2 "----------------------------------------"
    echo >&2 "Server Response: $login_response"
    echo >&2 "----------------------------------------"

    if echo "$login_response" | grep -q -e '"suc_msg":"login_ok"' -e '"res":"ok"' -e 'E0000'; then
        log "Success: Login successful!"
    elif echo "$login_response" | grep -q '"error_msg":"no_response_data_error"'; then
        log "Received 'no_response_data_error', re-checking status..."
        if online_info=$(check_online_status "$auth_server"); then
            log "Re-check successful: You are now online! Login successful!"
            echo "User Info: $online_info"
        else
            log "Re-check failed: Login still unsuccessful." && exit 1
        fi
    else
        local error_msg
        error_msg=$(echo "$login_response" | sed -n 's/.*"error_msg":"\([^"]*\).*/\1/p')
        if [ -z "$error_msg" ]; then
            error_msg=$(echo "$login_response" | sed -n 's/.*"error":"\([^"]*\).*/\1/p')
        fi
        log "Failure: Login failed. Reason: ${error_msg:-'Unknown error'}" && exit 1
    fi
}

do_logout() {
    local auth_server="$1"
    local client_ip="${2:-""}"

    log "Checking current online status..."
    if ! online_info=$(check_online_status "$auth_server"); then
        log "You are currently offline, no need to logout." && exit 0
    fi

    log "Currently online, proceeding with logout..."
    local username
    username=$(echo "$online_info" | cut -d',' -f1)
    log "Auto-detected username: ${username}"

    if [ -z "$client_ip" ]; then
        client_ip=$(echo "$online_info" | cut -d',' -f9)
        log "Auto-detected online IP: ${client_ip}"
    fi

    local html_content
    html_content=$(curl -sSL -A "$USER_AGENT" "http://${auth_server}/index_1.html")
    local location_path_raw
    location_path_raw=$(echo "$html_content" | sed -n 's/.*content="0;url=\([^"]*\).*/\1/p')
    if [ -z "$location_path_raw" ]; then log "Error: Could not parse redirect URL." && exit 1; fi
    local location_path=${location_path_raw//'&amp;'/'&'}
    local referer_url="http://${auth_server}${location_path}"
    local ac_id
    ac_id=$(echo "$location_path" | grep -o 'ac_id=[0-9]*' | cut -d= -f2)

    log "Sending logout request..."
    local timestamp
    timestamp=$(date +%s)
    local random_digits
    random_digits=$(generate_random_digits)
    local callback="jQuery11240${random_digits}_${timestamp}"
    local logout_url="http://${auth_server}/cgi-bin/srun_portal"
    logout_url+="?callback=${callback}&action=logout&username=${username}&ip=${client_ip}&ac_id=${ac_id}&_=${timestamp}"
    local logout_response
    logout_response=$(curl -s -A "$USER_AGENT" --referer "$referer_url" "$logout_url")

    log "Analyzing logout response and re-checking status..."
    echo >&2 "----------------------------------------"
    echo >&2 "Server Response: $logout_response"
    echo >&2 "----------------------------------------"

    sleep 1
    if ! check_online_status "$auth_server"; then
        log "Success: Logout successful!"
    else
        log "Failure: Logout failed, server status still shows online." && exit 1
    fi
}

print_usage() {
    echo "Usage: $0 COMMAND [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  login   <server_address> <username> <password> [client_ip]    Perform login. IP is auto-detected if omitted."
    echo "  logout  <server_address> [client_ip]                        Perform logout. Username and IP are auto-detected."
    echo "  check   <server_address>                                   Check current online status."
    echo ""
}

# --- Main Logic ---
COMMAND="$1"
shift

case "$COMMAND" in
    login)
        if [ "$#" -lt 3 ]; then log "Error: login command requires at least 3 arguments." && print_usage && exit 1; fi
        do_login "$@"
        ;;
    logout)
        if [ "$#" -lt 1 ]; then log "Error: logout command requires at least 1 argument." && print_usage && exit 1; fi
        do_logout "$@"
        ;;
    check)
        if [ "$#" -ne 1 ]; then log "Error: check command requires 1 argument." && print_usage && exit 1; fi
        log "Checking online status..."
        if online_info=$(check_online_status "$1"); then
            log "Current Status: Online"
            echo "User Info: $online_info"
        else
            log "Current Status: Offline"
        fi
        ;;
    *)
        log "Error: Unknown command '$COMMAND'"
        print_usage
        exit 1
        ;;
esac
