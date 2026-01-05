#!/bin/bash
VER='1.0.1 (Extracted Global Only)'
UA_BROWSER="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
UA_SEC_CH_UA='"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"'
UA_ANDROID="Mozilla/5.0 (Linux; Android 10; Pixel 4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36"

# --- 基础工具函数 ---
color_print() {
    Font_Black="\033[30m"
    Font_Red="\033[31m"
    Font_Green="\033[32m"
    Font_Yellow="\033[33m"
    Font_Blue="\033[34m"
    Font_Purple="\033[35m"
    Font_SkyBlue="\033[36m"
    Font_White="\033[37m"
    Font_Suffix="\033[0m"
}
command_exists() {
    command -v "$1" > /dev/null 2>&1
}
gen_uuid() {
    if [ -f /proc/sys/kernel/random/uuid ]; then
        local genuuid=$(cat /proc/sys/kernel/random/uuid)
        echo "${genuuid}"
        return 0
    fi
    if command_exists uuidgen; then
        local genuuid=$(uuidgen)
        echo "${genuuid}"
        return 0
    fi
    return 1
}
resolve_ip_address() {
    local domain="$1"
    local recordType="$2"
    if command_exists nslookup && [ "$OS_WINDOWS" != 1 ]; then
        if [ "$recordType" == 'AAAA' ]; then
            nslookup -q=AAAA "${domain}" | grep -woP "Address: \K[\d:a-f]+"
            return
        else
            nslookup -q=A "${domain}" | grep -woP "Address: \K[\d.]+"
            return
        fi
    fi
    if command_exists dig; then
        if [ "$recordType" == 'AAAA' ]; then
            dig +short "${domain}" AAAA
            return
        else
            dig +short "${domain}" A
            return
        fi
    fi
}
validate_intranet() {
    local tmpresult=$(echo "$1" | grep -E '(^|\s)(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|100\.([6-9][4-9]|1[0-2][0-7])\.|169\.254\.|127\.)')
    if [ -z "$tmpresult" ]; then
        return 1
    fi
    return 0
}
check_net_connctivity() {
    if [ "$1" == 4 ]; then
        local result1=$(curl -4 ${CURL_OPTS} -fs 'https://www.google.com' -o /dev/null -s -w '%{http_code}\n')
        if [ "$result1" != '000' ]; then return 0; fi
    fi
    if [ "$1" == 6 ]; then
        local result2=$(curl -6 ${CURL_OPTS} -fs 'https://www.google.com' -o /dev/null -s -w '%{http_code}\n')
        if [ "$result2" != '000' ]; then return 0; fi
    fi
    return 1
}
check_os_type() {
    OS_TYPE='linux'
    if [ -n "$(uname -a | grep -i 'Darwin')" ]; then OS_MACOS=1; fi
    if [ -n "$(uname -a | grep -i 'android')" ]; then OS_ANDROID=1; fi
}
check_dependencies() {
    if ! command_exists curl; then echo -e "${Font_Red}Error: curl is missing.${Font_Suffix}"; exit 1; fi
    if ! command_exists openssl; then echo -e "${Font_Red}Error: openssl is missing.${Font_Suffix}"; exit 1; fi
}
process() {
    CURL_OPTS="--max-time 10 --retry 3 --retry-max-time 20"
}
delay() {
    sleep $1
}
download_extra_data() {
    MEDIA_COOKIE=$(curl ${CURL_OPTS} -s "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/cookies")
    IATACODE=$(curl ${CURL_OPTS} -s "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/reference/IATACode.txt")
    IATACODE2=$(curl ${CURL_OPTS} -s "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/reference/IATACode2.txt")
}
get_ip_info() {
    LOCAL_IP_ASTERISK=''
    LOCAL_ISP=''
    local local_ip=$(curl ${CURL_DEFAULT_OPTS} -s https://api64.ipify.org --user-agent "${UA_BROWSER}")
    local get_local_isp=$(curl ${CURL_DEFAULT_OPTS} -s "https://api.ip.sb/geoip/${local_ip}" --user-agent "${UA_BROWSER}")
    if echo "$local_ip" | grep -q ':'; then
        LOCAL_IP_ASTERISK=$(awk -F":" '{print $1":"$2":"$3":*:*"}' <<<"${local_ip}")
    else
        LOCAL_IP_ASTERISK=$(awk -F"." '{print $1"."$2".*.*"}' <<<"${local_ip}")
    fi
    LOCAL_ISP=$(echo "$get_local_isp" | sed -n 's/.*"organization":"\([^"]*\)".*/\1/p')
}
show_region() {
    echo -e "${Font_Yellow} ---${1}---${Font_Suffix}"
}
echo_result() {
    for ((i=0;i<${#array[@]};i++)); do
        echo "$result" | grep "${array[i]}"
        delay 0.03
    done
}

# --- 测试函数集 (仅保留 Option 0 所需) ---

function GameTest_Steam() {
    if [ "${USE_IPV6}" == 1 ]; then
        echo -n -e "\r Steam Currency:\t\t\t${Font_Red}IPv6 Is Not Currently Supported${Font_Suffix}\n"
        return
    fi
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://store.steampowered.com/app/761830' --user-agent "${UA_BROWSER}")
    local result=$(echo "$tmpresult" | grep 'priceCurrency' | cut -d '"' -f4)
    if [ -z "$result" ]; then
        echo -n -e "\r Steam Currency:\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    fi
    echo -n -e "\r Steam Currency:\t\t\t${Font_Green}${result}${Font_Suffix}\n"
}

function GameTest_SDGGGE() {
    local result=$(echo -n "1CR6PntuLeI3yaCYAZdOPxn18bOFYJxUiYtcavqqAHDCjc3C/wozplHYwfhykUStp7Bb/LAhV8aWQkS9sLliHCIgXBvDsWe4pwXvV3cSXkoaBfL23/zytEHlAatOi/32UVYLJhyUsegCRMMGREr2fXqyx970imQ35hqWVj/MRTHS9Bi8iqo9nIqSDTcQqVn3BbuyhJcz52nhfSda2may3QVHkH9QDdFjW9S/2re2cxE3iaE/DUbjB9H8KUpihQB1Emf88I0241ea7CAI1jHel6aZ5Ul4XjTf8ug3Rl/T80A=" | base64 -d | curl ${CURL_DEFAULT_OPTS} -s  'https://api.gl.eternal.channel.or.jp/api/pvt/consent/view?user_id=649635267711712178' -X POST -H 'Host: api.gl.eternal.channel.or.jp' -H 'Content-Type: application/protobuf' --data-binary @- -w %{http_code} -o /dev/null)
    case "$result" in
        '200') echo -n -e "\r SD Gundam G Generation Eternal:\t${Font_Green}Yes${Font_Suffix}\n" ;;
        '483') echo -n -e "\r SD Gundam G Generation Eternal:\t${Font_Red}No${Font_Suffix}\n" ;;
        *) echo -n -e "\r SD Gundam G Generation Eternal:\t${Font_Red}Failed${Font_Suffix}\n" ;;
    esac
}

function MediaUnlockTest_Netflix() {
    local tmpresult1=$(curl ${CURL_DEFAULT_OPTS} -fsL 'https://www.netflix.com/title/81280792' --user-agent "${UA_BROWSER}")
    local tmpresult2=$(curl ${CURL_DEFAULT_OPTS} -fsL 'https://www.netflix.com/title/70143836' --user-agent "${UA_BROWSER}")
    if [ -z "${tmpresult1}" ] || [ -z "${tmpresult2}" ]; then
        echo -n -e "\r Netflix:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local result1=$(echo ${tmpresult1} | grep 'Oh no!')
    local result2=$(echo ${tmpresult2} | grep 'Oh no!')
    if [ -n "${result1}" ] && [ -n "${result2}" ]; then
        echo -n -e "\r Netflix:\t\t\t\t${Font_Yellow}Originals Only${Font_Suffix}\n"
        return
    fi
    if [ -z "${result1}" ] || [ -z "${result2}" ]; then
        local region=$(echo "$tmpresult1" | sed -n 's/.*"id":"\([^"]*\)".*"countryName":"[^"]*".*/\1/p'| head -n1)
        echo -n -e "\r Netflix:\t\t\t\t${Font_Green}Yes (Region: ${region})${Font_Suffix}\n"
        return
    fi
    echo -n -e "\r Netflix:\t\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
}

function MediaUnlockTest_DisneyPlus() {
    if [ "${USE_IPV6}" == 1 ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}IPv6 Is Not Currently Supported${Font_Suffix}\n"
        return
    fi
    local tempresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://disney.api.edge.bamgrid.com/devices' -X POST -H "authorization: Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -H "content-type: application/json; charset=UTF-8" -d '{"deviceFamily":"browser","applicationRuntime":"chrome","deviceProfile":"windows","attributes":{}}' --user-agent "${UA_BROWSER}")
    if [ -n "$(echo "$tempresult" | grep -i '403 ERROR')" ]; then echo -n -e "\r Disney+:\t\t\t\t${Font_Red}No (IP Banned)${Font_Suffix}\n"; return; fi
    local assertion=$(echo "$tempresult" | grep -woP '"assertion"\s{0,}:\s{0,}"\K[^"]+')
    if [ -z "$assertion" ]; then echo -n -e "\r Disney+:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"; return; fi
    
    local preDisneyCookie=$(echo "$MEDIA_COOKIE" | sed -n '1p')
    local disneyCookie=$(echo "$preDisneyCookie" | sed "s/DISNEYASSERTION/${assertion}/g")
    local tokenContent=$(curl ${CURL_DEFAULT_OPTS} -s 'https://disney.api.edge.bamgrid.com/token' -X POST -H "authorization: Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -d "${disneyCookie}" --user-agent "${UA_BROWSER}")
    if [ -n "$(echo "$tokenContent" | grep -i 'forbidden-location')" ]; then echo -n -e "\r Disney+:\t\t\t\t${Font_Red}No${Font_Suffix}\n"; return; fi
    
    local refreshToken=$(echo "$tokenContent" | grep -woP '"refresh_token"\s{0,}:\s{0,}"\K[^"]+')
    local fakeContent=$(echo "$MEDIA_COOKIE" | sed -n '8p')
    local disneyContent=$(echo "$fakeContent" | sed "s/ILOVEDISNEY/${refreshToken}/g")
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://disney.api.edge.bamgrid.com/graph/v1/device/graphql' -X POST -H "authorization: ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -d "${disneyContent}" --user-agent "${UA_BROWSER}")
    local region=$(echo "$tmpresult" | grep -woP '"countryCode"\s{0,}:\s{0,}"\K[^"]+')
    local inSupportedLocation=$(echo "$tmpresult" | grep -woP '"inSupportedLocation"\s{0,}:\s{0,}\K(false|true)')
    
    if [ "$inSupportedLocation" == 'true' ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Green}Yes (Region: ${region})${Font_Suffix}\n"
    elif [ "$region" == 'JP' ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Green}Yes (Region: JP)${Font_Suffix}\n"
    else
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_Dazn() {
    if [ "${USE_IPV6}" == 1 ]; then echo -n -e "\r Dazn:\t\t\t\t\t${Font_Red}IPv6 Is Not Currently Supported${Font_Suffix}\n"; return; fi
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://startup.core.indazn.com/misl/v5/Startup' -H 'content-type: application/json' --data-raw '{"Version":"2","LandingPageKey":"generic","Languages":"zh-CN","Platform":"web","Manufacturer":"","PromoCode":"","PlatformAttributes":{}}' --user-agent "${UA_BROWSER}")
    if echo "$tmpresult" | grep -qi "Security policy has been breached"; then echo -n -e "\r Dazn:\t\t\t\t\t${Font_Red}IP Banned${Font_Suffix}\n"; return; fi
    local result=$(echo "$tmpresult" | grep -woP '"isAllowed"\s{0,}:\s{0,}\K(false|true)')
    local region=$(echo "$tmpresult" | grep -woP '"GeolocatedCountry"\s{0,}:\s{0,}"\K[^"]+' | tr a-z A-Z)
    if [ "$result" == 'true' ]; then
        echo -n -e "\r Dazn:\t\t\t\t\t${Font_Green}Yes (Region: ${region})${Font_Suffix}\n"
    else
        echo -n -e "\r Dazn:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_YouTube_Premium() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://www.youtube.com/premium' -H 'accept-language: en-US,en;q=0.9' --user-agent "${UA_BROWSER}")
    if [ -n "$(echo "$tmpresult" | grep 'www.google.cn')" ]; then echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}No${Font_Suffix} ${Font_Green} (Region: CN)${Font_Suffix} \n"; return; fi
    local region=$(echo "$tmpresult" | grep -woP '"INNERTUBE_CONTEXT_GL"\s{0,}:\s{0,}"\K[^"]+')
    local isAvailable=$(echo "$tmpresult" | grep -i 'ad-free')
    if [ -n "$isAvailable" ]; then
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Green}Yes (Region: ${region})${Font_Suffix}\n"
    else
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi
}

function RegionTest_YouTubeCDN() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://redirector.googlevideo.com/report_mapping' --user-agent "${UA_BROWSER}")
    local iata=$(echo "$tmpresult" | grep '=>' | awk "NR==1" | awk '{print $3}' | cut -f2 -d'-' | cut -c 1-3 | tr a-z A-Z)
    local isIDC=$(echo "$tmpresult" | grep 'router')
    if [ -n "$iata" ]; then
        if [ -n "$isIDC" ]; then
            echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Green}${iata}${Font_Suffix}\n"
        else
            echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Yellow}${iata} (ISP)${Font_Suffix}\n"
        fi
    else
        echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi
}

function RegionTest_NetflixCDN() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://api.fast.com/netflix/speedtest/v2?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=1' --user-agent "${UA_BROWSER}")
    local cdnDomain=$(echo "$tmpresult" | grep -woP '"url":"\K[^"]+' | awk -F'[/:]' '{print $4}')
    if [ -z "$cdnDomain" ]; then echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Red}Failed${Font_Suffix}\n"; return; fi
    
    local iata=$(echo "$cdnDomain" | cut -f3 -d'-' | sed 's/.\{3\}$//' | tr a-z A-Z)
    if [ -n "$iata" ]; then
        echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Green}${iata}${Font_Suffix}\n"
    else
        echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_PrimeVideo() {
    if [ "${USE_IPV6}" == 1 ]; then echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}IPv6 Is Not Currently Supported${Font_Suffix}\n"; return; fi
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://www.primevideo.com' --user-agent "${UA_BROWSER}")
    local region=$(echo "$tmpresult" | grep -woP '"currentTerritory":"\K[^"]+' | head -n 1)
    if [ -n "$region" ]; then
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Green}Yes (Region: ${region})${Font_Suffix}\n"
    elif [ -n "$(echo "$tmpresult" | grep -i 'isServiceRestricted')" ]; then
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}No${Font_Suffix}\n"
    else
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_TVBAnywhere() {
    if [ "${USE_IPV6}" == 1 ]; then echo -n -e "\r TVBAnywhere+:\t\t\t\t${Font_Red}IPv6 Is Not Currently Supported${Font_Suffix}\n"; return; fi
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://uapisfm.tvbanywhere.com.sg/geoip/check/platform/android' --user-agent "${UA_BROWSER}")
    local result=$(echo "$tmpresult" | grep -woP '"allow_in_this_country"\s{0,}:\s{0,}\K(false|true)')
    if [ "$result" == 'true' ]; then
        echo -n -e "\r TVBAnywhere+:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    else
        echo -n -e "\r TVBAnywhere+:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_Spotify() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://spclient.wg.spotify.com/signup/public/v1/account' -d "birth_day=11&birth_month=11&birth_year=2000&collect_personal_info=undefined&creation_flow=&creation_point=https%3A%2F%2Fwww.spotify.com%2Fhk-en%2F&displayname=Gay%20Lord&gender=male&iagree=1&key=a1e486e2729f46d6bb368d6b2bcda326&platform=www&referrer=&send-email=0&thirdpartyemail=0&identifier_token=AgE6YTvEzkReHNfJpO114514" -X POST -H "Accept-Language: en" --user-agent "${UA_BROWSER}")
    local statusCode=$(echo "$tmpresult" | grep -woP '"status"\s{0,}:\s{0,}\K\d+')
    local region=$(echo "$tmpresult" | grep -woP '"country"\s{0,}:\s{0,}"\K[^"]+')
    if [ "$statusCode" == '311' ] || [ "$statusCode" == '20' ]; then
        echo -n -e "\r Spotify Registration:\t\t\t${Font_Green}Yes (Region: ${region})${Font_Suffix}\n"
    else
        echo -n -e "\r Spotify Registration:\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi
}

function RegionTest_oneTrust() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://geolocation.onetrust.com/cookieconsentpub/v1/geo/location'  --user-agent "${UA_BROWSER}")
    local region=$(echo "$tmpresult" | grep -woP '"country"\s{0,}:\s{0,}"\K[^"]+')
    local stateName=$(echo "$tmpresult" | grep -woP '"stateName"\s{0,}:\s{0,}"\K[^"]+')
    if [ -n "$region" ]; then
        echo -n -e "\r OneTrust Region:\t\t\t${Font_Green}${region} [${stateName:-Unknown}]${Font_Suffix}\n"
    else
        echo -n -e "\r OneTrust Region:\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi
}

function RegionTest_iQYI() {
    if [ "${USE_IPV6}" == 1 ]; then echo -n -e "\r iQyi Oversea Region:\t\t\t${Font_Red}IPv6 Is Not Currently Supported${Font_Suffix}\n"; return; fi
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://www.iq.com/' -D - --user-agent "${UA_BROWSER}")
    local region=$(echo "$tmpresult" | grep -woP 'mod=\K[a-z]+' | tr a-z A-Z)
    if [ -n "$region" ]; then
        echo -n -e "\r iQyi Oversea Region:\t\t\t${Font_Green}${region}${Font_Suffix}\n"
    else
        echo -n -e "\r iQyi Oversea Region:\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi
}

function RegionTest_Bing() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://www.bing.com/search?q=curl' --user-agent "${UA_BROWSER}")
    local region=$(echo "$tmpresult" | grep -woP 'Region\s{0,}:\s{0,}"\K[^"]+')
    if [ -n "$(echo "$tmpresult" | grep 'cn.bing.com')" ]; then
        echo -n -e "\r Bing Region:\t\t\t\t${Font_Yellow}CN${Font_Suffix}\n"
    elif [ -n "$region" ]; then
        echo -n -e "\r Bing Region:\t\t\t\t${Font_Green}${region}${Font_Suffix}\n"
    else
        echo -n -e "\r Bing Region:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi
}

function RegionTest_Apple() {
    local result=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://gspe1-ssl.ls.apple.com/pep/gcc')
    if [ -n "$result" ]; then
        echo -n -e "\r Apple Region:\t\t\t\t${Font_Green}${result}${Font_Suffix}\n"
    else
        echo -n -e "\r Apple Region:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi
}

function WebTest_OpenAI() {
    local tmpresult2=$(curl ${CURL_DEFAULT_OPTS} -s 'https://ios.chat.openai.com/' --user-agent "${UA_BROWSER}")
    local result2=$(echo "$tmpresult2" | grep -i 'VPN')
    if [ -z "$result2" ] && [ -n "$tmpresult2" ]; then
        echo -n -e "\r ChatGPT:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    else
        echo -n -e "\r ChatGPT:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi
}

function WebTest_Gemini() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL "https://gemini.google.com" --user-agent "${UA_BROWSER}")
    local countrycode=$(echo "$tmpresult" | grep -o ',2,1,200,"[A-Z]\{3\}"' | sed 's/,2,1,200,"//;s/"//' || echo "")
    if echo "$tmpresult" | grep -q '45631641,null,true'; then
        echo -n -e "\r Google Gemini:\t\t\t\t${Font_Green}Yes (Region: ${countrycode})${Font_Suffix}\n"
    else
        echo -n -e "\r Google Gemini:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi
}

function WebTest_Claude() {
    local response=$(curl ${CURL_DEFAULT_OPTS} -s -L -o /dev/null -w '%{url_effective}' "https://claude.ai/" --user-agent "${UA_BROWSER}")
    if [[ "$response" == "https://claude.ai/" ]]; then
        echo -e "\r Claude:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    else
        echo -e "\r Claude:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi
}

function WebTest_Wikipedia_Editable() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://zh.wikipedia.org/w/index.php?title=Wikipedia%3A%E6%B2%99%E7%9B%92&action=edit' --user-agent "${UA_BROWSER}")
    if [ -z "$(echo "$tmpresult" | grep -i 'Banned')" ]; then
        echo -n -e "\r Wikipedia Editability:\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    else
        echo -n -e "\r Wikipedia Editability:\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi
}

function WebTest_GooglePlayStore() {
    local result=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://play.google.com/' --user-agent "${UA_BROWSER}" | grep -oP '<div class="yVZQTb">\K[^<(]+')
    if [ -n "$result" ]; then
        echo -n -e "\r Google Play Store:\t\t\t${Font_Green}${result}${Font_Suffix}\n"
    else
        echo -n -e "\r Google Play Store:\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi
}

function WebTest_GoogleSearchCAPTCHA() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://www.google.com/search?q=curl' --user-agent "${UA_BROWSER}")
    if [ -z "$(echo "$tmpresult" | grep -iE 'unusual traffic from|is blocked|unaddressed abuse')" ]; then
        echo -n -e "\r Google Search CAPTCHA Free:\t\t${Font_Green}Yes${Font_Suffix}\n"
    else
        echo -n -e "\r Google Search CAPTCHA Free:\t\t${Font_Red}No${Font_Suffix}\n"
    fi
}

function WebTest_Reddit() {
    if [ "${USE_IPV6}" == 1 ]; then echo -n -e "\r Reddit:\t\t\t\t${Font_Red}IPv6 Is Not Currently Supported${Font_Suffix}\n"; return; fi
    local result=$(curl ${CURL_DEFAULT_OPTS} -fsL 'https://www.reddit.com/' -w %{http_code} -o /dev/null --user-agent "${UA_BROWSER}")
    if [ "$result" == '200' ]; then
        echo -n -e "\r Reddit:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    else
        echo -n -e "\r Reddit:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi
}

function Global_UnlockTest() {
    echo ""
    echo "============[ Multination ]============"
    local result=$(
        MediaUnlockTest_Dazn &
        MediaUnlockTest_DisneyPlus &
        MediaUnlockTest_Netflix &
        MediaUnlockTest_YouTube_Premium &
        MediaUnlockTest_PrimeVideo &
        MediaUnlockTest_TVBAnywhere &
        MediaUnlockTest_Spotify &
        RegionTest_oneTrust &
        RegionTest_iQYI &
    )
    wait
    local array=("Dazn:" "Disney+:" "Netflix:" "YouTube Premium:" "Amazon Prime Video:" "TVBAnywhere+:" "Spotify Registration:" "OneTrust Region:" "iQyi Oversea Region:")
    echo_result ${result} ${array}
    local result=$(
        RegionTest_Bing &
        RegionTest_Apple &
        RegionTest_YouTubeCDN &
        RegionTest_NetflixCDN &
        WebTest_OpenAI &
        WebTest_Gemini &
        WebTest_Claude &
        WebTest_Wikipedia_Editable &
        WebTest_GooglePlayStore &
        WebTest_GoogleSearchCAPTCHA &
        GameTest_Steam &
    )
    wait
    local array=("Bing Region:" "Apple Region:" "YouTube CDN:" "Netflix Preferred CDN:" "ChatGPT:" "Google Gemini:" "Claude:" "Wikipedia Editability:" "Google Play Store:" "Google Search CAPTCHA Free:" "Steam Currency:")
    echo_result ${result} ${array}
    show_region Forum
    WebTest_Reddit
    show_region Game
    GameTest_SDGGGE
    echo "======================================="
}

# --- 主执行逻辑 ---
color_print
check_os_type
check_dependencies
process "$@"
download_extra_data

# IPv4 检测
check_net_connctivity 4
if [ $? -eq 0 ]; then
    echo ''
    echo -e " ${Font_SkyBlue}** Checking Results Under IPv4${Font_Suffix}"
    USE_IPV4=1
    USE_IPV6=0
    CURL_DEFAULT_OPTS="-4 ${CURL_OPTS}"
    get_ip_info
    echo -e " ${Font_SkyBlue}** Your Network Provider: ${LOCAL_ISP} (${LOCAL_IP_ASTERISK})${Font_Suffix} "
    Global_UnlockTest
else
    echo -e "${Font_SkyBlue}No IPv4 Connectivity, IPv4 Test Skipped...${Font_Suffix}"
fi

# IPv6 检测
check_net_connctivity 6
if [ $? -eq 0 ]; then
    echo ''
    echo -e " ${Font_SkyBlue}** Checking Results Under IPv6${Font_Suffix}"
    USE_IPV4=0
    USE_IPV6=1
    CURL_DEFAULT_OPTS="-6 ${CURL_OPTS}"
    get_ip_info
    echo -e " ${Font_SkyBlue}** Your Network Provider: ${LOCAL_ISP} (${LOCAL_IP_ASTERISK})${Font_Suffix} "
    Global_UnlockTest
else
    echo -e "${Font_SkyBlue}No IPv6 Connectivity, IPv6 Test Skipped...${Font_Suffix}"
fi
