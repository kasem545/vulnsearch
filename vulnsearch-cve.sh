#!/bin/bash

GREEN='\e[32m'
RED='\e[31m'

echo "[*] vulnsearch"
read -p "Enter target URL or IP: " target

# Check if the input is an IP address or a URL
if [[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ip="$target"
else
    ip=$(dig +short "$target" | head -n 1)
fi

# Check if IP retrieval was successful
if [ -z "$ip" ]; then
    echo "Error retrieving IP address."
else
    echo "Retrieved IP address: $ip"
    response=$(curl -s "https://internetdb.shodan.io/$ip")
    if [ -z "$response" ]; then
        echo "Error retrieving information from Shodan." 
    else
        cvelist=$(echo "$response" | jq -r '.vulns[] | select(test("CVE-"; "i"))' | sed 's/^"//;s/",$//;s/CVE-//g')
        #echo "CVE List: $cvelist"

        for cve in $cvelist; do
            echo -e "${GREEN}[*]Searching for valid exploits in Exploit-DB for ${RED}CVE-$cve${GREEN} "
            searchsploit --cve "$cve" | grep -v "No Results"
        done
    fi
fi
