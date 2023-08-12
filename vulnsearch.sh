#!/bin/bash

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
        echo "$response" | jq .

        # Search for PoC code
        cve_list=$(echo "$response" | jq -r '.vulns[]')
        for cve in $cve_list; do
            echo "Searching for PoC code for CVE: $cve"
            
            # Search for CVE information using circl.lu API
            cve_info=$(curl -s -q -X 'GET' "https://cvepremium.circl.lu/api/cve/$cve" -H 'accept: application/json')
            references=$(echo "$cve_info" | jq -r '.references')
            if [ -z "$references" ]; then
                echo "No references found for CVE: $cve"
            else
                echo "References for CVE $cve:"
                echo "$references"
            fi
        done
    fi
fi
