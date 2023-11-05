#!/bin/bash

GREEN='\e[32m'
RED='\e[31m'
BLUE='\e[34m'

echo -e "[*] vulnsearch\n"
read -p "Enter target URL or IP: " target

# Check if the input is an IP address or a URL
if [[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ip="$target"
else
    ip=$(dig +short "$target" | head -n 1)
fi

# Check if IP retrieval was successful
if [ -z "$ip" ]; then
    echo "Error retrieving IP address.\n"
else
    echo -e "Retrieved IP address: $ip \n"
    response=$(curl -s "https://internetdb.shodan.io/$ip")
    if [ -z "$response" ]; then
        echo "Error retrieving information from Shodan.\n" 
    else
        cvelist=$(echo "$response" | jq -r '.vulns[] | select(test("CVE-"; "i"))' | sed 's/^"//;s/",$//;s/CVE-//g')
        
	#echo "CVE List: $cvelist"
	if [ -d "Exploits" ]; then
		echo -e "${RED}Exploit Directory Exists\n"
	else
		echo -e "${BLUE}Creating Exploits Directory\n"
		mkdir Exploits
  fi 
  
  for cve1 in $cvelist; do
    response=$(curl -s "https://poc-in-github.motikan2010.net/api/v1/?cve_id=CVE-$cve1")
    html_urls=$(echo "$response" | jq -r '.pocs[] | .html_url')
    
    if [ -z "$html_urls" ] || [ "$html_urls" == "null" ]; then
        echo -e "${RED}POC CVE-$cve1 URL not found in poc-in-github"
    else
        echo -e "${BLUE}CVE-$cve1 URLs:${BLUE}"
        echo -e "${GREEN}$html_urls${RED}"
    fi
    done

	for cve2 in $cvelist; do
            echo -e "${BLUE}[*]Searching for valid exploits in Exploit-DB for ${RED}CVE-$cve2${GREEN}"
            searchsploit --cve "$cve2" | grep -v "No Results"
	done
	
	for cve3 in $cvelist; do
		echo -e "${BLUE}[*]Searching for valid POC exploit in cve-mitre for ${RED}CVE-$cve3${GREEN}"
		svn checkout https://github.com/nu11secur1ty/CVE-mitre/trunk/$cve3 ./exploits 2>/dev/null
        done

    fi
fi