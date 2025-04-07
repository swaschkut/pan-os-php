#!/bin/bash
###############################################################
#request SOPHOS XG configuration data
###############################################################
#https://docs.sophos.com/nsg/sophos-firewall/19.5/API/index.html


echo "Request SOPHOS XG configuration data"

username="USER from SOPHOS XG"
password="Password from SOPHOS XG"
fqdn="SOPHOS IP / FQDN"


urlbase2="https://$fqdn:4444/webconsole/APIController?reqxml=<Request><Login><Username>$username</Username><Password>$password</Password></Login><Get>"
urlend2="</Get></Request>"

# Create a temporary directory for downloaded files

# the temp directory used
TEMP_DIR=$(mktemp -d -p ./)

OUTPUT_FILE="merged output.txt"

j=0
err=0

arrapi=(
  "Interface" \
  "LAG" \
  "VLAN" \
  "GatewayConfiguration" \
  "Zone"
  "FQDNHost" \
  "FQDNHostGroup" \
  "IPHost" \
  "IPHostGroup" \
  "MACHost" \
  "Services" \
  "ServiceGroup"
  "SDWANPolicyRoute" \
  "UnicastRoute" \
  "FirewallRule" \
  "FirewallRuleGroup" \
  "NATRule" \
  "SSLTLSInspectionRule"

)


############################
for i in "${arrapi[@]}"
do
	curl -X GET -k -H "Accept: application/json" \
				"$urlbase2<$i></$i>$urlend2" -o "$TEMP_DIR/file-$j-$i.xml"
	response_code=$?

	if [ $response_code -eq 0 ]; then
		echo "Downloaded $urlbase2<$i></$i>$urlend2"
	else
		echo "Fehler beim Download von $urlbase2<$i></$i>$urlend2"
		let "err++"
	fi
	let "j++"
done



# Merge downloaded files into a single output file
#cat "$TEMP_DIR"/*.txt > "$fqdn-$OUTPUT_FILE"

# Clean up temporary directory
#rm -rf "$TEMP_DIR"




