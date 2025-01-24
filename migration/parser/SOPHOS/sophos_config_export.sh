#!/bin/bash
###############################################################
#request SOPHOS UTM configuration data
###############################################################

echo "Request SOPHOS UTM configuration data"

apikey="APIKEY from SOPHOS UTM"
fqdn="SOPHOS IP / FQDN"

urlbase="https://$fqdn:4444/api/objects/"

# Create a temporary directory for downloaded files

# the temp directory used
TEMP_DIR=$(mktemp -d -p ./)

OUTPUT_FILE="merged output.txt"

j=0
err=0

arrapi=("network/host/" \
		"network/dns_host/" \
		"network/dns_group/" \
		"network/group/" \
		"network/range/" \
		"network/network/" \
		"network/interface_network/" \
		"service/group/" \
		"service/tcp/" \
		"service/udp/" \
		"service/tcpudp/" \
		"packetfilter/packetfilter/" \
)


for i in "${arrapi[@]}"
do
	curl -X GET -k -H "Accept: application/json" \
				-H "Authorization: Basic $apikey" "$urlbase$i" -o "$TEMP_DIR/file$j.txt"
	response_code=$?

	if [ $response_code -eq 0 ]; then
		echo "Downloaded $urlbase$i"
	else
		echo "Fehler beim Download von $urlbase$i"
		let "err++"
	fi
	let "j++"
done


# Merge downloaded files into a single output file
cat "$TEMP_DIR"/*.txt > "$fqdn-$OUTPUT_FILE"

# Clean up temporary directory
rm -rf "$TEMP_DIR"

################################################################
# Rule Order
##############################################################
urlorder="https://$fqdn:4444/api/nodes/packetfilter.rules"

curl -X GET -k -H "Accept: application/json" \
				 -H "Authorization: Basic $apikey" "$urlorder" -o "$fqdn-ruleorder.txt"


