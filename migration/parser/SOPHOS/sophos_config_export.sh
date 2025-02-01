#!/bin/bash
###############################################################
#request SOPHOS UTM configuration data
###############################################################
#https://fqdn:4444/api/definitions



echo "Request SOPHOS UTM configuration data"


apikey="APIKEY from SOPHOS UTM"
#NOT WORKING with USERNAME/PASSWORD
#username="USERNAME from SOPHOS UTM"
#password="PASSWORD from SOPHOS UTM"
fqdn="SOPHOS IP / FQDN"

#authkey=$(echo -n $username + ":" + $password | base64)

echo $authkey

urlbase="https://$fqdn:4444/api/objects/"

# Create a temporary directory for downloaded files

# the temp directory used
TEMP_DIR=$(mktemp -d -p ./)

OUTPUT_FILE="merged output.txt"

j=0
err=0

arrapi=(
    "network/any/" \
    "network/host/" \
		"network/dns_host/" \
		"network/dns_group/" \
		"network/group/" \
		"network/range/" \
		"network/network/" \
		"network/interface_address/" \
		"network/interface_broadcast/" \
		"network/interface_network/" \
		"network/multicast/" \
		"network/aaa/" \
		"service/ah/" \
		"service/esp/" \
		"service/any/" \
		"service/icmp/" \
		"service/icmpv6/" \
		"service/ip/" \
		"service/group/" \
		"service/tcp/" \
		"service/udp/" \
		"service/tcpudp/" \
		"packetfilter/packetfilter/" \
		"packetfilter/nat/" \
		"packetfilter/1to1nat/" \
		"packetfilter/generic_proxy/" \
		"packetfilter/group/" \
		"packetfilter/loadbalance/" \
		"packetfilter/mangle/" \
		"packetfilter/masq/" \
		"packetfilter/ruleset/" \

		"geoip/geoipgroup/" \
		"geoip/dstexception/" \
		"geoip/srcexception/" \
		"geoip/group/" \

		"interface/bridge/" \
		"interface/ethernet/" \
		"interface/group/" \
		"interface/tunnel/" \
		"interface/vlan/" \

		"ipsec/group/" \
		"ipsec/policy/" \
		"ipsec/remote_gateway/" \

		"route/group/" \
		"route/policy/" \
		"route/static/" \
)


for i in "${arrapi[@]}"
do
	#curl -X GET -k -H "Accept: application/json" \
	#      -H "Authorization: Basic $authkey" "$urlbase$i" -o "$TEMP_DIR/file$j.txt"
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


