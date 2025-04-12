###Sophos

SOPHOS UTM

//USAGE:
////pan-os-php type=vendor-migration vendor=sophos
//  file=/Users/swaschkut/Documents/Expedition_config/XYZ output\ DMZ.txt
//  out=/tmp/sophos.xml in=/Users/swaschkut/Documents/VM300-Baseline.xml
//  ruleorder=/Users/swaschkut/Documents/Expedition_config/XYZ/packetfilter\ order.txt


/*
//Todo: NEEDED config files:
Sophos UTM API export (copy / past)
https://www.sophos.com/en-us/medialibrary/PDFs/documentation/UTMonAWS/Sophos-UTM-RESTful-API.pdf?la=en
https://ip_address_of_ UTM:4444/api/



//copy all these information into one file
objects/network/host
objects/network/dns_host
objects/network/dns_group
objects/network/group
objects/network/range
objects/network/network
objects/network/interface_network

objects/service/group
objects/service/tcp
objects/service/udp
objects/service/tcpudp

objects/packetfilter/packetfilter




//rule order information MUST be placed in a separate file
rule order
nodes/packetfilter.rules



export script is available in ../SOPHOS/sophos_config_export.sh