<?php

$test = "gateway_objects.json";

$filename = "policy-fw-alt-una-dortmund_gateway_objects.json";

$json1 = file_get_contents($filename);

$json2 = json_encode(json_decode($json1), JSON_PRETTY_PRINT);
#echo '<pre>' . $json2 . '</pre>';

$json_array = json_decode($json1, true);

foreach ($json_array as $json)
{
    #print_r($json);

    if( $json['type'] == "cluster-member" )
        continue;


    #"type": "CpmiGatewayCluster",
    print $json['type']."\n";

    print $json['name']."\n";
    print $json['policy']['access-policy-name']."\n";
    if( $json['type'] == "CpmiGatewayCluster" )
    {
        //cluster-member-names
        print_r( $json['cluster-member-names'] );
    }

    foreach( $json['interfaces'] as $interface )
    {
        #print_r($interface );

        $int_array = explode( ".", $interface['interface-name'] );
        $main_interface = $int_array[0];


        if( isset($int_array[1]) )
        {
            $subInterface_tag = $int_array[1];
            print " - ".$main_interface.".".$subInterface_tag."\n";
        }
        else
            print " - ".$main_interface."\n";

        $int_value = $interface['ipv4-address']."/".$interface['ipv4-mask-length'];
        print "    - ".$int_value."\n";
    }

    print "-------------------------------\n";
}