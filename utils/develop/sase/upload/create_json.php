<?php


$array = array();

$tmp_array = array();



$data_array = array();
$data_array['data'][0] = array( "name" => "dummy_test2", "ip_netmask" => "192.168.10.2/32" );


$tmp_array[0]['url'] = "https://api.strata.paloaltonetworks.com/config/objects/v1/addresses?device=Remote Networks";
$tmp_array[0]['requestMethod'] = "POST";
$tmp_array[0]['body'] = $data_array;



print json_encode($tmp_array, JSON_PRETTY_PRINT);