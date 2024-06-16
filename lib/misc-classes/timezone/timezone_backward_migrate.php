<?php

$timezone_backward = array();

$filename = "timezone_backward.txt";

$lines = file($filename);
$count = 0;
foreach($lines as $line) {
    $count += 1;
    $line = str_replace("\t\t\t", "\t", $line);
    $line = str_replace("\t\t", "\t", $line);
    $line = str_replace("\n", "", $line);
    $line = str_replace("Link\t", "", $line);

    if( !str_starts_with( $line, "#") && strlen($line) > 0 )
    {
        $timezoneID_backward = explode("\t", $line);
        $timezone_backward[$timezoneID_backward[1]] = $timezoneID_backward[0];
    }
}

ksort($timezone_backward);
#print_r( $timezone_backward );

$json = json_encode($timezone_backward, JSON_PRETTY_PRINT);
file_put_contents("timezone_backward.json", $json);
