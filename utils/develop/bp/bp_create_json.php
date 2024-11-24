<?php

$checkArray = array();

$checkArray['spyware'] = array();
$checkArray['vulnerability'] = array();
$checkArray['virus'] = array();


$checkArray['spyware']['rule'] = array();
$checkArray['spyware']['rule']['bp'] = array();
$checkArray['spyware']['rule']['visibility'] = array();
$checkArray['spyware']['rule']['bp']['severity'] = array('any', 'critical', 'high', 'medium');
$checkArray['spyware']['rule']['bp']['action'] = array('reset-both');
$checkArray['spyware']['rule']['bp']['packet-capture'] = array('single-packet', 'extended-capture');
$checkArray['spyware']['rule']['visibility']['severity'] = array('any', 'critical', 'high', 'medium','low','informational');
$checkArray['spyware']['rule']['visibility']['action'] = array('!allow');


$checkArray['vulnerability']['rule'] = array();
$checkArray['vulnerability']['rule']['bp'] = array();
$checkArray['vulnerability']['rule']['visibility'] = array();
$checkArray['vulnerability']['rule']['bp']['severity'] = array('any', 'critical', 'high', 'medium');
$checkArray['vulnerability']['rule']['bp']['action'] = array('reset-both');
$checkArray['vulnerability']['rule']['bp']['packet-capture'] = array('single-packet', 'extended-capture');
$checkArray['vulnerability']['rule']['bp']['category-exclude'] = array('brute-force', 'app-id-change');
$checkArray['vulnerability']['rule']['visibility']['severity'] = array('any', 'critical', 'high', 'medium','low','informational');
$checkArray['vulnerability']['rule']['visibility']['action'] = array('!allow');


$checkArray['virus']['rule'] = array();
$checkArray['virus']['rule']['bp'] = array();
$checkArray['virus']['rule']['visibility'] = array();
$checkArray['virus']['rule']['bp']['action'] = array();
$checkArray['virus']['rule']['visibility']['action'] = array();
$checkArray['virus']['rule']['bp']['action']['type'] = array('ftp', 'http', 'http2', 'smb');
$checkArray['virus']['rule']['bp']['action']['action'] = array('reset-both', 'default');
$checkArray['virus']['rule']['bp']['action']['action-not-matching-type'] = array('reset-both');
$checkArray['virus']['rule']['visibility']['action'] = array('!allow');

$checkArray['virus']['rule']['bp']['wildfire-action'] = array();
$checkArray['virus']['rule']['visibility']['wildfire-action'] = array();
$checkArray['virus']['rule']['bp']['wildfire-action']['type'] = array('ftp', 'http', 'http2', 'smb');
$checkArray['virus']['rule']['bp']['wildfire-action']['action'] = array('reset-both', 'default');
$checkArray['virus']['rule']['bp']['wildfire-action']['action-not-matching-type'] = array('reset-both');
$checkArray['virus']['rule']['visibility']['wildfire-action'] = array('!allow');

$checkArray['virus']['rule']['bp']['mlav-action'] = array();
$checkArray['virus']['rule']['visibility']['mlav-action'] = array();
$checkArray['virus']['rule']['bp']['mlav-action']['type'] = array('ftp', 'http', 'http2', 'smb');
$checkArray['virus']['rule']['bp']['mlav-action']['action'] = array('reset-both', 'default');
$checkArray['virus']['rule']['bp']['mlav-action']['action-not-matching-type'] = array('reset-both');
$checkArray['virus']['rule']['visibility']['mlav-action'] = array('!allow');


$checkArray['virus']['cloud-inline'] = array();
$checkArray['spyware']['cloud-inline'] = array();
$checkArray['vulnerability']['cloud-inline'] = array();
$checkArray['virus']['cloud-inline']['bp'] = array();
$checkArray['spyware']['cloud-inline']['bp'] = array();
$checkArray['vulnerability']['cloud-inline']['bp'] = array();
$checkArray['virus']['cloud-inline']['bp']['inline-policy-action'] = array('enable');
$checkArray['spyware']['cloud-inline']['bp']['inline-policy-action'] = array('reset-both');
$checkArray['vulnerability']['cloud-inline']['bp']['inline-policy-action'] = array('reset-both');

$checkArray['virus']['cloud-inline']['visibility'] = array();
$checkArray['spyware']['cloud-inline']['visibility'] = array();
$checkArray['vulnerability']['cloud-inline']['visibility'] = array();
$checkArray['virus']['cloud-inline']['visibility']['inline-policy-action'] = array('!disable');
$checkArray['spyware']['cloud-inline']['visibility']['inline-policy-action'] = array('!allow');
$checkArray['vulnerability']['cloud-inline']['visibility']['inline-policy-action'] = array('!allow');


$checkArray['spyware']['dns'] = array();
$checkArray['spyware']['dns']['bp'] = array();
$checkArray['spyware']['dns']['bp']['action'] = array();
$checkArray['spyware']['dns']['bp']['action'][0]['type'] = array('pan-dns-sec-malware','pan-dns-sec-phishing');
$checkArray['spyware']['dns']['bp']['action'][0]['action'] = array('sinkhole');
$checkArray['spyware']['dns']['bp']['action'][0]['packet-capture'] = array('single-packet');

$checkArray['spyware']['dns']['bp']['action'][1]['type'] = array('pan-dns-sec-cc');
$checkArray['spyware']['dns']['bp']['action'][1]['action'] = array('sinkhole');
$checkArray['spyware']['dns']['bp']['action'][1]['packet-capture'] = array('extended-capture');



$json = json_encode($checkArray, JSON_PRETTY_PRINT);
echo $json;