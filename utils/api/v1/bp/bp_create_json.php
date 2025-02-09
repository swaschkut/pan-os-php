<?php

$checkArray = array();

$checkArray['virus'] = array();
$checkArray['spyware'] = array();
$checkArray['vulnerability'] = array();


######################################################################################################################
######## RULE

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

####################

$checkArray['spyware']['rule'] = array();
$checkArray['spyware']['rule']['bp'] = array();
$checkArray['spyware']['rule']['visibility'] = array();
$checkArray['spyware']['rule']['bp']['severity'] = array('any', 'critical', 'high', 'medium');
$checkArray['spyware']['rule']['bp']['action'] = array('reset-both');
$checkArray['spyware']['rule']['bp']['packet-capture'] = array('single-packet', 'extended-capture');
$checkArray['spyware']['rule']['visibility']['severity'] = array('any', 'critical', 'high', 'medium','low','informational');
$checkArray['spyware']['rule']['visibility']['action'] = array('!allow');

####################

$checkArray['vulnerability']['rule'] = array();
$checkArray['vulnerability']['rule']['bp'] = array();
$checkArray['vulnerability']['rule']['visibility'] = array();
$checkArray['vulnerability']['rule']['bp']['severity'] = array('any', 'critical', 'high', 'medium');
$checkArray['vulnerability']['rule']['bp']['action'] = array('reset-both');
$checkArray['vulnerability']['rule']['bp']['packet-capture'] = array('single-packet', 'extended-capture');
$checkArray['vulnerability']['rule']['bp']['category-exclude'] = array('brute-force', 'app-id-change');
$checkArray['vulnerability']['rule']['visibility']['severity'] = array('any', 'critical', 'high', 'medium','low','informational');
$checkArray['vulnerability']['rule']['visibility']['action'] = array('!allow');


######################################################################################################################
######## SPYWARE DNS


$checkArray['spyware']['dns'] = array();
$checkArray['spyware']['dns']['bp'] = array();
$checkArray['spyware']['dns']['bp']['action'] = array();
$checkArray['spyware']['dns']['bp']['action'][0]['type'] = array('pan-dns-sec-malware','pan-dns-sec-phishing');
$checkArray['spyware']['dns']['bp']['action'][0]['action'] = array('sinkhole');
$checkArray['spyware']['dns']['bp']['action'][0]['packet-capture'] = array('single-packet');

$checkArray['spyware']['dns']['bp']['action'][1]['type'] = array('pan-dns-sec-cc');
$checkArray['spyware']['dns']['bp']['action'][1]['action'] = array('sinkhole');
$checkArray['spyware']['dns']['bp']['action'][1]['packet-capture'] = array('extended-capture');


$checkArray['spyware']['lists']['bp']['action'][0]['type'] = array('default-paloalto-dns');
$checkArray['spyware']['lists']['bp']['action'][0]['action'] = array('sinkhole');
$checkArray['spyware']['lists']['visibility']['action'][0]['type'] = array('default-paloalto-dns');
$checkArray['spyware']['lists']['visibility']['action'][0]['action'] = array('!allow');


######################################################################################################################
######## CLOUD INLINE

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


######################################################################################################################
######## URL
$checkArray['url']['site_access']['visibility'] = array('!allow');
$checkArray['url']['site_access']['bp']['action'][0]['type'] = array('command-and-control','grayware', 'malware', 'phishing', 'ransamware', 'scanning-activity');
$checkArray['url']['site_access']['bp']['action'][0]['action'] = array('block');
$checkArray['url']['site_access']['bp']['action'][1]['type'] = array('dynamic-dns', 'hacking', 'insufficient-content', 'newly-registered-domains', 'not-resolved', 'parked', 'proxy-avoidance-and-anonymizers', 'unknown');
$checkArray['url']['site_access']['bp']['action'][1]['action'] = array('alert');
$checkArray['url']['site_access']['bp']['action'][1]['type'] = array('abused-drugs', 'adult', 'copyright-infringement', 'extremism', 'gambling', 'peer-to-peer', 'questionable', 'weapons');
$checkArray['url']['site_access']['bp']['action'][1]['action'] = array('alert');
$checkArray['url']['user_credential_submission']['visibility'] = array('!allow');
$checkArray['url']['user_credential_submission']['bp']['action'][0]['type'] = array('command-and-control','grayware', 'malware', 'phishing', 'ransamware', 'scanning-activity');
$checkArray['url']['user_credential_submission']['bp']['action'][0]['action'] = array('block');
$checkArray['url']['user_credential_submission']['bp']['action'][1]['type'] = array('dynamic-dns', 'hacking', 'insufficient-content', 'newly-registered-domains', 'not-resolved', 'parked', 'proxy-avoidance-and-anonymizers', 'unknown');
$checkArray['url']['user_credential_submission']['bp']['action'][1]['action'] = array('alert');
$checkArray['url']['user_credential_submission']['bp']['action'][1]['type'] = array('abused-drugs', 'adult', 'copyright-infringement', 'extremism', 'gambling', 'peer-to-peer', 'questionable', 'weapons');
$checkArray['url']['user_credential_submission']['bp']['action'][1]['action'] = array('alert');


######################################################################################################################
######## FB
$checkArray['fb']['visibility']['action'][0]['type'] = array('any');
$checkArray['fb']['visibility']['action'][0]['action'] = array('alert');
$checkArray['fb']['visibility']['action'][1]['type'] = array('7z', 'bat','chm','class','cpl','dll','hlp','hta','jar','ocx','pif','scr','torrent','vbe','wsf');
$checkArray['fb']['visibility']['action'][1]['action'] = array('alert');

$checkArray['fb']['bp']['action'][0]['type'] = array('any');
$checkArray['fb']['bp']['action'][0]['action'] = array('alert');
$checkArray['fb']['bp']['action'][1]['type'] = array('7z', 'bat','chm','class','cpl','dll','hlp','hta','jar','ocx','pif','scr','torrent','vbe','wsf');
$checkArray['fb']['bp']['action'][1]['action'] = array('block');


######################################################################################################################
######## WF
$checkArray['wf']['visibility'][0]['application'] = array('any');
$checkArray['wf']['visibility'][0]['file-type'] = array('any');
$checkArray['wf']['visibility'][0]['direction'] = array('both');
$checkArray['wf']['visibility'][0]['analysis'] = array('public-cloud');

$checkArray['wf']['bp'][0]['application'] = array('any');
$checkArray['wf']['bp'][0]['file-type'] = array('any');
$checkArray['wf']['bp'][0]['direction'] = array('both');
$checkArray['wf']['bp'][0]['analysis'] = array('public-cloud');


######################################################################################################################

$json = json_encode($checkArray, JSON_PRETTY_PRINT);

$fileName = "bp_sp_panw.json";
file_put_contents($fileName, $json);
echo $json;