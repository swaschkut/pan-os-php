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
$checkArray['spyware']['dns']['bp_custom'] = array();
$checkArray['spyware']['dns']['bp_custom']['action'] = array();
$checkArray['spyware']['dns']['bp_custom']['action'][0]['type'] = array('pan-dns-sec-malware','pan-dns-sec-phishing');
$checkArray['spyware']['dns']['bp_custom']['action'][0]['action'] = array('sinkhole');
$checkArray['spyware']['dns']['bp_custom']['action'][0]['packet-capture'] = array('single-packet');

$checkArray['spyware']['dns']['bp'] = array();
$checkArray['spyware']['dns']['bp']['action'] = array();
$checkArray['spyware']['dns']['bp']['action'][0]['type'] = array('pan-dns-sec-adtracking', 'pan-dns-sec-ddns', 'pan-dns-sec-grayware', 'pan-dns-sec-malware', 'pan-dns-sec-parked', 'pan-dns-sec-phishing', 'pan-dns-sec-proxy', 'pan-dns-sec-recent');
$checkArray['spyware']['dns']['bp']['action'][0]['action'] = array('sinkhole');
$checkArray['spyware']['dns']['bp']['action'][0]['packet-capture'] = array('single-packet');

$checkArray['spyware']['dns']['bp_panw'] = array();
$checkArray['spyware']['dns']['bp_panw']['action'] = array();
$checkArray['spyware']['dns']['bp_panw']['action'][0]['type'] = array('pan-dns-sec-adtracking', 'pan-dns-sec-ddns', 'pan-dns-sec-grayware', 'pan-dns-sec-malware', 'pan-dns-sec-parked', 'pan-dns-sec-phishing', 'pan-dns-sec-proxy', 'pan-dns-sec-recent');
$checkArray['spyware']['dns']['bp_panw']['action'][0]['action'] = array('sinkhole');
$checkArray['spyware']['dns']['bp_panw']['action'][0]['packet-capture'] = array('single-packet');


$checkArray['spyware']['dns']['bp']['action'][1]['type'] = array('pan-dns-sec-cc');
$checkArray['spyware']['dns']['bp']['action'][1]['action'] = array('sinkhole');
$checkArray['spyware']['dns']['bp']['action'][1]['packet-capture'] = array('extended-capture');


$checkArray['spyware']['lists']['bp']['action'][0]['type'] = array('default-paloalto-dns');
$checkArray['spyware']['lists']['bp']['action'][0]['action'] = array('sinkhole');
$checkArray['spyware']['lists']['visibility']['action'][0]['type'] = array('default-paloalto-dns');
$checkArray['spyware']['lists']['visibility']['action'][0]['action'] = array('!allow');


######################################################################################################################
######## CLOUD INLINE

#SCM AIops is not checking this
#$checkArray['virus']['cloud-inline'] = array();
#$checkArray['spyware']['cloud-inline'] = array();
#$checkArray['vulnerability']['cloud-inline'] = array();
#$checkArray['virus']['cloud-inline']['bp'] = array();
#$checkArray['spyware']['cloud-inline']['bp'] = array();
#$checkArray['vulnerability']['cloud-inline']['bp'] = array();
#$checkArray['virus']['cloud-inline']['bp']['inline-policy-action'] = array('enable');
#$checkArray['spyware']['cloud-inline']['bp']['inline-policy-action'] = array('reset-both');
#$checkArray['vulnerability']['cloud-inline']['bp']['inline-policy-action'] = array('reset-both');

#$checkArray['virus']['cloud-inline']['visibility'] = array();
#$checkArray['spyware']['cloud-inline']['visibility'] = array();
#$checkArray['vulnerability']['cloud-inline']['visibility'] = array();
#$checkArray['virus']['cloud-inline']['visibility']['inline-policy-action'] = array('!disable');
#$checkArray['spyware']['cloud-inline']['visibility']['inline-policy-action'] = array('!allow');
#$checkArray['vulnerability']['cloud-inline']['visibility']['inline-policy-action'] = array('!allow');


######################################################################################################################
######## URL
$checkArray['url']['site_access']['visibility'] = '!allow';
$checkArray['url']['site_access']['bp'][0]['type'] = array('command-and-control', 'compromised-website','grayware', 'malware', 'phishing', 'ransomware', 'scanning-activity');
$checkArray['url']['site_access']['bp'][0]['action'] = 'block';
$checkArray['url']['site_access']['bp'][1]['type'] = array('dynamic-dns', 'hacking', 'insufficient-content', 'newly-registered-domains', 'not-resolved', 'parked', 'proxy-avoidance-and-anonymizers', 'unknown');
$checkArray['url']['site_access']['bp'][1]['action'] = 'alert';
$checkArray['url']['site_access']['bp'][2]['type'] = array('abused-drugs', 'adult', 'copyright-infringement', 'extremism', 'gambling', 'peer-to-peer', 'questionable', 'weapons');
$checkArray['url']['site_access']['bp'][2]['action'] = 'alert';

$checkArray['url']['user_credential_submission']['visibility']['category'] = '!allow';
$checkArray['url']['user_credential_submission']['visibility']['tab']['mode'] = '!disabled';
$checkArray['url']['user_credential_submission']['bp']['category'][0]['type'] = array('command-and-control', 'compromised-website','grayware', 'malware', 'phishing', 'ransomware', 'scanning-activity');
$checkArray['url']['user_credential_submission']['bp']['category'][0]['action'] = 'block';
$checkArray['url']['user_credential_submission']['bp']['category'][1]['type'] = array('dynamic-dns', 'hacking', 'insufficient-content', 'newly-registered-domains', 'not-resolved', 'parked', 'proxy-avoidance-and-anonymizers', 'unknown');
$checkArray['url']['user_credential_submission']['bp']['category'][1]['action'] = 'alert';
$checkArray['url']['user_credential_submission']['bp']['category'][2]['type'] = array('abused-drugs', 'adult', 'copyright-infringement', 'extremism', 'gambling', 'peer-to-peer', 'questionable', 'weapons');
$checkArray['url']['user_credential_submission']['bp']['category'][2]['action'] = 'alert';
$checkArray['url']['user_credential_submission']['bp']['tab']['mode'] = 'ip-user';
$checkArray['url']['user_credential_submission']['bp']['tab']['log-severity'] = 'medium';


######################################################################################################################
######## FB
$checkArray['file-blocking']['rule'] = array();
$checkArray['file-blocking']['rule']['bp'] = array();
$checkArray['file-blocking']['rule']['visibility'] = array();

$checkArray['file-blocking']['rule']['visibility']['alert']['filetype'] = array('any');
$checkArray['file-blocking']['rule']['visibility']['alert']['action'] = 'alert';

$checkArray['file-blocking']['rule']['bp_custom']['block']['filetype'] = array('7z', 'bat','chm','class','cpl','dll','hlp','hta','jar','ocx','pif','scr','torrent','vbe','wsf');
$checkArray['file-blocking']['rule']['bp_custom']['block']['action'] = 'block';

$checkArray['file-blocking']['rule']['bp']['block']['filetype'] = array('7z', 'bat','chm','class','cpl','dll','hlp','hta','jar','ocx','pif','scr','torrent','vbe','wsf', 'cab','exe','flash','msi','Multi-Level-Encoding','PE','rar','tar','encrypted-rar','encrypted-zip');
$checkArray['file-blocking']['rule']['bp']['block']['action'] = 'block';

$checkArray['file-blocking']['rule']['bp_panw']['block']['filetype'] = array('7z', 'bat','chm','class','cpl','dll','hlp','hta','jar','ocx','pif','scr','torrent','vbe','wsf', 'cab','exe','flash','msi','Multi-Level-Encoding','PE','rar','tar','encrypted-rar','encrypted-zip');
$checkArray['file-blocking']['rule']['bp_panw']['block']['action'] = 'block';

######################################################################################################################
######## WF
$checkArray['wildfire']['rule'] = array();
$checkArray['wildfire']['rule']['bp'] = array();
$checkArray['wildfire']['rule']['visibility'] = array();

$checkArray['wildfire']['rule']['visibility'][0]['application'] = array('any');
$checkArray['wildfire']['rule']['visibility'][0]['filetype'] = array('any');
$checkArray['wildfire']['rule']['visibility'][0]['direction'] = 'both';
$checkArray['wildfire']['rule']['visibility'][0]['analysis'] = 'public-cloud';

$checkArray['wildfire']['rule']['bp'][0]['application'] = array('any');
$checkArray['wildfire']['rule']['bp'][0]['filetype'] = array('any');
$checkArray['wildfire']['rule']['bp'][0]['direction'] = 'both';
$checkArray['wildfire']['rule']['bp'][0]['analysis'] = 'public-cloud';


######################################################################################################################

$json = json_encode($checkArray, JSON_PRETTY_PRINT);

$fileName = "scm_bp_sp_panw.json";
file_put_contents($fileName, $json);
echo $json;