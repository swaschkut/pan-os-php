<?php
/**
 * ISC License
 *
 * Copyright (c) 2026, Sven Waschkut - pan-os-php@waschkut.net
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * Field actions of EDL, schedule, log forwarding profile and the details of security profiles (offline), as on the
 * command line. Synthetic inputs tests/input/edl-schedule-logprofile.xml, tests/input/securityprofile-details.xml.
 *
 *   php tests/test_object_field_actions.php
 */
$repo = dirname( __DIR__ );
$in = $repo . '/tests/input/edl-schedule-logprofile.xml';
$tmp = sys_get_temp_dir() . '/objfield-' . getmypid();
@mkdir( $tmp, 0700 );

$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};

// pan-os-php type=… in=$from out=$to; returns the lines '* …' / '*** SKIPPED …'
$step = 0;
$run = function( string $type, string $from, string $filter, string $actions ) use ( $repo, $tmp, &$step ) {
    $to = $tmp . '/' . ( ++$step ) . '.xml';
    $args = array( 'type=' . $type, 'in=' . $from, 'out=' . $to, 'location=vsys1', 'actions=' . $actions );
    if( $filter !== '' )
        $args[] = 'filter=' . $filter;
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' ' . implode( ' ', array_map( 'escapeshellarg', $args ) ) . ' 2>&1', $o );
    return array( $to, array_values( array_map( 'trim', preg_grep( '/^\s+\*+ (SKIPPED|[a-z])/', $o ) ) ) );
};
$xp = function( string $file, string $q ) {
    $d = new DOMDocument();
    $d->load( $file );
    $out = array();
    foreach( ( new DOMXPath( $d ) )->query( $q ) as $n )
        $out[] = trim( $n->textContent );
    return $out;
};
$edl = "//external-list/entry[@name='%s']/type";

// ---- EDL
list( $f, $l ) = $run( 'edl', $in, '(name eq edl-domain)',
    'recurring-set:weekly,3,monday/exception-add:ads.example.com/exception-add:ads.example.com/expand-domain-set:true/description-set:domain$$comma$$ blocked' .
    '/certificate-profile-set:cp-lists/source-set:https$$colon$$$$forwardslash$$$$forwardslash$$new.example.com$$forwardslash$$d.txt/source-set:ftp$$colon$$$$forwardslash$$$$forwardslash$$x' );
$eq( array(
    $xp( $f, sprintf( $edl, 'edl-domain' ) . '/domain/recurring/weekly/day-of-week' ), $xp( $f, sprintf( $edl, 'edl-domain' ) . '/domain/recurring/weekly/at' ),
    $xp( $f, sprintf( $edl, 'edl-domain' ) . '/domain/exception-list/member' ), $xp( $f, sprintf( $edl, 'edl-domain' ) . '/domain/expand-domain' ),
    $xp( $f, sprintf( $edl, 'edl-domain' ) . '/domain/description' ), $xp( $f, sprintf( $edl, 'edl-domain' ) . '/domain/certificate-profile' ),
    $xp( $f, sprintf( $edl, 'edl-domain' ) . '/domain/url' ) ),
    array( array( 'monday' ), array( '03' ), array( 'ads.example.com' ), array( 'yes' ), array( 'domain, blocked' ), array( 'cp-lists' ), array( 'https://new.example.com/d.txt' ) ),
    'EDL: recurring, exception list, expand domain, description in the type, certificate profile, source (aliases)' );
$eq( array_values( preg_grep( '/SKIPPED/', $l ) ), array( "*** SKIPPED : 'ads.example.com' is in the exception list already", "*** SKIPPED : source 'ftp://x': http:// or https:// URL" ),
    'EDL: a second exception the same, a source without http(s) - refused' );

list( $f, $l ) = $run( 'edl', $f, '(name eq edl-ip)', 'recurring-set:daily,25/type-set:predefined-ip/type-set:predefined-ip,panw-bulletproof-ip-list/recurring-set:hourly/name-rename:edl-bulletproof' );
$eq( array( $xp( $f, sprintf( $edl, 'edl-bulletproof' ) . '/predefined-ip/url' ), $xp( $f, sprintf( $edl, 'edl-bulletproof' ) . '/predefined-ip/recurring' ),
    $xp( $f, "//rules/entry[@name='block-edl']/source/member" ) ),
    array( array( 'panw-bulletproof-ip-list' ), array(), array( 'edl-bulletproof' ) ), 'EDL: type predefined-ip (no recurring), renamed - the rule too' );
$eq( array_values( preg_grep( '/SKIPPED/', $l ) ), array( "*** SKIPPED : at '25': the hour 0-23",
    "*** SKIPPED : source 'https://lists.example.com/ip.txt': the name of a predefined list (e.g. panw-bulletproof-ip-list)",
    '*** SKIPPED : a predefined list has no update interval' ), 'EDL: wrong hour, predefined type without the list name, interval of a predefined list - refused' );

// ---- schedule
list( $f, $l ) = $run( 'schedule', $in, '(name eq office-hours)', 'range-add:daily,-,1800-2000/range-add:daily,,18$$colon$$00-20$$colon$$00/range-add:weekly,monday,0800-1000/range-add:daily,-,2500-2600' );
$eq( $xp( $f, "//schedule/entry[@name='office-hours']//daily/member" ), array( '08:00-17:00', '18:00-20:00' ), 'schedule: a daily range more (short form)' );
$eq( array_values( preg_grep( '/SKIPPED/', $l ) ), array( "*** SKIPPED : '18:00-20:00' is set already", '*** SKIPPED : the schedule is daily - type-set to change the type',
    "*** SKIPPED : range '2500-2600': HH:MM-HH:MM (or HHMM-HHMM)" ), 'schedule: the same range, another type, a wrong time - refused' );

list( $f, $l ) = $run( 'schedule', $f, '(name eq weekend)', 'range-add:weekly,sunday,0000-2359/range-remove:weekly,saturday,00$$colon$$00-23$$colon$$59/range-remove:weekly,sunday,0000-2359' );
$eq( array( $xp( $f, "//schedule/entry[@name='weekend']//weekly/sunday/member" ), $xp( $f, "//schedule/entry[@name='weekend']//weekly/saturday" ) ),
    array( array( '00:00-23:59' ), array() ), 'schedule: weekly ranges added / removed' );
$eq( array_values( preg_grep( '/SKIPPED/', $l ) ), array( '*** SKIPPED : the last range of a schedule can not be removed' ), 'schedule: the last range stays' );

list( $f, $l ) = $run( 'schedule', $f, '(name eq office-hours)', 'type-set:non-recurring,-,20260301@0800-20260302@1700/type-set:non-recurring,-,20260302@0800-20260301@1700/name-rename:office-march' );
$eq( array( $xp( $f, "//schedule/entry[@name='office-march']//non-recurring/member" ), $xp( $f, "//schedule/entry[@name='office-march']//recurring" ),
    $xp( $f, "//rules/entry[@name='office']/schedule" ) ),
    array( array( '2026/03/01@08:00-2026/03/02@17:00' ), array(), array( 'office-march' ) ), 'schedule: type-set non-recurring (one range), renamed - the rule too' );
$eq( array_values( preg_grep( '/SKIPPED/', $l ) ), array( "*** SKIPPED : range '20260302@0800-20260301@1700': the start must be before the end" ), 'schedule: end before start - refused' );

// ---- log forwarding profile
list( $f, $l ) = $run( 'log-profile', $in, '',
    'match-add:threat-high,threat,(severity geq high),true/match-send-add:threat-high,syslog,siem/match-send-add:threat-high,email,mail-soc' .
    '/match-send-remove:threat-high,email,mail-soc/match-set:traffic-all,filter,(addr.src in 10.0.0.0$$forwardslash$$8)/match-set:traffic-all,quarantine,no' .
    '/description-set:central logging/enhanced-application-logging-set:true/name-rename:lf-central/match-remove:nothere/match-add:x,firewall' );
$m = "//log-settings/profiles/entry[@name='lf-central']/match-list/entry[@name='%s']";
$eq( array( $xp( $f, sprintf( $m, 'threat-high' ) . '/log-type' ), $xp( $f, sprintf( $m, 'threat-high' ) . '/filter' ), $xp( $f, sprintf( $m, 'threat-high' ) . '/send-to-panorama' ),
    $xp( $f, sprintf( $m, 'threat-high' ) . '/send-syslog/member' ), $xp( $f, sprintf( $m, 'threat-high' ) . '/send-email' ),
    $xp( $f, sprintf( $m, 'traffic-all' ) . '/filter' ), $xp( $f, sprintf( $m, 'traffic-all' ) . '/quarantine' ) ),
    array( array( 'threat' ), array( '(severity geq high)' ), array( 'yes' ), array( 'siem' ), array(), array( '(addr.src in 10.0.0.0/8)' ), array( 'no' ) ),
    'log forwarding: match list entry added, server profiles, filter / quarantine set' );
$eq( array( $xp( $f, "//log-settings/profiles/entry[@name='lf-central']/description" ), $xp( $f, "//log-settings/profiles/entry[@name='lf-central']/enhanced-application-logging" ),
    $xp( $f, "//rules/entry/log-setting" ), $xp( $f, "//zone/entry/network/log-setting" ) ),
    array( array( 'central logging' ), array( 'yes' ), array( 'lf-central', 'lf-central' ), array( 'lf-central' ) ),
    'log forwarding: description, enhanced logging; renamed - the rules and the zone too' );
$eq( count( preg_grep( "/SKIPPED : match list entry 'nothere' not found|SKIPPED : log type 'firewall'/", $l ) ), 2, 'log forwarding: unknown entry, unknown log type - refused' );

// ---- security profile details (lists and options)
$sp = $repo . '/tests/input/securityprofile-details.xml';
$runSp = function( string $sptype, string $from, string $actions ) use ( $repo, $tmp, &$step ) {
    $to = $tmp . '/' . ( ++$step ) . '.xml';
    $args = array( 'type=securityprofile', 'securityprofiletype=' . $sptype, 'in=' . $from, 'out=' . $to, 'location=vsys1', 'actions=' . $actions );
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' ' . implode( ' ', array_map( 'escapeshellarg', $args ) ) . ' 2>&1', $o );
    return array( $to, array_values( array_map( 'trim', preg_grep( '/^\s+\*+ SKIPPED/', $o ) ) ) );
};
list( $f, $l ) = $runSp( 'spyware', $sp, 'detail-entry-add:rule,r-high/detail-entry-set:rule,r-high,severity,high+medium/detail-entry-set:rule,r-high,action,reset-both' .
    '/detail-entry-add:threat-exception,30003/detail-entry-set:threat-exception,30003,exempt-ip,192.0.2.10+192.0.2.11/detail-entry-set:dns-category,pan-dns-sec-malware,action,sinkhole' .
    '/detail-entry-set:rule,r-high,severity,any+high/detail-entry-remove:rule,r-critical/detail-entry-add:threat-exception,abc' );
$r = "//spyware/entry[@name='as-1']";
$eq( array( $xp( $f, $r . "/rules/entry/@name" ), $xp( $f, $r . "/rules/entry[@name='r-high']/severity/member" ), $xp( $f, "name(" . $r . "/rules/entry[@name='r-high']/action/*)" ),
    $xp( $f, $r . "/threat-exception/entry[@name='30003']/exempt-ip/entry/@name" ), $xp( $f, $r . "/botnet-domains/dns-security-categories/entry[@name='pan-dns-sec-malware']/action" ) ),
    array( array( 'r-high' ), array( 'high', 'medium' ), array(), array( '192.0.2.10', '192.0.2.11' ), array( 'sinkhole' ) ),
    'anti-spyware: rule added / set / removed, threat exception with exempt IPs, DNS category action' );
$eq( $l, array( '*** SKIPPED : severity: any with other values', "*** SKIPPED : name 'abc' is not valid for threat-exception" ),
    'anti-spyware: any with other severities, a threat exception that is no ID - refused' );
$d = new DOMDocument(); $d->load( $f );
$eq( ( new DOMXPath( $d ) )->query( $r . "/rules/entry[@name='r-high']/action/reset-both" )->length, 1, 'anti-spyware: the action as an element (<action><reset-both/></action>)' );

list( $f, $l ) = $runSp( 'virus', $sp, 'detail-entry-set:decoder,smtp,action,reset-both/detail-entry-set:decoder,imap,mlav-action,alert/detail-entry-add:decoder,x' .
    '/detail-entry-add:application-exception,web-browsing/detail-entry-set:application-exception,web-browsing,action,alert/detail-option-set:packet-capture,yes' );
$r = "//virus/entry[@name='av-1']";
$eq( array( $xp( $f, $r . "/decoder/entry[@name='smtp']/action" ), $xp( $f, $r . "/decoder/entry[@name='imap']/*" ), $xp( $f, $r . "/application-exception/entry[@name='web-browsing']/action" ),
    $xp( $f, $r . "/packet-capture" ), $l ),
    array( array( 'reset-both' ), array( 'default', 'default', 'alert' ), array( 'alert' ), array( 'yes' ), array( "*** SKIPPED : the entries of 'decoder' are fixed (PAN-OS) - detail-entry-set to change them" ) ),
    'antivirus: decoder actions (a missing decoder of PAN-OS created), application exception, packet capture; no own decoders' );

list( $f, $l ) = $runSp( 'vulnerability', $sp, 'detail-entry-add:rule,client-crit/detail-entry-set:rule,client-crit,host,client/detail-entry-set:rule,client-crit,cve,CVE-2021-44228/detail-entry-set:rule,client-crit,action,block-ip' );
$eq( array( $xp( $f, "//vulnerability/entry[@name='vp-1']/rules/entry[@name='client-crit']/host" ), $xp( $f, "//vulnerability/entry[@name='vp-1']/rules/entry[@name='client-crit']/cve/member" ), count( $l ) ),
    array( array( 'client' ), array( 'CVE-2021-44228' ), 1 ), 'vulnerability: rule with host and CVE; block-ip (needs more fields) refused' );

list( $f, $l ) = $runSp( 'url-filtering', $sp, 'detail-option-set:log-http-hdr-xff,yes/url.credential-action-set:financial-services,block/url.credential-action-set:financial-services,alert/detail-option-set:safe-search-enforcement,maybe' );
$eq( array( $xp( $f, "//url-filtering/entry/log-http-hdr-xff" ), $xp( $f, "//url-filtering/entry/credential-enforcement/alert/member" ), $xp( $f, "//url-filtering/entry/credential-enforcement/block" ), $l ),
    array( array( 'yes' ), array( 'financial-services' ), array(), array( "*** SKIPPED : safe-search-enforcement 'maybe': yes, no" ) ),
    'url filtering: option, credential detection action of a category (moved, no empty list)' );

list( $f, $l ) = $runSp( 'file-blocking', $sp, 'detail-entry-add:rule,block-exe/detail-entry-set:rule,block-exe,file-type,exe+dll/detail-entry-set:rule,block-exe,action,block/detail-entry-set:rule,block-exe,direction,sideways' );
$eq( array( $xp( $f, "//file-blocking/entry/rules/entry/@name" ), $xp( $f, "//file-blocking/entry/rules/entry[@name='block-exe']/file-type/member" ), $xp( $f, "//file-blocking/entry/rules/entry[@name='block-exe']/action" ), count( $l ) ),
    array( array( 'log-all', 'block-exe' ), array( 'exe', 'dll' ), array( 'block' ), 1 ), 'file blocking: rule at the end, file types, action; wrong direction refused' );

list( $f, $l ) = $runSp( 'wildfire-analysis', $sp, 'detail-entry-set:rule,all,analysis,private-cloud' );
$eq( $xp( $f, "//wildfire-analysis/entry/rules/entry[@name='all']/analysis" ), array( 'private-cloud' ), 'wildfire analysis: rule analysis' );

foreach( glob( $tmp . '/*' ) as $x )
    @unlink( $x );
@rmdir( $tmp );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
