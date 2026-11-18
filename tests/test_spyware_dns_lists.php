<?php
/**
 * Tests of the set-actions on the DNS lists of an Anti-Spyware profile (botnet-domains -> lists),
 * trait sp_action_spyware: botnet_AlertOnlySet() / botnet_BestPracticeSet().
 *   - the Palo Alto Networks list 'default-paloalto-dns' follows the BP JSON (spyware -> lists)
 *   - a list the BP JSON does not name (custom EDL):
 *       alert-only-set     'allow' -> 'alert' (packet-capture kept), every other action kept
 *       best-practice-set  not changed
 *       no DNS license     block / sinkhole / alert are never set back to 'allow'
 * The expected results are the ones of the beta branch (regression: a custom EDL stayed on 'allow' with
 * alert-only-set, and every list was set to 'allow' without a DNS license).
 *
 *   cd tests && php test_spyware_dns_lists.php
 *
 * Input: input/panorama-10.0-merger.xml with profiles added to shared at runtime. Exit code 0 = all passed.
 */

$here = dirname(__FILE__);
$cli = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($here . '/../utils/pan-os-php.php') . ' type=securityprofile securityprofiletype=spyware location=shared';
$work = sys_get_temp_dir() . '/pan-os-php-test-spyware-dns-lists-' . getmypid();
@mkdir( $work, 0700, TRUE );

$failed = array();
$checks = 0;

function eq( $actual, $expected, $msg )
{
    global $failed, $checks;
    $checks++;
    if( $actual !== $expected )
        $failed[] = $msg . "\n      expected " . json_encode($expected) . "\n      got      " . json_encode($actual);
}

function dnsList( $name, $action, $pcap )
{
    return '<entry name="' . $name . '"><action><' . $action . '/></action><packet-capture>' . $pcap . '</packet-capture></entry>';
}

$profiles = array(
    'AS-A' => dnsList( 'default-paloalto-dns', 'allow', 'disable' ) . dnsList( 'BCP SINKHOLE', 'allow', 'disable' )
        . dnsList( 'EDL-block', 'block', 'single-packet' ) . dnsList( 'EDL-alert', 'alert', 'disable' ),
    'AS-B' => dnsList( 'default-paloalto-dns', 'sinkhole', 'extended-capture' ) . dnsList( 'EDL-allow-pc', 'allow', 'single-packet' ),
    'AS-C' => dnsList( 'default-paloalto-dns', 'block', 'disable' ) . dnsList( 'EDL-sinkhole', 'sinkhole', 'disable' ),
);
$xml = '<profiles><spyware>';
foreach( $profiles as $n => $l )
    $xml .= '<entry name="' . $n . '"><botnet-domains><lists>' . $l . '</lists><sinkhole><ipv4-address>pan-sinkhole-default-ip</ipv4-address>'
        . '<ipv6-address>::1</ipv6-address></sinkhole></botnet-domains></entry>';
$xml .= '</spyware></profiles>';

$d = new DOMDocument();
$d->load( $here . '/input/panorama-10.0-merger.xml' );
$f = new DOMDocument();
$f->loadXML( $xml );
$shared = ( new DOMXPath( $d ) )->query( '/config/shared' )->item( 0 );
$shared->appendChild( $d->importNode( $f->documentElement, TRUE ) );
$in = $work . '/in.xml';
$d->save( $in );

/** runs one action, returns profile => list of "name|action|packet-capture" of its DNS lists */
function listsAfter( $action )
{
    global $cli, $in, $work;
    $out = $work . '/out.xml';
    @unlink( $out );
    exec( $cli . ' in=' . escapeshellarg($in) . ' out=' . escapeshellarg($out) . ' ' . escapeshellarg( 'actions=' . $action ) . ' 2>&1', $o, $rc );
    if( $rc != 0 || !is_file($out) )
        return array( 'ERROR' => array( 'exit code ' . $rc ) );
    $r = new DOMDocument();
    $r->load( $out );
    $x = new DOMXPath( $r );
    $res = array();
    foreach( $x->query( '/config/shared/profiles/spyware/entry' ) as $p )
    {
        $list = array();
        foreach( $x->query( 'botnet-domains/lists/entry', $p ) as $e )
        {
            $a = $x->query( 'action/*', $e );
            $pc = $x->query( 'packet-capture', $e );
            $list[] = $e->getAttribute('name') . '|' . ( $a->length ? $a->item(0)->nodeName : '-' ) . '|' . ( $pc->length ? trim($pc->item(0)->textContent) : '-' );
        }
        $res[$p->getAttribute('name')] = $list;
    }
    return $res;
}

$expected = array(
    'spyware.botnet.alert-only-set' => array(
        'AS-A' => array( 'default-paloalto-dns|alert|disable', 'BCP SINKHOLE|alert|disable', 'EDL-block|block|single-packet', 'EDL-alert|alert|disable' ),
        'AS-B' => array( 'default-paloalto-dns|sinkhole|extended-capture', 'EDL-allow-pc|alert|single-packet' ),
        'AS-C' => array( 'default-paloalto-dns|block|disable', 'EDL-sinkhole|sinkhole|disable' ),
    ),
    'spyware.botnet.alert-only-set:false' => array(
        'AS-A' => array( 'default-paloalto-dns|allow|disable', 'BCP SINKHOLE|allow|disable', 'EDL-block|block|single-packet', 'EDL-alert|alert|disable' ),
        'AS-B' => array( 'default-paloalto-dns|sinkhole|extended-capture', 'EDL-allow-pc|allow|disable' ),
        'AS-C' => array( 'default-paloalto-dns|block|disable', 'EDL-sinkhole|sinkhole|disable' ),
    ),
    'spyware.botnet.best-practice-set' => array(
        'AS-A' => array( 'default-paloalto-dns|sinkhole|extended-capture', 'BCP SINKHOLE|allow|disable', 'EDL-block|block|single-packet', 'EDL-alert|alert|disable' ),
        'AS-B' => array( 'default-paloalto-dns|sinkhole|extended-capture', 'EDL-allow-pc|allow|single-packet' ),
        'AS-C' => array( 'default-paloalto-dns|sinkhole|extended-capture', 'EDL-sinkhole|sinkhole|disable' ),
    ),
    'spyware.botnet.best-practice-set:false' => array(
        'AS-A' => array( 'default-paloalto-dns|allow|disable', 'BCP SINKHOLE|allow|disable', 'EDL-block|block|single-packet', 'EDL-alert|alert|disable' ),
        'AS-B' => array( 'default-paloalto-dns|allow|disable', 'EDL-allow-pc|allow|single-packet' ),
        'AS-C' => array( 'default-paloalto-dns|allow|disable', 'EDL-sinkhole|sinkhole|disable' ),
    ),
);
foreach( $expected as $action => $byProfile )
{
    $r = listsAfter( $action );
    foreach( $byProfile as $profile => $lists )
        eq( $r[$profile] ?? null, $lists, $action . ' - ' . $profile );
}

// the profile-wide alert-only-set covers the lists the same way
$r = listsAfter( 'spyware.alert-only-set' );
eq( $r['AS-A'] ?? null, $expected['spyware.botnet.alert-only-set']['AS-A'], 'spyware.alert-only-set - AS-A (custom EDL allow -> alert)' );

exec( 'rm -rf ' . escapeshellarg($work) );
print "\n" . $checks . " checks, " . count($failed) . " failed\n";
if( count($failed) )
{
    foreach( $failed as $m ) print " - " . $m . "\n";
    exit( 1 );
}
exit( 0 );
