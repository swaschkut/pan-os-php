<?php
/**
 * Tests of type=master-key (utils/lib/MASTER_KEY__.php, utils/common/ConfigSecrets.php).
 *
 *   cd tests && php test_master_key.php
 *
 * Input: input/panorama-move/panorama-move-A.xml, extended at runtime with encrypted values (generated with PanosCrypto):
 * default master key, a custom master key, another (unknown) key, an unknown format version, a malformed value and
 * values that only look similar. Exit code 0 = all passed.
 */

$here = dirname(__FILE__);
require_once $here . '/../lib/pan_php_framework.php';
require_once $here . '/../utils/common/ConfigSecrets.php';

$cli = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($here . '/../utils/pan-os-php.php') . ' type=master-key';
$work = sys_get_temp_dir() . '/pan-os-php-test-master-key-' . getmypid();
@mkdir( $work, 0700, TRUE );

$failed = array();
$checks = 0;

function check( $cond, $msg )
{
    global $failed, $checks;
    $checks++;
    if( !$cond )
        $failed[] = $msg;
}

function eq( $actual, $expected, $msg )
{
    check( $actual === $expected, $msg . ' (expected ' . json_encode($expected) . ', got ' . json_encode($actual) . ')' );
}

/** runs the type, returns array( exit code, output, JSON (shadow-json) or null ) */
function mk( array $args, $json = FALSE )
{
    global $cli;
    $cmd = $cli;
    foreach( $args as $a ) $cmd .= ' ' . escapeshellarg($a);
    if( $json ) $cmd .= ' shadow-json';
    exec( $cmd . ' 2>&1', $out, $rc );
    $text = implode( "\n", $out );
    $j = null;
    if( $json )
    {
        $p = strpos( $text, '{' );
        $j = $p === FALSE ? null : json_decode( substr($text, $p), TRUE );
    }
    return array( $rc, $text, $j );
}

$CUSTOM = 'Cust0mMasterKey!';   // 16 characters
$OTHER = 'An0therMasterKey';
$crypto = new PanosCrypto();
$clear = array( 'default' => 'clear-DEFAULT-secret', 'custom' => 'clear-CUSTOM-secret', 'other' => 'clear-OTHER-secret' );
$enc = array(
    'default' => $crypto->encrypt( $clear['default'] ),
    'custom' => $crypto->encrypt( $clear['custom'], $CUSTOM ),
    'other' => $crypto->encrypt( $clear['other'], $OTHER ),
    // version byte 2 (e.g. another encryption level) - format not known to pan-os-php
    'v2' => '-Ag==' . base64_encode( random_bytes(48) ),
    // version 1 with a ciphertext that is no multiple of 16 bytes
    'malformed' => '-AQ==' . base64_encode( sha1('x', TRUE) ) . base64_encode( 'short' ),
);

// ---- unit: ConfigSecrets::parse / keyOf
eq( ConfigSecrets::parse( $enc['default'] ), array( 'version' => 1, 'format' => 'aes-256-cbc' ), 'parse: version 1' );
eq( ConfigSecrets::parse( $enc['v2'] ), array( 'version' => 2, 'format' => 'unknown' ), 'parse: version 2 unknown' );
eq( ConfigSecrets::parse( $enc['malformed'] ), array( 'version' => 1, 'format' => 'malformed' ), 'parse: malformed' );
foreach( array( '-AQ== not a secret', '-', '-10', '--default--', 'AQ==abcdefghijklmnopqrstuvwxyz', '-any-text-with-dashes-and-more-characters', '' ) as $no )
    eq( ConfigSecrets::parse( $no ), null, 'parse: not encrypted "' . $no . '"' );
eq( ConfigSecrets::parse( '-AQ==A4vEGnxsZCP7poqzjhJD4Gc+tbE=DS4xndFfZiigUHPCm4ASFQ==' ), array( 'version' => 1, 'format' => 'aes-256-cbc' ), 'parse: known vector' );
eq( ConfigSecrets::keyOf( '-AQ==A4vEGnxsZCP7poqzjhJD4Gc+tbE=DS4xndFfZiigUHPCm4ASFQ==' ), 'default', 'keyOf: known vector uses the default key' );
eq( ConfigSecrets::keyOf( $enc['custom'] ), 'unknown', 'keyOf: custom without key' );
eq( ConfigSecrets::keyOf( $enc['custom'], $CUSTOM ), 'given', 'keyOf: custom with key' );
eq( ConfigSecrets::keyOf( $enc['custom'], $OTHER ), 'unknown', 'keyOf: custom with the wrong key' );
eq( ConfigSecrets::keyOf( $enc['default'], $CUSTOM ), 'default', 'keyOf: default wins' );
eq( ConfigSecrets::keyOf( $enc['v2'], $CUSTOM ), 'unknown', 'keyOf: unknown version' );

// ---- fixture
$d = new DOMDocument();
$d->load( $here . '/input/panorama-move/panorama-move-A.xml' );
$x = new DOMXPath( $d );
$add = function( $xpath, $xml ) use ( $d, $x ) {
    $n = $x->query( $xpath )->item(0);
    if( $n === null ) { print "fixture: xpath not found " . $xpath . "\n"; exit( 2 ); }
    $f = new DOMDocument();
    $f->loadXML( $xml );
    $n->appendChild( $d->importNode( $f->documentElement, TRUE ) );
};
$dev = "/config/devices/entry[@name='localhost.localdomain']";
$add( '/config/shared', '<log-settings><syslog><entry name="sl1"><server><entry name="s1"><password>' . $enc['default'] . '</password></entry></server></entry></syslog></log-settings>' );
$add( '/config/shared', '<server-profile><ldap><entry name="ldap1"><bind-password>' . $enc['custom'] . '</bind-password><description>-AQ== not a secret</description></entry></ldap></server-profile>' );
$add( $dev . "/device-group/entry[@name='testDG']", '<authentication-object><entry name="a1"><secret>' . $enc['other'] . '</secret></entry></authentication-object>' );
$add( $dev . "/template/entry[@name='Paris Datacenter']/config/devices/entry", '<network><ike><gateway><entry name="gw1"><authentication><pre-shared-key><key>' . $enc['custom'] . '</key></pre-shared-key></authentication></entry>'
    . '<entry name="gw2"><authentication><pre-shared-key><key>' . $enc['v2'] . '</key></pre-shared-key></authentication></entry></gateway></ike></network>' );
$add( $dev . "/template-stack/entry[@name='Paris_Datacenter_Stack']", '<config><devices><entry name="localhost.localdomain"><deviceconfig><system><snmp-setting><access-setting><version><v3><users><entry name="u1"><authpwd>' . $enc['malformed'] . '</authpwd></entry></users></v3></version></access-setting></snmp-setting></system></deviceconfig></entry></devices></config>' );
$add( '/config/mgt-config', '<users><entry name="apiuser"><phash>$1$abcdefgh$0123456789abcdefghijkl</phash><comment>--default--</comment></entry></users>' );
$in = $work . '/secrets.xml';
$d->save( $in );
$md5in = md5_file( $in );
$keyFile = $work . '/key.txt';
file_put_contents( $keyFile, $CUSTOM . "\n" );
$baseItems = ConfigSecrets::scan( (function() use ( $here ) { $o = new DOMDocument(); $o->load( $here . '/input/panorama-move/panorama-move-A.xml' ); return $o; })() );
$base = count( $baseItems );
$baseUnknown = count( array_filter( $baseItems, function( $i ) { return $i['key'] === 'unknown'; } ) );

/** output must never contain a value: neither encrypted nor clear text nor the key */
$noLeak = function( $text, $what ) use ( $enc, $clear, $CUSTOM ) {
    foreach( $enc as $k => $v ) check( strpos($text, $v) === FALSE && strpos($text, substr($v, 5, 24)) === FALSE, $what . ': encrypted value "' . $k . '" not in the output' );
    foreach( $clear as $k => $v ) check( strpos($text, $v) === FALSE, $what . ': clear text "' . $k . '" not in the output' );
    check( strpos($text, $CUSTOM) === FALSE, $what . ': master key not in the output' );
};

// ---- display without key
list( $rc, $t, $j ) = mk( array( 'in=' . $in ), TRUE );
eq( $rc, 0, 'display exit code' );
$items = isset($j['encrypted_values']) ? $j['encrypted_values'] : array();
eq( count($items), $base + 6, 'six added encrypted values found (look-alikes and phash not counted)' );
$by = array();
foreach( $items as $i ) $by[$i['xpath']] = $i;
$xp = array(
    'syslog' => "/config/shared/log-settings/syslog/entry[@name='sl1']/server/entry[@name='s1']/password",
    'ldap' => "/config/shared/server-profile/ldap/entry[@name='ldap1']/bind-password",
    'dg' => $dev . "/device-group/entry[@name='testDG']/authentication-object/entry[@name='a1']/secret",
    'gw1' => $dev . "/template/entry[@name='Paris Datacenter']/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway/entry[@name='gw1']/authentication/pre-shared-key/key",
    'gw2' => $dev . "/template/entry[@name='Paris Datacenter']/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway/entry[@name='gw2']/authentication/pre-shared-key/key",
    'snmp' => $dev . "/template-stack/entry[@name='Paris_Datacenter_Stack']/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/snmp-setting/access-setting/version/v3/users/entry[@name='u1']/authpwd",
);
foreach( $xp as $k => $p ) check( isset($by[$p]), 'xpath listed: ' . $k );
$get = function( $k, $f ) use ( &$by, $xp ) { return isset($by[$xp[$k]]) ? $by[$xp[$k]][$f] : null; };
eq( $get('syslog', 'key'), 'default', 'default key detected' );
eq( $get('ldap', 'key'), 'unknown', 'custom key value: unknown without key' );
eq( $get('syslog', 'location'), 'shared', 'location shared' );
eq( $get('dg', 'location'), 'device-group testDG', 'location device group' );
eq( $get('gw1', 'location'), 'template Paris Datacenter', 'location template' );
eq( $get('snmp', 'location'), 'template-stack Paris_Datacenter_Stack', 'location template stack' );
eq( $get('gw1', 'field'), 'network/ike/gateway/entry/authentication/pre-shared-key/key', 'field without names' );
eq( $get('gw2', 'format'), 'unknown', 'version 2: format unknown' );
eq( $get('gw2', 'version'), 2, 'version 2 reported' );
eq( $get('snmp', 'format'), 'malformed', 'malformed value reported' );
eq( $get('ldap', 'length'), strlen($enc['custom']), 'length reported' );
check( !isset($items[0]['value']), 'no value field in JSON' );
eq( $j['summary'][0]['hashed_values_not_master_key_encrypted'] >= 1, TRUE, 'phash counted separately' );
eq( $j['summary'][0]['other_master_key'], 3, 'summary: three well-formed values need another master key' );
eq( $j['summary'][0]['by_format']['unknown'], 1, 'summary: one unsupported version' );
$noLeak( $t, 'display JSON' );

list( $rc, $t ) = mk( array( 'in=' . $in ) );
check( strpos($t, $xp['gw1']) !== FALSE && strpos($t, 'UNKNOWN (other master key)') !== FALSE, 'text display: xpath and key state' );
check( strpos($t, 'version 2 - not supported') !== FALSE, 'text display: unsupported version' );
$noLeak( $t, 'display text' );

// ---- with the custom master key (file)
list( $rc, $t, $j ) = mk( array( 'in=' . $in, 'master-key-file=' . $keyFile ), TRUE );
$by = array();
foreach( $j['encrypted_values'] as $i ) $by[$i['xpath']] = $i;
eq( $get('ldap', 'key'), 'given', 'custom key value: given key (file)' );
eq( $get('gw1', 'key'), 'given', 'second custom key value' );
eq( $get('dg', 'key'), 'unknown', 'value of another key stays unknown' );
eq( $get('syslog', 'key'), 'default', 'default stays default' );
eq( $j['summary'][0]['by_key']['given'], 2, 'summary: two with the given key' );
$noLeak( $t, 'display with key' );

// ---- key= filter, master-key= argument
list( $rc, $t, $j ) = mk( array( 'in=' . $in, 'master-key=' . $CUSTOM, 'key=unknown' ), TRUE );
eq( isset($j['encrypted_values']) ? count($j['encrypted_values']) : 0, $baseUnknown + 3, 'key=unknown: other key, version 2, malformed' );
eq( $j['summary'][0]['other_master_key'], 1, 'with the key: one value of another master key left' );
eq( $j['summary'][0]['total'], $base + 6, 'key= filter keeps the total in the summary' );
list( $rc, $t, $j ) = mk( array( 'in=' . $in, 'master-key=' . $CUSTOM, 'key=given' ), TRUE );
eq( count($j['encrypted_values']), 2, 'key=given' );

// ---- HTML export
$html = $work . '/secrets.html';
list( $rc ) = mk( array( 'in=' . $in, 'master-key-file=' . $keyFile, 'actions=exportToHtml:' . str_replace('/', '//', $html) ) );
$h = (string)@file_get_contents( $html );
check( strpos($h, 'template Paris Datacenter') !== FALSE && strpos($h, 'pre-shared-key') !== FALSE && strpos($h, 'given master key') !== FALSE, 'HTML export: location, field, key' );
$noLeak( $h, 'HTML export' );

// ---- errors
list( $rc, $t ) = mk( array( 'in=' . $in, 'key=given' ) );
check( $rc != 0 && strpos($t, 'master-key') !== FALSE, 'key=given without key refused' );
list( $rc, $t ) = mk( array( 'in=' . $in, 'master-key-file=' . $work . '/missing.txt' ) );
check( $rc != 0, 'missing key file refused' );
list( $rc, $t ) = mk( array( 'in=' . $in, 'actions=decrypt' ) );
check( $rc != 0 && strpos($t, 'not supported') !== FALSE, 'unknown action refused' );
list( $rc, $t ) = mk( array( 'in=' . $in, 'master-key=short' ) );
check( $rc == 0 && strpos($t, '16 characters') !== FALSE, 'key length warning' );

// ---- hashes flag: password hashes with xpath and algorithm, never the hash
eq( ConfigSecrets::hashAlgorithm( '$1$abcdefgh$0123456789abcdefghijkl' ), 'MD5-crypt', 'hash algorithm $1$' );
eq( ConfigSecrets::hashAlgorithm( '$5$salt$xyz' ), 'SHA-256-crypt', 'hash algorithm $5$' );
eq( ConfigSecrets::hashAlgorithm( '$6$salt$xyz' ), 'SHA-512-crypt', 'hash algorithm $6$' );
eq( ConfigSecrets::hashAlgorithm( 'fnRL/G5lXVMug' ), 'DES-crypt', 'hash algorithm DES' );
eq( ConfigSecrets::hashAlgorithm( '*' ), 'no password (locked)', 'hash algorithm locked' );
list( $rc, $t, $j ) = mk( array( 'in=' . $in ), TRUE );
check( !isset($j['hashed_values']), 'without hashes flag: no hash list' );
list( $rc, $t, $j ) = mk( array( 'in=' . $in, 'hashes' ), TRUE );
$hx = "/config/mgt-config/users/entry[@name='apiuser']/phash";
$hit = array_values( array_filter( isset($j['hashed_values']) ? $j['hashed_values'] : array(), function( $h ) use ( $hx ) { return $h['xpath'] === $hx; } ) );
eq( count($hit), 1, 'hashes flag: phash xpath listed' );
eq( isset($hit[0]) ? array( $hit[0]['algorithm'], $hit[0]['weak'], $hit[0]['location'] ) : null, array( 'MD5-crypt', TRUE, 'mgt-config' ), 'hashes flag: algorithm, weak, location' );
eq( count($j['hashed_values']), $j['summary'][0]['hashed_values_not_master_key_encrypted'], 'hashes flag: list matches the count' );
check( isset($j['summary'][0]['hash_algorithms']['MD5-crypt']), 'hashes flag: algorithms in the summary' );
eq( count($j['encrypted_values']), $base + 6, 'hashes flag: encrypted values unchanged' );
check( strpos($t, '0123456789abcdefghijkl') === FALSE && strpos($t, '$1$abcdefgh') === FALSE, 'hashes flag: hash not in the JSON output' );
list( $rc, $t ) = mk( array( 'in=' . $in, 'hashes' ) );
check( strpos($t, $hx) !== FALSE && strpos($t, 'WEAK algorithm') !== FALSE, 'hashes flag: text display' );
check( strpos($t, '0123456789abcdefghijkl') === FALSE, 'hashes flag: hash not in the text output' );
$html2 = $work . '/hashes.html';
mk( array( 'in=' . $in, 'hashes', 'actions=exportToHtml:' . str_replace('/', '//', $html2) ) );
$h2 = (string)@file_get_contents( $html2 );
check( strpos($h2, 'password hash: MD5-crypt') !== FALSE && strpos($h2, '0123456789abcdefghijkl') === FALSE, 'hashes flag: HTML export without the hash' );
list( $rc, $t ) = mk( array( 'in=' . $in, 'out=' . $work . '/h.xml', 'master-key=' . $CUSTOM, 'hashes', 'actions=rekey' ) );
check( $rc != 0, 'hashes with rekey refused' );

// ---- rekey
/** secrets of a file by xpath */
$valuesOf = function( $file ) {
    $o = new DOMDocument();
    $o->load( $file );
    $x = new DOMXPath( $o );
    $r = array();
    foreach( $x->query('//text()[starts-with(normalize-space(.),"-")]') as $t )
        if( ConfigSecrets::parse( trim($t->nodeValue) ) !== null )
            $r[ DH::elementToPanXPath( $t->parentNode ) ] = trim( $t->nodeValue );
    return $r;
};
/** canonical XML with every encrypted value replaced - everything except the secrets */
$skeleton = function( $file ) {
    $o = new DOMDocument();
    $o->preserveWhiteSpace = FALSE;
    $o->load( $file );
    $x = new DOMXPath( $o );
    foreach( iterator_to_array( $x->query('//text()') ) as $t )
        if( ConfigSecrets::parse( trim($t->nodeValue) ) !== null )
            $t->nodeValue = 'SECRET';
        elseif( trim($t->nodeValue) === '' )
            $t->parentNode->removeChild( $t );
        else
            $t->nodeValue = trim( $t->nodeValue );
    return md5( $o->C14N() );
};
$newKeyFile = $work . '/newkey.txt';
$NEW = 'N3wTargetKey1234';
file_put_contents( $newKeyFile, $NEW );

// values of another key / other formats: refused without allow-partial, nothing written
$out = $work . '/rekey-partial.xml';
list( $rc, $t ) = mk( array( 'in=' . $in, 'out=' . $out, 'master-key-file=' . $keyFile, 'actions=rekey' ) );
check( $rc != 0 && !file_exists($out), 'rekey with values that can not be re-encrypted: refused, out= not written' );
check( strpos($t, 'allow-partial') !== FALSE, 'rekey refused: hint allow-partial' );
$noLeak( $t, 'rekey refused' );

list( $rc, $t, $j ) = mk( array( 'in=' . $in, 'out=' . $out, 'master-key-file=' . $keyFile, 'actions=rekey', 'allow-partial' ), TRUE );
eq( $rc, 0, 'rekey allow-partial exit code' );
eq( isset($j['summary'][0]) ? array( $j['summary'][0]['rekeyed'], $j['summary'][0]['already_target_key'], $j['summary'][0]['failed'], $j['summary'][0]['unsupported'] ) : null,
    array( 2, 1, 1, 2 + $baseUnknown ), 'rekey summary: 2 re-encrypted, 1 already default, 1 other key, unsupported / malformed' );
$noLeak( $t, 'rekey output' );
$v = $valuesOf( $out );
$orig = $valuesOf( $in );
eq( $crypto->decrypt( $v[$xp['ldap']] ), $clear['custom'], 'rekey: custom value decrypts with the default key, same clear text' );
eq( $crypto->decrypt( $v[$xp['gw1']] ), $clear['custom'], 'rekey: second custom value' );
eq( $v[$xp['syslog']], $orig[$xp['syslog']], 'rekey: default value unchanged' );
eq( $v[$xp['dg']], $orig[$xp['dg']], 'rekey: value of another key unchanged' );
eq( $v[$xp['gw2']], $orig[$xp['gw2']], 'rekey: unsupported version unchanged' );
eq( $v[$xp['snmp']], $orig[$xp['snmp']], 'rekey: malformed unchanged' );
eq( count($v), count($orig), 'rekey: same number of encrypted values' );
eq( $skeleton( $out ), $skeleton( $in ), 'rekey: nothing but the secrets changed' );
check( md5_file($in) === $md5in, 'rekey: input file unchanged' );
$p = new PanoramaConf();
$p->load_from_file( $out );
check( $p->findDeviceGroup('testDG') !== null, 'rekey: output loads with pan-os-php' );

// clean configuration (default + custom only): custom -> default without allow-partial
$c = new DOMDocument();
$c->load( $in );
$cx = new DOMXPath( $c );
foreach( iterator_to_array( $cx->query('//text()[starts-with(normalize-space(.),"-")]') ) as $tn )
{
    $val = trim( $tn->nodeValue );
    if( ConfigSecrets::parse($val) !== null && $val !== $enc['default'] && $val !== $enc['custom'] )
        $tn->nodeValue = $enc['custom'];
}
$clean = $work . '/clean.xml';
$c->save( $clean );
$out2 = $work . '/rekey-default.xml';
list( $rc, $t, $j ) = mk( array( 'in=' . $clean, 'out=' . $out2, 'master-key-file=' . $keyFile, 'actions=rekey' ), TRUE );
eq( $rc, 0, 'rekey custom -> default exit code' );
eq( $j['summary'][0]['failed'] + $j['summary'][0]['unsupported'], 0, 'rekey custom -> default: nothing left' );
list( $rc, $t, $j ) = mk( array( 'in=' . $out2 ), TRUE );
eq( $j['summary'][0]['by_key'], array( 'default' => $base + 6 ), 'after rekey: every value uses the default master key' );
list( $rc, $t ) = mk( array( 'in=' . $clean, 'out=' . $out2, 'master-key-file=' . $keyFile, 'actions=rekey' ) );
check( strpos($t, 'as good as clear text') !== FALSE, 'rekey to the default key: note about the public default key' );

// custom -> new custom key
$out3 = $work . '/rekey-new.xml';
list( $rc, $t, $j ) = mk( array( 'in=' . $clean, 'out=' . $out3, 'master-key-file=' . $keyFile, 'new-master-key-file=' . $newKeyFile, 'actions=rekey' ), TRUE );
eq( $rc, 0, 'rekey custom -> new key exit code' );
eq( $j['summary'][0]['rekeyed'], $base + 6, 'rekey custom -> new key: default and custom values re-encrypted' );
$v = $valuesOf( $out3 );
eq( $crypto->decrypt( $v[$xp['ldap']], $NEW ), $clear['custom'], 'new key decrypts the former custom value' );
eq( $crypto->decrypt( $v[$xp['syslog']], $NEW ), $clear['default'], 'new key decrypts the former default value' );
eq( $crypto->decrypt( $v[$xp['syslog']] ), '', 'default key no longer decrypts' );
check( strpos($t, $NEW) === FALSE, 'target key not in the output' );
eq( $skeleton( $out3 ), $skeleton( $clean ), 'rekey to a new key: nothing but the secrets changed' );

// round trip: back to the custom key gives the original values (encryption is deterministic)
$out4 = $work . '/rekey-back.xml';
mk( array( 'in=' . $out3, 'out=' . $out4, 'master-key-file=' . $newKeyFile, 'new-master-key-file=' . $keyFile, 'actions=rekey' ) );
$back = $valuesOf( $out4 );
eq( $back[$xp['ldap']], $enc['custom'], 'round trip: original value' );

// default -> custom (only the target key given), second run: already target key
$out5 = $work . '/rekey-fromdefault.xml';
list( $rc, $t, $j ) = mk( array( 'in=' . $out2, 'out=' . $out5, 'new-master-key=' . $NEW, 'actions=rekey' ), TRUE );
eq( array( $rc, $j['summary'][0]['rekeyed'] ), array( 0, $base + 6 ), 'rekey default -> custom' );
list( $rc, $t, $j ) = mk( array( 'in=' . $out5, 'out=' . $work . '/again.xml', 'new-master-key=' . $NEW, 'actions=rekey' ), TRUE );
eq( array( $j['summary'][0]['rekeyed'], $j['summary'][0]['already_target_key'] ), array( 0, $base + 6 ), 'second run: already target key' );

// errors
list( $rc, $t ) = mk( array( 'in=' . $in, 'master-key-file=' . $keyFile, 'actions=rekey' ) );
check( $rc != 0 && strpos($t, 'out=') !== FALSE, 'rekey without out= refused' );
list( $rc, $t ) = mk( array( 'in=' . $in, 'out=' . $work . '/x.xml', 'actions=rekey' ) );
check( $rc != 0 && strpos($t, 'nothing to do') !== FALSE, 'rekey without any key refused' );
list( $rc, $t ) = mk( array( 'in=' . $in, 'out=' . $work . '/x.xml', 'master-key=' . $CUSTOM, 'new-master-key=' . $CUSTOM, 'actions=rekey' ) );
check( $rc != 0 && strpos($t, 'are the same') !== FALSE, 'rekey with identical keys refused' );
list( $rc, $t ) = mk( array( 'in=' . $in, 'out=' . $work . '/x.xml', 'master-key=' . $CUSTOM, 'actions=rekey/display' ) );
check( $rc != 0 && strpos($t, 'can not be combined') !== FALSE, 'rekey combined with display refused' );
list( $rc, $t ) = mk( array( 'in=' . $in, 'new-master-key=' . $NEW ) );
check( $rc != 0 && strpos($t, 'actions=rekey') !== FALSE, 'new-master-key without rekey refused' );
check( !file_exists($work . '/x.xml'), 'refused runs write nothing' );

// ---- the input file is not changed
check( md5_file($in) === $md5in, 'input file unchanged' );

exec( 'rm -rf ' . escapeshellarg($work) );
print "\n" . $checks . " checks, " . count($failed) . " failed\n";
if( count($failed) )
{
    foreach( $failed as $f ) print " - " . $f . "\n";
    exit( 1 );
}
exit( 0 );
