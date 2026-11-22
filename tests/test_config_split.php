<?php
/**
 * ConfigObjectSplit / type=config-split: a configuration as one entry per object and back (git on object level, step 1).
 * Synthetic configurations only (tests/input and the firewall built here) - no customer data.
 *
 *   php tests/test_config_split.php [big]     big: also a large synthetic Panorama (timing)
 */
$repo = dirname( __DIR__ );
require_once $repo . '/lib/pan_php_framework.php';
$checks = 0; $failed = array();
$ok = function( $cond, $msg ) use ( &$checks, &$failed ) { $checks++; print ( $cond ? "ok   " : "FAIL " ) . $msg . "\n"; if( !$cond ) $failed[] = $msg; };
$same = function( DOMDocument $d, array $files ) {
    return ConfigObjectSplit::canonical( $d ) === ConfigObjectSplit::canonical( ConfigObjectSplit::join( $files ) );
};
$xml = function( $text ) { $d = new DOMDocument(); $d->loadXML( $text ); return $d; };

// ---- the configurations of tests/input: Panorama 8.0 - 11.0, SCM
foreach( glob( $repo . '/tests/input/*.xml' ) as $f )
{
    $d = new DOMDocument(); $d->load( $f );
    $files = ConfigObjectSplit::split( $d );
    $ok( $same( $d, $files ), 'round trip: ' . basename( $f ) . ' (' . ( count( preg_grep( '/\.xml$/', array_keys( $files ) ) ) - 1 ) . ' objects)' );
}
$d = new DOMDocument(); $d->load( $repo . '/tests/input/panorama-10.0-merger.xml' );
$files = ConfigObjectSplit::split( $d );
$ok( isset( $files['shared/address/shared-host1.xml'], $files['shared/address/_order'] ), 'Panorama: shared object and the order of its store' );
$ok( isset( $files['devices/localhost.localdomain/device-group/DE-Berlin Office/pre-rulebase/nat/rules/219f3d6a-d061-4e3c-9388-7440dfe455a2.xml'] ),
    'Panorama: a rule of a device group by its UUID' );
// a template is one entry as a whole (nothing below it split); the firewalls of a device group are its store
$tpl = preg_grep( '#/template/#', array_keys( $files ) );
$ok( count( $tpl ) > 0 && !preg_grep( '#/template/[^/]+/.#', $tpl ) && !preg_grep( '#^devices/[^/]+/template/[^/]+/#', array_keys( $files ) ),
    'Panorama: a template is one entry (nothing below it split)' );
$ok( count( preg_grep( '#^mgt-config/devices/[^/]+\.xml$#', array_keys( $files ) ) ) > 0 && count( preg_grep( '#/device-group/[^/]+/devices/_order$#', array_keys( $files ) ) ) > 0,
    'Panorama: managed firewalls and the firewalls of a device group are entries' );
$ok( strpos( $files['_rest.xml'], 'shared-host1' ) === FALSE || strpos( $files['_rest.xml'], '<entry name="shared-host1"' ) === FALSE, 'the split objects are not in _rest.xml' );
$ok( $files['shared/address/shared-host1.xml'] === "<entry name=\"shared-host1\">\n  <ip-netmask>1.2.2.3/32</ip-netmask>\n  <tag>\n    <member>grp.shared-group1</member>\n  </tag>\n</entry>\n",
    'canonical XML of an object: one element per line, indentation 2' );
$d = new DOMDocument(); $d->load( $repo . '/tests/input/SCM-import.xml' );
$files = ConfigObjectSplit::split( $d );
$ok( isset( $files['devices/localhost.localdomain/snippet/Panorama-Shared/address/shared-host1.xml'] ) && preg_grep( '#/container/testDG/address/#', array_keys( $files ) ),
    'SCM: snippets and folders (container) are locations' );

// ---- a synthetic firewall with the special cases
$fw = <<<'XML'
<config version="11.1.0">
  <shared>
    <address>
      <entry name="sh-a"><ip-netmask>10.0.0.1</ip-netmask></entry>
    </address>
  </shared>
  <devices>
    <entry name="localhost.localdomain">
      <network><interface><ethernet><entry name="ethernet1/1"><layer3/></entry></ethernet></interface></network>
      <vsys>
        <entry name="vsys1">
          <address>
            <entry name="z-last"><ip-netmask>10.1.1.1</ip-netmask></entry>
            <entry name="net/24"><ip-netmask>10.1.0.0/24</ip-netmask><description>  two spaces, a/b, 100%  </description></entry>
            <entry name=".hidden"><fqdn>a.example.com</fqdn></entry>
            <entry name="dup"><ip-netmask>1.1.1.1</ip-netmask></entry>
            <entry name="dup"><ip-netmask>2.2.2.2</ip-netmask></entry>
            <entry name="a-first"><ip-netmask>10.1.1.2</ip-netmask></entry>
          </address>
          <service>
            <!-- a comment: the store stays whole -->
            <entry name="tcp-1"><protocol><tcp><port>1</port></tcp></protocol></entry>
          </service>
          <tag/>
          <profiles>
            <virus><entry name="av1"><decoder/></entry></virus>
            <custom-url-category><entry name="cat1"><list><member>a.example.com</member></list><type>URL List</type></entry></custom-url-category>
          </profiles>
          <rulebase>
            <security>
              <rules>
                <entry name="r2" uuid="22222222-2222-2222-2222-222222222222"><action>allow</action></entry>
                <entry name="r1"><action>deny</action></entry>
              </rules>
            </security>
            <nat><rules><entry name="n1" uuid="33333333-3333-3333-3333-333333333333"><to><member>any</member></to></entry></rules></nat>
          </rulebase>
          <zone><entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
XML;
$d = $xml( $fw );
$files = ConfigObjectSplit::split( $d );
$V = 'devices/localhost.localdomain/vsys/vsys1/';
$ok( $same( $d, $files ), 'firewall: round trip' );
$ok( isset( $files[$V . 'address/net%2F24.xml'], $files[$V . 'address/%2Ehidden.xml'] ), 'firewall: "/" and a leading "." in a name are encoded' );
$ok( isset( $files[$V . 'address/dup.xml'], $files[$V . 'address/dup~2.xml'] ), 'firewall: the same name twice in a store: dup, dup~2' );
$ok( $files[$V . 'address/_order'] === "z-last\nnet%2F24\n%2Ehidden\ndup\ndup~2\na-first\n", 'firewall: _order keeps the order of the configuration' );
$ok( strpos( $files[$V . 'address/net%2F24.xml'], '<description>  two spaces, a/b, 100%  </description>' ) !== FALSE, 'firewall: text of a field kept as it is' );
$ok( !preg_grep( '#/service/#', array_keys( $files ) ) && strpos( $files['_rest.xml'], 'tcp-1' ) !== FALSE, 'firewall: a store with a comment stays whole in _rest.xml' );
$ok( isset( $files[$V . 'profiles/virus/av1.xml'], $files[$V . 'profiles/custom-url-category/cat1.xml'] ), 'firewall: security profiles per profile type' );
$ok( isset( $files[$V . 'rulebase/security/rules/22222222-2222-2222-2222-222222222222.xml'], $files[$V . 'rulebase/security/rules/r1.xml'] ),
    'firewall: a rule by its UUID, a rule without one by its name' );
$ok( $files[$V . 'rulebase/security/rules/_order'] === "22222222-2222-2222-2222-222222222222\nr1\n", 'firewall: the rule order' );
$ok( isset( $files['shared/address/sh-a.xml'] ) && !preg_grep( '#/zone/|/network/#', array_keys( $files ) ), 'firewall: shared objects split; zones / network stay in _rest.xml (not yet)' );

// ---- join: changes made in the entries
$f2 = $files;
$f2[$V . 'address/a-first.xml'] = str_replace( '10.1.1.2', '10.9.9.9', $f2[$V . 'address/a-first.xml'] );     // changed
unset( $f2[$V . 'address/z-last.xml'] );                                                                           // deleted (still in _order)
$f2[$V . 'address/new.xml'] = "<entry name=\"new\"><ip-netmask>10.7.7.7</ip-netmask></entry>\n";                    // added without _order
$f2[$V . 'rulebase/security/rules/_order'] = "r1\n22222222-2222-2222-2222-222222222222\n";                         // rules moved
$f2[$V . 'schedule/s1.xml'] = "<entry name=\"s1\"><schedule-type><recurring><daily><member>08:00-17:00</member></daily></recurring></schedule-type></entry>\n";  // store that did not exist
$j = ConfigObjectSplit::join( $f2 );
$x = new DOMXPath( $j );
$names = array(); foreach( $x->query( '//vsys/entry/address/entry' ) as $e ) $names[] = $e->getAttribute( 'name' );
$ok( $names === array( 'net/24', '.hidden', 'dup', 'dup', 'a-first', 'new' ), 'join: deleted entry gone, an entry not in _order at the end' );
$ok( $x->evaluate( 'string(//vsys/entry/address/entry[@name="a-first"]/ip-netmask)' ) === '10.9.9.9', 'join: a changed entry' );
$r = array(); foreach( $x->query( '//vsys/entry/rulebase/security/rules/entry' ) as $e ) $r[] = $e->getAttribute( 'name' );
$ok( $r === array( 'r1', 'r2' ), 'join: the rule order of _order' );
$ok( $x->evaluate( 'count(//vsys/entry[@name="vsys1"]/schedule/entry[@name="s1"])' ) == 1, 'join: a store added after the split is created in its location' );
$ok( ConfigObjectSplit::split( $j )[$V . 'address/_order'] === "net%2F24\n%2Ehidden\ndup\ndup~2\na-first\nnew\n", 'split after join: the new order' );
$bad = $files; $bad['devices/localhost.localdomain/vsys/vsys9/address/x.xml'] = '<entry name="x"/>';
$err = ''; try { ConfigObjectSplit::join( $bad ); } catch( Exception $e ) { $err = $e->getMessage(); }
$ok( strpos( $err, 'not in _rest.xml' ) !== FALSE, 'join: an entry of a location that does not exist is refused' );
$bad = $files; $bad[$V . 'address/a-first.xml'] = '<entry name="a-first">';
$err = ''; try { ConfigObjectSplit::join( $bad ); } catch( Exception $e ) { $err = $e->getMessage(); }
$ok( strpos( $err, 'no valid XML' ) !== FALSE, 'join: an entry that is no XML is refused' );
$ok( $d->saveXML() === $xml( $fw )->saveXML(), 'split does not change the document it gets' );

// ---- state / changes: the DOM in memory (as pan-os-php loaded it, with its whitespace) gives the same entries
foreach( glob( $repo . '/tests/input/*.xml' ) as $f )
{
    $dd = new DOMDocument(); $dd->load( $f );
    $ok( ConfigObjectSplit::files( ConfigObjectSplit::state( $dd ) ) === ConfigObjectSplit::split( $dd ), 'state = split: ' . basename( $f ) );
}
$d = $xml( $fw );
$before = ConfigObjectSplit::state( $d );
$ok( ConfigObjectSplit::changes( $before, ConfigObjectSplit::state( $d ) ) === array( 'put' => array(), 'delete' => array() ), 'changes: nothing changed, nothing to write' );
$x = new DOMXPath( $d );
$x->query( '//vsys/entry/address/entry[@name="a-first"]/ip-netmask' )->item( 0 )->nodeValue = '10.5.5.5';         // changed
$e = $x->query( '//vsys/entry/address/entry[@name="z-last"]' )->item( 0 ); $e->setAttribute( 'name', 'z-renamed' );  // renamed
$r1 = $x->query( '//rulebase/security/rules/entry[@name="r1"]' )->item( 0 ); $r1->parentNode->insertBefore( $r1, $r1->parentNode->firstChild ); // moved
$x->query( '//devices/entry/network' )->item( 0 )->appendChild( $d->createElement( 'dns-proxy' ) );               // the rest
$c = ConfigObjectSplit::changes( $before, ConfigObjectSplit::state( $d ) );
$ok( array_keys( $c['put'] ) === array( '_rest.xml', $V . 'address/_order', $V . 'address/a-first.xml', $V . 'address/z-renamed.xml', $V . 'rulebase/security/rules/_order' )
    && $c['delete'] === array( $V . 'address/z-last.xml' ), 'changes: changed, renamed (new + deleted), moved (order), the rest' );
$apply = $files = ConfigObjectSplit::split( $xml( $fw ) );
foreach( $c['put'] as $p => $t ) $apply[$p] = $t;
foreach( $c['delete'] as $p ) unset( $apply[$p] );
ksort( $apply, SORT_STRING );
$ok( $apply === ConfigObjectSplit::split( $d ), 'changes applied to the split before = the split after' );
$ok( $d->saveXML() === ConfigObjectSplit::state( $d )['doc']->saveXML() && $x->query( '//vsys/entry/address/entry' )->length === 6, 'state: the DOM is the same afterwards (entries back in place)' );

// ---- type=config-split (CLI)
$tmp = sys_get_temp_dir() . '/cfgsplit-' . getmypid();
@mkdir( $tmp );
file_put_contents( $tmp . '/fw.xml', $fw );
$run = function( $args ) use ( $repo ) {
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' type=config-split ' . $args . ' 2>&1', $out, $rc );
    return array( $rc, implode( "\n", $out ) );
};
list( $rc, $o ) = $run( 'in=' . escapeshellarg( $tmp . '/fw.xml' ) . ' out=' . escapeshellarg( $tmp . '/split' ) );
$ok( $rc === 0 && is_file( $tmp . '/split/' . $V . 'address/net%2F24.xml' ) && strpos( $o, '12 objects' ) !== FALSE, 'CLI: split into a folder' );
list( $rc, $o ) = $run( 'in=' . escapeshellarg( $tmp . '/fw.xml' ) . ' out=' . escapeshellarg( $tmp . '/split' ) );
$ok( strpos( $o, 'new or empty folder' ) !== FALSE, 'CLI: a folder with an old split is refused' );
list( $rc, $o ) = $run( 'mode=join in=' . escapeshellarg( $tmp . '/split' ) . ' out=' . escapeshellarg( $tmp . '/joined.xml' ) );
$ok( $rc === 0 && is_file( $tmp . '/joined.xml' ) && ConfigObjectSplit::canonical( $xml( $fw ) ) === file_get_contents( $tmp . '/joined.xml' ), 'CLI: join gives the configuration again' );
list( $rc, $o ) = $run( 'mode=check in=' . escapeshellarg( $tmp . '/fw.xml' ) );
$ok( strpos( $o, 'the same configuration' ) !== FALSE, 'CLI: check' );
exec( 'rm -rf ' . escapeshellarg( $tmp ) );

// ---- a large synthetic Panorama (timing): php tests/test_config_split.php big
if( in_array( 'big', $argv, TRUE ) )
{
    $dgs = ''; $n = 0;
    for( $g = 1; $g <= 20; $g++ )
    {
        $a = ''; $r = '';
        for( $i = 1; $i <= 2500; $i++, $n++ )
            $a .= '<entry name="h-' . $g . '-' . $i . '"><ip-netmask>10.' . $g . '.' . ( $i >> 8 ) . '.' . ( $i & 255 ) . '</ip-netmask><description>host ' . $i . '</description><tag><member>t1</member></tag></entry>';
        for( $i = 1; $i <= 500; $i++, $n++ )
            $r .= '<entry name="r-' . $i . '" uuid="' . sprintf( '%08d-0000-0000-0000-%012d', $g, $i ) . '"><from><member>any</member></from><to><member>any</member></to><source><member>h-' . $g . '-' . $i . '</member></source><destination><member>any</member></destination><service><member>any</member></service><application><member>any</member></application><action>allow</action></entry>';
        $dgs .= '<entry name="DG' . $g . '"><address>' . $a . '</address><pre-rulebase><security><rules>' . $r . '</rules></security></pre-rulebase></entry>';
    }
    $big = $xml( '<config version="11.1.0"><shared><tag><entry name="t1"/></tag></shared><devices><entry name="localhost.localdomain"><device-group>' . $dgs . '</device-group></entry></devices></config>' );
    $t = microtime( TRUE ); $files = ConfigObjectSplit::split( $big ); $ts = microtime( TRUE ) - $t;
    $t = microtime( TRUE ); $j = ConfigObjectSplit::join( $files ); $tj = microtime( TRUE ) - $t;
    $t = microtime( TRUE ); $st = ConfigObjectSplit::state( $big ); $tst = microtime( TRUE ) - $t;
    $ok( ConfigObjectSplit::canonical( $big ) === ConfigObjectSplit::canonical( $j ), sprintf( 'large Panorama: %d objects, split %.2f s, join %.2f s, state %.2f s, memory %d MB', $n + 1, $ts, $tj, $tst, memory_get_peak_usage( TRUE ) >> 20 ) );
}

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
