<?php
/**
 * Tests of pan-os-php type=panorama-move (utils/develop/panorama_move) - concept step 6 + conflict=rename + master key.
 *
 *   cd tests && php test_panorama_move.php [scenario ...]
 *
 * Fixtures: input/panorama-move/ (see build_fixtures.php for what each file contains). Exit code 0 = all passed.
 */

$here = dirname(__FILE__);
$cli = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($here . '/../utils/pan-os-php.php') . ' type=panorama-move';
$in = $here . '/input/panorama-move';
$A = $in . '/panorama-move-A.xml';
$Bclean = $in . '/panorama-move-B-clean.xml';
$Bconflict = $in . '/panorama-move-B-conflict.xml';
$work = sys_get_temp_dir() . '/pan-os-php-test-panorama-move-' . getmypid();
@mkdir( $work, 0700, TRUE );

// fake encrypted values of the fixtures - must never show up in a report
$SECRETS = array( '-AQ==FIXTUREpskPARISgw1AAAAAAAAAAAAAAAA=', '-AQ==FIXTUREhttpSIEMpwdBBBBBBBBBBBBBBBB=' );

$failed = array();
$current = '';
$checks = 0;

function check( $cond, $msg )
{
    global $failed, $current, $checks;
    $checks++;
    if( !$cond )
    {
        $failed[] = $current . ': ' . $msg;
        print "    FAIL " . $msg . "\n";
    }
}

function eq( $actual, $expected, $msg )
{
    check( $actual === $expected, $msg . ' - expected ' . json_encode($expected) . ', got ' . json_encode($actual) );
}

/** run the tool: returns array( rc, plan, dir, output ) */
function run( $name, $dgs, $args )
{
    global $cli, $work;
    $dir = $work . '/' . $name;
    @mkdir( $dir, 0700, TRUE );
    file_put_contents( $dir . '/dgs.txt', "# test\n" . implode("\n", $dgs) . "\n" );
    $cmd = $cli . ' dg-list=' . escapeshellarg($dir . '/dgs.txt') . ' report=' . escapeshellarg($dir . '/report')
        . ' out1=' . escapeshellarg($dir . '/A.xml') . ' out2=' . escapeshellarg($dir . '/B.xml');
    foreach( $args as $a ) $cmd .= ' ' . escapeshellarg($a);
    exec( $cmd . ' 2>&1', $out, $rc );
    $plan = is_file($dir . '/report/plan.json') ? json_decode( file_get_contents($dir . '/report/plan.json'), TRUE ) : null;
    return array( $rc, $plan, $dir, implode("\n", $out) );
}

function xp( $file )
{
    $d = new DOMDocument();
    if( !@$d->load($file) ) return null;
    return new DOMXPath( $d );
}

function cnt( $x, $q ) { return $x === null ? -1 : $x->query($q)->length; }

function txt( $x, $q ) { $n = $x === null ? null : $x->query($q); return ( $n !== null && $n->length ) ? trim($n->item(0)->textContent) : null; }

function byName( $list, $key = 'name' ) { $o = array(); foreach( $list as $e ) $o[$e[$key]] = $e; return $o; }

function findings( $plan, $severity, $category = null )
{
    return array_values( array_filter( $plan['findings'], function( $f ) use ( $severity, $category ) {
        return $f['severity'] == $severity && ( $category === null || $f['category'] == $category ); } ) );
}

function noSecretsIn( $dir )
{
    global $SECRETS;
    foreach( glob($dir . '/report/*') as $f )
        foreach( $SECRETS as $s )
            check( strpos(file_get_contents($f), $s) === FALSE && strpos(file_get_contents($f), substr($s, 5, 20)) === FALSE, 'no encrypted value in ' . basename($f) );
}

const DG = '/config/devices/entry/device-group/entry';
const RO = '/config/readonly/devices/entry/device-group/entry';
const MGT = '/config/mgt-config/devices/entry';

$scenarios = array();

////////////////////////////////////////////////////////////////////////////////
// concept step 6

$scenarios['leaf-dg-parent-moves'] = function() use ( $A, $Bclean ) {
    // FR Datacenter: parent Datacenter-Firewalls has no other child and no own firewall -> moved too
    list( $rc, $p, $dir ) = run( 'leaf', array( 'FR Datacenter' ), array( 'file1=' . $A, 'file2=' . $Bclean, 'mode=execute' ) );
    eq( $rc, 0, 'exit code' );
    $dg = byName( $p['device_groups'] );
    eq( $dg['FR Datacenter']['action'], 'move', 'FR Datacenter action' );
    eq( $dg['Datacenter-Firewalls']['action'], 'move', 'parent action' );
    eq( $dg['FR Datacenter']['parent_in_file2'], 'Datacenter-Firewalls', 'parent in file2' );
    eq( array_column($p['devices'], 'serial'), array( '000007777' ), 'firewalls' );
    $so = array(); foreach( $p['shared_objects'] as $o ) $so[$o['path'] . ' ' . $o['name']] = $o['action'];
    eq( $so['address new test 1'], 'copy', 'shared object missing in file2 -> copy' );
    eq( $so['address shared-host1'], 'reuse', 'shared object with the same value -> reuse' );
    eq( count(findings($p, 'blocking')), 0, 'no blocking finding' );
    $b = xp( $dir . '/B.xml' ); $a = xp( $dir . '/A.xml' );
    eq( txt($b, RO . '[@name="FR Datacenter"]/parent-dg'), 'Datacenter-Firewalls', 'file2 readonly parent-dg' );
    eq( cnt($b, DG . '[@name="FR Datacenter"]/devices/entry[@name="000007777"]'), 1, 'file2 device group keeps the firewall' );
    eq( cnt($b, MGT . '[@name="000007777"]'), 1, 'file2 managed device' );
    eq( cnt($b, '/config/shared/address/entry[@name="new test 1"]'), 1, 'file2 copied shared object' );
    eq( cnt($a, DG . '[@name="FR Datacenter"] | ' . DG . '[@name="Datacenter-Firewalls"]'), 0, 'file1 device groups removed' );
    eq( cnt($a, RO . '[@name="FR Datacenter"] | ' . RO . '[@name="Datacenter-Firewalls"]'), 0, 'file1 readonly entries removed' );
    eq( cnt($a, MGT . '[@name="000007777"]'), 0, 'file1 managed device removed' );
    eq( $p['stats']['validation']['file1']['unresolved'], 0, 'file1 unresolved' );
    eq( $p['stats']['validation']['file2']['unresolved'], 0, 'file2 unresolved' );
};

$scenarios['parent-used-by-others-copied'] = function() use ( $A, $Bclean ) {
    // DE-Berlin Office: sibling Hamburg Office (own firewall) stays -> parent Perimeter-FWs and the shared stack are copied
    list( $rc, $p, $dir ) = run( 'parentcopy', array( 'DE-Berlin Office' ), array( 'file1=' . $A, 'file2=' . $Bclean, 'mode=execute' ) );
    eq( $rc, 0, 'exit code' );
    $dg = byName( $p['device_groups'] );
    eq( $dg['DE-Berlin Office']['action'], 'move', 'selected action' );
    eq( $dg['Perimeter-FWs']['action'], 'copy', 'parent action' );
    $st = byName( $p['template_stacks'] ); $tp = byName( $p['templates'] );
    eq( $st['DE_Berlin_Office_Stack']['action'], 'copy', 'stack used by a kept firewall -> copy' );
    eq( $tp['Internet Perimeter Master']['action'], 'copy', 'template of a copied stack -> copy' );
    $b = xp( $dir . '/B.xml' ); $a = xp( $dir . '/A.xml' );
    eq( cnt($b, DG . '[@name="Perimeter-FWs"]/devices/entry'), 0, 'copied parent has no firewalls in file2' );
    eq( cnt($b, '/config/devices/entry/template-stack/entry[@name="DE_Berlin_Office_Stack"]/devices/entry'), 1, 'copied stack: only the moved firewall in file2' );
    eq( cnt($a, DG . '[@name="Perimeter-FWs"]'), 1, 'file1 keeps the parent' );
    eq( cnt($a, DG . '[@name="Hamburg Office"]/devices/entry[@name="007200006721"]'), 1, 'file1 keeps the sibling firewall' );
    eq( cnt($a, '/config/devices/entry/template-stack/entry[@name="DE_Berlin_Office_Stack"]/devices/entry[@name="000000000101"]'), 0, 'file1 stack without the moved firewall' );
    eq( cnt($a, '/config/devices/entry/template-stack/entry[@name="DE_Berlin_Office_Stack"]/devices/entry[@name="007200006721"]'), 1, 'file1 stack keeps the other firewall' );
    eq( $p['stats']['validation']['file2']['unresolved'], 0, 'file2 unresolved' );
};

$scenarios['shared-parent-stack-template'] = function() use ( $A, $Bclean ) {
    // testDG under shared: its stack moves, the template shared with a kept stack is copied; master-key=same (default)
    list( $rc, $p, $dir ) = run( 'stack', array( 'testDG' ), array( 'file1=' . $A, 'file2=' . $Bclean, 'mode=execute' ) );
    eq( $rc, 0, 'exit code' );
    eq( byName($p['device_groups'])['testDG']['parent_in_file2'], null, 'parent in file2 = shared' );
    $st = byName( $p['template_stacks'] ); $tp = byName( $p['templates'] );
    eq( $st['Paris_Datacenter_Stack']['action'], 'move', 'stack action' );
    eq( $tp['Paris Datacenter']['action'], 'move', 'template only in the moved stack -> move' );
    eq( $tp['Datacenter Master Template']['action'], 'copy', 'template also in a kept stack -> copy' );
    eq( count($p['encrypted_values']), 2, 'encrypted values found' );
    eq( count(findings($p, 'warning', 'encrypted value')), 1, 'master-key=same warning' );
    check( is_file($dir . '/report/SECRETS_CHECKLIST.md'), 'SECRETS_CHECKLIST.md written' );
    $b = xp( $dir . '/B.xml' ); $a = xp( $dir . '/A.xml' );
    eq( cnt($b, '//text()[starts-with(normalize-space(.),"-AQ==")]'), 2, 'file2: encrypted values copied unchanged' );
    eq( cnt($a, '/config/devices/entry/template-stack/entry[@name="Paris_Datacenter_Stack"]'), 0, 'file1 moved stack removed' );
    eq( cnt($a, '/config/devices/entry/template/entry[@name="Paris Datacenter"]'), 0, 'file1 moved template removed' );
    eq( cnt($a, '/config/devices/entry/template/entry[@name="Datacenter Master Template"]'), 1, 'file1 copied template kept' );
    eq( cnt($a, '/config/shared/log-settings/http/entry[@name="http-siem"]'), 0, 'file1 shared object used only by the moved DG removed' );
    noSecretsIn( $dir );
};

$scenarios['multi-vsys-firewall-blocks'] = function() use ( $A, $Bclean ) {
    list( $rc, $p, $dir ) = run( 'multivsys', array( 'MV-Left' ), array( 'file1=' . $A, 'file2=' . $Bclean, 'mode=execute' ) );
    eq( $rc, 2, 'exit code' );
    $f = findings( $p, 'blocking', 'device' );
    eq( count($f), 1, 'blocking device finding' );
    eq( $f[0]['name'], '000000000555', 'finding names the firewall' );
    check( !is_file($dir . '/B.xml') && !is_file($dir . '/A.xml'), 'execute refused - no output written' );
};

$scenarios['name-conflicts-stop'] = function() use ( $A, $Bconflict ) {
    list( $rc, $p, $dir ) = run( 'stop', array( 'FR Datacenter' ), array( 'file1=' . $A, 'file2=' . $Bconflict, 'mode=execute' ) );
    eq( $rc, 2, 'exit code' );
    eq( $p['conflict'], 'stop', 'conflict mode' );
    eq( count(findings($p, 'blocking', 'device group')), 2, 'D4 device groups blocking' );
    eq( count(findings($p, 'blocking', 'rule name')), 1, 'rule name blocking' );
    eq( count(findings($p, 'blocking', 'shared object')), 2, 'D5 shared objects blocking' );
    check( !is_file($dir . '/B.xml'), 'execute refused - no output written' );
};

////////////////////////////////////////////////////////////////////////////////
// conflict=rename:<suffix>

$scenarios['rename-dg-rule-objects'] = function() use ( $A, $Bconflict ) {
    list( $rc, $p, $dir ) = run( 'rename', array( 'FR Datacenter' ), array( 'file1=' . $A, 'file2=' . $Bconflict, 'mode=execute', 'conflict=rename:_A' ) );
    eq( $rc, 0, 'exit code' );
    eq( count(findings($p, 'blocking')), 0, 'no blocking finding' );
    eq( $p['renames']['device_groups'], array( 'FR Datacenter' => 'FR Datacenter_A', 'Datacenter-Firewalls' => 'Datacenter-Firewalls_A' ), 'device group renames' );
    eq( array_values($p['renames']['rules']), array( 'DC Firewall level CP rules 1_A' ), 'rule rename' );
    $so = $p['renames']['shared_objects']; ksort( $so );
    eq( $so, array( 'shared-host1' => 'shared-host1_A', 'shared-host2' => 'shared-host2_A', 'test-group2' => 'test-group2_A' ), 'shared object renames incl. cascade (test-group2)' );
    eq( count($p['rewritten_references']), 5, 'rewritten references' );
    $b = xp( $dir . '/B.xml' ); $a = xp( $dir . '/A.xml' );
    eq( txt($b, RO . '[@name="FR Datacenter_A"]/parent-dg'), 'Datacenter-Firewalls_A', 'file2 parent of the renamed child' );
    eq( cnt($b, DG . '[@name="FR Datacenter"] | ' . DG . '[@name="Datacenter-Firewalls"]'), 2, 'file2 own device groups untouched' );
    eq( txt($b, '/config/shared/address/entry[@name="shared-host1_A"]/ip-netmask'), '1.2.2.3/32', 'renamed object has the file1 value' );
    eq( txt($b, '/config/shared/address/entry[@name="shared-host1"]/ip-netmask'), '9.9.9.1/32', 'file2 object keeps its value' );
    eq( txt($b, '/config/shared/address-group/entry[@name="test-group2_A"]/static/member'), 'shared-host2_A', 'cascaded group points to the renamed member' );
    $dg = DG . '[@name="Datacenter-Firewalls_A"]';
    eq( cnt($b, $dg . '/pre-rulebase/authentication/rules/entry[@name="DC Firewall level CP rules 1_A"]'), 1, 'renamed rule' );
    eq( txt($b, $dg . '/pre-rulebase/authentication/rules/entry/destination/member'), 'shared-host1_A', 'rule reference rewritten' );
    eq( cnt($b, $dg . '//member[.="shared-host1" or .="shared-host2" or .="test-group2"]'), 0, 'no reference to an old name left' );
    eq( cnt($a, '//entry[contains(@name,"_A")]'), 0, 'file1 not renamed' );
    eq( $p['stats']['validation']['file2']['unresolved'], 0, 'file2 unresolved' );
};

$scenarios['rename-templates-stack-shared-rules'] = function() use ( $A, $Bconflict ) {
    list( $rc, $p, $dir ) = run( 'renametpl', array( 'testDG' ), array( 'file1=' . $A, 'file2=' . $Bconflict, 'mode=execute', 'conflict=rename:_A', 'shared-rules=to-top-dg' ) );
    eq( $rc, 0, 'exit code' );
    eq( $p['renames']['template_stacks'], array( 'Paris_Datacenter_Stack' => 'Paris_Datacenter_Stack_A' ), 'stack rename' );
    eq( count($p['renames']['templates']), 2, 'template renames' );
    eq( array_values($p['renames']['shared_rules']), array( 'shared pre rule 1_A' ), 'copied shared rule renamed' );
    $b = xp( $dir . '/B.xml' );
    $stack = '/config/devices/entry/template-stack/entry[@name="Paris_Datacenter_Stack_A"]';
    eq( cnt($b, $stack . '/templates/member[.="Datacenter Master Template_A"]') + cnt($b, $stack . '/templates/member[.="Paris Datacenter_A"]'), 2, 'stack members renamed' );
    eq( txt($b, DG . '[@name="testDG_A"]/reference-templates/member'), 'Paris_Datacenter_Stack_A', 'reference-templates renamed' );
    eq( cnt($b, '/config/readonly/devices/entry/template-stack/entry[@name="Paris_Datacenter_Stack_A"]'), 1, 'readonly entry of the renamed stack' );
    eq( cnt($b, DG . '[@name="testDG_A"]/pre-rulebase/security/rules/entry[@name="shared pre rule 1_A"]'), 1, 'shared rule copied with the new name' );
    eq( cnt($b, '/config/devices/entry/template-stack/entry[@name="Paris_Datacenter_Stack"]'), 1, 'file2 own stack untouched' );
    noSecretsIn( $dir );
};

$scenarios['rename-target-taken'] = function() use ( $A, $Bconflict ) {
    list( $rc, $p ) = run( 'taken', array( 'FR Datacenter' ), array( 'file1=' . $A, 'file2=' . $Bconflict, 'conflict=rename:_taken' ) );
    eq( $rc, 2, 'exit code' );
    $f = findings( $p, 'blocking', 'device group' );
    eq( count($f), 1, 'one blocking device group' );
    check( count($f) && strpos($f[0]['proposal'], 'exists already') !== FALSE, 'proposal: choose another suffix' );
};

$scenarios['rename-ambiguous-local-object'] = function() use ( $A, $Bconflict ) {
    // Amb-DG has a local SERVICE shared-host1 and references the shared ADDRESS shared-host1
    list( $rc, $p ) = run( 'ambiguous', array( 'Amb-DG' ), array( 'file1=' . $A, 'file2=' . $Bconflict, 'conflict=rename:_A' ) );
    eq( $rc, 2, 'exit code' );
    $f = findings( $p, 'blocking', 'shared object' );
    eq( count($f), 1, 'blocking shared object' );
    check( count($f) && strpos($f[0]['proposal'], 'rename manually') !== FALSE, 'proposal: rename manually' );
    eq( $p['renames']['shared_objects'], array(), 'nothing renamed' );
};

////////////////////////////////////////////////////////////////////////////////
// master key

$scenarios['master-key-different'] = function() use ( $A, $Bclean, $SECRETS ) {
    list( $rc, $p, $dir ) = run( 'mkdiff', array( 'testDG' ), array( 'file1=' . $A, 'file2=' . $Bclean, 'mode=execute', 'master-key=different' ) );
    eq( $rc, 0, 'exit code' );
    eq( $p['stats']['encrypted_values_removed'], 2, 'encrypted values removed' );
    $b = xp( $dir . '/B.xml' );
    eq( cnt($b, '//text()[starts-with(normalize-space(.),"-AQ==")]'), 0, 'file2 without encrypted values' );
    eq( cnt($b, '//pre-shared-key/key'), 0, 'IKE key element removed' );
    eq( cnt($b, '/config/shared/log-settings/http/entry[@name="http-siem"]/server/entry[@name="siem1"]/address'), 1, 'rest of the server profile copied' );
    $cl = @file_get_contents( $dir . '/report/SECRETS_CHECKLIST.md' );
    check( $cl !== FALSE && substr_count($cl, '- [ ]') == 2, 'checklist lists 2 fields' );
    check( $cl !== FALSE && strpos($cl, 'pre-shared-key/key') !== FALSE && strpos($cl, 'server/entry[siem1]/password') !== FALSE, 'checklist paths' );
    $a = xp( $dir . '/A.xml' );
    eq( cnt($a, '//text()[starts-with(normalize-space(.),"-AQ==")]'), 0, 'file1: moved template / shared profile removed' );
    noSecretsIn( $dir );
};

////////////////////////////////////////////////////////////////////////////////
// arguments

$scenarios['arguments'] = function() use ( $A, $Bclean ) {
    foreach( array( 'conflict=rename:', 'conflict=rename:_A!', 'conflict=foo', 'master-key=other', 'mode=run', 'shared-rules=all' ) as $bad )
    {
        list( $rc ) = run( 'args', array( 'testDG' ), array( 'file1=' . $A, 'file2=' . $Bclean, $bad ) );
        eq( $rc, 1, $bad . ' rejected' );
    }
    list( $rc, $p ) = run( 'unknowndg', array( 'does-not-exist' ), array( 'file1=' . $A, 'file2=' . $Bclean ) );
    eq( $rc, 2, 'unknown device group - exit code' );
    eq( count(findings($p, 'blocking', 'selection')), 1, 'unknown device group - blocking' );
};

////////////////////////////////////////////////////////////////////////////////

$only = array_slice( $argv, 1 );
foreach( $scenarios as $name => $fn )
{
    if( count($only) && !in_array($name, $only, TRUE) )
        continue;
    $current = $name;
    $before = count( $failed );
    print "  " . $name . "\n";
    $fn();
    print "    " . ( count($failed) == $before ? "ok" : "FAILED" ) . "\n";
}
exec( 'rm -rf ' . escapeshellarg($work) );
print "\n" . $checks . " checks, " . count($failed) . " failed\n";
if( count($failed) )
{
    foreach( $failed as $f ) print " - " . $f . "\n";
    exit( 1 );
}
exit( 0 );
