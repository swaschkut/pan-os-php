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
    // rule equivalence by resolved values: a-to-dc (shared-host1) = b-to-dc (dc-host), both 1.2.2.3
    check( in_array('a-to-dc = b-to-dc', $p['shared_rule_impact'][0]['covered'], TRUE), 'shared rule covered by a rule to another object with the same value' );
    eq( $p['shared_rule_impact'][0]['lost'], array(), 'no shared rule lost' );
    eq( count($p['effective_rulebase']), 1, 'effective rule base: one group' );
    $g = $p['effective_rulebase'][0];
    eq( array( $g['transferred_same'], count($g['transferred_changed']), count($g['lost']), count($g['added']), $g['order_kept'] ), array( 1, 0, 0, 0, TRUE ), 'effective rule base unchanged' );
    eq( $g['covered']['shared/pre/security/a-to-dc'], 'shared/pre/security/b-to-dc', 'effective rule base: a-to-dc covered by b-to-dc' );
};

$scenarios['override-in-target-parent'] = function() use ( $A, $Bclean ) {
    // target parent Region-EU has a local shared-host1 (198.51.100.77): the transferred rule to shared-host1 changes
    list( $rc, $p, $dir ) = run( 'override', array( 'FR Datacenter' ), array( 'file1=' . $A, 'file2=' . $Bclean, 'target-parent-dg=Region-EU' ) );
    eq( $rc, 0, 'exit code (warning only)' );
    $g = $p['effective_rulebase'][0];
    $k = 'Datacenter-Firewalls/pre/authentication/DC Firewall level CP rules 1';
    check( isset($g['transferred_changed'][$k]), 'transferred rule reported as changed' );
    if( isset($g['transferred_changed'][$k]) )
        eq( $g['transferred_changed'][$k][1], array( 'destination' => array( 'only_in_a' => array( '1.2.2.3' ), 'only_in_b' => array( '198.51.100.77' ) ) ), 'diff: destination value' );
    eq( count(findings($p, 'warning', 'effective rule base')), 1, 'warning finding' );
    check( strpos(@file_get_contents($dir . '/report/MIGRATION_FOLLOWUP.md'), '1 transferred rule(s) resolve differently') !== FALSE, 'follow-up item' );
    check( strpos(@file_get_contents($dir . '/report/REPORT.md'), "destination: file1 only `1.2.2.3` – file2 only `198.51.100.77`") !== FALSE, 'report shows the values' );
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
    // D8 without panorama-ip: reported, not changed
    eq( array_column($p['panorama_settings'], 'action'), array( 'keep', 'keep' ), 'Panorama server settings kept' );
    eq( txt($b, '//template/entry[@name="Paris Datacenter"]//panorama-server'), '192.0.2.1', 'file2 Panorama server unchanged' );
    check( strpos(@file_get_contents($dir . '/report/MIGRATION_FOLLOWUP.md'), 'still points to Panorama A') !== FALSE, 'follow-up: Panorama server still Panorama A' );
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
    $fu = @file_get_contents( $dir . '/report/MIGRATION_FOLLOWUP.md' );
    check( $fu !== FALSE && strpos($fu, 'Resolve the findings in REPORT.md: 5 blocking') !== FALSE, 'follow-up written with the blocking findings first' );
    check( isset($p['effective_rulebase']['skipped']), 'effective rule base skipped while blocking' );
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
    // renamed objects keep their values: the transferred rule resolves the same; shared rule 1 of file2 has another
    // destination (lost + added), a-to-dc is missing in file2
    $g = $p['effective_rulebase'][0];
    eq( array( $g['transferred_same'], count($g['transferred_changed']), $g['order_kept'] ), array( 1, 0, TRUE ), 'effective rule base: transferred rule unchanged after rename' );
    eq( $g['lost'], array( 'shared/pre/security/shared pre rule 1', 'shared/pre/security/a-to-dc' ), 'effective rule base: lost' );
    eq( $g['added'], array( 'shared/pre/security/shared pre rule 1', 'shared/pre/authentication/DC Firewall level CP rules 1' ), 'effective rule base: added' );
};

$scenarios['to-top-dg-copies-resolve-the-same'] = function() use ( $A, $Bconflict ) {
    list( $rc, $p ) = run( 'totop', array( 'FR Datacenter' ), array( 'file1=' . $A, 'file2=' . $Bconflict, 'conflict=rename:_A', 'shared-rules=to-top-dg' ) );
    eq( $rc, 0, 'exit code' );
    $g = $p['effective_rulebase'][0];
    eq( array( $g['transferred_same'], count($g['transferred_changed']), count($g['lost']), $g['order_kept'] ), array( 3, 0, 0, TRUE ), 'copied shared rules resolve the same, order kept' );
    eq( array( $g['rules_before'], $g['rules_after'] ), array( 6, 8 ), 'rules before / after' );
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
    $fu = @file_get_contents( $dir . '/report/MIGRATION_FOLLOWUP.md' );
    check( $fu !== FALSE && strpos($fu, '| [ ] | 007100000290 | vsys1 | testDG_A | Paris_Datacenter_Stack_A |') !== FALSE, 'follow-up firewall row with the file2 names' );
    check( $fu !== FALSE && strpos($fu, 'with testDG_A, Paris_Datacenter_Stack_A, firewall 007100000290') !== FALSE, 'follow-up access domain with the file2 names' );
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
// follow-up / panorama-ip (D8)

$scenarios['followup-panorama-ip'] = function() use ( $A, $Bclean ) {
    list( $rc, $p, $dir ) = run( 'followup', array( 'testDG' ), array( 'file1=' . $A, 'file2=' . $Bclean, 'mode=execute', 'panorama-ip=203.0.113.50,203.0.113.51' ) );
    eq( $rc, 0, 'exit code' );
    eq( $p['panorama_ip'], array( '203.0.113.50', '203.0.113.51' ), 'panorama-ip in plan' );
    eq( array_column($p['panorama_settings'], 'action'), array( 'replace', 'replace' ), 'Panorama server settings replaced' );
    $b = xp( $dir . '/B.xml' ); $a = xp( $dir . '/A.xml' );
    $tpl = '/config/devices/entry/template/entry[@name="Paris Datacenter"]//deviceconfig/system/panorama/local-panorama/';
    eq( txt($b, $tpl . 'panorama-server'), '203.0.113.50', 'file2 panorama-server' );
    eq( txt($b, $tpl . 'panorama-server-2'), '203.0.113.51', 'file2 panorama-server-2' );
    eq( txt($a, '//template/entry[@name="Internet Perimeter Master"]//panorama-server'), '192.0.2.1', 'file1 kept templates unchanged' );
    // access domain cleanup in file1
    eq( cnt($a, '/config/mgt-config/access-domain/entry[@name="ad-paris"]//member[.="testDG" or .="Paris_Datacenter_Stack"]'), 0, 'file1 access domain: moved names removed' );
    eq( cnt($a, '/config/mgt-config/access-domain/entry[@name="ad-paris"]//entry[@name="007100000290"]'), 0, 'file1 access domain: moved firewall removed' );
    eq( cnt($a, '/config/devices/entry/log-collector-group/entry[@name="lcg-paris"]//entry[@name="007100000290"]'), 0, 'file1 log collector group: moved firewall removed' );
    eq( cnt($a, '/config/devices/entry/log-collector-group/entry[@name="lcg-paris"]'), 1, 'file1 log collector group kept' );
    eq( $p['access_domains']['ad-paris']['admins'], array( 'paris-admin' ), 'admin of the access domain' );
    eq( $p['log_collector_groups'], array( 'lcg-paris' => array( '007100000290' ) ), 'log collector group' );
    eq( $p['master_devices_not_moved'], array( 'testDG' => '000000000101' ), 'master device not moved' );
    $fu = @file_get_contents( $dir . '/report/MIGRATION_FOLLOWUP.md' );
    check( $fu !== FALSE, 'MIGRATION_FOLLOWUP.md written' );
    foreach( array(
        '- [x] Panorama server in template Paris Datacenter: panorama-server 192.0.2.1 → 203.0.113.50',
        '- [x] Panorama server in template Paris Datacenter: panorama-server-2 192.0.2.2 → 203.0.113.51',
        'Access domain `ad-paris`: create / extend it in Panorama B with testDG, Paris_Datacenter_Stack, firewall 007100000290 and assign it to the administrator(s) paris-admin',
        'Log collection: add 007100000290 to a collector group of Panorama B (Panorama A: `lcg-paris`)',
        'Plugin `sd_wan` references firewall 007100000290',
        'Plugin `sd_wan` of Panorama A still references firewall 007100000290',
        'master device 000000000101 is not moved',
        '`request authkey add name <key-name> lifetime <minutes> count 1 serial <serial> devtype fw`',
        '`set deviceconfig system panorama local-panorama panorama-server 203.0.113.50` and `... panorama-server-2 203.0.113.51`',
        '| [ ] | 007100000290 | vsys1 | testDG | Paris_Datacenter_Stack |',
        'Master key: confirm Panorama B uses the same master key',
        'Logs of 007100000290 stay in collector group `lcg-paris`',
        ) as $s )
        check( $fu !== FALSE && strpos($fu, $s) !== FALSE, 'follow-up contains: ' . substr($s, 0, 70) );
    noSecretsIn( $dir );
};

$scenarios['panorama-ip-single-address'] = function() use ( $A, $Bclean ) {
    // testDG: panorama-server-2 removed (one address); DE-Berlin Office: old format replaced, variable unchanged
    list( $rc, $p, $dir ) = run( 'pipsingle', array( 'testDG' ), array( 'file1=' . $A, 'file2=' . $Bclean, 'mode=execute', 'panorama-ip=panorama-b.example.net' ) );
    eq( $rc, 0, 'exit code' );
    eq( array_column($p['panorama_settings'], 'action'), array( 'replace', 'remove' ), 'server replaced, server-2 removed' );
    $b = xp( $dir . '/B.xml' );
    eq( txt($b, '//template/entry[@name="Paris Datacenter"]//panorama-server'), 'panorama-b.example.net', 'file2 FQDN set' );
    eq( cnt($b, '//template/entry[@name="Paris Datacenter"]//panorama-server-2'), 0, 'file2 panorama-server-2 removed' );
    check( strpos(@file_get_contents($dir . '/report/MIGRATION_FOLLOWUP.md'), 'removed (panorama-ip has one address)') !== FALSE, 'follow-up: secondary removed' );

    list( $rc, $p, $dir ) = run( 'pipvar', array( 'DE-Berlin Office' ), array( 'file1=' . $A, 'file2=' . $Bclean, 'mode=execute', 'panorama-ip=panorama-b.example.net' ) );
    eq( $rc, 0, 'exit code (DE-Berlin Office)' );
    $ps = array(); foreach( $p['panorama_settings'] as $s ) $ps[$s['location']] = $s['action'];
    eq( $ps, array( 'template Internet Perimeter Master' => 'replace', 'template stack DE_Berlin_Office_Stack' => 'variable' ), 'old format replaced, variable kept' );
    $b = xp( $dir . '/B.xml' ); $a = xp( $dir . '/A.xml' );
    eq( txt($b, '//template/entry[@name="Internet Perimeter Master"]//deviceconfig/system/panorama-server'), 'panorama-b.example.net', 'file2 old format replaced' );
    eq( txt($b, '//template-stack/entry[@name="DE_Berlin_Office_Stack"]//panorama-server'), '$panorama_primary', 'file2 variable unchanged' );
    eq( txt($a, '//template/entry[@name="Internet Perimeter Master"]//deviceconfig/system/panorama-server'), '192.0.2.1', 'file1 copied template unchanged' );
    check( strpos(@file_get_contents($dir . '/report/MIGRATION_FOLLOWUP.md'), 'uses the variable `$panorama_primary`') !== FALSE, 'follow-up: variable item' );
};

////////////////////////////////////////////////////////////////////////////////
// unresolved references and content (concept 11.1 / 11.2): fixture A + one rule with references that exist nowhere

$scenarios['unresolved-and-content'] = function() use ( $A, $Bclean, $work ) {
    $d = new DOMDocument();
    $d->load( $A );
    $x = new DOMXPath( $d );
    $dg = $x->query("/config/devices/entry/device-group/entry[@name='testDG']")->item(0);
    $f = new DOMDocument();
    $f->loadXML( '<root>'
        . '<profiles><vulnerability><entry name="vp-test"><threat-exception><entry name="30000"><action><default/></action></entry>'
        . '<entry name="99999999"><action><default/></action></entry></threat-exception></entry></vulnerability></profiles>'
        . '<profile-group><entry name="pg-test"><virus><member>default</member></virus><spyware><member>ghost-spyware</member></spyware></entry></profile-group>'
        . '<application-group><entry name="ag-test"><members><member>ssl</member><member>ghost-app-in-group</member></members></entry></application-group>'
        . '<pre-rulebase><security><rules>'
        . '<entry name="ref-rule-1"><from><member>any</member></from><to><member>any</member></to><source><member>any</member></source>'
        . '<destination><member>any</member></destination><source-user><member>any</member></source-user>'
        . '<category><member>social-networking</member><member>ghost-category</member></category>'
        . '<application><member>web-browsing</member><member>ag-test</member><member>ghost-app</member></application>'
        . '<service><member>application-default</member></service><action>allow</action>'
        . '<tag><member>ghost-tag</member></tag><schedule>ghost-schedule</schedule><log-setting>ghost-log</log-setting>'
        . '<profile-setting><profiles><vulnerability><member>vp-test</member></vulnerability><url-filtering><member>ghost-url</member></url-filtering></profiles></profile-setting></entry>'
        . '<entry name="ref-rule-2"><from><member>any</member></from><to><member>any</member></to><source><member>any</member></source>'
        . '<destination><member>any</member></destination><source-user><member>any</member></source-user><category><member>any</member></category>'
        . '<application><member>any</member></application><service><member>any</member></service><action>allow</action>'
        . '<profile-setting><group><member>pg-test</member></group></profile-setting></entry>'
        . '</rules></security></pre-rulebase></root>' );
    $old = null;
    foreach( $dg->childNodes as $c ) if( $c->nodeName == 'pre-rulebase' ) $old = $c;
    if( $old !== null ) $dg->removeChild( $old );
    foreach( $f->documentElement->childNodes as $c )
        $dg->appendChild( $d->importNode($c, TRUE) );
    $file1 = $work . '/panorama-move-A-refs.xml';
    $d->save( $file1 );

    list( $rc, $p, $dir ) = run( 'refs', array( 'testDG' ), array( 'file1=' . $file1, 'file2=' . $Bclean ) );
    eq( $rc, 0, 'check run - exit code (warnings only)' );
    $names = array();
    foreach( findings($p, 'warning', 'unresolved') as $w ) $names[] = $w['name'];
    foreach( array( 'tag ghost-tag', 'schedule ghost-schedule', 'log forwarding profile ghost-log', 'category ghost-category',
                 'url-filtering profile ghost-url', 'spyware profile ghost-spyware' ) as $exp )
        check( in_array($exp, $names, TRUE), 'unresolved: ' . $exp );
    foreach( array( 'category social-networking', 'virus profile default', 'application web-browsing' ) as $no )
        check( !in_array($no, $names, TRUE), 'resolved (predefined): ' . $no );
    $content = array();
    foreach( findings($p, 'warning', 'content') as $w ) $content[] = $w['name'];
    foreach( array( 'application ghost-app', 'application ghost-app-in-group', 'threat ID 99999999' ) as $exp )
        check( in_array($exp, $content, TRUE), 'content: ' . $exp );
    eq( $p['content']['unknown_threat_ids'], array( '99999999' ), 'plan.json unknown threat IDs' );
    check( in_array('30000', $p['content']['threat_ids'], TRUE), 'plan.json predefined threat ID 30000' );
    check( in_array('ssl', $p['content']['applications'], TRUE) && in_array('web-browsing', $p['content']['applications'], TRUE), 'plan.json predefined applications' );
    eq( count(findings($p, 'info', 'content')), 1, 'content summary (info)' );
    check( strpos(@file_get_contents($dir . '/report/MIGRATION_FOLLOWUP.md'), 'App-ID / threat content version') !== FALSE, 'follow-up: content item' );

    list( $rc, $p ) = run( 'refs-exec', array( 'testDG' ), array( 'file1=' . $file1, 'file2=' . $Bclean, 'mode=execute' ) );
    eq( $rc, 0, 'execute - exit code' );
    check( $p['stats']['validation']['file2']['unresolved'] > 0, 'validation file2 reports the unresolved references' );
    check( count( array_filter( $p['stats']['validation']['file2']['unresolved_list'], function( $l ) { return strpos($l, 'schedule ghost-schedule') !== FALSE; } ) ) == 1, 'validation lists the schedule' );
};

////////////////////////////////////////////////////////////////////////////////
// Panorama settings (config sections, concept 11.3): deployment-update-schedule referencing moved firewalls

$scenarios['panorama-settings'] = function() use ( $A, $Bclean, $work ) {
    $d = new DOMDocument();
    $d->load( $A );
    $x = new DOMXPath( $d );
    $system = $x->query("/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system")->item(0);
    $f = new DOMDocument();
    // structure of a real Panorama configuration (Device Deployment > Dynamic Updates > Schedules), fixture serials
    $f->loadXML( '<deployment-update-schedule>'
        . '<entry name="AppAndThreats"><app-and-threat><recurring><threshold>24</threshold><daily><action><download-and-install>'
        . '<devices><member>007100000290</member><member>000000000101</member></devices>'
        . '</download-and-install></action><at>03:00</at></daily></recurring></app-and-threat>'
        . '<download-source><update-server/></download-source><disabled>no</disabled></entry>'
        . '<entry name="WF"><wildfire><recurring><every-min><action><download-and-install>'
        . '<devices><member>000000000555</member></devices>'
        . '</download-and-install></action></every-min></recurring></wildfire>'
        . '<download-source><update-server/></download-source><disabled>no</disabled></entry>'
        . '<entry name="AV"><anti-virus><recurring><threshold>48</threshold><daily><action><download-and-install>'
        . '<devices><member>007100000290</member></devices>'
        . '</download-and-install></action><at>03:00</at></daily></recurring></anti-virus>'
        . '<download-source><update-server/></download-source><disabled>no</disabled></entry>'
        . '</deployment-update-schedule>' );
    $system->appendChild( $d->importNode($f->documentElement, TRUE) );
    $file1 = $work . '/panorama-move-A-settings.xml';
    $d->save( $file1 );

    list( $rc, $p, $dir ) = run( 'settings', array( 'testDG' ), array( 'file1=' . $file1, 'file2=' . $Bclean ) );
    eq( $rc, 0, 'check run - exit code' );
    $s = findings( $p, 'info', 'Panorama setting' );
    eq( count($s), 2, 'two Panorama setting findings (unrelated entry not reported)' );
    eq( isset($s[0]) ? $s[0]['name'] : null, 'deployment-update-schedule AppAndThreats', 'finding names section and entry' );
    $refs = isset($p['panorama_settings_referencing_moved'][0]) ? $p['panorama_settings_referencing_moved'][0]['references'] : array();
    eq( $refs, array( 'firewall 007100000290' ), 'plan.json references (only the moved firewall)' );
    check( strpos(@file_get_contents($dir . '/report/MIGRATION_FOLLOWUP.md'), 'type=config-section') !== FALSE, 'follow-up: set commands hint' );

    list( $rc, $p, $dir ) = run( 'settings-exec', array( 'testDG' ), array( 'file1=' . $file1, 'file2=' . $Bclean, 'mode=execute' ) );
    eq( $rc, 0, 'execute - exit code' );
    $a = xp( $dir . '/A.xml' );
    $devs = "/config/devices/entry/deviceconfig/system/deployment-update-schedule/entry[@name='AppAndThreats']/app-and-threat/recurring/daily/action/download-and-install/devices";
    eq( cnt($a, $devs . "/member[.='007100000290']"), 0, 'file1: moved firewall removed from the schedule' );
    eq( cnt($a, $devs . "/member[.='000000000101']"), 1, 'file1: kept firewall stays' );
    eq( cnt($a, "//deployment-update-schedule/entry[@name='WF']//devices/member"), 1, 'file1: unrelated entry unchanged' );
    eq( cnt($a, "//deployment-update-schedule/entry[@name='AV']//devices/member"), 0, 'file1: only firewall of AV removed' );
    $fu = (string)@file_get_contents( $dir . '/report/MIGRATION_FOLLOWUP.md' );
    check( strpos($fu, 'Empty member list') !== FALSE && strpos($fu, 'deployment-update-schedule AV') !== FALSE, 'follow-up: empty member list of AV' );
    check( strpos($fu, 'deployment-update-schedule AppAndThreats:') === FALSE || strpos(substr($fu, strpos($fu, 'Empty member list')), 'AppAndThreats') === FALSE, 'follow-up: AppAndThreats not empty' );
    $b = xp( $dir . '/B.xml' );
    eq( cnt($b, "//deployment-update-schedule"), 0, 'file2: Panorama settings not transferred' );
};

////////////////////////////////////////////////////////////////////////////////
// concept 11.3 / 11.6: scheduled config push and auto-push / to-sw-version are not transferred, only reported

$scenarios['push-not-transferred'] = function() use ( $A, $Bclean, $work ) {
    $d = new DOMDocument();
    $d->load( $A );
    $x = new DOMXPath( $d );
    // moved firewall (testDG): auto push + upgrade; kept firewall: auto push off
    $m = $x->query("/config/mgt-config/devices/entry[@name='007100000290']")->item(0);
    $m->appendChild( $d->createElement('auto-push', 'yes') );
    $m->appendChild( $d->createElement('to-sw-version', '11.1.6') );
    $x->query("/config/mgt-config/devices/entry[@name='000000000101']")->item(0)->appendChild( $d->createElement('auto-push', 'no') );
    // scheduled config push - the xpath is not documented, element name with "push" and "schedul" below the Panorama entry
    $f = new DOMDocument();
    $f->loadXML( '<scheduled-config-push>'
        . '<entry name="weekly-push"><disabled>no</disabled><recurring><weekly><day-of-week>sunday</day-of-week><at>02:00</at></weekly></recurring>'
        . '<device-group><member>testDG</member></device-group>'
        . '<devices><member>007100000290</member><member>000000000101</member></devices></entry>'
        . '<entry name="only-kept"><disabled>no</disabled><devices><member>000000000101</member></devices></entry>'
        . '<entry name="only-moved"><disabled>yes</disabled><devices><member>007100000290</member></devices></entry>'
        . '</scheduled-config-push>' );
    $x->query("/config/devices/entry[@name='localhost.localdomain']")->item(0)->appendChild( $d->importNode($f->documentElement, TRUE) );
    $file1 = $work . '/panorama-move-A-push.xml';
    $d->save( $file1 );

    list( $rc, $p, $dir ) = run( 'push', array( 'testDG' ), array( 'file1=' . $file1, 'file2=' . $Bclean ) );
    eq( $rc, 0, 'check run - exit code' );
    $sp = byName( isset($p['scheduled_config_push_not_transferred']) ? $p['scheduled_config_push_not_transferred'] : array(), 'entry' );
    eq( array_keys($sp), array( 'weekly-push', 'only-kept', 'only-moved' ), 'plan.json: all scheduled pushes of file1 listed' );
    eq( isset($sp['weekly-push']) ? $sp['weekly-push']['references'] : null, array( 'device group testDG', 'firewall 007100000290' ), 'plan.json: references of weekly-push' );
    eq( isset($sp['only-kept']) ? $sp['only-kept']['references'] : null, array(), 'plan.json: only-kept without moved items' );
    eq( isset($sp['weekly-push']) ? $sp['weekly-push']['path'] : null, 'devices/entry[localhost.localdomain]/scheduled-config-push', 'plan.json: path' );
    eq( count(findings($p, 'warning', 'scheduled config push')), 2, 'two warnings (schedules with moved items)' );
    eq( count(findings($p, 'info', 'scheduled config push')), 1, 'one info (schedule without moved items)' );
    eq( isset($p['device_settings_not_transferred']['007100000290']) ? $p['device_settings_not_transferred']['007100000290'] : null,
        array( 'auto-push' => 'yes', 'to-sw-version' => '11.1.6' ), 'plan.json: settings of the moved firewall' );
    check( !isset($p['device_settings_not_transferred']['000000000101']), 'plan.json: kept firewall not listed' );
    eq( count(findings($p, 'warning', 'firewall setting')), 2, 'warnings auto-push yes / to-sw-version' );
    $rep = (string)@file_get_contents( $dir . '/report/REPORT.md' );
    check( strpos($rep, '## Scheduled config push of file1 (not transferred)') !== FALSE && strpos($rep, 'only-kept') !== FALSE, 'REPORT.md: scheduled push section' );
    check( strpos($rep, '## Firewall settings not transferred') !== FALSE && strpos($rep, '11.1.6') !== FALSE, 'REPORT.md: firewall settings section' );
    $fu = (string)@file_get_contents( $dir . '/report/MIGRATION_FOLLOWUP.md' );
    check( strpos($fu, 'Auto Push on 1st Connect') !== FALSE && strpos($fu, 'To SW Version') !== FALSE, 'follow-up: firewall settings' );
    check( strpos($fu, 'Scheduled config push `weekly-push`') !== FALSE && strpos($fu, '`only-kept`') === FALSE, 'follow-up: only schedules with moved items' );

    list( $rc, $p, $dir ) = run( 'push-exec', array( 'testDG' ), array( 'file1=' . $file1, 'file2=' . $Bclean, 'mode=execute' ) );
    eq( $rc, 0, 'execute - exit code' );
    $b = xp( $dir . '/B.xml' );
    eq( cnt($b, "/config/mgt-config/devices/entry[@name='007100000290']"), 1, 'file2: firewall transferred' );
    eq( cnt($b, "/config/mgt-config/devices/entry[@name='007100000290']/auto-push"), 0, 'file2: auto-push not transferred' );
    eq( cnt($b, "/config/mgt-config/devices/entry[@name='007100000290']/to-sw-version"), 0, 'file2: to-sw-version not transferred' );
    eq( cnt($b, "//scheduled-config-push"), 0, 'file2: scheduled config push not transferred' );
    $a = xp( $dir . '/A.xml' );
    $w = "//scheduled-config-push/entry[@name='weekly-push']";
    eq( cnt($a, $w . "/devices/member"), 1, 'file1: moved firewall removed from weekly-push' );
    eq( txt($a, $w . "/devices/member"), '000000000101', 'file1: kept firewall stays in weekly-push' );
    eq( cnt($a, $w . "/device-group/member[.='testDG']"), 0, 'file1: moved device group removed from weekly-push' );
    eq( cnt($a, "//scheduled-config-push/entry[@name='only-kept']/devices/member"), 1, 'file1: only-kept unchanged' );
    eq( cnt($a, "/config/mgt-config/devices/entry[@name='000000000101']/auto-push"), 1, 'file1: kept firewall keeps auto-push' );
    $fu = (string)@file_get_contents( $dir . '/report/MIGRATION_FOLLOWUP.md' );
    check( strpos($fu, 'Empty member list') !== FALSE && strpos($fu, 'scheduled config push only-moved') !== FALSE
        && strpos($fu, 'scheduled config push weekly-push: devices') === FALSE, 'follow-up: empty member lists (only-moved device list, weekly-push device group)' );
};

////////////////////////////////////////////////////////////////////////////////
// arguments

$scenarios['arguments'] = function() use ( $A, $Bclean ) {
    foreach( array( 'conflict=rename:', 'conflict=rename:_A!', 'conflict=foo', 'master-key=other', 'mode=run', 'shared-rules=all',
                 'panorama-ip=', 'panorama-ip=not_valid!', 'panorama-ip=192.0.2.1,192.0.2.2,192.0.2.3', 'panorama-ip=300.1.1.1' ) as $bad )
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
