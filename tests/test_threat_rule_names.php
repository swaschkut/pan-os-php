<?php
/**
 * Tests of the rules that the set-actions of Vulnerability Protection / Anti-Spyware profiles add for a severity no
 * rule matches (SecurityProfile2::threatRules_setFromJSON(), ThreatPolicy::uniqueRuleName()):
 *   - VP, no rule of the profile covers the severity   -> one rule '<severity>', host any
 *   - VP, other rules of that severity exist           -> '<severity>_client' / '<severity>_server', one per missing host
 *   - AS (no host)                                     -> '<severity>'
 *   - name already used                                -> '<name>_1'
 * The names and hosts of alert-only-set are the ones of the beta branch (regression: 'critical' with host any was
 * created where 'critical_client' is expected).
 *
 *   cd tests && php test_threat_rule_names.php
 *
 * Input: input/panorama-10.0-merger.xml with profiles added to shared at runtime. Exit code 0 = all passed.
 */

$here = dirname(__FILE__);
$cli = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($here . '/../utils/pan-os-php.php') . ' type=securityprofile location=shared';
$work = sys_get_temp_dir() . '/pan-os-php-test-threat-rule-names-' . getmypid();
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

function vpRule( $name, array $severity, $host, $action = 'alert', $category = 'any' )
{
    $s = '';
    foreach( $severity as $x ) $s .= '<member>' . $x . '</member>';
    return '<entry name="' . $name . '"><action><' . $action . '/></action><vendor-id><member>any</member></vendor-id><severity>' . $s
        . '</severity><cve><member>any</member></cve><threat-name>any</threat-name><host>' . $host . '</host><category>' . $category
        . '</category><packet-capture>disable</packet-capture></entry>';
}

function asRule( $name, array $severity, $action = 'alert', $category = 'any' )
{
    $s = '';
    foreach( $severity as $x ) $s .= '<member>' . $x . '</member>';
    return '<entry name="' . $name . '"><action><' . $action . '/></action><severity>' . $s . '</severity><threat-name>any</threat-name><category>'
        . $category . '</category><packet-capture>disable</packet-capture></entry>';
}

$vp = array(
    'VP-empty' => '',
    'VP-crit-server' => vpRule( 'srv-crit', array('critical'), 'server' ),
    'VP-crit-client-high-server' => vpRule( 'c1', array('critical'), 'client' ) . vpRule( 'h1', array('high'), 'server' ),
    'VP-any-category' => vpRule( 'codeexec', array('any'), 'any', 'alert', 'code-execution' ),
    'VP-name-taken' => vpRule( 'critical', array('low'), 'any' ) . vpRule( 'critical_client', array('informational'), 'any' ),
    'VP-all-server' => vpRule( 'srv-all', array('critical', 'high', 'medium', 'low', 'informational'), 'server' ),
);
$as = array(
    'AS-empty' => '',
    'AS-crit' => asRule( 'crit', array('critical') ),
    'AS-name-taken' => asRule( 'critical', array('low') ),
);
$xml = '<profiles><vulnerability>';
foreach( $vp as $n => $r ) $xml .= $r === '' ? '<entry name="' . $n . '"/>' : '<entry name="' . $n . '"><rules>' . $r . '</rules></entry>';
$xml .= '</vulnerability><spyware>';
foreach( $as as $n => $r ) $xml .= $r === '' ? '<entry name="' . $n . '"/>' : '<entry name="' . $n . '"><rules>' . $r . '</rules></entry>';
$xml .= '</spyware></profiles>';

$d = new DOMDocument();
$d->load( $here . '/input/panorama-10.0-merger.xml' );
$f = new DOMDocument();
$f->loadXML( $xml );
$shared = ( new DOMXPath( $d ) )->query( '/config/shared' )->item( 0 );
$shared->appendChild( $d->importNode( $f->documentElement, TRUE ) );
$in = $work . '/in.xml';
$d->save( $in );

/** runs one action, returns profile => list of "name|severity|host" of its rules */
function rulesAfter( $type, $action )
{
    global $cli, $in, $work;
    $out = $work . '/out.xml';
    @unlink( $out );
    exec( $cli . ' securityprofiletype=' . $type . ' in=' . escapeshellarg($in) . ' out=' . escapeshellarg($out) . ' actions=' . $action . ' 2>&1', $o, $rc );
    if( $rc != 0 || !is_file($out) )
        return array( 'ERROR' => array( 'exit code ' . $rc ) );
    $r = new DOMDocument();
    $r->load( $out );
    $x = new DOMXPath( $r );
    $res = array();
    foreach( $x->query( '/config/shared/profiles/' . $type . '/entry' ) as $p )
    {
        $list = array();
        foreach( $x->query( 'rules/entry', $p ) as $rule )
        {
            $sev = array();
            foreach( $x->query( 'severity/member', $rule ) as $m ) $sev[] = trim( $m->textContent );
            $host = $x->query( 'host', $rule );
            $list[] = $rule->getAttribute('name') . '|' . implode( ',', $sev ) . '|' . ( $host->length ? trim($host->item(0)->textContent) : '-' );
        }
        $res[$p->getAttribute('name')] = $list;
    }
    return $res;
}

// ---- VP alert-only-set (names / hosts as on the beta branch)
$r = rulesAfter( 'vulnerability', 'vulnerability.rules.alert-only-set' );
eq( $r['VP-empty'] ?? null, array( 'critical|critical|any', 'high|high|any', 'medium|medium|any', 'low|low|any', 'informational|informational|any' ),
    'VP empty profile: one rule per severity, host any' );
eq( $r['VP-crit-server'] ?? null, array( 'srv-crit|critical|server', 'critical_client|critical|client', 'high|high|any', 'medium|medium|any', 'low|low|any', 'informational|informational|any' ),
    'VP critical covered for server only: critical_client (not "critical" with host any)' );
eq( $r['VP-crit-client-high-server'] ?? null, array( 'c1|critical|client', 'h1|high|server', 'critical_server|critical|server', 'high_client|high|client', 'medium|medium|any', 'low|low|any', 'informational|informational|any' ),
    'VP partial coverage: the missing host per severity' );
eq( $r['VP-any-category'] ?? null, array( 'codeexec|any|any',
        'critical_client|critical|client', 'critical_server|critical|server', 'high_client|high|client', 'high_server|high|server', 'medium_client|medium|client', 'medium_server|medium|server',
        'low_client|low|client', 'low_server|low|server', 'informational_client|informational|client', 'informational_server|informational|server' ),
    'VP rule limited to a category: client and server rule per severity' );
eq( $r['VP-all-server'] ?? null, array( 'srv-all|critical,high,medium,low,informational|server',
        'critical_client|critical|client', 'high_client|high|client', 'medium_client|medium|client', 'low_client|low|client', 'informational_client|informational|client' ),
    'VP all severities for server: client rules' );
eq( $r['VP-name-taken'] ?? null, array( 'critical|low|any', 'critical_client|informational|any', 'critical_1|critical|any', 'high|high|any', 'medium|medium|any' ),
    'VP rule name already used: unique name critical_1' );

// ---- VP best-practice-set uses the same names for the rules it adds
$r = rulesAfter( 'vulnerability', 'vulnerability.rules.best-practice-set' );
$names = function( $list ) { return array_map( function( $l ) { return substr( $l, 0, strpos($l, '|') ); }, (array)$list ); };
eq( $names( $r['VP-empty'] ?? null ), array( 'critical', 'high', 'medium', 'low', 'informational' ), 'VP best-practice-set, empty profile: <severity>' );
eq( in_array( 'critical_client|critical|client', $r['VP-crit-server'] ?? array(), TRUE ), TRUE, 'VP best-practice-set: critical_client for the missing host' );
eq( in_array( 'critical|critical|any', $r['VP-crit-server'] ?? array(), TRUE ), FALSE, 'VP best-practice-set: no "critical" host any next to the server rule' );

// ---- AS: no host, '<severity>', unique names
$r = rulesAfter( 'spyware', 'spyware.rules.alert-only-set' );
eq( $r['AS-empty'] ?? null, array( 'critical|critical|-', 'high|high|-', 'medium|medium|-', 'low|low|-', 'informational|informational|-' ), 'AS empty profile: one rule per severity' );
eq( $r['AS-crit'] ?? null, array( 'crit|critical|-', 'high|high|-', 'medium|medium|-', 'low|low|-', 'informational|informational|-' ), 'AS: only the missing severities' );
eq( $r['AS-name-taken'] ?? null, array( 'critical|low|-', 'critical_1|critical|-', 'high|high|-', 'medium|medium|-', 'informational|informational|-' ), 'AS rule name already used: critical_1' );

exec( 'rm -rf ' . escapeshellarg($work) );
print "\n" . $checks . " checks, " . count($failed) . " failed\n";
if( count($failed) )
{
    foreach( $failed as $m ) print " - " . $m . "\n";
    exit( 1 );
}
exit( 0 );
