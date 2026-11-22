<?php
/**
 * Prisma Access egress IPs (SCMEgressIP, scm_egress_ip.php): request from the option file of the Palo Alto
 * documentation and arguments, the answer as rows, formats, compare with an earlier state, offline from an export.
 * Synthetic data (documentation IP ranges), no tenant.
 *
 *   php tests/test_scm_egress_ip.php
 */
$repo = dirname( __DIR__ );
require_once $repo . "/lib/pan_php_framework.php";
require_once $repo . "/utils/develop/sase/scm/lib/SCMEgressIP.php";
$checks = 0;
$failed = array();
function eq( $got, $want, $what )
{
    global $checks, $failed;
    $checks++;
    echo ( $got === $want ? "ok  " : "FAIL " ) . $what . "\n";
    if( $got !== $want )
        $failed[] = " - " . $what . "\n      expected " . json_encode( $want ) . "\n      got      " . json_encode( $got );
}
$dir = sys_get_temp_dir() . '/egx-' . getmypid();
@mkdir( $dir . '/infra', 0700, TRUE );
$answer = array(
    array( 'zone' => 'Germany Central', 'zone_subnet' => array( '198.51.100.0/24' ), 'address_details' => array(
        array( 'address' => '198.51.100.10', 'serviceType' => 'gp_gateway', 'addressType' => 'active', 'allow_listed' => TRUE ),
        array( 'address' => '198.51.100.11', 'serviceType' => 'remote_network', 'addressType' => 'active' ) ) ),
    array( 'zone' => 'France North', 'addresses' => array( '203.0.113.5' ) ),
);
file_put_contents( $dir . '/infra/92_egress-ip.json', json_encode( array( 'request' => array( 'serviceType' => 'all' ), 'status' => 'ok', 'fetched_at' => '2026-11-01', 'data' => $answer ) ) );
file_put_contents( $dir . '/option.txt', '{ "serviceType": "gp_gateway", "addrType": "all", "location": "deployed" }' );

eq( SCMEgressIP::request( $dir . '/option.txt', array( 'addrtype' => 'active' ) ), array( 'serviceType' => 'gp_gateway', 'addrType' => 'active', 'location' => 'deployed' ),
    'request: the option file of the documentation, arguments override it' );
$bad = null;
try { SCMEgressIP::request( null, array( 'servicetype' => 'x"; rm' ) ); } catch( Exception $e ) { $bad = 'rejected'; }
eq( $bad, 'rejected', 'request: a value that is no keyword is rejected' );
$rows = SCMEgressIP::rows( $answer );
eq( array_map( function( $r ) { return $r['service_type'] . ' ' . $r['location'] . ' ' . $r['address'] . ' ' . $r['address_type'] . ' ' . $r['allow_listed']; }, $rows ),
    array( 'all France North 203.0.113.5  ', 'gp_gateway Germany Central 198.51.100.10 active yes', 'remote_network Germany Central 198.51.100.11 active ' ),
    'rows: address_details and plain addresses per location' );
eq( SCMEgressIP::format( $rows, 'list' ), "198.51.100.10\n198.51.100.11\n203.0.113.5\n", 'format list: one address per line' );
$old = $rows;
array_pop( $old );
$old[] = array( 'service_type' => 'gp_gateway', 'location' => 'Germany Central', 'address' => '198.51.100.99', 'address_type' => 'active', 'allow_listed' => '' );
$d = SCMEgressIP::compare( $old, $rows );
eq( array( array_column( $d['added'], 'address' ), array_column( $d['removed'], 'address' ) ), array( array( '198.51.100.11' ), array( '198.51.100.99' ) ), 'compare: added / removed addresses' );
$cli = 'php ' . escapeshellarg( $repo . '/utils/develop/sase/scm/scm_egress_ip.php' );
shell_exec( $cli . ' in=' . escapeshellarg( $dir ) . ' save=' . escapeshellarg( $dir . '/snap.json' ) . ' format=list' );
$csv = (string)shell_exec( $cli . ' in=' . escapeshellarg( $dir . '/snap.json' ) . ' format=csv' );
eq( array( count( SCMEgressIP::fromFile( $dir . '/snap.json' )['rows'] ), substr_count( $csv, "\n" ) ), array( 3, 4 ), 'CLI: offline from an export, snapshot, CSV' );
eq( array( SCMEgressIP::ENV_DEFAULT, strpos( SCMEgressIP::loginHint( '[{"message":"HTTP 401","details":{"message":"Unauthorized"}}]', 'prod6', '1234' ), 'try env=prod ' ) !== FALSE,
    strpos( SCMEgressIP::loginHint( '[{"message":"HTTP 403"}]', 'prod' ), 'try env=prod6 ' ) !== FALSE, SCMEgressIP::loginHint( '[{"message":"HTTP 500"}]', 'prod6' ) ),
    array( 'prod6', TRUE, TRUE, '' ), 'environment: default prod6; login error (401 / 403): hint to the other environment; other errors: no hint' );
eq( array( SCMEgressIP::ENVIRONMENTS, SCMEgressIP::url( 'prod8' ), SCMEgressIP::validEnv( 'prod12' ), SCMEgressIP::validEnv( 'prod-x' ), SCMEgressIP::validEnv( 'evil.com/x' ) ),
    array( array( 'prod8', 'prod6', 'prod' ), 'https://api.prod8.datapath.prismaaccess.com/getPrismaAccessIP/v2', TRUE, FALSE, FALSE ),
    'environments: prod6 / prod / prod8 known, any other prod<N> (nothing else in the host name)' );
array_map( 'unlink', array_filter( glob( $dir . '/{,infra/}*', GLOB_BRACE ), 'is_file' ) );
echo "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
foreach( $failed as $f )
    echo $f . "\n";
exit( count( $failed ) ? 1 : 0 );
