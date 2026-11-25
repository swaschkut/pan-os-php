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
 * The value of a filter never becomes code: a value that is not a number is refused for the math operators
 * ( > < = != >= <= ), a name with a quote is only a name, every filter is a function and nothing below lib/ uses eval().
 * Synthetic input tests/input/filter-eval.xml.
 *
 *   php tests/test_filter_no_eval.php
 */
$repo = dirname( __DIR__ );
$in = $repo . '/tests/input/filter-eval.xml';
$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};
$run = function( string $type, string $filter ) use ( $repo, $in ) {
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' type=' . $type . ' in=' . escapeshellarg( $in ) .
        ' location=any ' . escapeshellarg( 'filter=' . $filter ) . ' actions=display 2>&1', $o );
    return implode( "\n", $o );
};
$names = function( string $out ) {
    preg_match_all( "/- object '(?:\e\[1m)?([^'\e]+)/", $out, $m );
    return $m[1];
};

// 1) the filters still answer as before
$eq( $names( $run( 'address', '(refcount > 0)' ) ), array( 'h-192.0.2.10', 'h-192.0.2.11' ), 'address refcount > 0' );
$eq( $names( $run( 'address', '(netmask < 32)' ) ), array( 'n-198.51.100.0_24' ), 'address netmask < 32' );
$eq( $names( $run( 'address', '(members.count = 2)' ) ), array( 'servers' ), 'address members.count = 2' );
$eq( $names( $run( 'address', '(ip.count >= 256)' ) ), array( 'n-198.51.100.0_24' ), 'address ip.count >= 256 (was built for eval inside the filter)' );
$eq( $names( $run( 'address', '(tag has prod)' ) ), array( 'h-192.0.2.10' ), 'address tag has prod (object finder)' );
$eq( $names( $run( 'address', "(tag has it's)" ) ), array( 'h-192.0.2.11' ), 'a name with a quote is found, it does not break the filter' );
$eq( $names( $run( 'service', '(members.count > 1)' ) ), array( 'web-group' ), 'service members.count > 1' );
$eq( $names( $run( 'service', '(port.count > 1)' ) ), array( 'service-http', 'web-alt', 'web-group' ), 'service port.count > 1 (with the predefined service-http)' );
$eq( $names( $run( 'address', '(name.length != 12)' ) ), array( 'n-198.51.100.0_24', 'servers' ), 'address name.length != 12' );
$eq( $names( $run( 'schedule', '(expire.in.days > 30)' ) ), array( 'far-future' ), 'schedule expire.in.days > 30' );
$out = $run( 'schedule', '(object expire.in.days 30)' );
$eq( array( (bool)preg_match( '/Parse error|Fatal error/', $out ), (bool)preg_match( '/END OF SCRIPT/', $out ) ), array( FALSE, TRUE ), 'schedule object expire.in.days 30: runs (before: PHP parse error)' );
$eq( $names( $run( 'schedule', '(object is.expired)' ) ), array( 'old-project' ), 'schedule object is.expired' );

// 2) a value that is code is refused and not executed
$marker = sys_get_temp_dir() . '/pan-os-php-filter-eval-' . getmypid();
@unlink( $marker );
$attempts = array(
    array( 'address', '(refcount > `touch ' . $marker . '`)', 'backticks, math operator' ),
    array( 'address', '(refcount > 0 || touch("' . $marker . '"))', 'function call, math operator' ),
    array( 'address', '(refcount > 0; touch("' . $marker . '"))', 'second statement, math operator' ),
    array( 'service', '(members.count > 0+touch("' . $marker . '"))', 'expression, math operator' ),
    array( 'service', '(port.count > `touch ' . $marker . '`)', 'backticks, filter that built its own eval' ),
    array( 'address', '(ip.count > 0 || touch("' . $marker . '"))', 'function call, filter that built its own eval' ),
    array( 'schedule', '(expire.in.days < 0+touch("' . $marker . '"))', 'expression, schedule' ),
    array( 'address', "(tag has x');touch('" . $marker . "');//)", 'quote and statement, object finder' ),
    array( 'address', "(tag has x'.`touch " . $marker . "`.')", 'quote and backticks, object finder' ),
);
foreach( $attempts as $a )
{
    $out = $run( $a[0], $a[1] );
    $eq( file_exists( $marker ), FALSE, 'not executed: ' . $a[2] );
    $eq( $names( $out ), array(), 'no object listed: ' . $a[2] );
    @unlink( $marker );
}
$eq( (bool)preg_match( '/has to be a number/', $run( 'address', '(refcount > abc)' ) ), TRUE, 'refcount > abc: the message says a number is expected' );
$eq( (bool)preg_match( '/has to be a number/', $run( 'service', '(port.count > abc)' ) ), TRUE, 'port.count > abc: the message says a number is expected' );

// 3) the comparison itself
require_once $repo . '/lib/pan_php_framework.php';
$eq( RQuery::mathCompare( 5, '>', '3' ), TRUE, 'mathCompare 5 > 3' );
$eq( RQuery::mathCompare( '5', '<', 3 ), FALSE, 'mathCompare 5 < 3' );
$eq( RQuery::mathCompare( 3, '=', ' 3 ' ), TRUE, 'mathCompare 3 = 3' );
$eq( RQuery::mathCompare( 3, '==', 3.0 ), TRUE, 'mathCompare 3 == 3.0' );
$eq( RQuery::mathCompare( 3, '!=', 4 ), TRUE, 'mathCompare 3 != 4' );
$eq( RQuery::mathCompare( 3, '>=', 3 ), TRUE, 'mathCompare 3 >= 3' );
$eq( RQuery::mathCompare( 3, '<=', 2 ), FALSE, 'mathCompare 3 <= 2' );
$eq( RQuery::mathCompare( '', '>', 0 ), FALSE, 'mathCompare: an object without a number does not match' );
$eq( array( RQuery::compare( 5, '>', 3 ), RQuery::compare( 5, '=', 5 ), RQuery::compare( 5, '!=', 5 ), RQuery::compare( 2, '<=', '3' ) ),
    array( TRUE, TRUE, FALSE, TRUE ), 'compare: the math operators of an eval filter' );

// 4) nothing below lib/ evaluates text as code, and no filter is defined as text
$found = array(); $asText = array();
$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $repo . '/lib', FilesystemIterator::SKIP_DOTS ) );
foreach( $it as $f )
{
    if( substr( $f->getFilename(), -4 ) !== '.php' )
        continue;
    foreach( file( $f->getPathname() ) as $no => $line )
    {
        if( preg_match( '~^\s*(//|#|\*)~', $line ) )
            continue;
        $at = substr( $f->getPathname(), strlen( $repo ) + 1 ) . ':' . ( $no + 1 );
        if( preg_match( '/(?<![\w>$:])eval\s*\(/', $line ) )
            $found[] = $at;
        if( preg_match( '/[\'"](eval|argObjectFinder)[\'"]\s*=>\s*[\'"]/', $line ) )
            $asText[] = $at;
    }
}
$eq( $found, array(), 'no eval() below lib/' );
$eq( $asText, array(), "no filter with 'eval' / 'argObjectFinder' written as text" );
$bad = array();
foreach( RQuery::$defaultFilters as $type => $fields )
    foreach( $fields as $field => $def )
        foreach( (array)( $def['operators'] ?? array() ) as $op => $o )
        {
            if( !is_array( $o ) )
                continue;
            foreach( array( 'eval', 'argObjectFinder' ) as $k )
                if( isset( $o[$k] ) && !( $o[$k] instanceof Closure ) )
                    $bad[] = $type . ' ' . $field . ' ' . $op . ' ' . $k;
            if( !isset( $o['eval'] ) && !isset( $o['Function'] ) )
                $bad[] = $type . ' ' . $field . ' ' . $op . ' (neither eval nor Function)';
        }
$eq( $bad, array(), 'every registered filter is a function' );

// a filter written as text is refused, not evaluated
PH::$useExceptions = TRUE;
RQuery::$defaultFilters['address']['zz-text']['operators']['is.set'] = array( 'eval' => 'touch("' . $marker . '")', 'arg' => FALSE );
$refused = FALSE;
try
{
    $q = new RQuery( 'address' ); $err = '';
    $q->parseFromString( '(zz-text is.set)', $err );
    $q->matchSingleObject( new stdClass() );
}
catch( Throwable $e )
{
    $refused = (bool)preg_match( '/has to be a function/', $e->getMessage() );
}
$eq( array( $refused, file_exists( $marker ) ), array( TRUE, FALSE ), 'a filter defined as text is refused and not executed' );
if( file_exists( $marker ) )
    unlink( $marker );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
