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
 * object-merger (address) and dynamic address groups: a merge must never give a dynamic address group a new member
 * (more traffic) - an object with tags moved / created at an upper level or kept with more tags is checked against
 * every dynamic address group at that location and below. Synthetic inputs tests/input/merger-dag-*.xml (Panorama,
 * device groups pA and pB, the object in pA has the tag, the dynamic address group is in pB).
 *
 *   php tests/test_merger_dag.php
 */
$repo = dirname( __DIR__ );
$tmp = sys_get_temp_dir() . '/mergerdag-' . getmypid();
@mkdir( $tmp, 0700 );
$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};
$php = function( array $args ) use ( $repo ) {
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' ' . implode( ' ', array_map( 'escapeshellarg', $args ) ) . ' 2>&1', $o, $rc );
    return array( $rc, implode( "\n", $o ) );
};
$dagMembers = function( string $file ) use ( $php ) {
    list( , $o ) = $php( array( 'type=address', 'in=' . $file, 'location=pB', 'filter=(name eq dag)', 'actions=display' ) );
    return preg_match( '/\(([0-9]+) members\)/', $o, $m ) ? (int)$m[1] : -1;
};
$inShared = function( string $file ) {
    $d = new DOMDocument(); $d->load( $file );
    return ( new DOMXPath( $d ) )->query( '/config/shared/address/entry' )->length;
};

foreach( array(
    'new-member' => array( 'a dynamic address group in pB would get the tagged object of pA as a new member: not merged', TRUE, 0 ),
    'already-member' => array( 'the dynamic address group in pB has an object with this value already: merged', FALSE, 1 ),
    'and-filter' => array( "filter 't' and 'u', the object has only t: merged", FALSE, 1 ),
    'or-filter' => array( "filter 'u' or 't', the object has t: not merged", TRUE, 0 ),
) as $case => $def )
{
    list( $msg, $blocked, $shared ) = $def;
    $in = $repo . '/tests/input/merger-dag-' . $case . '.xml';
    $out = $tmp . '/' . $case . '.xml';
    list( $rc, $log ) = $php( array( 'type=object-merger', 'objecttype=address', 'in=' . $in, 'out=' . $out, 'location=any', 'allowMergingWithUpperLevel' ) );
    $eq( array( $rc, strpos( $log, 'SKIP-DAG' ) !== FALSE, $inShared( $out ), $dagMembers( $out ) ), array( 0, $blocked, $shared, $dagMembers( $in ) ),
        $msg . ' - the members of the dynamic address group stay the same' );
}

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
