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
 * git merge driver of the history (ViewerGit: merge.panos.driver, info/attributes): merges one entry per field.
 *   php git-merge-entry.php <base> <ours> <theirs> <path>
 * The result goes into <ours>; exit 0 = merged, 1 = conflict (git keeps the conflict).
 */
if( PHP_SAPI !== 'cli' || $argc < 4 )
    exit( 2 );
require_once dirname( __FILE__ ) . '/../../../../lib/misc-classes/ConfigObjectMerge.php';
$read = function( $f ) { $t = @file_get_contents( $f ); return $t === FALSE ? null : $t; };
$o = $read( $argv[1] );
$a = $read( $argv[2] );
$b = $read( $argv[3] );
if( $o === null || $a === null || $b === null )
    exit( 2 );
try
{
    $m = ConfigObjectMerge::merge( $o, $a, $b, $argv[4] ?? '' );
}
catch( Throwable $e )
{
    $m = null;
}
if( $m === null )
    exit( 1 );
exit( file_put_contents( $argv[2], $m ) === FALSE ? 2 : 0 );
