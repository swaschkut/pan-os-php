<?php
/**
 * ISC License
 *
 * Copyright (c) 2024, Sven Waschkut - pan-os-php@waschkut.net
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

// Check the secret lists of an export (psk-list.csv, bgp-secret-list.csv, secret-list.csv) - offline, prints no secret
//
// php utils/develop/sase/scm/scm_pa_secret_check.php dir=<export dir>        all lists of the export
// php utils/develop/sase/scm/scm_pa_secret_check.php file=<list.csv>[,<list.csv>]
//
// per entry: which value is used (psk_new / psk_current), and whether it is the secret of the source tenant:
// the exported (encrypted) value contains the SHA1 of the cleartext (column *_sha1), so a value filled in by hand can
// be checked without the master key of the tenant.

require_once("lib/pan_php_framework.php");
require_once(dirname(__FILE__) . "/lib/SCMPrismaAccessExport.php");

$args = array();
foreach( array_slice($argv, 1) as $a )
{
    $p = strpos($a, "=");
    $args[ strtolower($p === false ? $a : substr($a, 0, $p)) ] = $p === false ? true : substr($a, $p + 1);
}
$usage = "USAGE: php " . basename(__FILE__) . " dir=<export dir> | file=<list.csv>[,<list.csv>] [details] [fail-on-missing]\n"
    . "  details          one line per entry (default: summary + entries that need attention)\n"
    . "  fail-on-missing  exit code 2 if an entry has no usable value\n";
if( isset($args['help']) || ( !isset($args['dir']) && !isset($args['file']) ) )
{
    print $usage;
    exit( isset($args['help']) ? 0 : 1 );
}

$files = array();
if( isset($args['file']) && $args['file'] !== true )
    $files = array_filter( array_map('trim', explode(",", $args['file'])) );
if( isset($args['dir']) && $args['dir'] !== true )
{
    foreach( array( SCMPrismaAccessExport::AREA_RN, SCMPrismaAccessExport::AREA_SC, SCMPrismaAccessExport::AREA_MU ) as $area )
        foreach( array('psk-list.csv', 'bgp-secret-list.csv', 'secret-list.csv') as $f )
            if( is_readable($args['dir'] . "/" . $area . "/" . $f) )
                $files[] = $args['dir'] . "/" . $area . "/" . $f;
    if( count($files) == 0 )
        derr( "no secret list in " . $args['dir'] . " - export with psk-list", null, FALSE );
}

$missingTotal = 0;
foreach( $files as $file )
{
    $name = basename($file);
    if( $name == 'psk-list.csv' )
    {
        $l = SCMPrismaAccessExport::loadPSKList( $file );
        $l['secret'] = $l['psk'];
    }
    elseif( $name == 'bgp-secret-list.csv' )
        $l = SCMPrismaAccessExport::loadBGPSecretList( $file );
    else
        $l = SCMPrismaAccessExport::loadSecretList( $file );

    $c = array( 'current_verified' => 0, 'new_same_secret' => 0, 'new_different_secret' => 0, 'not_verifiable' => 0, 'missing' => count($l['errors']) );
    $lines = array();
    foreach( $l['secret'] as $key => $v )
    {
        $source = $l['source'][$key];
        $ver = isset($l['verified'][$key]) ? $l['verified'][$key] : null;
        if( $ver === null )
        {
            $c['not_verifiable']++;
            $state = "used " . $source . ", not verifiable (no SHA1)";
        }
        elseif( $source == 'current' )
        {
            $c['current_verified']++;
            $state = $ver ? "OK  current (decrypted)" : "!!  current does not match the exported SHA1";
        }
        elseif( $ver )
        {
            $c['new_same_secret']++;
            $state = "OK  new = secret of the source tenant";
        }
        else
        {
            $c['new_different_secret']++;
            $state = "NEW new secret (differs from the source tenant)";
        }
        if( isset($args['details']) || $ver === false )
            $lines[] = sprintf( "   %-45s %s", $key, $state );
    }
    foreach( $l['errors'] as $key => $msg )
        $lines[] = sprintf( "   %-45s MISSING %s", $key, $msg );
    $missingTotal += $c['missing'];

    PH::print_stdout( " * " . $file );
    PH::print_stdout( "   " . count($l['secret']) . " usable: " . $c['current_verified'] . " decrypted, " . $c['new_same_secret'] . " filled = source secret, "
        . $c['new_different_secret'] . " filled = different secret, " . $c['not_verifiable'] . " not verifiable | " . $c['missing'] . " missing" );
    foreach( $lines as $line )
        PH::print_stdout( $line );
    PH::print_stdout();
}

if( isset($args['fail-on-missing']) && $missingTotal > 0 )
    exit(2);
