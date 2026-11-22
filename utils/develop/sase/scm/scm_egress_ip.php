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

// Prisma Access egress IPs (getPrismaAccessIP/v2) - live from the egress-IP API or from an export / snapshot, as a
// table, CSV, JSON or address list, compared with an earlier state.
// https://docs.paloaltonetworks.com/prisma-access/administration/prisma-access-setup/api-examples-for-retrieving-prisma-access-ip-addresses
//
// php utils/develop/sase/scm/scm_egress_ip.php tsg=<TSG> [servicetype=all] [addrtype=all] [location=all] [env=prod|prod6]
//     [option=option.txt] [format=table|csv|json|list] [out=file] [save=snapshot.json] [compare=snapshot.json|export-dir]
// php utils/develop/sase/scm/scm_egress_ip.php in=<export-dir|92_egress-ip.json|snapshot.json> [format=…] [compare=…]
//
// The API key (header-api-key, Prisma Access > Infrastructure Settings > Egress IP API) comes from .panconfkeystore
// (entry egressip_tsg_id<TSG>, pan-os-php key-manager / config viewer "My API keys", kind egress IP), else it is asked for.

require_once dirname( __FILE__ ) . "/../../../../lib/pan_php_framework.php";
require_once dirname( __FILE__ ) . "/lib/SCMEgressIP.php";

$usage = "USAGE: php " . basename( __FILE__ ) . " tsg=<TSG> [servicetype=" . implode( '|', SCMEgressIP::SERVICE_TYPES ) . "] [addrtype=all|active|…] [location=all|deployed]\n"
    . "         [env=prod|prod6] [option=option.txt] [format=table|csv|json|list] [out=file] [save=snapshot.json] [compare=snapshot.json|export-dir] [debugapi]\n"
    . "       php " . basename( __FILE__ ) . " in=<export-dir|92_egress-ip.json|snapshot.json> [format=…] [compare=…] [out=…]\n"
    . "  option=  the request body of the Palo Alto documentation ({\"serviceType\": …, \"addrType\": …, \"location\": …}); arguments override it\n"
    . "  format=list  one address per line (e.g. an external dynamic list)\n";

$args = array();
foreach( array_slice( $argv, 1 ) as $a )
{
    $p = strpos( $a, '=' );
    $args[strtolower( $p === FALSE ? $a : substr( $a, 0, $p ) )] = $p === FALSE ? TRUE : substr( $a, $p + 1 );
}
// type= (pan-os-php type=scm-egress-ip passes it on)
$known = array( 'type', 'tsg', 'servicetype', 'addrtype', 'location', 'env', 'option', 'format', 'out', 'save', 'compare', 'in', 'debugapi', 'help', 'shadow-json' );
foreach( array_keys( $args ) as $k )
    if( !in_array( $k, $known, TRUE ) )
    {
        fwrite( STDERR, "unknown argument '" . $k . "'\n" . $usage );
        exit( 1 );
    }
if( isset( $args['help'] ) || ( !isset( $args['tsg'] ) && !isset( $args['in'] ) ) )
{
    echo $usage;
    exit( isset( $args['help'] ) ? 0 : 1 );
}
$format = isset( $args['format'] ) && is_string( $args['format'] ) ? $args['format'] : 'table';
if( !in_array( $format, array( 'table', 'csv', 'json', 'list' ), TRUE ) )
{
    fwrite( STDERR, "format: table, csv, json or list\n" );
    exit( 1 );
}

try
{
    if( isset( $args['in'] ) )
    {
        $state = SCMEgressIP::fromFile( (string)$args['in'] );
        $rows = $state['rows'];
        $request = $state['request'];
        $fetched = $state['fetched_at'];
        $tsg = null;
    }
    else
    {
        $tsg = (string)$args['tsg'];
        if( !preg_match( '/^[0-9]{1,20}$/', $tsg ) )
            throw new Exception( "tsg: the TSG id (digits)" );
        $env = isset( $args['env'] ) ? (string)$args['env'] : 'prod';
        if( !in_array( $env, array( 'prod', 'prod6' ), TRUE ) )
            throw new Exception( "env: prod or prod6" );
        $request = SCMEgressIP::request( isset( $args['option'] ) ? (string)$args['option'] : null, $args );
        $connector = new PanSCMAPIConnector( $tsg );
        if( isset( $args['debugapi'] ) )
            $connector->setShowApiCalls( TRUE );
        $key = $connector->getEgressIPApiKey( $tsg, TRUE );
        if( $key === null || $key === '' )
            throw new Exception( "no egress-IP API key for TSG " . $tsg );
        $r = $connector->getPrismaAccessEgressIP( $key, $request['serviceType'], $request['addrType'], $request['location'], $env );
        if( $r['errors'] !== null )
            throw new Exception( "egress-IP API (" . $r['url'] . "): " . json_encode( $r['errors'] ) );
        $rows = SCMEgressIP::rows( $r['json']['result'] ?? array(), $request['serviceType'] );
        $fetched = date( 'c' );
    }

    if( isset( $args['save'] ) && is_string( $args['save'] ) && $args['save'] !== '' )
    {
        file_put_contents( $args['save'], json_encode( array( 'tsg_id' => $tsg, 'request' => $request, 'fetched_at' => $fetched, 'rows' => $rows ),
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n" );
        @chmod( $args['save'], 0600 );
    }

    $text = SCMEgressIP::format( $rows, $format );
    $diff = null;
    if( isset( $args['compare'] ) && is_string( $args['compare'] ) && $args['compare'] !== '' )
    {
        $diff = SCMEgressIP::compare( SCMEgressIP::fromFile( $args['compare'] )['rows'], $rows );
        if( $format === 'json' )
            $text = json_encode( array( 'rows' => $rows, 'compare' => $diff ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n";
        elseif( $format === 'table' )
        {
            $text .= "\ncompare with " . $args['compare'] . ": " . count( $diff['added'] ) . " added, " . count( $diff['removed'] ) . " removed, " . count( $diff['changed'] ) . " changed\n";
            foreach( $diff['added'] as $x )
                $text .= "  + " . $x['service_type'] . "  " . $x['location'] . "  " . $x['address'] . "\n";
            foreach( $diff['removed'] as $x )
                $text .= "  - " . $x['service_type'] . "  " . $x['location'] . "  " . $x['address'] . "\n";
            foreach( $diff['changed'] as $x )
                $text .= "  ~ " . $x['new']['service_type'] . "  " . $x['new']['location'] . "  " . $x['new']['address'] . "  " . $x['old']['address_type'] . " -> " . $x['new']['address_type'] . "\n";
        }
    }

    if( isset( $args['out'] ) && is_string( $args['out'] ) && $args['out'] !== '' )
    {
        file_put_contents( $args['out'], $text );
        echo count( $rows ) . " egress IP(s) written to " . $args['out'] . ( $diff !== null ? " (" . count( $diff['added'] ) . " added, " . count( $diff['removed'] ) . " removed)" : '' ) . "\n";
    }
    else
        echo $text;
}
catch( Exception $e )
{
    fwrite( STDERR, "ERROR: " . $e->getMessage() . "\n" );
    exit( 1 );
}
