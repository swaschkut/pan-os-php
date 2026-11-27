<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
 * Copyright (c) 2019, Palo Alto Networks Inc.
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
 */

/**
 * The types with actions ( type=<name> actions=… ): UTIL::$typeCallContext is the one table type => class of its
 * actions. supportedActions(), extracting_actions() and loadplugin() read it (before: three if-chains over the same
 * types, the one of loadplugin with 20 of the 36 types).
 *
 *   php tests/test_type_table.php
 */
$repo = dirname( __DIR__ );
require_once $repo . '/lib/pan_php_framework.php';
require_once $repo . '/utils/lib/UTIL.php';
$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};
$cli = function( $args ) use ( $repo ) {
    $out = array();
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' ' . $args . ' 2>&1', $out, $rc );
    return array( $rc, implode( "\n", $out ) );
};

// ---- the table
$noClass = array(); $noActions = array(); $noFile = array();
foreach( UTIL::$typeCallContext as $type => $class )
{
    if( !class_exists( $class ) )
        $noClass[] = $type;
    elseif( !is_array( $class::$supportedActions ) || count( $class::$supportedActions ) == 0 )
        $noActions[] = $type;
    if( !is_file( $repo . '/utils/common/' . $class . '.php' ) )
        $noFile[] = $type;
}
$eq( array( $noClass, $noActions, $noFile ), array( array(), array(), array() ), 'every type of the table: its class exists (utils/common/<class>.php) and has actions' );
$eq( array( UTIL::callContextClass( 'address' ), UTIL::callContextClass( 'ssl-tls-service-profile' ), UTIL::callContextClass( 'stats' ), UTIL::callContextClass( null ) ),
    array( 'AddressCallContext', 'SSL_TLSServiceProfileCallContext', null, null ), 'callContextClass: the class of a type, null for a type without actions' );

// a class with actions that is in no line of the table would be a type nobody can call
$classes = array();
foreach( glob( $repo . '/utils/common/*CallContext.php' ) as $file )
    if( basename( $file, '.php' ) !== 'CallContext' )
        $classes[] = basename( $file, '.php' );
$eq( array_values( array_diff( $classes, array_values( UTIL::$typeCallContext ) ) ), array(), 'every *CallContext class of utils/common is in the table' );

// the types of the table that pan-os-php offers as type= ( vsys is used by other types only )
$eq( array_values( array_diff( array_keys( UTIL::$typeCallContext ), PH::$supportedUTILTypes ) ), array( 'vsys' ), 'the types of the table are types of pan-os-php (all but vsys)' );

// ---- the three readers, through the CLI
$bad = array();
foreach( array_keys( UTIL::$typeCallContext ) as $type )
{
    if( $type === 'vsys' )
        continue;
    list( $rc, $out ) = $cli( 'type=' . escapeshellarg( $type ) . ' listactions' );
    if( $rc !== 0 || strpos( $out, 'Listing of supported actions' ) === FALSE || strpos( $out, '* display' ) === FALSE )
        $bad[] = $type;
}
$eq( $bad, array(), 'listactions of every type lists its actions (display is one of them)' );

$in = escapeshellarg( $repo . '/tests/input/many-objects-panorama.xml' );
list( $rc, $out ) = $cli( 'type=address in=' . $in . ' location=any actions=display' );
$eq( array( $rc, strpos( $out, '**ERROR**' ) ), array( 0, FALSE ), 'an action runs (type=address actions=display)' );
list( $rc, $out ) = $cli( 'type=address in=' . $in . ' location=any actions=no-such-action' );
$eq( array( $rc !== 0, strpos( $out, 'unsupported Action: "no-such-action"' ) !== FALSE ), array( TRUE, TRUE ), 'an unknown action is refused as before' );

// loadplugin: the actions of a plugin are prepared for every type - 'interface' was not in the old chain, so an
// action of a plugin (key as written, here with capitals) was never found
$plugin = tempnam( sys_get_temp_dir(), 'plugin' ) . '.php';
file_put_contents( $plugin, "<?php\nInterfaceCallContext::\$supportedActions['Plugin-Hello'] = array( 'name' => 'Plugin-Hello',\n"
    . "    'MainFunction' => function( InterfaceCallContext \$context ) { PH::print_stdout( 'hello from the plugin: ' . \$context->object->name() ); } );\n" );
list( $rc, $out ) = $cli( 'type=interface in=' . $in . ' location=any actions=plugin-hello loadplugin=' . escapeshellarg( $plugin ) );
$eq( array( $rc, strpos( $out, 'unsupported Action' ) ), array( 0, FALSE ), 'loadplugin: an action of a plugin for type=interface is found (not in the old chain of 20 types)' );
@unlink( $plugin );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
