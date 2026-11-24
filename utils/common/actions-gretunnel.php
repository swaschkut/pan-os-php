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
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

GREtunnelCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( GREtunnelCallContext $context )
    {
        $object = $context->object;


        $text = " - "."Tunnel: " . str_pad($object->name(), 25);

        foreach( $object->tunnelInterface->interfaces() as $interface )
            $text .= " - tunnelinterface: " .$interface->name() ;
        foreach( $object->localInterface->interfaces() as $interface )
            $text .= " - localinterface: " .$interface->name() ;

        $text .= " -disabled: " . $object->disabled;
        PH::print_stdout($text);


        if( PH::$shadow_displayxmlnode )
        {
            PH::print_stdout(  "" );
            DH::DEBUGprintDOMDocument($context->object->xmlroot);
        }

        PH::print_stdout();
    },

);

// ---- changes (offline: an XML file / the config viewer) - one edit… method of the class each (NetworkObjectEdit)

GREtunnelCallContext::$supportedActions['local-interface-set'] = array(
    'name' => 'local-interface-Set',
    'MainFunction' => function ( GREtunnelCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editLocalInterface( $a['interface'] );
            return "local interface '" . $a['interface'] . "'";
        } );
    },
    'args' => array( 'interface' => array( 'type' => 'string', 'default' => '*nodefault*' ) ),
    'help' => 'local interface (it must exist)',
);

GREtunnelCallContext::$supportedActions['local-ip-set'] = array(
    'name' => 'local-ip-Set',
    'MainFunction' => function ( GREtunnelCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editLocalIp( $a['ip'] );
            return $a['ip'] === '' ? "local IP removed" : "local IP '" . $a['ip'] . "'";
        } );
    },
    'args' => array( 'ip' => array( 'type' => 'string', 'default' => '', 'help' => 'IPv4 address with mask (// is a /) or address object; empty: removed' ) ),
    'help' => 'local IP',
);

GREtunnelCallContext::$supportedActions['peer-address-set'] = array(
    'name' => 'peer-address-Set',
    'MainFunction' => function ( GREtunnelCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editPeerAddress( $a['ip'] );
            return "peer address '" . $a['ip'] . "'";
        } );
    },
    'args' => array( 'ip' => array( 'type' => 'string', 'default' => '*nodefault*' ) ),
    'help' => 'peer address',
);

GREtunnelCallContext::$supportedActions['tunnel-interface-set'] = array(
    'name' => 'tunnel-interface-Set',
    'MainFunction' => function ( GREtunnelCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editTunnelInterface( $a['interface'] );
            return "tunnel interface '" . $a['interface'] . "'";
        } );
    },
    'args' => array( 'interface' => array( 'type' => 'string', 'default' => '*nodefault*' ) ),
    'help' => 'tunnel interface (it must exist)',
);

GREtunnelCallContext::$supportedActions['ttl-set'] = array(
    'name' => 'ttl-Set',
    'MainFunction' => function ( GREtunnelCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editTtl( $a['ttl'] );
            return "TTL " . $a['ttl'];
        } );
    },
    'args' => array( 'ttl' => array( 'type' => 'string', 'default' => '*nodefault*', 'help' => '1-255' ) ),
    'help' => 'TTL',
);

GREtunnelCallContext::$supportedActions['copy-tos-set'] = array(
    'name' => 'copy-tos-Set',
    'MainFunction' => function ( GREtunnelCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editFlag( 'copy-tos', $a['enable'] );
            return "copy TOS header " . ( $a['enable'] ? 'yes' : 'no' );
        } );
    },
    'args' => array( 'enable' => array( 'type' => 'bool', 'default' => '*nodefault*' ) ),
    'help' => 'copy TOS header',
);

GREtunnelCallContext::$supportedActions['disabled-set'] = array(
    'name' => 'disabled-Set',
    'MainFunction' => function ( GREtunnelCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editFlag( 'disabled', $a['disabled'] );
            return "disabled " . ( $a['disabled'] ? 'yes' : 'no' );
        } );
    },
    'args' => array( 'disabled' => array( 'type' => 'bool', 'default' => '*nodefault*' ) ),
    'help' => 'disable the tunnel',
);

GREtunnelCallContext::$supportedActions['keep-alive-set'] = array(
    'name' => 'keep-alive-Set',
    'MainFunction' => function ( GREtunnelCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editKeepAlive( $a['enable'], $a['interval'], $a['retry'], $a['hold-timer'] );
            return "keep alive " . ( $a['enable'] ? 'yes' : 'no' );
        } );
    },
    'args' => array( 'enable' => array( 'type' => 'bool', 'default' => '*nodefault*' ), 'interval' => array( 'type' => 'string', 'default' => '', 'help' => '1-50 s; empty: kept' ), 'retry' => array( 'type' => 'string', 'default' => '', 'help' => '1-255; empty: kept' ), 'hold-timer' => array( 'type' => 'string', 'default' => '', 'help' => '1-64; empty: kept' ) ),
    'help' => 'keep alive',
);
