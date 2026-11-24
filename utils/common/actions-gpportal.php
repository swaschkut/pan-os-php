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

GPPortalCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( GPPortalCallContext $context )
    {
        $object = $context->object;
        PH::print_stdout("     * ".get_class($object)." '{$object->name()}'" );


        PH::print_stdout("       - localAddress:" );
        PH::print_stdout("          - Interface: '{$object->getLocalAddress_interface()}'" );
        PH::print_stdout("          - IPFamily: '{$object->getLocalAddress_IPfamiliy()}'" );
        PH::print_stdout("          - IPv4: '{$object->getLocalAddress_ipv4()}'" );
        PH::print_stdout("          - IPv6: '{$object->getLocalAddress_ipv6()}'" );


        if( PH::$shadow_displayxmlnode )
        {
            PH::print_stdout(  "" );
            DH::DEBUGprintDOMDocument($context->object->xmlroot);
        }

        PH::print_stdout();
    },

);

// ---- changes (offline: an XML file / the config viewer) - one edit… method of the class each (NetworkObjectEdit)

GPPortalCallContext::$supportedActions['local-interface-set'] = array(
    'name' => 'local-interface-Set',
    'MainFunction' => function ( GPPortalCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editLocalInterface( $a['interface'] );
            return "local interface '" . $a['interface'] . "'";
        } );
    },
    'args' => array( 'interface' => array( 'type' => 'string', 'default' => '*nodefault*' ) ),
    'help' => 'local interface (an interface of the vsys)',
);

GPPortalCallContext::$supportedActions['local-ip-set'] = array(
    'name' => 'local-ip-Set',
    'MainFunction' => function ( GPPortalCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editLocalIp( $a['ip'] );
            return $a['ip'] === '' ? "local IP removed" : "local IP '" . $a['ip'] . "'";
        } );
    },
    'args' => array( 'ip' => array( 'type' => 'string', 'default' => '', 'help' => 'IPv4 address with mask (// is a /) or address object; empty: removed' ) ),
    'help' => 'local IPv4 address',
);

GPPortalCallContext::$supportedActions['ssl-tls-profile-set'] = array(
    'name' => 'ssl-tls-profile-Set',
    'MainFunction' => function ( GPPortalCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editSslTlsProfile( $a['profile'] );
            return $a['profile'] === '' ? "SSL/TLS service profile removed" : "SSL/TLS service profile '" . $a['profile'] . "'";
        } );
    },
    'args' => array( 'profile' => array( 'type' => 'string', 'default' => '', 'help' => 'empty: removed' ) ),
    'help' => 'SSL/TLS service profile of the portal',
);
