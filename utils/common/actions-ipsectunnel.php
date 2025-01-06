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

IPsectunnelCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( IPsectunnelCallContext $context )
    {
        $object = $context->object;


        $text = $context->padding." - "."Tunnel: " . str_pad($object->name(), 25) . " - IKE Gateway: " . $object->gateway;
        $text .= " - interface: " . $object->interface . " - proposal: " . $object->proposal;
        $text .= " -disabled: " . $object->disabled;
        PH::print_stdout($text);

        foreach( $object->proxyIdList() as $proxyId )
        {
            $text = $context->padding."   - Name: " . $proxyId['name'] . " - ";
            $text .= "local: " . $proxyId['local'] . " - ";
            $text .= "remote: " . $proxyId['remote'] . " - ";
            $text .= "protocol: " . $proxyId['protocol']['type'] . " - ";
            $text .= "local-port: " . $proxyId['protocol']['localport'] . " - ";
            $text .= "remote-port: " . $proxyId['protocol']['remoteport'] . " - ";
            $text .= "type: " . $proxyId['type'];
            PH::print_stdout($text);
        }


        if( PH::$shadow_displayxmlnode )
        {
            PH::print_stdout(  "" );
            DH::DEBUGprintDOMDocument($context->object->xmlroot);
        }

        PH::print_stdout();
    },

);