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

VirtualWireCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( VirtualWireCallContext $context )
    {
        $object = $context->object;
        PH::print_stdout("     * ".get_class($object)." '{$object->name()}'" );

        PH::$JSON_TMP['sub']['object'][$object->name()]['name'] = $object->name();
        PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);
        PH::$JSON_TMP['sub']['object'][$object->name()]['interface1'] = $object->attachedInterface1;
        PH::$JSON_TMP['sub']['object'][$object->name()]['interface2'] = $object->attachedInterface2;

        $text = "       - ";
        $text .= "interface1: ".$object->attachedInterface1." - ";
        $text .= "interface2: ".$object->attachedInterface2;
        PH::print_stdout( $text );

        PH::print_stdout();
    },

);

// ---- changes (offline: an XML file / the config viewer) - one edit… method of the class each (NetworkObjectEdit)

VirtualWireCallContext::$supportedActions['interface-set'] = array(
    'name' => 'interface-Set',
    'MainFunction' => function ( VirtualWireCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editInterface( $a['number'], $a['interface'] );
            return "interface" . $a['number'] . " '" . $a['interface'] . "'";
        } );
    },
    'args' => array( 'number' => array( 'type' => 'string', 'default' => '*nodefault*', 'choices' => array( '1', '2' ) ), 'interface' => array( 'type' => 'string', 'default' => '*nodefault*' ) ),
    'help' => 'interface 1 / 2 (of type virtual-wire)',
);

VirtualWireCallContext::$supportedActions['tag-allowed-set'] = array(
    'name' => 'tag-allowed-Set',
    'MainFunction' => function ( VirtualWireCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editTagAllowed( $a['tags'] );
            return $a['tags'] === '' ? "tag allowed removed" : "tag allowed " . $a['tags'];
        } );
    },
    'args' => array( 'tags' => array( 'type' => 'string', 'default' => '', 'help' => 'tags / ranges, separated by | (e.g. 0|10-20); empty: removed' ) ),
    'help' => 'allowed VLAN tags',
);

VirtualWireCallContext::$supportedActions['multicast-firewalling-set'] = array(
    'name' => 'multicast-firewalling-Set',
    'MainFunction' => function ( VirtualWireCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editFlag( 'multicast-firewalling', $a['enable'] );
            return "multicast firewalling " . ( $a['enable'] ? 'yes' : 'no' );
        } );
    },
    'args' => array( 'enable' => array( 'type' => 'bool', 'default' => '*nodefault*' ) ),
    'help' => 'multicast firewalling',
);

VirtualWireCallContext::$supportedActions['link-state-pass-through-set'] = array(
    'name' => 'link-state-pass-through-Set',
    'MainFunction' => function ( VirtualWireCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editFlag( 'link-state-pass-through', $a['enable'] );
            return "link state pass through " . ( $a['enable'] ? 'yes' : 'no' );
        } );
    },
    'args' => array( 'enable' => array( 'type' => 'bool', 'default' => '*nodefault*' ) ),
    'help' => 'link state pass through',
);
