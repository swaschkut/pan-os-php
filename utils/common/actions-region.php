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


// type=region: the regions of a location (custom, in the configuration) and the predefined regions of PAN-OS (country
// codes of predefined.xml, location=predefined, read only). A region is used like an address (rules, address groups).

RegionCallContext::$supportedActions['display'] = array(
    'name' => 'display',
    'MainFunction' => function (RegionCallContext $context) {
        $object = $context->object;
        $key = PH::jsonObjectKey( $object );

        $kind = $object->isPredefined() ? 'predefined' : 'custom';
        $txt = "     * Region '" . $object->name() . "'  (" . $kind . ")";
        if( $object->description() !== '' )
            $txt .= "  '" . $object->description() . "'";
        PH::print_stdout( $txt );

        PH::$JSON_TMP['sub']['object'][$key]['name'] = $object->name();
        PH::$JSON_TMP['sub']['object'][$key]['type'] = get_class( $object );
        PH::$JSON_TMP['sub']['object'][$key]['region-type'] = $kind;
        PH::$JSON_TMP['sub']['object'][$key]['description'] = $object->description();

        if( !$object->isPredefined() )
        {
            if( $object->latitude() !== null || $object->longitude() !== null )
            {
                PH::print_stdout( "       - geo-location: latitude " . $object->latitude() . ", longitude " . $object->longitude() );
                PH::$JSON_TMP['sub']['object'][$key]['latitude'] = $object->latitude();
                PH::$JSON_TMP['sub']['object'][$key]['longitude'] = $object->longitude();
            }
            foreach( $object->members() as $member )
            {
                PH::print_stdout( "       - '" . $member . "'" );
                PH::$JSON_TMP['sub']['object'][$key]['address'][] = $member;
            }
        }
        else
            PH::print_stdout( "       - addresses: only known on the firewall (country database)" );

        PH::$JSON_TMP['sub']['object'][$key]['refcount'] = $object->countReferences();
    },
);

RegionCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (RegionCallContext $context) {
        $context->object->display_references(7);
    },
);

RegionCallContext::$supportedActions['delete'] = array(
    'name' => 'delete',
    'MainFunction' => function (RegionCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            PH::ACTIONstatus( $context, "SKIPPED", "this region is used by other objects and cannot be deleted (remove it from the rules / groups first)" );
            return;
        }
        if( method_exists( $object, 'isUsedViaSameNameOverride' ) && $object->isUsedViaSameNameOverride() )
        {
            PH::ACTIONstatus( $context, "SKIPPED", "this region has no direct reference, but through a same-name object in another device-group level firewalls use it" );
            return;
        }
        if( $context->isAPI )
            $object->owner->API_remove( $object );
        else
            $object->owner->remove( $object );
    },
);

RegionCallContext::$supportedActions['name-rename'] = array(
    'name' => 'name-rename',
    'MainFunction' => function (RegionCallContext $context) {
        $context->runEdit( function( Region $o, $a ) {
            $old = $o->name();
            $n = $o->editRename( (string)$a['newname'] );
            return "renamed '" . $old . "' -> '" . $o->name() . "' (users updated: " . $n . ")";
        } );
    },
    'args' => array( 'newname' => array( 'type' => 'string', 'default' => '*nodefault*' ) ),
    'help' => "renames the region and every rule / address group that uses it; not to a predefined region (country code) or an IP value"
);

RegionCallContext::$supportedActions['address-add'] = array(
    'name' => 'address-add',
    'MainFunction' => function (RegionCallContext $context) {
        $context->runEdit( function( Region $o, $a ) {
            $value = PH::textAliases( (string)$a['address'] );
            $o->editAddressAdd( $value );
            return "address '" . trim( $value ) . "' added";
        } );
    },
    'args' => array( 'address' => array( 'type' => 'string', 'default' => '*nodefault*', 'help' => 'ip-netmask or ip-range, IPv4 or IPv6' ) ),
    'help' => "adds an address to the region. '/' and ':' as aliases. Example: 'actions=address-add:192.0.2.0\$\$forwardslash\$\$24', " .
        "'actions=address-add:198.51.100.1-198.51.100.20'"
);

RegionCallContext::$supportedActions['address-remove'] = array(
    'name' => 'address-remove',
    'MainFunction' => function (RegionCallContext $context) {
        $context->runEdit( function( Region $o, $a ) {
            $value = PH::textAliases( (string)$a['address'] );
            $o->editAddressRemove( $value );
            return "address '" . trim( $value ) . "' removed";
        } );
    },
    'args' => array( 'address' => array( 'type' => 'string', 'default' => '*nodefault*' ) ),
    'help' => "removes an address of the region"
);

RegionCallContext::$supportedActions['geo-location-set'] = array(
    'name' => 'geo-location-set',
    'MainFunction' => function (RegionCallContext $context) {
        $context->runEdit( function( Region $o, $a ) {
            $o->editGeoLocationSet( (string)$a['latitude'], (string)$a['longitude'] );
            return "geo-location latitude " . $o->latitude() . ", longitude " . $o->longitude();
        } );
    },
    'args' => array(
        'latitude' => array( 'type' => 'string', 'default' => '*nodefault*', 'help' => '-90 .. 90' ),
        'longitude' => array( 'type' => 'string', 'default' => '*nodefault*', 'help' => '-180 .. 180' ),
    ),
    'help' => "the place of the region on the map (ACC / reports). Example: 'actions=geo-location-set:48.137,11.575'"
);

RegionCallContext::$supportedActions['geo-location-remove'] = array(
    'name' => 'geo-location-remove',
    'MainFunction' => function (RegionCallContext $context) {
        $context->runEdit( function( Region $o, $a ) {
            $o->editGeoLocationRemove();
            return "geo-location removed";
        } );
    },
    'help' => "removes the geo-location of the region"
);
