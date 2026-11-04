<?php

// <editor-fold desc=" ***** Zone filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['zone-protection-profile']['object']['operators']['is.visibility'] = array(
    'Function' => function (ZoneProtectionProfileRQueryContext $context) {

        if( $context->object->is_visibility())
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE
);



RQuery::$defaultFilters['zone-protection-profile']['template.owner']['operators']['is.unused'] = array(
    'Function' => function (ZoneProtectionProfileRQueryContext $context) {
        $object = $context->object;

        $template = $object->owner->owner->owner;

        if( count($template->getReferences()) == 0 )
            return true;
        else
            return false;

        return null;
    },
    'arg' => FALSE
);

RQuery::$defaultFilters['zone-protection-profile']['template.owner']['operators']['is.unused.recursive'] = array(
    'Function' => function (ZoneProtectionProfileRQueryContext $context) {
        $owner = $context->object->owner->owner->owner;   // the Template, or the TemplateStack for a zone the stack defines itself
        if( !is_object( $owner ) || !method_exists( $owner, 'managedDevices' ) )
            return null;
        $devices = $owner->managedDevices();

        // unused when no template stack that holds the template carries a firewall
        return count( $devices ) == 0;
    },
    'arg' => FALSE,
    'help' => "TRUE when no template stack holding the owning template (or the owning template stack itself) carries a firewall"
);

RQuery::$defaultFilters['zone-protection-profile']['manageddevice']['operators']['is.in.file'] = array(
    'Function' => function (ZoneProtectionProfileRQueryContext $context) {
        $list = $context->cachedNameList( TRUE );
        $owner = $context->object->owner->owner->owner;   // the Template, or the TemplateStack for a zone the stack defines itself
        if( !is_object( $owner ) || !method_exists( $owner, 'managedDevices' ) )
            return null;
        $devices = $owner->managedDevices();
        if( count( $devices ) == 0 )
            return null;   // no firewall receives the template

        foreach( $devices as $serial => $device )
            if( isset( $list[$serial] ) )
                return TRUE;   // at least one firewall that receives the template is listed
        return FALSE;
    },
    'arg' => TRUE,
    'help' => "TRUE when at least one firewall that receives the owning template (through any template stack) is listed, e.g. 'filter=(manageddevice is.in.file FILENAME)'"
);

RQuery::$defaultFilters['zone-protection-profile']['manageddevice']['operators']['is.in.list'] = array(
    'Function' => function (ZoneProtectionProfileRQueryContext $context) {
        $list = $context->cachedNameList( FALSE );
        $owner = $context->object->owner->owner->owner;   // the Template, or the TemplateStack for a zone the stack defines itself
        if( !is_object( $owner ) || !method_exists( $owner, 'managedDevices' ) )
            return null;
        $devices = $owner->managedDevices();
        if( count( $devices ) == 0 )
            return null;   // no firewall receives the template

        foreach( $devices as $serial => $device )
            if( isset( $list[$serial] ) )
                return TRUE;   // at least one firewall that receives the template is listed
        return FALSE;
    },
    'arg' => TRUE,
    'help' => "TRUE when at least one firewall that receives the owning template (through any template stack) is listed, e.g. 'filter=(manageddevice is.in.list serial1,serial2)'"
);

RQuery::$defaultFilters['zone-protection-profile']['manageddevice.all']['operators']['is.in.file'] = array(
    'Function' => function (ZoneProtectionProfileRQueryContext $context) {
        $list = $context->cachedNameList( TRUE );
        $owner = $context->object->owner->owner->owner;   // the Template, or the TemplateStack for a zone the stack defines itself
        if( !is_object( $owner ) || !method_exists( $owner, 'managedDevices' ) )
            return null;
        $devices = $owner->managedDevices();
        if( count( $devices ) == 0 )
            return null;   // no firewall receives the template

        foreach( $devices as $serial => $device )
            if( !isset( $list[$serial] ) )
                return FALSE;  // a firewall that receives the template is not listed
        return TRUE;
    },
    'arg' => TRUE,
    'help' => "TRUE when every firewall that receives the owning template (through any template stack) is listed, e.g. 'filter=(manageddevice.all is.in.file FILENAME)'"
);

RQuery::$defaultFilters['zone-protection-profile']['manageddevice.all']['operators']['is.in.list'] = array(
    'Function' => function (ZoneProtectionProfileRQueryContext $context) {
        $list = $context->cachedNameList( FALSE );
        $owner = $context->object->owner->owner->owner;   // the Template, or the TemplateStack for a zone the stack defines itself
        if( !is_object( $owner ) || !method_exists( $owner, 'managedDevices' ) )
            return null;
        $devices = $owner->managedDevices();
        if( count( $devices ) == 0 )
            return null;   // no firewall receives the template

        foreach( $devices as $serial => $device )
            if( !isset( $list[$serial] ) )
                return FALSE;  // a firewall that receives the template is not listed
        return TRUE;
    },
    'arg' => TRUE,
    'help' => "TRUE when every firewall that receives the owning template (through any template stack) is listed, e.g. 'filter=(manageddevice.all is.in.list serial1,serial2)'"
);

RQuery::$defaultFilters['zone-protection-profile']['manageddevice.all']['operators']['with-no-dg'] = array(
    'Function' => function (ZoneProtectionProfileRQueryContext $context) {
        $owner = $context->object->owner->owner->owner;   // the Template, or the TemplateStack for a profile the stack defines itself
        if( !is_object( $owner ) || !method_exists( $owner, 'managedDevices' ) )
            return null;
        $devices = $owner->managedDevices();
        if( count( $devices ) == 0 )
            return null;   // no firewall receives the template / template-stack

        foreach( $devices as $serial => $device )
            if( !$device->hasNoDeviceGroup() )
                return FALSE;   // a firewall that receives the template is in a device group
        return TRUE;
    },
    'arg' => FALSE,
    'help' => "TRUE when the owning template (through any template stack) reaches at least one firewall and none of these firewalls is assigned to a device group, e.g. 'filter=(manageddevice.all with-no-dg)'"
);

RQuery::$defaultFilters['zone-protection-profile']['manageddevice']['operators']['with-no-dg'] = array(
    'Function' => function (ZoneProtectionProfileRQueryContext $context) {
        $owner = $context->object->owner->owner->owner;   // the Template, or the TemplateStack for a profile the stack defines itself
        if( !is_object( $owner ) || !method_exists( $owner, 'managedDevices' ) )
            return null;
        $devices = $owner->managedDevices();
        if( count( $devices ) == 0 )
            return null;   // no firewall receives the template / template-stack

        foreach( $devices as $serial => $device )
            if( $device->hasNoDeviceGroup() )
                return TRUE;   // a firewall that receives the template is in no device group
        return FALSE;
    },
    'arg' => FALSE,
    'help' => "TRUE when at least one firewall that receives the owning template (through any template stack) is not assigned to a device group, e.g. 'filter=(manageddevice with-no-dg)'"
);

// </editor-fold>