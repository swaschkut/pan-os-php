<?php

// <editor-fold desc=" ***** Zone filters *****" defaultstate="collapsed" >

/*
RQuery::$defaultFilters['device']['name']['operators']['eq.nocase'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        return strtolower($context->object->name()) == strtolower($context->value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['device']['name']['operators']['contains'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        return strpos($context->object->name(), $context->value) !== FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
);
*/

RQuery::$defaultFilters['device']['name']['operators']['is.child.of'] = array(
    'Function' => function (DeviceRQueryContext $context) {

        $object = $context->object;
        $value = $context->value;

        $sub = $context->object->owner;
        while( get_class($sub) == "RuleStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
            $sub = $sub->owner;

        if( get_class($sub) !== "PanoramaConf" )
            derr("filter location is.child.of is only working against a panorama configuration");

        if( strtolower($context->value) == 'shared' )
            return TRUE;

        $DG = $sub->findDeviceGroup($context->value);
        if( $DG == null )
        {
            PH::print_stdout( "ERROR: location '$context->value' was not found. Here is a list of available ones:" );
            PH::print_stdout( " - shared" );
            foreach( $sub->getDeviceGroups() as $sub1 )
            {
                PH::print_stdout( " - " . $sub1->name()  );
            }
            PH::print_stdout();
            exit(1);
        }

        $childDeviceGroups = $DG->childDeviceGroups(TRUE);

        if( strtolower($context->value) == strtolower($object->name()) )
            return TRUE;

        foreach( $childDeviceGroups as $childDeviceGroup )
        {
            if( $childDeviceGroup->name() == $object->name() )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches / is child the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  Datacenter-Firewalls)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['device']['templatestack']['operators']['has.member'] = array(
    'Function' => function (DeviceRQueryContext $context) {

        $object = $context->object;

        $class = get_class( $object );
        if( $class !== "TemplateStack" )
            return null;

        $used_templates = $context->object->templates;
        foreach( $used_templates as $template )
        {
            if( $template->name() == $context->value )
                return true;
        }
        return false;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['device']['template']['operators']['has-multi-vsys'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        /** @var Template $object */
        $object = $context->object;

        $class = get_class( $object );
        if( $class !== "Template" && $class !== "TemplateStack" )
            return null;

        $vsyses = $object->deviceConfiguration->getVirtualSystems();
        if( count($vsyses) > 1 )
            return TRUE;

        return false;
    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['device']['template']['operators']['is.unused'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        /** @var Template $object */
        $object = $context->object;

        if( get_class( $object ) !== "Template" )
            return null;

        if( count($object->getReferences()) == 0 )
            return true;

        return false;
    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['device']['template']['operators']['is.unused.recursive'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        /** @var Template $object */
        $object = $context->object;

        if( get_class( $object ) !== "Template" )
            return null;

        if( count($object->getReferences()) > 0 )
        {
            foreach( $object->getReferences() as $ref )
            {
                if( get_class( $ref ) == "TemplateStack" )
                {
                    if( count($ref->getReferences()) > 0 )
                        return false;
                }
            }
        }

        return true;
    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['device']['templatestack']['operators']['is.unused'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        /** @var TemplateStack $object */
        $object = $context->object;

        if( get_class( $object ) !== "TemplateStack" )
            return null;

        if( count($object->getReferences()) == 0 )
        {
            if( $object->name() !== "Service_Conn_Template_Stack"
                && $object->name() !== "Mobile_User_Template_Stack"
                && $object->name() !== "Remote_Network_Template_Stack"
                && $object->name() !== "Explicit_Proxy_Template_Stack"
            )
                return true;
        }


        return false;
    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['device']['manageddevice']['operators']['with-no-dg'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        /** @var ManagedDevice $object */
        $object = $context->object;

        $class = get_class( $object );
        if( $class !== "ManagedDevice" )
            return false;

        $DGs = $object->getDeviceGroup();
        if( empty( $DGs) )
            return TRUE;
        else
        {
            foreach( $DGs as $DG )
            {
                if( $DG === "" )
                    return TRUE;
            }
        }

        return false;
    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['device']['devicegroup']['operators']['is.unused'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        /** @var DeviceGroup $object */
        $object = $context->object;

        if( get_class( $object ) !== "DeviceGroup" )
            return null;

        if( count($object->getReferences()) === 0 )
            return TRUE;

        return false;
    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['device']['devicegroup']['operators']['has.vsys'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        /** @var DeviceGroup $object */
        $object = $context->object;

        $class = get_class( $object );
        if( $class !== "DeviceGroup" )
            return null;

        $DGdevices = $object->getDevicesInGroup();
        foreach( $DGdevices as $key => $device )
        {
            if( isset($device['vsyslist']) )
            {
                if( isset( $device['vsyslist'][$context->value] ) )
                    return TRUE;
                else
                    return FALSE;
            }
            else
            {
                return TRUE;
                #if( $context->value == "vsys1")
                #    return TRUE;
                #else
                #    return FALSE;
            }
        }

        return null;
    },
    'arg' => True,
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['device']['devicegroup']['operators']['has.template-name-reference'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        /** @var DeviceGroup $object */
        $object = $context->object;

        $class = get_class( $object );
        if( $class !== "DeviceGroup" )
            return null;

        $DGdevices = $object->getDevicesInGroup();
        foreach( $DGdevices as $key => $device )
        {
            $managedFirewall = $object->owner->managedFirewallsStore->find($key);
            if( $managedFirewall !== null )
            {
                $template_stack_obj = $object->owner->findTemplateStack($managedFirewall->template_stack);
                if( $template_stack_obj !== null )
                {
                    $templates_array = $template_stack_obj->templates;
                    foreach( $templates_array as $template )
                        if( $template->name() === $context->value)
                            return TRUE;
                }
            }
        }

        return null;
    },
    'arg' => True,
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['device']['devicegroup']['operators']['with-no-serial'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        /** @var DeviceGroup $object */
        $object = $context->object;

        $class = get_class( $object );
        if( $class !== "DeviceGroup" )
            return null;

        $DGdevices = $object->getDevicesInGroup();
        if( count($DGdevices) == 0 )
            return TRUE;
        elseif( count($DGdevices) > 0 )
            return False;

        return null;
    },
    'arg' => False,
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['device']['template']['operators']['manageddevice.all.in.file'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        /** @var Template|TemplateStack $object */
        $object = $context->object;

        $class = get_class( $object );
        if( $class !== "Template" && $class !== "TemplateStack" )
            return null;

        $list = $context->cachedNameList( TRUE );
        $devices = $object->managedDevices();
        if( count( $devices ) == 0 )
            return null;   // no firewall receives the template / template-stack

        foreach( $devices as $serial => $device )
            if( !isset( $list[$serial] ) )
                return FALSE;   // a firewall that receives the template is not listed
        return TRUE;
    },
    'arg' => TRUE,
    'help' => "TRUE when every firewall that receives the template (through any template stack) or the template-stack is listed in the file, one serial per line, e.g. 'filter=(template manageddevice.all.in.file FILENAME)'"
);

RQuery::$defaultFilters['device']['template']['operators']['manageddevice.all.in.list'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        /** @var Template|TemplateStack $object */
        $object = $context->object;

        $class = get_class( $object );
        if( $class !== "Template" && $class !== "TemplateStack" )
            return null;

        $list = $context->cachedNameList( FALSE );
        $devices = $object->managedDevices();
        if( count( $devices ) == 0 )
            return null;   // no firewall receives the template / template-stack

        foreach( $devices as $serial => $device )
            if( !isset( $list[$serial] ) )
                return FALSE;   // a firewall that receives the template is not listed
        return TRUE;
    },
    'arg' => TRUE,
    'help' => "TRUE when every firewall that receives the template (through any template stack) or the template-stack is listed, e.g. 'filter=(template manageddevice.all.in.list serial1,serial2)'"
);

RQuery::$defaultFilters['device']['template']['operators']['manageddevice.all.with-no-dg'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        /** @var Template|TemplateStack $owner */
        $owner = $context->object;
        $class = get_class( $owner );
        if( $class !== "Template" && $class !== "TemplateStack" )
            return null;
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
    'help' => "TRUE when the template (through any template stack) or the template-stack reaches at least one firewall and none of these firewalls is assigned to a device group, e.g. 'filter=(template manageddevice.all.with-no-dg)'"
);

RQuery::$defaultFilters['device']['template']['operators']['manageddevice.with-no-dg'] = array(
    'Function' => function (DeviceRQueryContext $context) {
        /** @var Template|TemplateStack $owner */
        $owner = $context->object;
        $class = get_class( $owner );
        if( $class !== "Template" && $class !== "TemplateStack" )
            return null;
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
    'help' => "TRUE when at least one firewall that receives the template (through any template stack) or the template-stack is not assigned to a device group, e.g. 'filter=(template manageddevice.with-no-dg)'"
);

// </editor-fold>