<?php

// <editor-fold desc=" ***** SecProfGroup filters *****" defaultstate="collapsed" >
RQuery::$defaultFilters['securityprofilegroup']['object']['operators']['is.best-practice'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        return $context->object->is_best_practice();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofilegroup']['object']['operators']['is.visibility'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        return $context->object->is_visibility();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofilegroup']['object']['operators']['is.adoption'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        return $context->object->is_adoption();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofilegroup']['location']['operators']['is.child.of'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprof_location = $context->object->getLocationString();

        $sub = $context->object->owner;
        while( get_class($sub) == "securityprofilegroupStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
            $sub = $sub->owner;

        if( get_class($sub) == "PANConf" )
            derr("filter location is.child.of is not working against a firewall configuration");

        if( strtolower($context->value) == 'shared' )
            return TRUE;

        $DG = $sub->findDeviceGroup($context->value);
        if( $DG == null )
        {
            PH::print_stdout( "ERROR: location '$context->value' was not found. Here is a list of available ones:" );
            PH::print_stdout( " - shared" );
            foreach( $sub->getDeviceGroups() as $sub1 )
            {
                PH::print_stdout( " - " . $sub1->name() . "" );
            }
            PH::print_stdout( "\n" );
            exit(1);
        }

        $childDeviceGroups = $DG->childDeviceGroups(TRUE);

        if( strtolower($context->value) == strtolower($secprof_location) )
            return TRUE;

        foreach( $childDeviceGroups as $childDeviceGroup )
        {
            if( $childDeviceGroup->name() == $secprof_location )
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
RQuery::$defaultFilters['securityprofilegroup']['location']['operators']['is.parent.of'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprof_location = $context->object->getLocationString();

        $sub = $context->object->owner;
        while( get_class($sub) == "securityprofilegroupStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
            $sub = $sub->owner;

        if( get_class($sub) == "PANConf" )
        {
            PH::print_stdout( "ERROR: filter location is.child.of is not working against a firewall configuration");
            return FALSE;
        }

        if( strtolower($context->value) == 'shared' )
            return TRUE;

        $DG = $sub->findDeviceGroup($context->value);
        if( $DG == null )
        {
            PH::print_stdout( "ERROR: location '$context->value' was not found. Here is a list of available ones:" );
            PH::print_stdout( " - shared" );
            foreach( $sub->getDeviceGroups() as $sub1 )
            {
                PH::print_stdout( " - " . $sub1->name() . "" );
            }
            PH::print_stdout( "\n" );
            exit(1);
        }

        $parentDeviceGroups = $DG->parentDeviceGroups();

        if( strtolower($context->value) == strtolower($secprof_location) )
            return TRUE;

        if( $secprof_location == 'shared' )
            return TRUE;

        foreach( $parentDeviceGroups as $childDeviceGroup )
        {
            if( $childDeviceGroup->name() == $secprof_location )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches / is parent the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  Datacenter-Firewalls)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofilegroup']['refobject']['operators']['rule.is.enabled'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $object = $context->object;

        $reference_array = $object->getReferences();

        foreach( $reference_array as $refobject )
        {
            if( get_class( $refobject ) == "SecurityRule" )
            {
                /** @var SecurityRule $refobject */
                if( $refobject->isEnabled() )
                    return TRUE;
            }
        }

        return FALSE;
    },
    'arg' => FALSE,
    'help' => 'returns TRUE if refobject is SecurityRule and disabled',
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);

#private $secprof_array = array('virus', 'spyware', 'vulnerability', 'file-blocking', 'wildfire-analysis', 'url-filtering');

RQuery::$defaultFilters['securityprofilegroup']['secprof']['operators']['av-profile.is'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;
        
        $profiles = $secprofgroup->securityProfiles();
        if( !isset($profiles['virus']) )
            return FALSE;

        return $profiles['virus'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% av-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofilegroup']['secprof']['operators']['as-profile.is'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;
        

        $profiles = $secprofgroup->securityProfiles();
        if( !isset($profiles['spyware']) )
            return FALSE;

        return $profiles['spyware'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% as-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofilegroup']['secprof']['operators']['url-profile.is'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;
        

        $profiles = $secprofgroup->securityProfiles();
        if( !isset($profiles['url-filtering']) )
            return FALSE;

        return $profiles['url-filtering'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% url-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofilegroup']['secprof']['operators']['wf-profile.is'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;
        

        $profiles = $secprofgroup->securityProfiles();
        if( !isset($profiles['wildfire-analysis']) )
            return FALSE;

        return $profiles['wildfire-analysis'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% wf-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofilegroup']['secprof']['operators']['vuln-profile.is'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;
        

        $profiles = $secprofgroup->securityProfiles();
        if( !isset($profiles['vulnerability']) )
            return FALSE;

        return $profiles['vulnerability'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% vuln-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofilegroup']['secprof']['operators']['file-profile.is'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;
        

        $profiles = $secprofgroup->securityProfiles();
        if( !isset($profiles['file-blocking']) )
            return FALSE;

        return $profiles['file-blocking'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% vuln-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['securityprofilegroup']['secprof']['operators']['data-profile.is'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;
        

        $profiles = $secprofgroup->securityProfiles();
        if( !isset($profiles['data-filtering']) )
            return FALSE;

        return $profiles['data-filtering'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% vuln-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofilegroup']['secprof']['operators']['is'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;

        $profiles = $secprofgroup->securityProfiles();
        foreach( $secprofgroup->owner->secprof_array as $secproftype )
        {
            if( $profiles[$secproftype] == $context->value )
                return TRUE;
        }
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% av-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['securityprofilegroup']['secprof']['operators']['av-profile.is.set'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;
        

        $profiles = $secprofgroup->securityProfiles();

        return isset($profiles['virus']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofilegroup']['secprof']['operators']['as-profile.is.set'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;
        

        $profiles = $secprofgroup->securityProfiles();

        return isset($profiles['spyware']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofilegroup']['secprof']['operators']['url-profile.is.set'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;
        

        $profiles = $secprofgroup->securityProfiles();

        return isset($profiles['url-filtering']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofilegroup']['secprof']['operators']['wf-profile.is.set'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;
        

        $profiles = $secprofgroup->securityProfiles();

        return isset($profiles['wildfire-analysis']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofilegroup']['secprof']['operators']['avwf-profile.is.set'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;


        $profiles = $secprofgroup->securityProfiles();

        return isset($profiles['virus-and-wildfire-analysis']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofilegroup']['secprof']['operators']['dnssec-profile.is.set'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;


        $profiles = $secprofgroup->securityProfiles();

        return isset($profiles['dns-security']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofilegroup']['secprof']['operators']['vuln-profile.is.set'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;
        

        $profiles = $secprofgroup->securityProfiles();

        return isset($profiles['vulnerability']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofilegroup']['secprof']['operators']['file-profile.is.set'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;
        

        $profiles = $secprofgroup->securityProfiles();

        return isset($profiles['file-blocking']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['securityprofilegroup']['secprof']['operators']['data-profile.is.set'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;
        

        $profiles = $secprofgroup->securityProfiles();

        return isset($profiles['data-filtering']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['securityprofilegroup']['secprof']['operators']['nothing.is.set'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;


        $profiles = $secprofgroup->securityProfiles();

        return empty($profiles);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['securityprofilegroup']['object']['operators']['has.predefined.secprof'] = array(
    'Function' => function (SecurityprofilegroupRQueryContext $context) {
        $secprofgroup = $context->object;

        $profiles = $secprofgroup->securityProfiles();
        foreach( $profiles as $key => $profile )
        {
            if( is_object($profile) )
            {
                if( str_contains($profile->owner->name(), "predefined") )
                    return TRUE;
            }
        }

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP% av-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
// </editor-fold>