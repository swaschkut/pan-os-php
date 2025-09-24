<?php

// <editor-fold desc=" ***** Schedule filters *****" defaultstate="collapsed" >
RQuery::$defaultFilters['edl']['refcount']['operators']['>,<,=,!'] = array(
    'eval' => '$object->countReferences() !operator! !value!',
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['edl']['object']['operators']['is.unused'] = array(
    'Function' => function (EDLRQueryContext $context) {
        return $context->object->countReferences() == 0;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['edl']['object']['operators']['is.expired'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $value = $context->object;

        return $value->isExpired();
    },
    'arg' => false,
);
RQuery::$defaultFilters['edl']['object']['operators']['expire.in.days'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $value = $context->object;

        $operator = $context->operator;
        if( $operator == '=' )
            $operator = '==';

        return $value->isExpired( $context->value, $operator );
    },
    'arg' => true,
);
RQuery::$defaultFilters['edl']['name']['operators']['is.in.file'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;

        if( !isset($context->cachedList) )
        {
            if( !file_exists($context->value) )
                derr("cannot find file '{$context->value}'", null, FALSE);

            $text = file_get_contents($context->value);

            if( $text === FALSE )
                derr("cannot open file '{$context->value}");

            $lines = explode("\n", $text);
            foreach( $lines as $line )
            {
                $line = trim($line);
                if( strlen($line) == 0 )
                    continue;
                $list[$line] = TRUE;
            }

            $context->cachedList = &$list;
        }
        else
            $list = &$context->cachedList;

        return isset($list[$object->name()]);
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['edl']['object']['operators']['is.tmp'] = array(
    'Function' => function (EDLRQueryContext $context) {
        return $context->object->isTmp();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['edl']['name']['operators']['eq'] = array(
    'Function' => function (EDLRQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['edl']['name']['operators']['eq.nocase'] = array(
    'Function' => function (EDLRQueryContext $context) {
        return strtolower($context->object->name()) == strtolower($context->value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['edl']['name']['operators']['contains'] = array(
    'Function' => function (EDLRQueryContext $context) {
        return strpos($context->object->name(), $context->value) !== FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['edl']['name']['operators']['regex'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( strlen($value) > 0 && $value[0] == '%' )
        {
            $value = substr($value, 1);
            if( !isset($context->nestedQueries[$value]) )
                derr("regular expression filter makes reference to unknown string alias '{$value}'");

            $value = $context->nestedQueries[$value];
        }

        $matching = preg_match($value, $object->name());
        if( $matching === FALSE )
            derr("regular expression error on '{$value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /-group/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['edl']['location']['operators']['is'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $owner = $context->object->owner->owner;
        if( strtolower($context->value) == 'shared' )
        {
            if( $owner->isPanorama() )
                return TRUE;
            if( $owner->isFirewall() )
                return TRUE;
            return FALSE;
        }
        if( strtolower($context->value) == strtolower($owner->name()) )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['edl']['location']['operators']['regex'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $name = $context->object->getLocationString();
        $matching = preg_match($context->value, $name);
        if( $matching === FALSE )
            derr("regular expression error on '{$context->value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /shared/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['edl']['location']['operators']['is.child.of'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $edl_location = $context->object->getLocationString();

        $sub = $context->object->owner;
        while( get_class($sub) == "ScheduleStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
            $sub = $sub->owner;

        if( get_class($sub) == "PANConf" )
            derr("filter location is.child.of is not working against a firewall configuration");

        if( strtolower($context->value) == 'shared' )
            return TRUE;

        $DG = $sub->findDeviceGroup($context->value);
        if( $DG == null )
        {
            PH::print_stdout("ERROR: location '$context->value' was not found. Here is a list of available ones:" );
            PH::print_stdout( " - shared" );
            foreach( $sub->getDeviceGroups() as $sub1 )
            {
                PH::print_stdout( " - " . $sub1->name() );
            }
            PH::print_stdout();
            exit(1);
        }

        $childDeviceGroups = $DG->childDeviceGroups(TRUE);

        if( strtolower($context->value) == strtolower($edl_location) )
            return TRUE;

        foreach( $childDeviceGroups as $childDeviceGroup )
        {
            if( $childDeviceGroup->name() == $edl_location )
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
RQuery::$defaultFilters['edl']['location']['operators']['is.parent.of'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $edl_location = $context->object->getLocationString();

        $sub = $context->object->owner;
        while( get_class($sub) == "ScheduleStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
            $sub = $sub->owner;

        if( get_class($sub) == "PANConf" )
        {
            PH::print_stdout( "ERROR: filter location is.child.of is not working against a firewall configuration" );
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
                PH::print_stdout( " - " . $sub1->name() );
            }
            PH::print_stdout();
            exit(1);
        }

        $parentDeviceGroups = $DG->parentDeviceGroups();

        if( strtolower($context->value) == strtolower($edl_location) )
            return TRUE;

        if( $edl_location == 'shared' )
            return TRUE;

        foreach( $parentDeviceGroups as $childDeviceGroup )
        {
            if( $childDeviceGroup->name() == $edl_location )
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
RQuery::$defaultFilters['edl']['reflocation']['operators']['is'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;
        $owner = $context->object->owner->owner;

        $reflocation_array = $object->getReferencesLocation();

        if( strtolower($context->value) == 'shared' )
        {
            if( $owner->isPanorama() )
                return TRUE;
            if( $owner->isFirewall() )
                return TRUE;
            return FALSE;
        }

        if( $owner->isPanorama() )
        {
            $DG = $owner->findDeviceGroup($context->value);
            if( $DG == null )
            {
                $test = new UTIL("custom", array(), 0,"");
                $test->configType = "panorama";
                $test->locationNotFound($context->value, null, $owner);
            }
        }

        foreach( $reflocation_array as $reflocation )
        {
            #if( strtolower($reflocation) == strtolower($owner->name()) )
            if( strtolower($reflocation) == strtolower($context->value) )
                return TRUE;
        }


        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['edl']['reflocation']['operators']['is.only'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $owner = $context->object->owner->owner;
        $reflocations = $context->object->getReferencesLocation();

        $reftypes = $context->object->getReferencesType();
        $refstore = $context->object->getReferencesStore();

        if( strtolower($context->value) == 'shared' )
        {
            if( $owner->isPanorama() )
                return TRUE;
            if( $owner->isFirewall() )
                return TRUE;
            return FALSE;
        }

        $return = FALSE;
        foreach( $reflocations as $reflocation )
        {
            if( strtolower($reflocation) == strtolower($context->value) )
                $return = TRUE;
        }

        if( count($reflocations) == 1 && $return )
            return TRUE;
        else
            return FALSE;

    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['edl']['refstore']['operators']['is'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $value = $context->value;
        $value = strtolower($value);

        $context->object->ReferencesStoreValidation($value);

        $refstore = $context->object->getReferencesStore();

        if( array_key_exists($value, $refstore) )
            return TRUE;

        return FALSE;

    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% rulestore )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['edl']['reftype']['operators']['is'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $value = $context->value;
        $value = strtolower($value);

        $context->object->ReferencesTypeValidation($value);

        $reftype = $context->object->getReferencesType();

        if( array_key_exists($value, $reftype) )
            return TRUE;

        return FALSE;

    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% securityrule )',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['edl']['object']['operators']['is.expired'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $value = $context->object;

        return $value->isExpired();
    },
    'arg' => false,
);
RQuery::$defaultFilters['edl']['expire.in.days']['operators']['>,<,=,!'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $value = $context->object;

        $operator = $context->operator;
        if( $operator == '=' )
            $operator = '==';

        return $value->isExpired( $context->value, $operator );
    },
    'arg' => true,
);

RQuery::$defaultFilters['edl']['type']['operators']['is.ip'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;

        return $object->type() == 'ip';
    },
    'arg' => false,
);

RQuery::$defaultFilters['edl']['type']['operators']['is.url'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;

        return $object->type() == 'url';
    },
    'arg' => false,
);

RQuery::$defaultFilters['edl']['type']['operators']['is.domain'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;

        return $object->type() == 'domain';
    },
    'arg' => false,
);
RQuery::$defaultFilters['edl']['type']['operators']['is.imei'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;

        return $object->type() == 'imei';
    },
    'arg' => false,
);
RQuery::$defaultFilters['edl']['type']['operators']['is.imsi'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;

        return $object->type() == 'imsi';
    },
    'arg' => false,
);
RQuery::$defaultFilters['edl']['type']['operators']['is.predefined-ip'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;

        return $object->type() == 'predefined-ip';
    },
    'arg' => false,
);
RQuery::$defaultFilters['edl']['type']['operators']['is.predefined-url'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;

        return $object->type() == 'predefined-url';
    },
    'arg' => false,
);

RQuery::$defaultFilters['edl']['url']['operators']['regex'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( strlen($value) > 0 && $value[0] == '%' )
        {
            $value = substr($value, 1);
            if( !isset($context->nestedQueries[$value]) )
                derr("regular expression filter makes reference to unknown string alias '{$value}'");

            $value = $context->nestedQueries[$value];
        }

        $matching = preg_match($value, $object->url());
        if( $matching === FALSE )
            derr("regular expression error on '{$value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /-group/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
// </editor-fold>