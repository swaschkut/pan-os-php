<?php

//Todo: swaschkut 20240725
/*
/*
ii) For AV Actions tab 3 BP settings
a) Signature Action = reset-both for all decoders
b) Wildfire Signature Action = reset-both for all decoders
c) Wildfire Inline ML Signature Action = reset-both for all decoders
** want to break into 3 components because some customers may want to ignore one or more of these
 */


// <editor-fold desc=" ***** SecProf filters *****" defaultstate="collapsed" >
RQuery::$defaultFilters['securityprofile']['refcount']['operators']['>,<,=,!'] = array(
    'eval' => '$object->countReferences() !operator! !value!',
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofile']['object']['operators']['is.unused'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        if( get_class($context->object ) == "PredefinedSecurityProfileURL" )
            return null;
        return $context->object->countReferences() == 0;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofile']['name']['operators']['is.in.file'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        $object = $context->object;

        if( !isset($context->cachedList) )
        {
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
RQuery::$defaultFilters['securityprofile']['object']['operators']['is.tmp'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        return $context->object->isTmp();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofile']['name']['operators']['eq'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofile']['name']['operators']['eq.nocase'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        return strtolower($context->object->name()) == strtolower($context->value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofile']['name']['operators']['contains'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        return strpos($context->object->name(), $context->value) !== FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofile']['name']['operators']['regex'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
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
RQuery::$defaultFilters['securityprofile']['location']['operators']['is'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        if( is_object($context->object->owner->owner) )
            $owner = $context->object->owner->owner;
        else
            return FALSE;

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
RQuery::$defaultFilters['securityprofile']['location']['operators']['regex'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
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
RQuery::$defaultFilters['securityprofile']['location']['operators']['is.child.of'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        $secprof_location = $context->object->getLocationString();

        $sub = $context->object->owner;
        while( get_class($sub) == "SecurityProfileStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
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
            PH::print_stdout();
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
RQuery::$defaultFilters['securityprofile']['location']['operators']['is.parent.of'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        $secprof_location = $context->object->getLocationString();

        $sub = $context->object->owner;
        while( get_class($sub) == "SecurityProfileStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
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
            PH::print_stdout();
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
RQuery::$defaultFilters['securityprofile']['reflocation']['operators']['is'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
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
RQuery::$defaultFilters['securityprofile']['reflocation']['operators']['is.only'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
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
            return null;
        }

        $return = FALSE;
        foreach( $reflocations as $reflocation )
        {
            if( strtolower($reflocation) == strtolower($context->value) )
                $return = TRUE;
        }

        if( count($reflocations) == 1 && $return )
            return TRUE;

        return NULL;

    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofile']['refstore']['operators']['is'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        $value = $context->value;
        $value = strtolower($value);

        $context->object->ReferencesStoreValidation($value);

        $refstore = $context->object->getReferencesStore();

        if( array_key_exists($value, $refstore) )
            return TRUE;

        return null;

    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% rulestore )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['securityprofile']['reftype']['operators']['is'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        $value = $context->value;
        $value = strtolower($value);

        $context->object->ReferencesTypeValidation($value);

        $reftype = $context->object->getReferencesType();

        if( array_key_exists($value, $reftype) )
            return TRUE;

        return null;

    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% securityrule )',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['securityprofile']['alert']['operators']['has'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;
        $value = strtolower($value);

        if( !$object->secprof_type == 'url-filtering'  )
            return null;

        if( array_key_exists($value, $object->alert) )
            return TRUE;

        return FALSE;

    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% securityrule )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=url'"
);

RQuery::$defaultFilters['securityprofile']['block']['operators']['has'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;
        $value = strtolower($value);

        if( !$object->secprof_type == 'url-filtering'  )
            return null;

        if( array_key_exists($value, $object->block) )
            return TRUE;

        return FALSE;

    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% securityrule )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=url'"
);

RQuery::$defaultFilters['securityprofile']['allow']['operators']['has'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;
        $value = strtolower($value);

        if( !$object->secprof_type == 'url-filtering'  )
            return null;

        if( array_key_exists($value, $object->allow) )
            return TRUE;

        return FALSE;

    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% securityrule )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=url'"
);

RQuery::$defaultFilters['securityprofile']['continue']['operators']['has'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;
        $value = strtolower($value);

        if( !$object->secprof_type == 'url-filtering'  )
            return null;

        if( array_key_exists($value, $object->continue) )
            return TRUE;

        return FALSE;

    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% securityrule )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=url'"
);

RQuery::$defaultFilters['securityprofile']['override']['operators']['has'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;
        $value = strtolower($value);

        if( !$object->secprof_type == 'url-filtering'  )
            return null;

        if( array_key_exists($value, $object->override) )
            return TRUE;

        return FALSE;

    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% securityrule )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=url'"
);

RQuery::$defaultFilters['securityprofile']['exception']['operators']['has'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( $object->secprof_type != 'virus' and $object->secprof_type != 'spyware' and $object->secprof_type != 'vulnerability' )
            return null;

        if( !empty( $object->threatException ) )
        {
            foreach( $object->threatException as $threatname => $threat )
            {
                if( $threatname == $value )
                    return TRUE;
            }
        }

        return FALSE;

    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% securityrule )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=spyware,vulnerability'"
);


RQuery::$defaultFilters['securityprofile']['exception']['operators']['is.set'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        $object = $context->object;

        if( $object->secprof_type != 'virus' and $object->secprof_type != 'spyware' and $object->secprof_type != 'vulnerability' )
            return null;

        if( !empty( $object->threatException ) )
            return TRUE;

        return FALSE;

    },
    'ci' => array(
        'fString' => '(%PROP% securityrule )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=spyware,vulnerability'"
);

RQuery::$defaultFilters['securityprofile']['action']['operators']['eq'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        /** @var ThreatPolicySpyware|ThreatPolicyVulnerability $object */
        $object = $context->object;
        $value = $context->value;

        #if( $object->secprof_type != 'virus' and $object->secprof_type != 'spyware' and $object->secprof_type != 'vulnerability' )
        if( $object->secprof_type != 'spyware' and $object->secprof_type != 'vulnerability' )
            return null;

        if( !empty( $object->rules_obj ) )
        {
            foreach( $object->rules_obj as $rulename => $rule )
            {
                if( $rule->action == $value )
                    return TRUE;
            }
        }

        return FALSE;

    },
    'arg' => TRUE,
    'deprecated' => 'this filter "action eq XYZ" is deprecated, you should use "filter=(threat-rule has.from.query subquery1) subquery1=(action eq XYZ)" instead!',
    'ci' => array(
        'fString' => '(%PROP% reset-both )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=spyware,vulnerability'"
);

RQuery::$defaultFilters['securityprofile']['packet-capture']['operators']['eq'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        #if( $object->secprof_type == 'virus' || $object->secprof_type == 'spyware' || $object->secprof_type == 'vulnerability' )
        if( $object->secprof_type != 'spyware' and $object->secprof_type != 'vulnerability' )
            return null;

        if( !empty( $object->rules_obj ) )
        {
            foreach( $object->rules_obj as $rulename => $rule )
            {
                if( $rule->packetCapture == $value )
                    return TRUE;
            }
        }

        return FALSE;
    },
    'arg' => TRUE,
    'deprecated' => 'this filter "packet-capture eq XYZ" is deprecated, you should use "filter=(threat-rule has.from.query subquery1) subquery1=(packet-capture eq XYZ)" instead!',
    'ci' => array(
        'fString' => '(%PROP% single-packet )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=spyware,vulnerability'"
);

RQuery::$defaultFilters['securityprofile']['severity']['operators']['eq'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        #if( $object->secprof_type == 'virus' || $object->secprof_type == 'spyware' || $object->secprof_type == 'vulnerability' )
        if( $object->secprof_type != 'spyware' and $object->secprof_type != 'vulnerability' )
            return null;

        if( !empty( $object->rules_obj ) )
        {
            foreach( $object->rules_obj as $rulename => $rule )
            {
                if( in_array( $value, $rule->severity) )
                    return TRUE;
            }
        }

        return FALSE;
    },
    'arg' => TRUE,
    'deprecated' => 'this filter "severity eq XYZ" is deprecated, you should use "filter=(threat-rule has.from.query subquery1) subquery1=(severity eq XYZ)" instead!',
    'ci' => array(
        'fString' => '(%PROP% critical )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=spyware,vulnerability'"
);

RQuery::$defaultFilters['securityprofile']['category']['operators']['eq'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        #if( $object->secprof_type == 'virus' || $object->secprof_type == 'spyware' || $object->secprof_type == 'vulnerability' )
        if( $object->secprof_type != 'spyware' and $object->secprof_type != 'vulnerability' )
            return null;

        if( !empty( $object->rules_obj ) )
        {
            foreach( $object->rules_obj as $rulename => $rule )
            {
                if( $rule->category == $value )
                    return TRUE;
            }
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% brute-force )',
        'deprecated' => 'this filter "category eq XYZ" is deprecated, you should use "filter=(threat-rule has.from.query subquery1) subquery1=(category eq XYZ)" instead!',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=spyware,vulnerability'"
);

RQuery::$defaultFilters['securityprofile']['host']['operators']['eq'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        #if( $object->secprof_type == 'virus' || $object->secprof_type == 'spyware' || $object->secprof_type == 'vulnerability' )
        if( $object->secprof_type != 'spyware' and $object->secprof_type != 'vulnerability' )
            return null;

        if( !empty( $object->rules_obj ) )
        {
            foreach( $object->rules_obj as $rulename => $rule )
            {
                if( $rule->host == $value )
                    return TRUE;
            }
        }

        return FALSE;
    },
    'arg' => TRUE,
    'deprecated' => 'this filter "host eq XYZ" is deprecated, you should use "filter=(threat-rule has.from.query subquery1) subquery1=(host eq XYZ)" instead!',
    'ci' => array(
        'fString' => '(%PROP% client )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=spyware,vulnerability'"
);

RQuery::$defaultFilters['securityprofile']['exempt-ip.count']['operators']['>,<,=,!'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        /** @var VulnerabilityProfile $object */
        $object = $context->object;
        $value = $context->value;
        $operator = $context->operator;

        if( $operator == '=' )
            $operator = '==';

        if( $object->secprof_type != 'spyware' and $object->secprof_type != 'vulnerability' )
            return null;

        foreach ($object->threatException as $exception) {
            if (isset($exception['exempt-ip'])) {
                $operator_string = count($exception['exempt-ip']) . " " . $operator . " " . $value;
                if (eval("return $operator_string;"))
                    return true;
                else
                    return false;
            }
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% rulestore )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=spyware,vulnerability'"
);

RQuery::$defaultFilters['securityprofile']['cloud-inline-analysis']['operators']['is.enabled'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        /** @var VulnerabilityProfile|AntiSpywareProfile $object */
        $object = $context->object;

        if( $object->secprof_type != 'spyware' and $object->secprof_type != 'vulnerability' )
            return null;

        if( $object->cloud_inline_analysis_enabled )
            return TRUE;

        return FALSE;
    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP% client )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=spyware,vulnerability'"
);

RQuery::$defaultFilters['securityprofile']['cloud-inline-analysis.action']['operators']['has'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        /** @var VulnerabilityProfile|AntiSpywareProfile $object */
        $object = $context->object;
        $value = $context->value;

        if( $object->secprof_type != 'spyware' and $object->secprof_type != 'vulnerability' )
            return null;

        if( isset($object->additional['mica-engine-vulnerability-enabled']) )
        {
            foreach( $object->additional['mica-engine-vulnerability-enabled'] as $name)
            {
                if( $name['inline-policy-action'] == $value )
                    return TRUE;
            }
        }

        if( isset($object->additional['mica-engine-spyware-enabled']) )
        {
            foreach( $object->additional['mica-engine-spyware-enabled'] as $name)
            {
                if( $name['inline-policy-action'] == $value )
                    return TRUE;
            }
        }

        return FALSE;
    },
    'arg' => true,
    'ci' => array(
        'fString' => '(%PROP% client )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=spyware,vulnerability'"
);
RQuery::$defaultFilters['securityprofile']['cloud-inline-analysis']['operators']['is.best-practice'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        /** @var VulnerabilityProfile|AntiSpywareProfile $object */
        $object = $context->object;
        $bestpractise = FALSE;

        if( $object->secprof_type != 'spyware' and $object->secprof_type != 'vulnerability' )
            return null;

        if( $object->cloud_inline_analysis_enabled )
        {
            if( isset($object->additional['mica-engine-vulnerability-enabled']) )
            {

                foreach( $object->additional['mica-engine-vulnerability-enabled'] as $name)
                {
                    if( $name['inline-policy-action'] == "reset-both" )
                        $bestpractise = TRUE;
                    else
                        return FALSE;
                }
            }

            if( isset($object->additional['mica-engine-spyware-enabled']) )
            {
                foreach( $object->additional['mica-engine-spyware-enabled'] as $name)
                {
                    if( $name['inline-policy-action'] == "reset-both" )
                        $bestpractise = TRUE;
                    else
                        return FALSE;
                }
            }

            //AV iii) Wildfire Inline ML Tab
            //- all models must be set to 'enable (inherit per-protocol actions)'
            if( isset($object->additional['mlav-engine-filebased-enabled']) )
            {
                foreach( $object->additional['mlav-engine-filebased-enabled'] as $name)
                {
                    if( $name['mlav-policy-action'] == "enable" )
                        $bestpractise = TRUE;
                    else
                        return FALSE;
                }
            }
        }

        return $bestpractise;
    },
    'arg' => false,
    'help' => "'securityprofiletype=spyware,vulnerability'"
);

RQuery::$defaultFilters['securityprofile']['av.action']['operators']['is.best-practice'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        /** @var VulnerabilityProfile|AntiSpywareProfile $object */
        $object = $context->object;
        $bestpractise = FALSE;

        if( $object->secprof_type != 'virus' )
            return null;

        if( isset($object->tmp_virus_prof_array) )
        {
            foreach( $object->tmp_virus_prof_array as $key => $type )
            {
                if( isset( $object->$type['action'] ) )
                {
                    if( $object->$type['action'] == "reset-both" )
                        $bestpractise = TRUE;
                    else
                        return False;
                }
            }
        }

        return $bestpractise;
    },
    'arg' => false,
    'help' => "'securityprofiletype=virus'"
);
RQuery::$defaultFilters['securityprofile']['av.wildfire-action']['operators']['is.best-practice'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        /** @var VulnerabilityProfile|AntiSpywareProfile $object */
        $object = $context->object;
        $bestpractise = FALSE;

        if( $object->secprof_type != 'virus' )
            return null;

        if( isset($object->tmp_virus_prof_array) )
        {
            foreach( $object->tmp_virus_prof_array as $key => $type )
            {
                if( isset( $this->$type['wildfire-action'] ) )
                {
                    if( $object->$type['wildfire-action'] == "reset-both" )
                        $bestpractise = TRUE;
                    else
                        return False;
                }
            }
        }

        return $bestpractise;
    },
    'arg' => false,
    'help' => "'securityprofiletype=virus'"
);
RQuery::$defaultFilters['securityprofile']['av.mlav-action']['operators']['is.best-practice'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        /** @var VulnerabilityProfile|AntiSpywareProfile $object */
        $object = $context->object;
        $bestpractise = FALSE;

        if( $object->secprof_type != 'virus' )
            return null;

        if( isset($object->tmp_virus_prof_array) )
        {
            foreach( $object->tmp_virus_prof_array as $key => $type )
            {
                if( isset( $this->$type['mlav-action'] ) )
                {
                    if( $object->$type['mlav-action'] == "reset-both" )
                        $bestpractise = FALSE;
                    else
                        return False;
                }
            }
        }

        return $bestpractise;
    },
    'arg' => false,
    'help' => "'securityprofiletype=virus'"
);
RQuery::$defaultFilters['securityprofile']['dns-list.action']['operators']['has'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        /** @var AntiSpywareProfile $object */
        $object = $context->object;
        $value = $context->value;

        if( $object->secprof_type != 'spyware' )
            return null;

        $tmp_value_array = array( 'alert','allow','block','sinkhole');

        if( !in_array($value, $tmp_value_array) )
            derr("filter-value: '".$value."' is not a valid value for dns-list.action filter");

        if( isset($object->additional['botnet-domain']) && isset($object->additional['botnet-domain']['lists']) )
        {
            foreach( $object->additional['botnet-domain']['lists'] as $name)
            {
                if( $name['action'] == $value )
                    return TRUE;
            }
        }

        return FALSE;
    },
    'arg' => true,
    'ci' => array(
        'fString' => '(%PROP% client )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=spyware' e.g. 'filter=(dns-list.action has sinkhole)' possible values: alert/allow/block/sinkhole"
);
RQuery::$defaultFilters['securityprofile']['dns-list']['operators']['is.best-practice'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        /** @var AntiSpywareProfile $object */
        $object = $context->object;

        if( $object->secprof_type != 'spyware' )
            return null;

        if( isset($object->additional['botnet-domain']) && isset($object->additional['botnet-domain']['lists']) )
        {
            foreach( $object->additional['botnet-domain']['lists'] as $name => $array)
            {
                if( $name == "default-paloalto-dns" )
                {
                    if( $array['action'] == "sinkhole" )
                        return TRUE;
                }
            }
        }

        return FALSE;
    },
    'arg' => false,
    'help' => "'securityprofiletype=spyware' e.g. 'filter=(dns-list is.best-practice)'"
);
RQuery::$defaultFilters['securityprofile']['dns-list.packet-capture']['operators']['has'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        /** @var AntiSpywareProfile $object */
        $object = $context->object;
        $value = $context->value;

        if( $object->secprof_type != 'spyware' )
            return null;

        $tmp_value_array = array( 'disable','single-packet','extended-capture');

        if( !in_array($value, $tmp_value_array) )
            derr("filter-value: '".$value."' is not a valid value for dns-list.packet-capture filter");

        if( isset($object->additional['botnet-domain']) && isset($object->additional['botnet-domain']['lists']) )
        {
            foreach( $object->additional['botnet-domain']['lists'] as $name)
            {
                if( $name['packet-capture'] == $value )
                    return TRUE;
            }
        }

        return FALSE;
    },
    'arg' => true,
    'ci' => array(
        'fString' => '(%PROP% client )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=spyware' e.g. 'filter=(dns-list.packet-capture has disable)' possible values: disable/single-packet/extended-capture"
);

RQuery::$defaultFilters['securityprofile']['dns-security.action']['operators']['has'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        /** @var AntiSpywareProfile $object */
        $object = $context->object;
        $value = $context->value;

        if( $object->secprof_type != 'spyware' )
            return null;

        $tmp_value_array = array( 'default','allow','block','sinkhole');

        if( !in_array($value, $tmp_value_array) )
            derr("filter-value: '".$value."' is not a valid value for dns-list.action filter");

        if( isset($object->additional['botnet-domain']) && isset($object->additional['botnet-domain']['dns-security-categories']) )
        {
            foreach( $object->additional['botnet-domain']['dns-security-categories'] as $name)
            {
                if( $name['action'] == $value )
                    return TRUE;
            }
        }

        return FALSE;
    },
    'arg' => true,
    'ci' => array(
        'fString' => '(%PROP% client )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=spyware' e.g. 'filter=(dns-security.action has sinkhole)' possible values: default/allow/block/sinkhole"
);
RQuery::$defaultFilters['securityprofile']['dns-security.packet-capture']['operators']['has'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        /** @var AntiSpywareProfile $object */
        $object = $context->object;
        $value = $context->value;

        if( $object->secprof_type != 'spyware' )
            return null;

        $tmp_value_array = array( 'disable','single-packet','extended-capture');

        if( !in_array($value, $tmp_value_array) )
            derr("filter-value: '".$value."' is not a valid value for dns-list.packet-capture filter");

        if( isset($object->additional['botnet-domain']) && isset($object->additional['botnet-domain']['dns-security-categories']) )
        {
            foreach( $object->additional['botnet-domain']['dns-security-categories'] as $name)
            {
                if( $name['packet-capture'] == $value )
                    return TRUE;
            }
        }

        return FALSE;
    },
    'arg' => true,
    'ci' => array(
        'fString' => '(%PROP% client )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => "'securityprofiletype=spyware' e.g. 'filter=(dns-security.packet-capture has disable)' possible values: disable/single-packet/extended-capture"
);


RQuery::$defaultFilters['securityprofile']['threat-rule']['operators']['has.from.query'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        $object = $context->object;

        if( $object->secprof_type != 'spyware' and $object->secprof_type != 'vulnerability' )
            return null;

        if( count($object->rules_obj) == 0 )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('threat-rule');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->rules_obj as $member )
        {
            if( $rQuery->matchSingleObject(array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => "'securityprofiletype=spyware,vulnerability' example: 'filter=(threat-rule has.from.query subquery1)' 'subquery1=(action eq alert)'",
);

RQuery::$defaultFilters['securityprofile']['dns-rule']['operators']['has.from.query'] = array(
    'Function' => function (SecurityProfileRQueryContext $context) {
        $object = $context->object;

        if( $object->secprof_type != 'spyware' )
            return null;

        if( count($object->dns_rules_obj) == 0 )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('dns-rule');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->dns_rules_obj as $member )
        {
            if( $rQuery->matchSingleObject(array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => "'securityprofiletype=spyware' example: 'filter=(dns-rule has.from.query subquery1)' 'subquery1=(action eq alert)'",
);
// </editor-fold>