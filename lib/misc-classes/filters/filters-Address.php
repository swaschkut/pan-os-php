<?php

// <editor-fold desc=" ***** Address filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['address']['refcount']['operators']['>,<,=,!'] = array(
    'eval' => '$object->countReferences() !operator! !value!',
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['reflocationcount']['operators']['>,<,=,!'] = array(
    'eval' => '$object->countLocationReferences() !operator! !value!',
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.unused'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        return $object->objectIsUnused();
        #return $context->object->countReferences() == 0;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.unused.recursive'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        return $object->objectIsUnusedRecursive();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.group'] = array(
    'Function' => function (AddressRQueryContext $context) {
        return $context->object->isGroup() == TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.region'] = array(
    'Function' => function (AddressRQueryContext $context) {
        return $context->object->isRegion() == TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.dynamic'] = array(
    'Function' => function (AddressRQueryContext $context) {
        if( $context->object->isGroup() )
            return $context->object->isDynamic() == TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.tmp'] = array(
    'Function' => function (AddressRQueryContext $context) {
        return $context->object->isTmpAddr() == TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.ip-range'] = array(
    'Function' => function (AddressRQueryContext $context) {
        if( !$context->object->isGroup() && !$context->object->isRegion() )
            return $context->object->isType_ipRange() == TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.ip-netmask'] = array(
    'Function' => function (AddressRQueryContext $context) {
        if( !$context->object->isGroup() && !$context->object->isRegion() )
            return $context->object->isType_ipNetmask() == TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.fqdn'] = array(
    'Function' => function (AddressRQueryContext $context) {
        if( !$context->object->isGroup() && !$context->object->isRegion() )
            return $context->object->isType_FQDN() == TRUE;
        else
            return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.edl'] = array(
    'Function' => function (AddressRQueryContext $context) {
        if( !$context->object->isGroup() && !$context->object->isRegion() )
            return $context->object->isEDL() == TRUE;
        else
            return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.ip-wildcard'] = array(
    'Function' => function (AddressRQueryContext $context) {
        if( !$context->object->isGroup() && !$context->object->isRegion() )
            return $context->object->isType_ipWildcard() == TRUE;
        else
            return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.ipv4'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( !$object->isGroup() && !$object->isRegion() && !$object->isEDL() )
        {
            if( $object->isType_FQDN() )
            {
                #PH::print_stdout( "SKIPPED: object is FQDN");
                return null;
            }

            if( $object->value() !== null && strpos( $object->value(), ":") !== false )
                return false;

            $addr_value = $object->value();

            if( $object->isType_ipRange() )
            {
                $ip_range = explode( "-", $object->value() );
                $addr_value = $ip_range[0];
            }

            if( $addr_value !== null && substr_count( $addr_value, '.' ) == 3 )
            {
                #check that all four octects are ipv4
                $tmp_addr_value = explode( "/", $addr_value );
                $tmp_addr_array =  explode( ".", $tmp_addr_value[0]);

                foreach( $tmp_addr_array as $occtet )
                {
                    if( $occtet >= 0 && $occtet <= 255 )
                        continue;
                    else
                        derr( "this is not a valid IPv4 address [".$addr_value."]" );
                }

                return true;
            }
        }
        else #howto check if group is IPv4 only
        {
            #PH::print_stdout( "object: ".$object->name()." is group. not supported yet" );
            return false;
        }

        return null;
    },
    'arg' => false
);

RQuery::$defaultFilters['address']['object']['operators']['is.ipv6'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( !$object->isGroup() && !$object->isRegion() && !$object->isEDL() )
        {
            if( $object->isType_FQDN() )
            {
                #PH::print_stdout( "SKIPPED: object is FQDN");
                return null;
            }

            $addr_value = $object->value();

            if( $object->isType_ipRange() )
            {
                $ip_range = explode( "-", $object->value() );
                $addr_value = $ip_range[0];
            }

            if( $addr_value == null )
                $addr_value = "";
            $ip_range = explode( "/", $addr_value );
            $addr_value = $ip_range[0];

            #if( strpos( $addr_value, ":") !== false )
            #if (preg_match("/^[0-9a-f:]+$/",$addr_value)) // IPv6 section
            if(filter_var($addr_value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
            {
                #check that ipv6
                return true;
            }
        }
        else #howto check if group is IPv6 only
        {
            #PH::print_stdout( "object: ".$object->name()." is group. not supported yet" );
            return false;
        }

        return null;
    },
    'arg' => false
);
RQuery::$defaultFilters['address']['object']['operators']['overrides.upper.level'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $location = PH::findLocationObjectOrDie($context->object);
        if( $location->isFirewall() || $location->isPanorama() || $location->isVirtualSystem() )
            return FALSE;

        $store = $context->object->owner;

        if( isset($store->parentCentralStore) && $store->parentCentralStore !== null )
        {
            $store = $store->parentCentralStore;
            $find = $store->find($context->object->name());

            return $find !== null;
        }
        else
            return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['overriden.at.lower.level'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        $location = PH::findLocationObjectOrDie($object);
        if( $location->isFirewall() || $location->isVirtualSystem() )
            return FALSE;

        if( $location->isPanorama() )
            $locations = $location->deviceGroups;
        else
        {
            $locations = $location->childDeviceGroups(TRUE);
        }

        foreach( $locations as $deviceGroup )
        {
            if( $deviceGroup->addressStore->find($object->name(), null, FALSE) !== null )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.member.of'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $addressGroup = $context->object->owner->find($context->value);

        if( $addressGroup === null )
            return FALSE;

        if( $addressGroup->has($context->object) )
            return TRUE;

        return FALSE;

    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.recursive.member.of'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $addressGroup = $context->object->owner->find($context->value);

        if( $addressGroup === null )
            return FALSE;

        if( !$context->object->isGroup() && !$context->object->isRegion() )
        {
            if( $addressGroup->hasObjectRecursive($context->object) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp-in-grp-test-1)',
        'input' => 'input/panorama-8.0-merger.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['has.group.as.member'] = array(
    'Function' => function (AddressRQueryContext $context) {


        if( !$context->object->isGroup() )
            return FALSE;

        foreach( $context->object->members() as $objectMember )
        {
            if( $objectMember->isGroup() )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['address']['name']['operators']['eq'] = array(
    'Function' => function (AddressRQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% new test 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['name']['operators']['eq.nocase'] = array(
    'Function' => function (AddressRQueryContext $context) {
        return strtolower($context->object->name()) == strtolower($context->value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% new test 2)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['name']['operators']['contains'] = array(
    'Function' => function (AddressRQueryContext $context) {
        return strpos($context->object->name(), $context->value) !== FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% -)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['name']['operators']['regex'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( strlen($value) > 0 && $value[0] == '%' )
        {
            $value = substr($value, 1);
            if( !isset($context->nestedQueries[$value]) )
                derr("regular expression filter makes reference to unknown string alias '{$value}'");

            $value = $context->nestedQueries[$value];
        }

        if( strpos($value, '$$value$$') !== FALSE )
        {
            $replace = '%%%INVALID\.FOR\.THIS\.TYPE\.OF\.OBJECT%%%';
            if( !$object->isGroup() && !$object->isRegion() && !$object->isEDL() && $object->value() !== null  )
                $replace = str_replace(array('.', '/'), array('\.', '\/'), $object->value());

            $value = str_replace('$$value$$', $replace, $value);

        }
        if( strpos($value, '$$ipv4$$') !== FALSE )
        {
            $replace = '%%%INVALID\.FOR\.THIS\.TYPE\.OF\.OBJECT%%%';

            $replace = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}';
            $value = str_replace('$$ipv4$$', $replace, $value);
        }
        if( strpos($value, '$$ipv6$$') !== FALSE )
        {
            $replace = '%%%INVALID\.FOR\.THIS\.TYPE\.OF\.OBJECT%%%';

            $replace = '[0-9a-f]{1,4}_([0-9a-f]{0,4}_){1,6}[0-9a-f]{1,4}';
            $value = str_replace('$$ipv6$$', $replace, $value);
        }
        if( strpos($value, '$$value.no-netmask$$') !== FALSE )
        {
            $replace = '%%%INVALID\.FOR\.THIS\.TYPE\.OF\.OBJECT%%%';
            if( !$object->isGroup() && !$object->isRegion() && !$object->isEDL() && $object->isType_ipNetmask() )
            {
                $replace = str_replace('.', '\.', $object->getNetworkValue());
                #PH::print_stdout( "|".$object->getNetworkValue()."|name:".$object->name() );
            }


            $value = str_replace('$$value.no-netmask$$', $replace, $value);
        }
        if( strpos($value, '$$netmask$$') !== FALSE )
        {
            $replace = '%%%INVALID\.FOR\.THIS\.TYPE\.OF\.OBJECT%%%';
            if( !$object->isGroup() && !$object->isRegion() && !$object->isEDL() && $object->isType_ipNetmask() )
                $replace = $object->getNetworkMask();

            $value = str_replace('$$netmask$$', $replace, $value);
        }
        if( strpos($value, '$$netmask.blank32$$') !== FALSE )
        {
            $replace = '%%%INVALID\.FOR\.THIS\.TYPE\.OF\.OBJECT%%%';
            if( !$object->isGroup() && !$object->isRegion() && !$object->isEDL() && $object->isType_ipNetmask() )
            {
                $netmask = $object->getNetworkMask();
                if( $netmask != 32 )
                    $replace = $object->getNetworkMask();
            }

            $value = str_replace('$$netmask.blank32$$', $replace, $value);
        }

        if( strlen($value) == 0 )
            return FALSE;
        #if( strpos($value, '//') !== FALSE )
        #    return FALSE;

        if( !$object->isGroup() && !$object->isRegion() && !$object->isEDL() && $object->isType_TMP() )
            return FALSE;

        $matching = preg_match($value, $object->name());
        if( $matching === FALSE )
            derr("regular expression error on '{$value}'");
        if( $matching === 1 )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'possible variables to bring in as argument: $$value$$ / $$ipv4$$ / $$ipv6$$ / $$value.no-netmask$$ / $$netmask$$ / $$netmask.blank32$$',
    'ci' => array(
        'fString' => '(%PROP% /n-/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['name']['operators']['is.in.file'] = array(
    'Function' => function (AddressRQueryContext $context) {
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
RQuery::$defaultFilters['address']['name']['operators']['same.as.region.predefined'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        if( !isset($context->cachedList) )
        {
            $list = array();
            $filename = dirname(__FILE__) . '/../../object-classes/predefined.xml';

            $xmlDoc_region = new DOMDocument();
            $xmlDoc_region->load($filename, XML_PARSE_BIG_LINES);

            $cursor = DH::findXPathSingleEntryOrDie('/predefined/region', $xmlDoc_region);
            foreach( $cursor->childNodes as $region_entry )
            {
                if( $region_entry->nodeType != XML_ELEMENT_NODE )
                    continue;

                $region_name = DH::findAttribute('name', $region_entry);
                #PH::print_stdout( $region_name );
                $list[$region_name] = TRUE;
            }

            $context->cachedList = &$list;
        }
        else
            $list = &$context->cachedList;

        return isset($list[$object->name()]);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['name']['operators']['has.wrong.characters'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        $newName = htmlspecialchars_decode( $object->name() );
        preg_match_all('/[^\w $\-.]/', $newName, $matches , PREG_SET_ORDER, 0);

        if( count($matches) == 0 )
            return FALSE;
        else
            return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['netmask']['operators']['>,<,=,!'] = array(
    'eval' => '!$object->isGroup() && !$object->isRegion() && !\$object->isEDL() && $object->isType_ipNetmask() && $object->getNetworkMask() !operator! !value!',
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['members.count']['operators']['>,<,=,!'] = array(
    'eval' => "\$object->isGroup() && !\$object->isDynamic() && \$object->count() !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['tag.count']['operators']['>,<,=,!'] = array(
    'eval' => "!\$object->isRegion() && !\$object->isEDL() && \$object->tags->count() !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['tag']['operators']['has'] = array(
    'Function' => function (AddressRQueryContext $context) {
        if( $context->object->isRegion() )
            return FALSE;
        return $context->object->tags->hasTag($context->value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->tags->parentCentralStore->find('!value!');",
    'ci' => array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['tag']['operators']['has.nocase'] = array(
    'Function' => function (AddressRQueryContext $context) {
        if( $context->object->isRegion() )
            return FALSE;
        return $context->object->tags->hasTag($context->value, FALSE) === TRUE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% test)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['tag']['operators']['has.regex'] = array(
    'Function' => function (AddressRQueryContext $context) {
        if( $context->object->isRegion() )
            return FALSE;
        foreach( $context->object->tags->tags() as $tag )
        {
            $matching = preg_match($context->value, $tag->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /grp/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['tag']['operators']['is.set'] = array(
    'Function' => function (AddressRQueryContext $context) {
        if( $context->object->isRegion() )
            return FALSE;
        return count($context->object->tags->getAll()) > 0;
    },
    'arg' => FALSE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->tags->parentCentralStore->find('!value!');",
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['location']['operators']['is'] = array(
    'Function' => function (AddressRQueryContext $context) {
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
        'fString' => '(%PROP% shared)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['location']['operators']['regex'] = array(
    'Function' => function (AddressRQueryContext $context) {
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
RQuery::$defaultFilters['address']['location']['operators']['is.child.of'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $address_location = $context->object->getLocationString();

        $sub = $context->object->owner;
        while( get_class($sub) == "AddressStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
            $sub = $sub->owner;

        if( get_class($sub) == "PANConf" )
            derr("filter location is.child.of is not working against a firewall configuration");

        if( strtolower($context->value) == 'shared' )
            return TRUE;

        $DG = $sub->findDeviceGroup($context->value);
        if( $DG == null )
        {
            PH::print_stdout( "ERROR: location '$context->value' was not found. Here is a list of available ones:");
            PH::print_stdout( " - shared");
            foreach( $sub->getDeviceGroups() as $sub1 )
            {
                PH::print_stdout( " - " . $sub1->name() );
            }
            PH::print_stdout();
            exit(1);
        }

        $childDeviceGroups = $DG->childDeviceGroups(TRUE);

        if( strtolower($context->value) == strtolower($address_location) )
            return TRUE;

        foreach( $childDeviceGroups as $childDeviceGroup )
        {
            if( $childDeviceGroup->name() == $address_location )
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
RQuery::$defaultFilters['address']['location']['operators']['is.parent.of'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $address_location = $context->object->getLocationString();

        $sub = $context->object->owner;
        while( get_class($sub) == "AddressStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
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
            PH::print_stdout( "ERROR: location '$context->value' was not found. Here is a list of available ones:");
            PH::print_stdout( " - shared");
            foreach( $sub->getDeviceGroups() as $sub1 )
            {
                PH::print_stdout( " - " . $sub1->name() );
            }
            PH::print_stdout();
            exit(1);
        }

        $parentDeviceGroups = $DG->parentDeviceGroups();

        if( strtolower($context->value) == strtolower($address_location) )
            return TRUE;

        if( $address_location == 'shared' )
            return TRUE;

        foreach( $parentDeviceGroups as $childDeviceGroup )
        {
            if( $childDeviceGroup->name() == $address_location )
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
RQuery::$defaultFilters['address']['reflocation']['operators']['is'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $owner = $context->object->owner->owner;

        #print "NAME: ".$object->name()."\n";
        $reflocation_array = $object->getReferencesLocation();
        #print_r( $reflocation_array );

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
                $test = new UTIL("custom", array(), 0, "");
                $test->configType = "panorama";
                $test->locationNotFound($context->value, null, $owner);
            }
        }

        $return = FALSE;
        foreach( $reflocation_array as $reflocation )
        {
            if( strtolower($reflocation) == strtolower($context->value) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches',
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['reflocationtype']['operators']['is.template'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $owner = $context->object->owner->owner;

        #print "NAME: ".$object->name()."\n";
        $reflocation_array = $object->getReferencesLocationType();
        #print_r( $reflocation_array );

        $return = FALSE;
        foreach( $reflocation_array as $reflocation )
        {
            if( $reflocation == "Template" || $reflocation == "TemplateStack" )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => FALSE,
    'help' => 'returns TRUE if object locationtype is Template or TemplateStack',
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['reflocationtype']['operators']['is.only.template'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $owner = $context->object->owner->owner;

        #print "NAME: ".$object->name()."\n";
        $reflocation_array = $object->getReferencesLocationType();
        #print_r( $reflocation_array );

        $return = FALSE;
        foreach( $reflocation_array as $reflocation )
        {
            if( $reflocation == "Template" || $reflocation == "TemplateStack" )
                $return = TRUE;
            else
                return FALSe;
        }

        return $return;
    },
    'arg' => FALSE,
    'help' => 'returns TRUE if object locationtype is Template or TemplateStack',
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['reflocationtype']['operators']['is.templatestack'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $owner = $context->object->owner->owner;

        #print "NAME: ".$object->name()."\n";
        $reflocation_array = $object->getReferencesLocationType();
        #print_r( $reflocation_array );

        $return = FALSE;
        foreach( $reflocation_array as $reflocation )
        {
            if( $reflocation == "TemplateStack" )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => FALSE,
    'help' => 'returns TRUE if object locationtype is Template or TemplateStack',
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['reflocationtype']['operators']['is.devicegroup'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $owner = $context->object->owner->owner;

        $reflocation_array = $object->getReferencesLocationType();
        #print_r( $reflocation_array );

        $return = FALSE;
        if (in_array("DeviceGroup", $reflocation_array)) {
            return TRUE;
        }

        return FALSE;
    },
    'arg' => FALSE,
    'help' => 'returns TRUE if object locationtype is Template or TemplateStack',
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['reflocationtype']['operators']['is.only.devicegroup'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $owner = $context->object->owner->owner;

        $reflocation_array = $object->getReferencesLocationType();
        #print_r( $reflocation_array );

        $return = FALSE;
        foreach( $reflocation_array as $reflocation )
        {
            if( $reflocation == "DeviceGroup" )
                $return = TRUE;
            else
                return FALSE;
        }

        return $return;
    },
    'arg' => FALSE,
    'help' => 'returns TRUE if object locationtype is Template or TemplateStack',
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['reflocationtype']['operators']['is.virtualsystem'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $owner = $context->object->owner->owner;

        $reflocation_array = $object->getReferencesLocationType();
        #print_r( $reflocation_array );

        $return = FALSE;
        if (in_array("VirtualSystem", $reflocation_array)) {
            return TRUE;
        }

        return FALSE;
    },
    'arg' => FALSE,
    'help' => 'returns TRUE if object locationtype is Template or TemplateStack',
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['reflocationtype']['operators']['is.only.virtualsystem'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $owner = $context->object->owner->owner;

        $reflocation_array = $object->getReferencesLocationType();
        #print_r( $reflocation_array );

        $return = FALSE;
        foreach( $reflocation_array as $reflocation )
        {
            if( $reflocation == "VirtualSystem" )
                $return = TRUE;
            else
                return FALSE;
        }

        return $return;
    },
    'arg' => FALSE,
    'help' => 'returns TRUE if object locationtype is Template or TemplateStack',
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['reflocation']['operators']['is.only'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $owner = $context->object->owner->owner;
        $object = $context->object;

        $reflocation_array = $object->getReferencesLocation();

        /*
                $DG = $owner->findDeviceGroup( $context->value );
                if( $DG == null )
                {
                    $test = new UTIL( "custom", array(), 0, "" );
                    $test->locationNotFound( $context->value, null, $owner );
                }
        */

        if( strtolower($context->value) == 'shared' )
        {
            if( $owner->isPanorama() )
                return TRUE;
            if( $owner->isFirewall() )
                return TRUE;
            return FALSE;
        }

        $return = FALSE;
        foreach( $reflocation_array as $reflocation )
        {
            if( strtolower($reflocation) == strtolower($context->value) )
                $return = TRUE;
            else
                return FALSE;
        }

        /*if( count($reflocation_array) == 1 && $return )
            return TRUE;
        else
            return FALSE;
        */
        return $return;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches',
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refstore']['operators']['is'] = array(
    'Function' => function (AddressRQueryContext $context) {
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
RQuery::$defaultFilters['address']['refstore']['operators']['is.rulestore'] = array(
    'Function' => function (AddressRQueryContext $context) {
        #$value = $context->value;
        #$value = strtolower($value);
        $value = "rulestore";

        $context->object->ReferencesStoreValidation($value);

        $refstore = $context->object->getReferencesStore();

        if( array_key_exists($value, $refstore) )
            return TRUE;

        return FALSE;

    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refstore']['operators']['is.only.rulestore'] = array(
    'Function' => function (AddressRQueryContext $context) {
        #$value = $context->value;
        #$value = strtolower($value);
        $value = "rulestore";

        $context->object->ReferencesStoreValidation($value);
        $refstore_array = $context->object->getReferencesStore();

        $return = FALSE;
        foreach( $refstore_array as $refstore => $value )
        {
            if( $refstore == $value )
                $return = TRUE;
            else
                return FALSE;
        }

        return $return;

    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refstore']['operators']['is.addressstore'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $value = "addressstore";

        $context->object->ReferencesStoreValidation($value);
        $refstore = $context->object->getReferencesStore();

        if( array_key_exists($value, $refstore) )
            return TRUE;

        return FALSE;

    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refstore']['operators']['is.only.addressstore'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $value = "addressstore";

        $context->object->ReferencesStoreValidation($value);
        $refstore_array = $context->object->getReferencesStore();

        $return = FALSE;
        foreach( $refstore_array as $refstore => $value )
        {
            if( $refstore == $value )
                $return = TRUE;
            else
                return FALSE;
        }

        return $return;

    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refstore']['operators']['is.logicalrouterstore'] = array(
    'Function' => function (AddressRQueryContext $context) {
        #$value = $context->value;
        #$value = strtolower($value);
        $value = "logicalrouterstore";

        $context->object->ReferencesStoreValidation($value);

        $refstore = $context->object->getReferencesStore();

        if( array_key_exists($value, $refstore) )
            return TRUE;

        return FALSE;

    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refstore']['operators']['is.virtualrouterstore'] = array(
    'Function' => function (AddressRQueryContext $context) {
        #$value = $context->value;
        #$value = strtolower($value);
        $value = "virtualrouterstore";

        $context->object->ReferencesStoreValidation($value);

        $refstore = $context->object->getReferencesStore();

        if( array_key_exists($value, $refstore) )
            return TRUE;

        return FALSE;

    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refstore']['operators']['is.tunnelifstore'] = array(
    'Function' => function (AddressRQueryContext $context) {
        #$value = $context->value;
        #$value = strtolower($value);
        $value = "tunnelifstore";

        $context->object->ReferencesStoreValidation($value);

        $refstore = $context->object->getReferencesStore();

        if( array_key_exists($value, $refstore) )
            return TRUE;

        return FALSE;

    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refstore']['operators']['is.gpgatewaystore'] = array(
    'Function' => function (AddressRQueryContext $context) {
        #$value = $context->value;
        #$value = strtolower($value);
        $value = "gpgatewaystore";

        $context->object->ReferencesStoreValidation($value);

        $refstore = $context->object->getReferencesStore();

        if( array_key_exists($value, $refstore) )
            return TRUE;

        return FALSE;

    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refstore']['operators']['is.ikegatewaystore'] = array(
    'Function' => function (AddressRQueryContext $context) {
        #$value = $context->value;
        #$value = strtolower($value);
        $value = "ikegatewaystore";

        $context->object->ReferencesStoreValidation($value);

        $refstore = $context->object->getReferencesStore();

        if( array_key_exists($value, $refstore) )
            return TRUE;

        return FALSE;

    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refstore']['operators']['is.ethernetifstore'] = array(
    'Function' => function (AddressRQueryContext $context) {
        #$value = $context->value;
        #$value = strtolower($value);
        $value = "ethernetifstore";

        $context->object->ReferencesStoreValidation($value);

        $refstore = $context->object->getReferencesStore();

        if( array_key_exists($value, $refstore) )
            return TRUE;

        return FALSE;

    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refstore']['operators']['is.gpportalstore'] = array(
    'Function' => function (AddressRQueryContext $context) {
        #$value = $context->value;
        #$value = strtolower($value);
        $value = "gpportalstore";

        $context->object->ReferencesStoreValidation($value);

        $refstore = $context->object->getReferencesStore();

        if( array_key_exists($value, $refstore) )
            return TRUE;

        return FALSE;

    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refstore']['operators']['is.gretunnelstore'] = array(
    'Function' => function (AddressRQueryContext $context) {
        #$value = $context->value;
        #$value = strtolower($value);
        $value = "gretunnelstore";

        $context->object->ReferencesStoreValidation($value);

        $refstore = $context->object->getReferencesStore();

        if( array_key_exists($value, $refstore) )
            return TRUE;

        return FALSE;

    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refstore']['operators']['is.loopbackifstore'] = array(
    'Function' => function (AddressRQueryContext $context) {
        #$value = $context->value;
        #$value = strtolower($value);
        $value = "loopbackifstore";

        $context->object->ReferencesStoreValidation($value);

        $refstore = $context->object->getReferencesStore();

        if( array_key_exists($value, $refstore) )
            return TRUE;

        return FALSE;

    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refstore']['operators']['is.vlanifstore'] = array(
    'Function' => function (AddressRQueryContext $context) {
        #$value = $context->value;
        #$value = strtolower($value);
        $value = "vlanifstore";

        $context->object->ReferencesStoreValidation($value);

        $refstore = $context->object->getReferencesStore();

        if( array_key_exists($value, $refstore) )
            return TRUE;

        return FALSE;

    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refstore']['operators']['is.zonestore'] = array(
    'Function' => function (AddressRQueryContext $context) {
        #$value = $context->value;
        #$value = strtolower($value);
        $value = "zonestore";

        $context->object->ReferencesStoreValidation($value);

        $refstore = $context->object->getReferencesStore();

        if( array_key_exists($value, $refstore) )
            return TRUE;

        return FALSE;

    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refstore']['operators']['all.interfacestore'] = array(
    'Function' => function (AddressRQueryContext $context) {
        #$value = $context->value;
        #$value = strtolower($value);
        $value = "tunnelifstore";
        $array_value[] = $value;
        $value = "vlanifstore";
        $array_value[] = $value;
        $value = "loopbackifstore";
        $array_value[] = $value;
        $value = "gretunnelstore";
        $array_value[] = $value;
        $value = "ethernetifstore";
        $array_value[] = $value;
        $value = "tunnelifstore";

        $context->object->ReferencesStoreValidation($value);

        $refstore = $context->object->getReferencesStore();

        foreach( $array_value as $value )
        {
            if( array_key_exists($value, $refstore) )
                return TRUE;
        }


        return FALSE;

    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['reftype']['operators']['is'] = array(
    'Function' => function (AddressRQueryContext $context) {
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
RQuery::$defaultFilters['address']['refobjectname']['operators']['is'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        $reference_array = $object->getReferences();

        foreach( $reference_array as $refobject )
        {
            if( get_class( $refobject ) == "AddressGroup" && $refobject->name() == $context->value )
                return TRUE;
            elseif( get_class( $refobject ) == "AddressRuleContainer" && $refobject->owner->name() == $context->value )
                return TRUE;
        }


        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object name matches refobjectname',
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refobjectname']['operators']['is.only'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $owner = $context->object->owner->owner;

        $reference_array = $object->getReferences();

        $return = FALSE;
        foreach( $reference_array as $refobject )
        {
            if( get_class( $refobject ) == "AddressGroup" && $refobject->name() == $context->value )
            {
                if( $return )
                    return FALSE;
                else
                    $return = TRUE;
            }

            elseif( get_class( $refobject ) == "AddressRuleContainer" && $refobject->owner->name() == $context->value )
                if( $return )
                    return FALSE;
                else
                    $return = TRUE;
        }

        return $return;

    },
    'arg' => TRUE,
    'help' => 'returns TRUE if RUE if object name matches only refobjectname',
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refobjectname']['operators']['is.recursive'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        $reference_array = $object->getReferencesRecursive();

        foreach( $reference_array as $refobject )
        {
            if( get_class( $refobject ) == "AddressGroup" && $refobject->name() == $context->value )
                return TRUE;
        }


        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object name matches refobjectname',
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refobject']['operators']['tag.has'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        $reference_array = $object->getReferences();

        foreach( $reference_array as $refobject )
        {
            if( get_class( $refobject ) == "AddressRuleContainer" )
            {
                /** @var AddressRuleContainer $refobject */
                $tmpTag = $refobject->owner->owner->owner->tagStore->find($context->value);
                if( $tmpTag == null )
                    return FALSE;
                if( $refobject->owner->tags->hasTag($tmpTag) )
                    return TRUE;
            }
        }


        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object name matches refobjectname',
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['value']['operators']['string.eq'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        if( $object->isGroup() )
            return null;

        if( $object->isRegion() || $object->isEDL())
            return null;

        if( $object->isAddress() )
        {
            if( $object->type() == 'ip-range' || $object->type() == 'ip-netmask' || $object->isType_TMP() )
            {
                if( $object->value() == $context->value )
                    return TRUE;
            }
        }
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['value']['operators']['ip4.match.exact'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        $values = explode(',', $context->value);


        if( !isset($context->cachedValueMapping) )
        {
            $mapping = new IP4Map();

            $count = 0;
            foreach( $values as $net )
            {
                $net = trim($net);
                if( strlen($net) < 1 )
                    derr("empty network/IP name provided for argument #$count");
                $mapping->addMap(IP4Map::mapFromText($net));
                $count++;
            }
            $context->cachedValueMapping = $mapping;
        }
        else
            $mapping = $context->cachedValueMapping;

        return $object->getIP4Mapping()->equals($mapping);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['value']['operators']['ip4.match.exact.from.file'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;


        if( !isset($context->cachedValueMapping) )
        {
            $text = file_get_contents($context->value);

            if( $text === false )
                derr("cannot open file '{$context->value}");

            #PH::print_stdout("--------");
            #PH::print_stdout($text);
            #PH::print_stdout("--------");
            $lines = explode("\n", $text);

            $mapping = new IP4Map();

            $count = 0;
            foreach( $lines as $net )
            {
                $net = trim($net);
                if( strlen($net) < 1 )
                {
                    continue;
                    derr("empty network/IP name provided for argument #$count");
                }

                $mapping->addMap(IP4Map::mapFromText($net));
                $count++;
            }
            $context->cachedValueMapping = $mapping;
        }
        else
            $mapping = $context->cachedValueMapping;

        return $object->getIP4Mapping()->equals($mapping);

    },
    'arg' => true
);
RQuery::$defaultFilters['address']['value']['operators']['ip4.included-in'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        if( $object->isEDL() )
            return null;

        if( $object->isAddress() && ( $object->isTmpAddr() || $object->isType_FQDN() ) )
            return null;

        if( $object->isGroup() && ( $object->isDynamic() || $object->count() < 1 || $object->hasFQDN() ) )
            return null;

        if( $context->value === "RFC1918" )
        {
            $values = array();
            $values[] = "10.0.0.0/8";
            $values[] = "172.16.0.0/12";
            $values[] = "192.168.0.0/16";
        }
        else
            $values = explode(',', $context->value);

        $mapping = new IP4Map();

        $count = 0;
        foreach( $values as $net )
        {
            $net = trim($net);
            if( strlen($net) < 1 )
                derr("empty network/IP name provided for argument #$count");
            $mapping->addMap(IP4Map::mapFromText($net));
            $count++;
        }

        return $object->getIP4Mapping()->includedInOtherMap($mapping) == 1;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml',
        'help' => "value ip4.included-in 1.1.1.1 or also possible with a variable 'value ip4.included-inl RFC1918' to cover all IPv4 private addresses"
    )
);
RQuery::$defaultFilters['address']['value']['operators']['ip4.includes-full'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        if( $object->isEDL() )
            return null;

        if( $object->isAddress() )
        {
            if( $object->isType_FQDN() )
                return null;
            elseif( $object->isTmpAddr() && $object->value() == "" )
                return null;
        }

        if( $object->isGroup() && ( $object->isDynamic() || $object->count() < 1 || $object->hasFQDN() ) )
            return null;

        if( $context->value === "RFC1918" )
        {
            $values = array();
            $values[] = "10.0.0.0/8";
            $values[] = "172.16.0.0/12";
            $values[] = "192.168.0.0/16";
        }
        else
            $values = explode(',', $context->value);

        $mapping = new IP4Map();

        $count = 0;
        foreach( $values as $net )
        {
            $net = trim($net);
            if( strlen($net) < 1 )
                derr("empty network/IP name provided for argument #$count");
            $mapping->addMap(IP4Map::mapFromText($net));
            $count++;
        }

        return $mapping->includedInOtherMap($object->getIP4Mapping()) == 1;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml',
        'help' => "value ip4.included-in 1.1.1.1 or also possible with a variable 'value ip4.included-in RFC1918' to cover all IPv4 private addresses"
    )
);
RQuery::$defaultFilters['address']['value']['operators']['ip4.includes-full-or-partial'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        if( $object->isEDL() )
            return null;

        if( $object->isAddress() )
        {
            if( $object->isType_FQDN() )
                return null;
            elseif( $object->isTmpAddr() && $object->value() == "" )
                return null;
        }

        if( $object->isGroup() && ( $object->isDynamic() || $object->count() < 1 || $object->hasFQDN() ) )
            return null;

        if( $context->value === "RFC1918" )
        {
            $values = array();
            $values[] = "10.0.0.0/8";
            $values[] = "172.16.0.0/12";
            $values[] = "192.168.0.0/16";
        }
        else
            $values = explode(',', $context->value);

        $mapping = new IP4Map();

        $count = 0;
        foreach( $values as $net )
        {
            $net = trim($net);
            if( strlen($net) < 1 )
                derr("empty network/IP name provided for argument #$count");
            $mapping->addMap(IP4Map::mapFromText($net));
            $count++;
        }

        return $mapping->includedInOtherMap($object->getIP4Mapping()) != 0;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml',
        'help' => "value ip4.includes-full-or-partial 1.1.1.1 or also possible with a variable 'value ip4.includes-full-or-partial RFC1918' to cover all IPv4 private addresses"
    )
);
RQuery::$defaultFilters['address']['value']['operators']['ip6.match.exact.from.file'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;


        if( !isset($context->cachedValueMapping) )
        {
            $text = file_get_contents($context->value);

            if( $text === false )
                derr("cannot open file '{$context->value}");

            #PH::print_stdout("--------");
            #PH::print_stdout($text);
            #PH::print_stdout("--------");
            $lines = explode("\n", $text);

            $mapping = new IP6Map();

            $count = 0;
            foreach( $lines as $net )
            {
                $net = trim($net);
                if( strlen($net) < 1 )
                {
                    continue;
                    #derr("empty network/IP name provided for argument #$count");
                }

                $mapping->addMap(IP6Map::mapFromText($net));
                $count++;
            }
            $context->cachedValueMapping = $mapping;
        }
        else
            $mapping = $context->cachedValueMapping;

        return $object->getIP6Mapping()->equals($mapping);

    },
    'arg' => true
);
RQuery::$defaultFilters['address']['value']['operators']['ip6.included-in.from.file'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        if( $object->isEDL() )
            return null;

        if( $object->isAddress() && ( $object->isTmpAddr() || $object->isType_FQDN() ) )
            return null;

        if( $object->isGroup() && ( $object->isDynamic() || $object->count() < 1 || $object->hasFQDN() ) )
            return null;


        if( !isset($context->cachedValueMapping) )
        {
            $text = file_get_contents($context->value);

            if( $text === false )
                derr("cannot open file '{$context->value}");

            $lines = explode("\n", $text);

            $mapping = new IP6Map();

            $count = 0;
            foreach( $lines as $net )
            {
                $net = trim($net);
                if( strlen($net) < 1 )
                    continue;

                $mapping->addMap(IP6Map::mapFromText($net));
                $count++;
            }
            $context->cachedValueMapping = $mapping;
        }
        else
            $mapping = $context->cachedValueMapping;

        return $object->getIP6Mapping()->includedInOtherMap($mapping) == 1;
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['address']['value']['operators']['ip6.includes-full.from.file'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        if( $object->isEDL() )
            return null;

        if( $object->isAddress() )
        {
            if( $object->isType_FQDN() )
                return null;
            elseif( $object->isTmpAddr() && $object->value() == "" )
                return null;
        }

        if( $object->isGroup() && ( $object->isDynamic() || $object->count() < 1 || $object->hasFQDN() ) )
            return null;


        if( !isset($context->cachedValueMapping) )
        {
            $text = file_get_contents($context->value);

            if( $text === false )
                derr("cannot open file '{$context->value}");

            $lines = explode("\n", $text);

            $mapping = new IP6Map();

            $count = 0;
            foreach( $lines as $net )
            {
                $net = trim($net);
                if( strlen($net) < 1 )
                    continue;

                $mapping->addMap(IP6Map::mapFromText($net));
                $count++;
            }
            $context->cachedValueMapping = $mapping;
        }
        else
            $mapping = $context->cachedValueMapping;

        return $mapping->includedInOtherMap($object->getIP6Mapping()) == 1;
    },
    'arg' => TRUE
    #'ci' => array('fString' => '(%PROP% 1.1.1.1)', 'input' => 'input/panorama-8.0.xml')
);
RQuery::$defaultFilters['address']['value']['operators']['ip6.includes-full-or-partial.from.file'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;

        if( $object->isAddress() )
        {
            if( $object->isType_FQDN() || $object->isEDL() )
                return null;
            elseif( $object->isTmpAddr() && $object->value() == "" )
                return null;
        }

        if( $object->isGroup() && ( $object->isDynamic() || $object->count() < 1 || $object->hasFQDN() ) )
            return null;

        if( !isset($context->cachedValueMapping) )
        {
            $text = file_get_contents($context->value);

            if( $text === false )
                derr("cannot open file '{$context->value}");

            $lines = explode("\n", $text);

            $mapping = new IP6Map();

            $count = 0;
            foreach( $lines as $net )
            {
                $net = trim($net);
                if( strlen($net) < 1 )
                {
                    continue;
                    #derr("empty network/IP name provided for argument #$count");
                }

                $mapping->addMap(IP6Map::mapFromText($net));
                $count++;
            }
            $context->cachedValueMapping = $mapping;
        }
        else
            $mapping = $context->cachedValueMapping;

        return $mapping->includedInOtherMap($object->getIP6Mapping()) != 0;
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['address']['value']['operators']['string.regex'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $regex = $context->value;

        if( $object->isGroup() )
            return null;

        if( $object->isRegion() || $object->isEDL())
            return null;

        if( $object->isAddress() )
        {
            if( $object->isTmpAddr() && $object->value() == "" )
                return null;
        }

        if( $object->isType_ipNetmask() || $object->isType_ipRange() || $object->isType_FQDN() || $object->isType_TMP() )
        {
            if( $object->isType_ipRange() || $object->isType_FQDN() || $object->isType_TMP() )
            {
                $addr_value = $object->value();
            }
            else
                $addr_value = $object->getNetworkValue();

            $matching = preg_match($context->value, $addr_value);
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;

        }

        return FALSE;
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['address']['value']['operators']['is.included-in.name'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( $object->isGroup()  )
        {
            return null;
        }


        if( $object->isType_ipNetmask() || $object->isType_ipRange() || $object->isType_FQDN() || $object->isType_TMP() )
        {
            $name = $object->name();
            if(  $object->isType_ipRange())
            {
                $addr_value = $object->value();
                $addr_value = explode( '-', $addr_value);
                $addr_value = $addr_value[0];
            }
            elseif( $object->isType_FQDN() || $object->isType_TMP() )
                $addr_value = $object->value();
            else
                $addr_value = $object->getNetworkValue();

            if( !empty( $addr_value ) && strpos(strtolower($name), strtolower($addr_value) ) !== FALSE )
            {
                $tmpPos = strpos( $name, $addr_value );
                $tmpPos += strlen( $addr_value);
                $substr = substr($name, $tmpPos, 1); //returns b
                if( is_numeric( $substr ) )
                    return FALSE;

                return true;
            }
        }

        return false;
    },
    'arg' => false
);
RQuery::$defaultFilters['address']['value']['operators']['is.in.file'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( !isset($context->cachedList) )
        {
            $text = file_get_contents($context->value);

            if( $text === false )
                derr("cannot open file '{$context->value}");

            $lines = explode("\n", $text);
            foreach( $lines as  $line)
            {
                $line = trim($line);
                if(strlen($line) == 0)
                    continue;
                $list[$line] = true;
            }

            $context->cachedList = &$list;
        }
        else
            $list = &$context->cachedList;

        if( !$object->isGroup() && !$object->isRegion() && !$object->isEDL() )
        {
            //TODO: if not IPv4 -  return false
            if( $object->getNetworkMask() == '32' )
                $addr_value = $object->getNetworkValue();
            else
                $addr_value = $object->value();

            return isset($list[ $addr_value ]);
            //TODO: if IPv6 check
        }
        else
            return false;

    },
    'arg' => true
);
RQuery::$defaultFilters['address']['value']['operators']['has.wrong.network'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( $object->isGroup() )
            return null;

        if( $object->isRegion() || $object->isEDL())
            return null;

        if( !$object->isType_ipNetmask() )
            return null;

        $value = $object->getNetworkValue();
        $netmask = $object->getNetworkMask();

        if( $netmask == '32' )
            return null;

        $calc_network = CIDR::cidr2network( $value, $netmask );

        if( $value != $calc_network )
            return true;

        return null;
    },
    'arg' => false
);
RQuery::$defaultFilters['address']['value']['operators']['netmask.blank32'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( $object->isGroup() )
            return null;

        if( $object->isRegion() || $object->isEDL())
            return null;

        if( !$object->isType_ipNetmask() )
            return null;

        $value = $object->getNetworkValue();
        $netmask = $object->getNetworkMask();

        if( $netmask == '32' )
            return true;

        return null;
    },
    'arg' => false
);

RQuery::$defaultFilters['address']['description']['operators']['regex'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( $object->isRegion() || $object->isEDL() )
            return FALSE;

        if( strlen($value) > 0 && $value[0] == '%' )
        {
            $value = substr($value, 1);
            if( !isset($context->nestedQueries[$value]) )
                derr("regular expression filter makes reference to unknown string alias '{$value}'");

            $value = $context->nestedQueries[$value];
        }

        $matching = preg_match($value, $object->description());
        if( $matching === FALSE )
            derr("regular expression error on '{$value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /test/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['description']['operators']['is.empty'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( $object->isRegion() || $object->isEDL() )
            return FALSE;

        if( strlen($object->description()) == 0 )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['address']['ip.count']['operators']['>,<,=,!'] = array(
    'Function' => function (AddressRQueryContext $context) {
        $object = $context->object;
        $arg = $context->value;

        $operator = $context->operator;
        if( $operator == '=' )
            $operator = '==';

        if( $object->isRegion() || $object->isEDL() )
        {
            //count IP addresses
            return false;
        }
        elseif( $object->isGroup() )
        {
            $int = 0;
            $members = $object->expand(FALSE);
            foreach( $members as $member )
                $int += $member->getIPcount();
        }
        else
            $int = $object->getIPcount();

        if( $int == FALSE )
            return FALSE;

        $operator_string = $int." ".$operator." ".$arg;

        if( eval("return $operator_string;" ) )
            return true;
        else
            return false;
    },
    'arg' => true,
    'help' => 'returns TRUE if object IP value describe multiple IP addresses; e.g. ip-range: 10.0.0.0-10.0.0.255 will match "ip.count > 200"',
    'ci' => array(
        'fString' => '(%PROP% 5)',
        'input' => 'input/panorama-8.0.xml'
    )
);
// </editor-fold>