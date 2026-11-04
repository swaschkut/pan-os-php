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

// <editor-fold desc=" ***** common filters *****" defaultstate="collapsed" >
//
// Filters with the same definition for several object types. Each is written once and registered
// for every listed type through RQuery::registerFilter(). A type-specific filter file loaded later may
// still define its own version of the same operator, which then replaces the common one for that type.
//
RQuery::registerFilter( array(
    'dns-rule',
    'threat-rule'
), 'action', 'eq', array(
    'Function' => function (RQueryContext $context) {
        /** @var ThreatPolicySpyware|ThreatPolicyVulnerability $object */
        $object = $context->object;
        $value = $context->value;

        if( $object->action == $value )
            return TRUE;

        return FALSE;

    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% reset-both )',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'rule',
    'securityprofilegroup'
), 'device', 'is.buckbeak', array(
    'Function' => function (RQueryContext $context) {
        $object = $context->object;

        $rootObject = PH::findRootObjectOrDie($context->object->owner->owner);

        if ( $rootObject->isBuckbeak() )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE
) );

RQuery::registerFilter( array(
    'rule',
    'address',
    'service'
), 'location', 'is', array(
    'Function' => function (RQueryContext $context) {
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
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP% shared)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'dns-rule',
    'securityprofile',
    'threat-rule'
), 'location', 'is', array(
    'Function' => function (RQueryContext $context) {
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
) );

RQuery::registerFilter( array(
    'edl',
    'gp-gateway',
    'gp-portal',
    'interface-management-profile',
    'log-profile',
    'profile',
    'schedule',
    'securityprofilegroup',
    'tag',
    'zone',
    'zone-protection-profile'
), 'location', 'is', array(
    'Function' => function (RQueryContext $context) {
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
) );

RQuery::registerFilter( array(
    'rule',
    'address',
    'dns-rule',
    'edl',
    'gp-gateway',
    'gp-portal',
    'interface-management-profile',
    'log-profile',
    'profile',
    'schedule',
    'securityprofile',
    'securityprofilegroup',
    'service',
    'tag',
    'threat-rule',
    'zone',
    'zone-protection-profile'
), 'location', 'regex', array(
    'Function' => function (RQueryContext $context) {
        $name = $context->object->getLocationString();
        $matching = preg_match($context->value, $name);
        if( $matching === FALSE )
            derr("regular expression error on '{$context->value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches the regular expression specified in argument',
    'ci' => array(
        'fString' => '(%PROP% /shared/)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'address',
    'service'
), 'member.name', 'is', array(
    'Function' => function (RQueryContext $context) {
        $object = $context->object;

        if( !$object->isGroup() )
            return FALSE;



        $member_name_array = array();
        foreach( $context->object->members() as $member_obj )
        {
            $member_name_array[$member_obj->name()] = $member_obj->name();
        }


        if( isset($member_name_array[$context->value]) )
            return TRUE;


        return FALSE;
    },
    'arg' => TRUE
) );

RQuery::registerFilter( array(
    'address',
    'service'
), 'member.name', 'is.in.file', array(
    'Function' => function (RQueryContext $context) {
        $object = $context->object;

        if( !$object->isGroup() )
            return FALSE;

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

        $member_name_array = array();
        foreach( $context->object->members() as $member_obj )
        {
            $member_name_array[$member_obj->name()] = $member_obj->name();
        }


        foreach( $list as $file_membername => $truefalse )
        {
            if( isset($member_name_array[$file_membername]) ) {
                return TRUE;
            }
        }

        return FALSE;
    },
    'arg' => TRUE
) );

RQuery::registerFilter( array(
    'address',
    'certificate',
    'threat'
), 'name', 'contains', array(
    'Function' => function (RQueryContext $context) {
        return strpos($context->object->name(), $context->value) !== FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object name contains the string specified in argument (case-sensitive; see contains.nocase)',
    'ci' => array(
        'fString' => '(%PROP% -)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'dns-rule',
    'edl',
    'gp-gateway',
    'gp-portal',
    'interface-management-profile',
    'log-profile',
    'profile',
    'schedule',
    'securityprofile',
    'securityprofilegroup',
    'tag',
    'threat-rule',
    'zone',
    'zone-protection-profile'
), 'name', 'contains', array(
    'Function' => function (RQueryContext $context) {
        return strpos($context->object->name(), $context->value) !== FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object name contains the string specified in argument (case-sensitive; see contains.nocase)',
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'rule',
    'service',
    'address',
    'certificate'
), 'name', 'eq', array(
    'Function' => function (RQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object name matches the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP% new test 1)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'app',
    'application',
    'threat'
), 'name', 'eq', array(
    'Function' => function (RQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object name matches the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP% ftp)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'dns-rule',
    'device',
    'edl',
    'gp-gateway',
    'gp-portal',
    'gre-tunnel',
    'ike-gateway',
    'ike-profile',
    'ipsec-profile',
    'ipsec-tunnel',
    'interface-management-profile',
    'log-profile',
    'profile',
    'schedule',
    'securityprofile',
    'securityprofilegroup',
    'tag',
    'threat-rule',
    'zone',
    'zone-protection-profile'
), 'name', 'eq', array(
    'Function' => function (RQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object name matches the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'rule',
    'service',
    'address',
    'certificate'
), 'name', 'eq.nocase', array(
    'Function' => function (RQueryContext $context) {
        return strtolower($context->object->name()) == strtolower($context->value);
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object name matches the one specified in argument, ignoring upper / lower case',
    'ci' => array(
        'fString' => '(%PROP% new test 2)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'dns-rule',
    'edl',
    'gp-gateway',
    'gp-portal',
    'interface-management-profile',
    'log-profile',
    'profile',
    'schedule',
    'securityprofile',
    'securityprofilegroup',
    'tag',
    'threat-rule',
    'zone',
    'zone-protection-profile'
), 'name', 'eq.nocase', array(
    'Function' => function (RQueryContext $context) {
        return strtolower($context->object->name()) == strtolower($context->value);
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object name matches the one specified in argument, ignoring upper / lower case',
    'ci' => array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'address',
    'rule',
    'service'
), 'name', 'has.wrong.characters', array(
    'Function' => function (RQueryContext $context) {
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
) );

RQuery::registerFilter( array(
    'rule',
    'address',
    'dns-rule',
    'device',
    'edl',
    'gp-gateway',
    'gp-portal',
    'interface-management-profile',
    'log-profile',
    'profile',
    'schedule',
    'securityprofile',
    'securityprofilegroup',
    'service',
    'tag',
    'threat-rule',
    'zone',
    'zone-protection-profile'
), 'name', 'is.in.file', array(
    'Function' => function (RQueryContext $context) {
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
) );

RQuery::registerFilter( array(
    'application',
    'interface',
    'dns-rule',
    'device',
    'edl',
    'gp-gateway',
    'gp-portal',
    'interface-management-profile',
    'log-profile',
    'profile',
    'schedule',
    'securityprofile',
    'securityprofilegroup',
    'tag',
    'threat-rule',
    'zone',
    'zone-protection-profile'
), 'name', 'regex', array(
    'Function' => function (RQueryContext $context) {
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
) );

RQuery::registerFilter( array(
    'address',
    'securityprofile'
), 'name.length', '>,<,=,!', array(
    'eval' => "strlen(\$object->name()) !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 63)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'address',
    'service'
), 'object', 'has.group.as.member', array(
    'Function' => function (RQueryContext $context) {


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
) );

RQuery::registerFilter( array(
    'address',
    'edl',
    'log-profile',
    'schedule',
    'securityprofilegroup',
    'service',
    'tag'
), 'object', 'has.same-name.other.level', array(
    'Function' => function (RQueryContext $context) {
        $status = $context->object->getSameNameLevelStatus();
        return $status['sameNameOtherLevel'];
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'address',
    'edl',
    'log-profile',
    'schedule',
    'securityprofilegroup',
    'service',
    'tag'
), 'object', 'is.overriden', array(
    'Function' => function (RQueryContext $context) {
        $status = $context->object->getSameNameLevelStatus();
        return $status['isOverridden'];
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'address',
    'edl',
    'log-profile',
    'schedule',
    'securityprofilegroup',
    'service',
    'tag'
), 'object', 'is.overriding', array(
    'Function' => function (RQueryContext $context) {
        $status = $context->object->getSameNameLevelStatus();
        return $status['isOverriding'];
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'application',
    'dns-rule',
    'edl',
    'interface-management-profile',
    'log-profile',
    'profile',
    'schedule',
    'securityprofile',
    'securityprofilegroup',
    'tag',
    'threat-rule',
    'zone',
    'zone-protection-profile'
), 'object', 'is.tmp', array(
    'Function' => function (RQueryContext $context) {
        return $context->object->isTmp();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'address',
    'service'
), 'object', 'is.unused', array(
    'Function' => function (RQueryContext $context) {
        $object = $context->object;

        return $object->objectIsUnused();
        #return $context->object->countReferences() == 0;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'dns-rule',
    'threat-rule'
), 'object', 'is.unused', array(
    'Function' => function (RQueryContext $context) {
        if( get_class($context->object ) == "PredefinedSecurityProfileURL" )
            return null;
        return $context->object->countReferences() == 0;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'edl',
    'log-profile',
    'schedule',
    'securityprofilegroup',
    'tag'
), 'object', 'is.unused', array(
    'Function' => function (RQueryContext $context) {
        return $context->object->objectIsUnused();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'gp-gateway',
    'gp-portal',
    'ike-gateway',
    'ike-profile',
    'ipsec-profile',
    'interface-management-profile',
    'profile',
    'zone',
    'zone-protection-profile'
), 'object', 'is.unused', array(
    'Function' => function (RQueryContext $context) {
        return $context->object->countReferences() == 0;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'address',
    'service'
), 'object', 'is.unused.recursive', array(
    'Function' => function (RQueryContext $context) {
        $object = $context->object;

        return $object->objectIsUnusedRecursive();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'address',
    'edl',
    'log-profile',
    'schedule',
    'securityprofilegroup',
    'service',
    'tag'
), 'object', 'overriden.at.lower.level', array(
    'Function' => function (RQueryContext $context) {
        $status = $context->object->getSameNameLevelStatus();
        return $status['overriddenAtLowerLevel'];
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'address',
    'edl',
    'log-profile',
    'schedule',
    'securityprofilegroup',
    'service',
    'tag'
), 'object', 'overrides.upper.level', array(
    'Function' => function (RQueryContext $context) {
        $status = $context->object->getSameNameLevelStatus();
        return $status['overridesUpperLevel'];
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'dns-rule',
    'threat-rule'
), 'packet-capture', 'eq', array(
    'Function' => function (RQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( $object->packetCapture == $value )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% single-packet )',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'address',
    'dns-rule',
    'edl',
    'gp-gateway',
    'gp-portal',
    'interface-management-profile',
    'log-profile',
    'profile',
    'schedule',
    'securityprofile',
    'securityprofilegroup',
    'service',
    'tag',
    'threat-rule',
    'zone',
    'zone-protection-profile'
), 'refcount', '>,<,=,!', array(
    'eval' => '$object->countReferences() !operator! !value!',
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'address',
    'service',
    'dns-rule',
    'edl',
    'gp-gateway',
    'gp-portal',
    'interface-management-profile',
    'log-profile',
    'profile',
    'schedule',
    'securityprofile',
    'securityprofilegroup',
    'tag',
    'threat-rule',
    'zone',
    'zone-protection-profile'
), 'reflocation', 'is', array(
    'Function' => function (RQueryContext $context) {
        $object = $context->object;
        // root config: works for every type (object->owner->owner is not the location for all types)
        $owner = PH::findRootObjectOrDie($object);

        $reflocation_array = $object->getReferencesLocation();

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
    'help' => 'returns TRUE if the object is referenced from the location (shared/device-group/vsys name) specified in argument',
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'address',
    'service'
), 'reflocationcount', '>,<,=,!', array(
    'eval' => '$object->countLocationReferences() !operator! !value!',
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'address',
    'edl',
    'gp-gateway',
    'gp-portal',
    'interface-management-profile',
    'log-profile',
    'profile',
    'schedule',
    'securityprofilegroup',
    'service',
    'tag',
    'zone',
    'zone-protection-profile'
), 'refstore', 'is', array(
    'Function' => function (RQueryContext $context) {
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
) );

RQuery::registerFilter( array(
    'dns-rule',
    'securityprofile',
    'threat-rule'
), 'refstore', 'is', array(
    'Function' => function (RQueryContext $context) {
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
) );

RQuery::registerFilter( array(
    'address',
    'service',
    'tag'
), 'refstore', 'is.rulestore', array(
    'Function' => function (RQueryContext $context) {
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
) );

RQuery::registerFilter( array(
    'address',
    'edl',
    'gp-gateway',
    'gp-portal',
    'interface-management-profile',
    'log-profile',
    'profile',
    'schedule',
    'securityprofilegroup',
    'service',
    'tag',
    'zone',
    'zone-protection-profile'
), 'reftype', 'is', array(
    'Function' => function (RQueryContext $context) {
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
) );

RQuery::registerFilter( array(
    'dns-rule',
    'securityprofile',
    'threat-rule'
), 'reftype', 'is', array(
    'Function' => function (RQueryContext $context) {
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
) );

RQuery::registerFilter( array(
    'rule',
    'service'
), 'tag.count', '>,<,=,!', array(
    'eval' => "\$object->tags->count() !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

// location hierarchy: one definition for every type with a location; logic in PH::locationIsChildOf() / PH::locationIsParentOf()
RQuery::registerFilter( array(
    'profile',
    'address',
    'dns-rule',
    'edl',
    'gp-gateway',
    'gp-portal',
    'interface-management-profile',
    'log-profile',
    'rule',
    'schedule',
    'securityprofile',
    'securityprofilegroup',
    'service',
    'tag',
    'threat-rule',
    'zone',
    'zone-protection-profile'
), 'location', 'is.child.of', array(
    'Function' => function (RQueryContext $context) {
        return PH::locationIsChildOf( $context->object, $context->value );
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) is the one specified in argument or one of its descendants (shared: every object). Objects in a template are not listed.',
    'ci' => array(
        'fString' => '(%PROP%  Datacenter-Firewalls)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'profile',
    'address',
    'dns-rule',
    'edl',
    'gp-gateway',
    'gp-portal',
    'interface-management-profile',
    'log-profile',
    'rule',
    'schedule',
    'securityprofile',
    'securityprofilegroup',
    'service',
    'tag',
    'threat-rule',
    'zone',
    'zone-protection-profile'
), 'location', 'is.parent.of', array(
    'Function' => function (RQueryContext $context) {
        return PH::locationIsParentOf( $context->object, $context->value );
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) is the one specified in argument or one of its ancestors (shared: only objects in shared). Objects in a template are not listed.',
    'ci' => array(
        'fString' => '(%PROP%  Datacenter-Firewalls)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

// name contains: case-sensitive for every type (rule used to compare case-insensitively); case-insensitive variant: contains.nocase
RQuery::registerFilter( array(
    'rule',
    'service'
), 'name', 'contains', array(
    'Function' => function (RQueryContext $context) {
        return strpos($context->object->name(), $context->value) !== FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object name contains the string specified in argument (case-sensitive; see contains.nocase)',
    'ci' => array(
        'fString' => '(%PROP% udp)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'address',
    'certificate',
    'dns-rule',
    'edl',
    'gp-gateway',
    'gp-portal',
    'interface-management-profile',
    'log-profile',
    'profile',
    'rule',
    'schedule',
    'securityprofile',
    'securityprofilegroup',
    'service',
    'tag',
    'threat',
    'threat-rule',
    'zone',
    'zone-protection-profile'
), 'name', 'contains.nocase', array(
    'Function' => function (RQueryContext $context) {
        return stripos($context->object->name(), $context->value) !== FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object name contains the string specified in argument, ignoring upper / lower case',
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

// is.member.of: DIRECT membership for address and service (recursive: is.recursive.member.of)
RQuery::registerFilter( array(
    'address',
    'service'
), 'object', 'is.member.of', array(
    'Function' => function (RQueryContext $context) {
        $group = $context->object->owner->find($context->value);

        if( $group === null )
            return FALSE;
        if( !$group->isGroup() )
            derr( "'" . $context->value . "' is not a group", null, FALSE );

        return $group->has($context->object) === TRUE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if the object is a direct member of the group specified in argument (members of sub-groups: is.recursive.member.of)',
    'ci' => array(
        'fString' => '(%PROP% shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

// reflocation is.only: referenced at least once, and only from the location specified (one definition for all types)
RQuery::registerFilter( array(
    'address',
    'dns-rule',
    'edl',
    'gp-gateway',
    'gp-portal',
    'interface-management-profile',
    'log-profile',
    'profile',
    'schedule',
    'securityprofile',
    'securityprofilegroup',
    'service',
    'tag',
    'threat-rule',
    'zone',
    'zone-protection-profile'
), 'reflocation', 'is.only', array(
    'Function' => function (RQueryContext $context) {
        $reflocations = $context->object->getReferencesLocation();

        if( count($reflocations) == 0 )
            return FALSE;

        foreach( $reflocations as $reflocation )
        {
            if( strtolower($reflocation) != strtolower($context->value) )
                return FALSE;
        }

        return TRUE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if the object is referenced, and only from the location (shared/device-group/vsys name) specified in argument',
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
) );

// template / managed-device filters for zone and zone-protection-profile: template found by PH::findTemplateOwner()
RQuery::registerFilter( array(
    'zone',
    'zone-protection-profile'
), 'template.owner', 'is.unused', array(
    'Function' => function (RQueryContext $context) {
        $object = $context->object;

        $template = PH::findTemplateOwner( $object );
        if( $template === null )
            return null;   // not inside a template / template-stack

        if( count($template->getReferences()) == 0 )
            return true;
        else
            return false;

        return null;
    },
    'arg' => FALSE
) );

RQuery::registerFilter( array(
    'zone',
    'zone-protection-profile'
), 'template.owner', 'is.unused.recursive', array(
    'Function' => function (RQueryContext $context) {
        $owner = PH::findTemplateOwner( $context->object );   // the Template, or the TemplateStack for a zone the stack defines itself
        if( !is_object( $owner ) || !method_exists( $owner, 'managedDevices' ) )
            return null;
        $devices = $owner->managedDevices();

        // unused when no template stack that holds the template carries a firewall
        return count( $devices ) == 0;
    },
    'arg' => FALSE,
    'help' => "TRUE when no template stack holding the owning template (or the owning template stack itself) carries a firewall"
) );

RQuery::registerFilter( array(
    'zone',
    'zone-protection-profile'
), 'manageddevice', 'is.in.file', array(
    'Function' => function (RQueryContext $context) {
        $list = $context->cachedNameList( TRUE );
        $owner = PH::findTemplateOwner( $context->object );   // the Template, or the TemplateStack for a zone the stack defines itself
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
) );

RQuery::registerFilter( array(
    'zone',
    'zone-protection-profile'
), 'manageddevice', 'is.in.list', array(
    'Function' => function (RQueryContext $context) {
        $list = $context->cachedNameList( FALSE );
        $owner = PH::findTemplateOwner( $context->object );   // the Template, or the TemplateStack for a zone the stack defines itself
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
) );

RQuery::registerFilter( array(
    'zone',
    'zone-protection-profile'
), 'manageddevice.all', 'is.in.file', array(
    'Function' => function (RQueryContext $context) {
        $list = $context->cachedNameList( TRUE );
        $owner = PH::findTemplateOwner( $context->object );   // the Template, or the TemplateStack for a zone the stack defines itself
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
) );

RQuery::registerFilter( array(
    'zone',
    'zone-protection-profile'
), 'manageddevice.all', 'is.in.list', array(
    'Function' => function (RQueryContext $context) {
        $list = $context->cachedNameList( FALSE );
        $owner = PH::findTemplateOwner( $context->object );   // the Template, or the TemplateStack for a zone the stack defines itself
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
) );

RQuery::registerFilter( array(
    'zone',
    'zone-protection-profile'
), 'manageddevice.all', 'with-no-dg', array(
    'Function' => function (RQueryContext $context) {
        $owner = PH::findTemplateOwner( $context->object );   // the Template, or the TemplateStack for a zone the stack defines itself
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
) );

RQuery::registerFilter( array(
    'zone',
    'zone-protection-profile'
), 'manageddevice', 'with-no-dg', array(
    'Function' => function (RQueryContext $context) {
        $owner = PH::findTemplateOwner( $context->object );   // the Template, or the TemplateStack for a zone the stack defines itself
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
) );

// is.group: address and service (isGroup() returns a bool, so '== TRUE' and the plain value are the same)
RQuery::registerFilter( array(
    'address',
    'service'
), 'object', 'is.group', array(
    'Function' => function (RQueryContext $context) {
        return $context->object->isGroup() == TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

// tag has: address and service (rule keeps its own definition)
RQuery::registerFilter( array(
    'address',
    'service'
), 'tag', 'has', array(
    'Function' => function (RQueryContext $context) {
        // address regions have no tags
        if( method_exists($context->object, 'isRegion') && $context->object->isRegion() )
            return FALSE;
        return $context->object->tags->hasTag($context->value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->tags->parentCentralStore->find('!value!');",
    'ci' => array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

// tag has.nocase: address and service (rule keeps its own definition)
RQuery::registerFilter( array(
    'address',
    'service'
), 'tag', 'has.nocase', array(
    'Function' => function (RQueryContext $context) {
        // address regions have no tags
        if( method_exists($context->object, 'isRegion') && $context->object->isRegion() )
            return FALSE;
        return $context->object->tags->hasTag($context->value, FALSE) === TRUE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% test)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

// tag has.regex: address and service (rule keeps its own definition)
RQuery::registerFilter( array(
    'address',
    'service'
), 'tag', 'has.regex', array(
    'Function' => function (RQueryContext $context) {
        // address regions have no tags
        if( method_exists($context->object, 'isRegion') && $context->object->isRegion() )
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
) );

// refobject tag.has: address / service / tag; the referencing container class decides
RQuery::registerFilter( array(
    'address',
    'service',
    'tag'
), 'refobject', 'tag.has', array(
    'Function' => function (RQueryContext $context) {
        $object = $context->object;

        $reference_array = $object->getReferences();

        foreach( $reference_array as $refobject )
        {
            if( in_array( get_class( $refobject ), array( "AddressRuleContainer", "ServiceRuleContainer", "TagRuleContainer" ), TRUE ) )
            {
                /** @var AddressRuleContainer|ServiceRuleContainer|TagRuleContainer $refobject */
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
) );

// is.predefined: application / log-profile / securityprofile
RQuery::registerFilter( array(
    'application',
    'log-profile',
    'securityprofile'
), 'object', 'is.predefined', array(
    'Function' => function (RQueryContext $context) {
        $object = $context->object;
        if( is_string($object) )
            return null;

        // application: own type information; log-profile / security profile: object lives in a predefined store
        if( method_exists($object, 'isPredefined') )
            return $object->isPredefined() == TRUE;

        return str_contains($object->owner->name(), "predefined");
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

// </editor-fold>
