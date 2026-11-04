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
    'ci' => array(
        'fString' => '(%PROP% grp)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'address',
    'certificate'
), 'name', 'eq', array(
    'Function' => function (RQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
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
    'ci' => array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'address',
    'certificate'
), 'name', 'eq.nocase', array(
    'Function' => function (RQueryContext $context) {
        return strtolower($context->object->name()) == strtolower($context->value);
    },
    'arg' => TRUE,
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
        $owner = $context->object->owner->owner;

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
    'ci' => array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
) );

RQuery::registerFilter( array(
    'dns-rule',
    'securityprofile',
    'threat-rule'
), 'reflocation', 'is.only', array(
    'Function' => function (RQueryContext $context) {
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
), 'reflocation', 'is.only', array(
    'Function' => function (RQueryContext $context) {
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

// </editor-fold>
