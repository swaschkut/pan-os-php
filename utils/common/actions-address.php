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

AddressCallContext::$commonActionFunctions['edl-create-list'] = array(
    'function' => function (AddressCallContext $context, $type = 'ip-netmask')
    {
        $object = $context->object;

        $filename = $context->arguments['filename'];

        if( !$object->isGroup() )
        {
            $string = "Address object is not of type ADDRESS-GROUP";
            PH::ACTIONstatus( $context, 'skipped', $string);
            return false;
        }

        $tmp_array = array();
        $list_array = array();
        if( $object->isGroup() )
        {
            $members = $object->expand(FALSE, $tmp_array, $object->owner->owner);

            foreach( $members as $member )
            {
                /** @var $member Address */
                if( $type == 'ip-netmask' )
                {
                    if( $member->isType_ipNetmask() || $member->isType_ipRange() )
                        $list_array[] = $member->value();
                }
                elseif( $type == 'fqdn' )
                {
                    if( $member->isType_FQDN() )
                        $list_array[] = $member->value();
                }
            }
        }
        $file_content = "";
        foreach( $list_array as $entry )
        {
            print $entry."\n";
            $file_content .= $entry."\n";
        }
        if( !empty($file_content) )
            file_put_contents($filename, $file_content, FILE_APPEND);
    }
);


AddressCallContext::$supportedActions[] = array(
    'name' => 'delete',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            $string = "this object is used by other objects and cannot be deleted (use delete-Force to try anyway)";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);
    },
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'delete-Force',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            $string = "this object seems to be used so deletion may fail.";
            PH::ACTIONstatus( $context, "WARNING", $string );
        }

        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);
    },
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'decommission',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $context->arguments['file'] !== "false" )
        {
            if( !isset($context->cachedList) )
            {
                $text = file_get_contents($context->arguments['file']);

                if( $text === FALSE )
                    derr("cannot open file '{$context->arguments['file']}");

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
        }
        else
            $list[] = $object->name();

        foreach( $list as $key => $item )
        {
            if( $object->countReferences() != 0 )
            {
                $string = "delete all references: " ;
                PH::ACTIONlog( $context, $string );
                $object->display_references();

                if( $context->isAPI )
                    $object->API_removeWhereIamUsed(TRUE);
                else
                    $object->removeWhereIamUsed(TRUE);
            }

            //error handling enabled because of address object reference settings in :
            //- interfaces: ethernet/vlan/loopback/tunnel
            //- IKE gateway
            // is not implemented yet
            PH::enableExceptionSupport();
            try
            {
                if( $object->owner != null )
                {
                    if( $context->isAPI )
                        $object->owner->API_remove($object);
                    else
                        $object->owner->remove($object);
                    $string = "finally delete address object: " . $object->name();
                    PH::ACTIONlog( $context, $string );
                }


            } catch(Exception $e)
            {
                PH::disableExceptionSupport();
                PH::print_stdout();
                PH::print_stdout();
                $string = PH::boldText("  ***** an error occured : ") . $e->getMessage();
                PH::ACTIONlog( $context, $string );

                $string = PH::boldText("address object: " . $object->name() . " can not be removed. Check error message above.");
                PH::ACTIONlog( $context, $string );

                return;
            }
        }
    },
    'args' => array(
        'file' => array('type' => 'string', 'default' => 'false'),
    ),
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'replace-IP-by-MT-like-Object',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( !$object->isTmpAddr() )
        {
            $string = "because object is not temporary or not an IP address/netmask";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( !$object->nameIsValidRuleIPEntry() )
        {
            $string = "because object is not an IP address/netmask or range";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $prefix = array();
        $prefix['host'] = "H-";

        $prefix['network'] = "N-";
        $prefix['networkmask'] = "-";

        $prefix['range'] = "R-";
        $prefix['rangeseparator'] = "-";

        $object->replaceIPbyObject( $context, $prefix );
    },
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'removeWhereUsed',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $context->isAPI )
            $object->API_removeWhereIamUsed(TRUE, $context->padding, $context->arguments['actionIfLastMemberInRule']);
        else
            $object->removeWhereIamUsed(TRUE, $context->padding, $context->arguments['actionIfLastMemberInRule']);
    },
    'args' => array('actionIfLastMemberInRule' => array('type' => 'string',
        'default' => 'delete',
        'choices' => array('delete', 'disable', 'setAny')
    ),
    ),
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'addObjectWhereUsed',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        $foundObject = $object->owner->find($context->arguments['objectName']);

        if( $foundObject === null )
            derr("cannot find an object named '{$context->arguments['objectName']}'");

        if( $context->isAPI )
            $object->API_addObjectWhereIamUsed($foundObject, TRUE, $context->padding . '  ', FALSE, $context->arguments['skipNatRules']);
        else
            $object->addObjectWhereIamUsed($foundObject, TRUE, $context->padding . '  ', FALSE, $context->arguments['skipNatRules']);
    },
    'args' => array('objectName' => array('type' => 'string', 'default' => '*nodefault*'),
        'skipNatRules' => array('type' => 'bool', 'default' => FALSE))
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'add-member',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        $addressObjectName = $context->arguments['addressobjectname'];

        if( !$object->isGroup() )
        {
            $string = "because object is not an address group";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $address0bjectToAdd = $object->owner->find($addressObjectName);
        if( $address0bjectToAdd === null )
        {
            $string = "because address object name: " . $addressObjectName . " not found";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $object->has($address0bjectToAdd) )
        {
            $string = "because address object is already a member of this address group";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $address0bjectToAdd->isType_ipWildcard() )
        {
            $string = "because wildcard address object can not be added as a member to a address group";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $context->isAPI )
            $object->API_addMember($address0bjectToAdd);
        else
            $object->addMember($address0bjectToAdd);

        return;

    },
    'args' => array(
        'addressobjectname' => array('type' => 'string', 'default' => '*nodefault*')
    )
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'AddToGroup',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        $objectlocation = $object->getLocationString();

        $addressGroupName = $context->arguments['addressgroupname'];
        $deviceGroupName = $context->arguments['devicegroupname'];

        if( $object->name() == $addressGroupName )
        {
            $string = "because address group can not added to itself";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $deviceGroupName == '*nodefault*' || $objectlocation == $deviceGroupName )
            $addressGroupToAdd = $object->owner->find($addressGroupName);
        else
        {
            if( get_class($object->owner->owner) == "DeviceGroup" )
            {
                if( isset($object->owner->owner->childDeviceGroups(TRUE)[$objectlocation]) )
                {
                    $string = "because address object is configured in Child DeviceGroup";
                    PH::ACTIONstatus( $context, "SKIPPED", $string );
                    return;
                }
                if( !isset($object->owner->owner->parentDeviceGroups()[$deviceGroupName]) )
                {
                    $string = "because address object is configured at another child DeviceGroup at same level";
                    PH::ACTIONstatus( $context, "SKIPPED", $string );
                    return;
                }

                $deviceGroupToAdd = $object->owner->owner->childDeviceGroups(TRUE)[$deviceGroupName];
            }
            elseif( get_class($object->owner->owner) == "PanoramaConf" )
                $deviceGroupToAdd = $object->owner->owner->findDeviceGroup($deviceGroupName);
            elseif( get_class($object->owner->owner) == "PANConf" )
                $deviceGroupToAdd = $object->owner->owner->findVirtualSystem($deviceGroupName);
            else
                derr("action is not defined yet for class: " . get_class($object->owner->owner));

            $addressGroupToAdd = $deviceGroupToAdd->addressStore->find($addressGroupName);
        }

        if( $addressGroupToAdd === null )
        {
            $string = "because address group name: " . $addressGroupName . " not found";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $addressGroupToAdd->isDynamic() )
        {
            $string = "because address group name: " . $addressGroupName . " is not static.";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $addressGroupToAdd->has($object) )
        {
            $string = "because address object is already a member of this address group";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $context->isAPI )
            $addressGroupToAdd->API_addMember($object);
        else
            $addressGroupToAdd->addMember($object);

        return;

    },
    'args' => array(
        'addressgroupname' => array('type' => 'string', 'default' => '*nodefault*'),
        'devicegroupname' => array(
            'type' => 'string',
            'default' => '*nodefault*',
            'help' =>
                "please define a DeviceGroup name for Panorama config or vsys name for Firewall config.\n"
        )
    )
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'replaceWithObject',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        $objectRefs = $object->getReferences();

        $foundObject = $object->owner->find($context->arguments['objectName']);

        if( $foundObject === null )
            derr("cannot find an object named '{$context->arguments['objectName']}'");

        /** @var AddressGroup|AddressRuleContainer $objectRef */

        foreach( $objectRefs as $objectRef )
        {
            $string = "replacing in {$objectRef->toString()}";
            PH::ACTIONlog( $context, $string );
            if( $context->isAPI )
                $objectRef->API_replaceReferencedObject($object, $foundObject);
            else
                $objectRef->replaceReferencedObject($object, $foundObject);
        }

    },
    'args' => array('objectName' => array('type' => 'string', 'default' => '*nodefault*')),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'tag-Add',
    'section' => 'tag',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        if( $object->isTmpAddr() )
        {
            $string = "because object is temporary";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $object->isRegion() )
        {
            $string = "because object is of type REGION";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $objectFind = $object->tags->parentCentralStore->find($context->arguments['tagName']);
        if( $objectFind === null )
            derr("tag named '{$context->arguments['tagName']}' not found");

        if( $context->isAPI )
            $object->tags->API_addTag($objectFind);
        else
            $object->tags->addTag($objectFind);
    },
    'args' => array('tagName' => array('type' => 'string', 'default' => '*nodefault*')),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'tag-Add-Force',
    'section' => 'tag',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            $string = "because object is temporary";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $object->isRegion() )
        {
            $string = "because object is of type REGION";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $context->isAPI )
        {
            $objectFind = $object->tags->parentCentralStore->find($context->arguments['tagName']);
            if( $objectFind === null )
                $objectFind = $object->tags->parentCentralStore->API_createTag($context->arguments['tagName']);
        }
        else
            $objectFind = $object->tags->parentCentralStore->findOrCreate($context->arguments['tagName']);

        if( $context->isAPI )
            $object->tags->API_addTag($objectFind);
        else
            $object->tags->addTag($objectFind);
    },
    'args' => array('tagName' => array('type' => 'string', 'default' => '*nodefault*')),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'tag-Remove',
    'section' => 'tag',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        if( $object->isTmpAddr() )
        {
            $string = "because object is temporary";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $object->isRegion() )
        {
            $string = "because object is of type REGION";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $objectFind = $object->tags->parentCentralStore->find($context->arguments['tagName']);
        if( $objectFind === null )
            derr("tag named '{$context->arguments['tagName']}' not found");

        if( $context->isAPI )
            $object->tags->API_removeTag($objectFind);
        else
            $object->tags->removeTag($objectFind);
    },
    'args' => array('tagName' => array('type' => 'string', 'default' => '*nodefault*')),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'tag-Remove-All',
    'section' => 'tag',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        if( $object->isTmpAddr() )
        {
            $string = "because object is temporary";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $object->isRegion() )
        {
            $string = "because object is of type REGION";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        foreach( $object->tags->tags() as $tag )
        {
            $text = $context->padding . "  - removing tag {$tag->name()}... ";
            if( $context->isAPI )
                $object->tags->API_removeTag($tag);
            else
                $object->tags->removeTag($tag);

            PH::ACTIONlog( $context, $text );
        }
    },
    //'args' => Array( 'tagName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'tag-Remove-Regex',
    'section' => 'tag',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        if( $object->isTmpAddr() )
        {
            $string = "because object is temporary";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $object->isRegion() )
        {
            $string = "because object is of type REGION";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $pattern = '/' . $context->arguments['regex'] . '/';
        foreach( $object->tags->tags() as $tag )
        {
            $result = preg_match($pattern, $tag->name());
            if( $result === FALSE )
                derr("'$pattern' is not a valid regex");
            if( $result == 1 )
            {
                $text = $context->padding . "  - removing tag {$tag->name()}... ";
                if( $context->isAPI )
                    $object->tags->API_removeTag($tag);
                else
                    $object->tags->removeTag($tag);

                PH::ACTIONlog( $context, $text );
            }
        }
    },
    'args' => array('regex' => array('type' => 'string', 'default' => '*nodefault*')),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'tag-add_lower_level_object',
    'MainFunction' => function (AddressCallContext $context)
    {
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

        $objectFind = $object->tags->parentCentralStore->find($context->arguments['tagName']);
        if( $objectFind === null )
            derr("tag named '{$context->arguments['tagName']}' not found");
        foreach( $locations as $deviceGroup )
        {
            $tmp_obj = $deviceGroup->addressStore->find($object->name(), null, FALSE);
            if( $tmp_obj !== null )
            {
                if( $context->isAPI )
                    $ret = $tmp_obj->tags->API_addTag($objectFind);
                else
                    $ret = $tmp_obj->tags->addTag($objectFind);

                if( $ret )
                    PH::print_stdout( $context->padding." * DG: '".$deviceGroup->name()."' OBJ: '".$tmp_obj->name()."' - add TAG: '".$objectFind->name()."'" );
            }
        }

    },
    'args' => array('tagName' => array('type' => 'string', 'default' => '*nodefault*')),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'z_BETA_summarize',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( !$object->isGroup() )
        {
            $string = "because object is not a group";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( $object->isDynamic() )
        {
            $string = "because group is dynamic";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        /** @var AddressGroup $object */
        $tmp_array = array();
        $members = $object->expand(FALSE,$tmp_array, $object->owner->owner);
        $mapping = new IP4Map();

        $listOfNotConvertibleObjects = array();

        foreach( $members as $member )
        {
            if( $member->isGroup() )
                derr('this is not supported');
            if( $member->type() == 'fqdn' )
            {
                $listOfNotConvertibleObjects[] = $member;
            }

            $mapping->addMap($member->getIP4Mapping(), TRUE);
        }
        $mapping->sortAndRecalculate();

        $object->removeAll();
        foreach( $listOfNotConvertibleObjects as $obj )
            $object->addMember($obj);

        foreach( $mapping->getMapArray() as $entry )
        {
            //Todo: swaschkut 20210421 - long2ip not working with IPv6 use cidr::inet_itop
            $objectName = 'R-' . long2ip($entry['start']) . '-' . long2ip($entry['start']);
            $newObject = $object->owner->find($objectName, null, false);
            if( $newObject === null )
                $newObject = $object->owner->newAddress($objectName, 'ip-range', long2ip($entry['start']) . '-' . long2ip($entry['start']));
            $object->addMember($newObject);
        }

        $string = "group had " . count($members) . " expanded members vs {$mapping->count()} IP4 entries and " . count($listOfNotConvertibleObjects) . " unsupported objects";
        PH::ACTIONlog( $context, $string );

    },
);


AddressCallContext::$supportedActions[] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (AddressCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (AddressCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;

        $addWhereUsed = FALSE;
        $addUsedInLocation = FALSE;
        $addResolveGroupIPCoverage = FALSE;
        $addNestedMembers = FALSE;
        $addResolveIPNestedMembers = FALSE;
        $addResolveLocationNestedMembers = FALSE;
        $addNestedMembersCount = FALSE;

        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = TRUE;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = TRUE;

        if( isset($optionalFields['ResolveIP']) )
            $addResolveGroupIPCoverage = TRUE;

        if( isset($optionalFields['NestedMembers']) )
        {
            $addNestedMembers = TRUE;
            $addResolveIPNestedMembers = TRUE;
            $addResolveLocationNestedMembers = TRUE;
            $addNestedMembersCount = TRUE;
        }


        $headers = '<th>ID</th><th>location</th><th>name</th><th>type</th><th>value</th><th>description</th><th>Memberscount</th><th>IPcount</th><th>tags</th>';

        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';
        if( $addResolveGroupIPCoverage )
            $headers .= '<th>ip resolution</th>';
        if( $addNestedMembers )
            $headers .= '<th>nested members</th>';
        if( $addResolveIPNestedMembers )
            $headers .= '<th>nested members ip resolution</th>';
        if( $addResolveLocationNestedMembers )
            $headers .= '<th>nested members location resolution</th>';
        if( $addNestedMembersCount )
            $headers .= '<th>nested members count</th>';

        $lines = '';

        $count = 0;
        if( isset($context->objectList) )
        {
            foreach( $context->objectList as $object )
            {
                $count++;

                /** @var Address|AddressGroup $object */
                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $context->encloseFunction( (string)$count );

                if( isset($object->owner) && isset($object->owner->owner) )
                {
                    if($object->owner->owner->isPanorama() || $object->owner->owner->isFirewall() )
                        $lines .= $context->encloseFunction('shared');
                    else
                        $lines .= $context->encloseFunction($object->owner->owner->name());
                }
                else
                    $lines .= $context->encloseFunction("---");


                $lines .= $context->encloseFunction($object->name());

                if( $object->isGroup() )
                {
                    if( $object->isDynamic() )
                    {
                        $lines .= $context->encloseFunction('group-dynamic');
                        #$lines .= $context->encloseFunction('');
                        $lines .= $context->encloseFunction($object->members());
                    }
                    else
                    {
                        $lines .= $context->encloseFunction('group-static');
                        $lines .= $context->encloseFunction($object->members());
                    }
                    $lines .= $context->encloseFunction($object->description(), FALSE);
                    if( $object->isGroup() )
                        $lines .= $context->encloseFunction( (string)count( $object->members() ));
                    else
                        $lines .= $context->encloseFunction( '---' );

                    $counter = 0;
                    $members = $object->expand(FALSE, $tmp_array, $object->owner->owner);
                    foreach( $members as $member )
                        $counter += $member->getIPcount();
                    $lines .= $context->encloseFunction((string)$counter);

                    $lines .= $context->encloseFunction($object->tags->tags());
                }
                elseif( $object->isAddress() )
                {
                    if( $object->isTmpAddr() )
                    {
                        $lines .= $context->encloseFunction('unknown');
                        $lines .= $context->encloseFunction('');
                        $lines .= $context->encloseFunction('');
                        $lines .= $context->encloseFunction('');
                        $lines .= $context->encloseFunction('');
                    }
                    else
                    {
                        $lines .= $context->encloseFunction($object->type());
                        $lines .= $context->encloseFunction($object->value());
                        $lines .= $context->encloseFunction($object->description(), FALSE);
                        $lines .= $context->encloseFunction( '---' );
                        $lines .= $context->encloseFunction( (string)$object->getIPcount() );
                        $lines .= $context->encloseFunction($object->tags->tags());
                    }
                }
                elseif( $object->isRegion() )
                {
                    //swaschkut - 20220417
                    //what to do here?
                }

                if( $addWhereUsed )
                {
                    $refTextArray = array();
                    foreach( $object->getReferences() as $ref )
                        $refTextArray[] = $ref->_PANC_shortName();

                    $lines .= $context->encloseFunction($refTextArray);
                }
                if( $addUsedInLocation )
                {
                    $refTextArray = array();
                    foreach( $object->getReferences() as $ref )
                    {
                        $location = PH::getLocationString($object->owner);
                        $refTextArray[$location] = $location;
                    }

                    $lines .= $context->encloseFunction($refTextArray);
                }
                if( $addResolveGroupIPCoverage )
                {
                    $mapping = $object->getIP4Mapping();
                    $strMapping = explode(',', $mapping->dumpToString());

                    foreach( array_keys($mapping->unresolved) as $unresolved )
                        $strMapping[] = $unresolved;

                    $lines .= $context->encloseFunction($strMapping);
                }
                if( $addNestedMembers )
                {
                    if( $object->isGroup() )
                    {
                        $tmp_array = array();
                        $members = $object->expand(FALSE, $tmp_array, $object->owner->owner);
                        $lines .= $context->encloseFunction($members);
                    }
                    else
                        $lines .= $context->encloseFunction('');
                }
                if( $addResolveIPNestedMembers )
                {
                    if( $object->isGroup() )
                    {   $resolve = array();
                        $tmp_array = array();
                        $members = $object->expand(FALSE, $tmp_array, $object->owner->owner);
                        foreach( $members as $member )
                            $resolve[] = $member->value();
                        $lines .= $context->encloseFunction($resolve);
                    }
                    else
                        $lines .= $context->encloseFunction('');
                }
                if( $addResolveLocationNestedMembers )
                {
                    if( $object->isGroup() )
                    {   $resolve = array();
                        $tmp_array = array();
                        $members = $object->expand(FALSE, $tmp_array, $object->owner->owner);
                        foreach( $members as $member )
                        {
                            $tmp_name = $member->owner->owner->name();
                            if( empty($tmp_name) )
                                $tmp_name = "shared";
                            $resolve[] = $tmp_name;
                        }

                        $lines .= $context->encloseFunction($resolve);
                    }
                    else
                        $lines .= $context->encloseFunction('');
                }
                if( $addNestedMembersCount )
                {
                    if( $object->isGroup() )
                    {   $resolve = array();
                        $tmp_array = array();
                        $members = $object->expand(FALSE, $tmp_array, $object->owner->owner);
                        $lines .= $context->encloseFunction( (string)count($members) );
                    }
                    else
                        $lines .= $context->encloseFunction('');
                }

                $lines .= "</tr>\n";

            }
        }

        $content = file_get_contents(dirname(__FILE__) . '/html/export-template.html');
        $content = str_replace('%TableHeaders%', $headers, $content);

        $content = str_replace('%lines%', $lines, $content);

        $jscontent = file_get_contents(dirname(__FILE__) . '/html/jquery.min.js');
        $jscontent .= "\n";
        $jscontent .= file_get_contents(dirname(__FILE__) . '/html/jquery.stickytableheaders.min.js');
        $jscontent .= "\n\$('table').stickyTableHeaders();\n";

        $content = str_replace('%JSCONTENT%', $jscontent, $content);

        file_put_contents($filename, $content);
    },
    'args' => array('filename' => array('type' => 'string', 'default' => '*nodefault*'),
        'additionalFields' =>
            array('type' => 'pipeSeparatedList',
                'subtype' => 'string',
                'default' => '*NONE*',
                'choices' => array('WhereUsed', 'UsedInLocation', 'ResolveIP', 'NestedMembers'),
                'help' =>
                    "pipe(|) separated list of additional fields (ie: Arg1|Arg2|Arg3...) to include in the report. The following is available:\n" .
                    "  - NestedMembers: lists all members, even the ones that may be included in nested groups\n" .
                    "  - ResolveIP\n" .
                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n" .
                    "  - WhereUsed : list places where object is used (rules, groups ...)\n"
            )
    )

);


AddressCallContext::$supportedActions[] = array(
    'name' => 'replaceByMembersAndDelete',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( !$object->isGroup() )
        {
            $string = "it's not a group";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $object->owner === null )
        {
            $string = "object was previously removed";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $object->replaceByMembersAndDelete($context, $context->isAPI);
    },
    'args' => array(
        'keepgroupname' => array(
            'type' => 'string',
            'default' => '*nodefault*',
            'choices' => array('tag', 'description'),
            'help' =>
                "- replaceByMembersAndDelete:tag -> create Tag with name from AddressGroup name and add to the object\n" .
                "- replaceByMembersAndDelete:description -> create Tag with name from AddressGroup name and add to the object\n"
        )
    )
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'replaceByMembers',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( !$object->isGroup() )
        {
            $string = "it's not a group";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $object->owner === null )
        {
            $string = "object was previously removed";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $object->replaceByMembers($context, FALSE, $context->isAPI);
    },
    'args' => array(
        'keepgroupname' => array(
            'type' => 'string',
            'default' => '*nodefault*',
            'choices' => array('tag', 'description'),
            'help' =>
                "- replaceByMembersAndDelete:tag -> create Tag with name from AddressGroup name and add to the object\n" .
                "- replaceByMembersAndDelete:description -> create Tag with name from AddressGroup name and add to the object\n"
        )
    )
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'name-Rename',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( $object->isGroup() )
        {
            $string = "not applicable to Group objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( $object->isRegion() )
        {
            $string = "not applicable to REGION objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $newName = $context->arguments['stringFormula'];

        if( strpos($newName, '$$current.name$$') !== FALSE )
        {
            $newName = str_replace('$$current.name$$', $object->name(), $newName);
        }
        if( strpos($newName, '$$value$$') !== FALSE )
        {
            $newName = str_replace('$$value$$', $object->value(), $newName);
            $newName = str_replace(':', "_", $newName);
            $newName = str_replace('/', "-", $newName);
        }
        if( strpos($newName, '$$value.no-netmask$$') !== FALSE )
        {
            if( $object->isType_ipNetmask() )
                $replace = $object->getNetworkValue();
            else
                $replace = $object->value();

            $newName = str_replace('$$value.no-netmask$$', $replace, $newName);
            $newName = str_replace(':', "_", $newName);
            $newName = str_replace('/', "-", $newName);
        }
        if( strpos($newName, '$$netmask$$') !== FALSE )
        {
            if( !$object->isType_ipNetmask() )
            {
                $string = "'netmask' alias is not compatible with this type of objects";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }
            $replace = $object->getNetworkMask();

            $newName = str_replace('$$netmask$$', $replace, $newName);
        }
        if( strpos($newName, '$$netmask.blank32$$') !== FALSE )
        {
            if( !$object->isType_ipNetmask() )
            {
                $string = "'netmask' alias is not compatible with this type of objects";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }

            $replace = '';
            $netmask = $object->getNetworkMask();
            if( $netmask != 32 )
                $replace = $object->getNetworkMask();

            $newName = str_replace('$$netmask.blank32$$', $replace, $newName);
        }
        if( strpos($newName, '$$reverse-dns$$') !== FALSE )
        {
            if( !$object->isType_ipNetmask() )
            {
                $string = "'reverse-dns' alias is compatible with ip-netmask type objects";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }
            if( $object->getNetworkMask() != 32 )
            {
                $string = "'reverse-dns' actions only works on /32 addresses";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }

            $ip = $object->getNetworkValue();
            $reverseDns = gethostbyaddr($ip);

            if( $ip == $reverseDns )
            {
                $string = "'reverse-dns' could not be resolved";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }

            $newName = str_replace('$$reverse-dns$$', $reverseDns, $newName);
        }
        if( strpos($newName, '$$tag$$') !== FALSE )
        {
            $tmp_tags = $object->tags->getAll();
            if( count($tmp_tags) > 0 )
            {
                $firstTag = reset($tmp_tags);
                $newName = str_replace('$$tag$$', $firstTag->name(), $newName);
            }
            else
                $newName = str_replace('$$tag$$', "", $newName);

        }

        if( $object->name() == $newName )
        {
            $string = "new name and old name are the same";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $max_length = 63;
        if( strlen($newName) > $max_length )
        {
            $string = "resulting name is too long";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        $findObject = $object->owner->find($newName, null, false);
        if( $findObject !== null )
        {
            $string = "an object with same name already exists";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        else
        {
            $text = $context->padding . " - renaming object... ";
            if( $context->isAPI )
                $object->API_setName($newName);
            else
                $object->setName($newName);

            PH::ACTIONlog( $context, $text );
        }

    },
    'args' => array('stringFormula' => array(
        'type' => 'string',
        'default' => '*nodefault*',
        'help' =>
            "This string is used to compose a name. You can use the following aliases :\n" .
            "  - \$\$current.name\$\$ : current name of the object\n" .
            "  - \$\$netmask\$\$ : netmask\n" .
            "  - \$\$netmask.blank32\$\$ : netmask or nothing if 32\n" .
            "  - \$\$reverse-dns\$\$ : value truncated of netmask if any\n" .
            "  - \$\$value\$\$ : value of the object\n" .
            "  - \$\$value.no-netmask\$\$ : value truncated of netmask if any\n" .
            "  - \$\$tag\$\$ : name of first tag object - if no tag attached '' blank\n")
    ),
    'help' => ''
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'name-Rename-location',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        $newName = $context->arguments['stringFormula'];

        if( strpos($newName, '$$current.name$$') !== FALSE )
        {
            $newName = str_replace('$$current.name$$', $object->name(), $newName);
        }
        if( strpos($newName, '$$location$$') !== FALSE )
        {
            $location_class = $object->owner->owner;
            if( get_class($location_class) == 'PanoramaConf' || get_class($location_class) == 'PANConf' )
                $location = "shared";
            else
                $location = $object->owner->owner->name();
            $newName = str_replace('$$location$$', $location, $newName);
        }

        if( $object->name() == $newName )
        {
            $string = "new name and old name are the same";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $max_length = 63;
        if( strlen($newName) > $max_length )
        {
            $string = "resulting name is too long";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        $findObject = $object->owner->find($newName, null, false);
        if( $findObject !== null )
        {
            $string = "an object with same name already exists";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        else
        {
            $text = $context->padding . " - renaming object... ";
            if( $context->isAPI )
                $object->API_setName($newName);
            else
                $object->setName($newName);

            PH::ACTIONlog( $context, $text );
        }

    },
    'args' => array('stringFormula' => array(
        'type' => 'string',
        'default' => '*nodefault*',
        'help' =>
            "This string is used to compose a name. You can use the following aliases :\n" .
            "  - \$\$current.name\$\$ : current name of the object\n" .
            "  - \$\$location\$\$ : name of the location where this object is based\n")
    ),
    'help' => ''
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'name-rename-wrong-characters',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }


        $newName = htmlspecialchars_decode( $object->name() );
        preg_match_all('/[^\w $\-.]/', $newName, $matches , PREG_SET_ORDER, 0);

        if( count($matches) == 0 )
            return;

        $findings = array();
        foreach( $matches as $match )
            $findings[$match[0]] = $match[0];

        $newName = str_replace("&amp;", "_", $newName);
        $newName = str_replace("–", "-", $newName);
        foreach( $findings as $replace )
            $newName = str_replace($replace, "_", $newName);

        if( $object->name() == $newName )
        {
            $string = "new name and old name are the same";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $max_length = 63;
        if( strlen($newName) > $max_length )
        {
            $string = "resulting name is too long";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        $findObject = $object->owner->find($newName, null, false);
        if( $findObject !== null )
        {
            $string = "an object with same name already exists";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        else
        {
            $text = $context->padding . " - renaming object... ";
            if( $context->isAPI )
                $object->API_setName($newName);
            else
                $object->setName($newName);

            PH::ACTIONlog( $context, $text );
        }

    },
    'help' => ''
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'name-Replace-Character',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $characterToreplace = $context->arguments['search'];
        $characterForreplace = $context->arguments['replace'];


        $newName = str_replace($characterToreplace, $characterForreplace, $object->name());


        if( $object->name() == $newName )
        {
            $string = "new name and old name are the same";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        $findObject = $object->owner->find($newName, null, false);
        if( $findObject !== null )
        {
            $string = "an object with same name already exists";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        else
        {
            $text = $context->padding . " - renaming object... ";
            if( $context->isAPI )
                $object->API_setName($newName);
            else
                $object->setName($newName);

            PH::ACTIONlog( $context, $text );
        }

    },
    'args' => array(
        'search' => array('type' => 'string', 'default' => '*nodefault*'),
        'replace' => array('type' => 'string', 'default' => '*nodefault*')
    ),
    'help' => ''
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'name-addPrefix',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $newName = $context->arguments['prefix'] . $object->name();
        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        if( strlen($newName) > 63 )
        {
            $string = "resulting name is too long";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $object->owner->find($newName, null, false ) !== null )
        {
            $string = "an object with same name already exists";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else
            $object->setName($newName);
    },
    'args' => array('prefix' => array('type' => 'string', 'default' => '*nodefault*')
    ),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'name-addSuffix',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $newName = $object->name() . $context->arguments['suffix'];
        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        if( strlen($newName) > 63 )
        {
            $string = "resulting name is too long";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $object->owner->find($newName, null, false ) !== null )
        {
            $string = "an object with same name already exists";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else
            $object->setName($newName);
    },
    'args' => array('suffix' => array('type' => 'string', 'default' => '*nodefault*')
    ),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'name-removePrefix',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $prefix = $context->arguments['prefix'];

        if( strpos($object->name(), $prefix) !== 0 )
        {
            $string = "prefix not found";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        $newName = substr($object->name(), strlen($prefix));

        if( !preg_match("/^[a-zA-Z0-9]/", $newName[0]) )
        {
            $string = "object name contains not allowed character at the beginning";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $object->owner->find($newName , null, false ) !== null )
        {
            $string = "an object with same name already exists";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else
            $object->setName($newName);
    },
    'args' => array('prefix' => array('type' => 'string', 'default' => '*nodefault*')
    ),
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'name-removeSuffix',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $suffix = $context->arguments['suffix'];
        $suffixStartIndex = strlen($object->name()) - strlen($suffix);

        if( substr($object->name(), $suffixStartIndex, strlen($object->name())) != $suffix )
        {
            $string = "suffix not found";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        $newName = substr($object->name(), 0, $suffixStartIndex);

        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $object->owner->find($newName, null, false ) !== null )
        {
            $string = "an object with same name already exists";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else
            $object->setName($newName);
    },
    'args' => array('suffix' => array('type' => 'string', 'default' => '*nodefault*')
    ),
);
AddressCallContext::$supportedActions['name-touppercase'] = array(
    'name' => 'name-toUpperCase',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        #$newName = $context->arguments['prefix'].$object->name();
        $newName = mb_strtoupper($object->name(), 'UTF8');

        if( $object->isTmpAddr() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $newName === $object->name() )
        {
            $string = "object is already uppercase";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, FALSE) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, TRUE) !== null )
        {
            $string = "an object with same name already exists";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            #use existing uppercase TAG and replace old lowercase where used with this existing uppercase TAG
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else

            $object->setName($newName);
    }
);
AddressCallContext::$supportedActions['name-tolowercase'] = array(
    'name' => 'name-toLowerCase',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        #$newName = $context->arguments['prefix'].$object->name();
        $newName = mb_strtolower($object->name(), 'UTF8');

        if( $object->isTmpAddr() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $newName === $object->name() )
        {
            $string = "object is already lowercase";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, FALSE) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, TRUE) !== null )
        {
            $string = "an object with same name already exists";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            #use existing lowercase TAG and replace old uppercase where used with this
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else

            $object->setName($newName);
    }
);
AddressCallContext::$supportedActions['name-toucwords'] = array(
    'name' => 'name-toUCWords',
    'MainFunction' => function (AddressCallContext $context) {
        /** @var Address $object */
        $object = $context->object;
        #$newName = $context->arguments['prefix'].$object->name();
        $newName = mb_strtolower($object->name(), 'UTF8');
        $newName = ucwords($newName);

        if( $object->isTmpAddr() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $newName === $object->name() )
        {
            $string = "object is already UCword";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, FALSE) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, TRUE) !== null )
        {
            $string = "an object with same name already exists";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            #use existing lowercase TAG and replace old uppercase where used with this
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else

            $object->setName($newName);
    }
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'move',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isGroup() && $context->arguments['recursive'] )
        {
            /** @var AddressGroup $member */
            foreach( $object->members() as $member )
            {
                PH::print_stdout( "      - member name: ".$member->name());
                $object->owner->move( $context, $member );
            }

        }

        $object->owner->move( $context, $object );
    },
    'args' => array('location' => array('type' => 'string', 'default' => '*nodefault*'),
        'mode' => array('type' => 'string', 'default' => 'skipIfConflict', 'choices' => array('skipIfConflict', 'removeIfMatch', 'removeIfNumericalMatch') ),
        'recursive' => array('type' => 'bool', 'default' => FALSE)
    )
);


AddressCallContext::$supportedActions[] = array(
    'name' => 'showIP4Mapping',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isGroup() )
        {
            $resolvMap = $object->getIP4Mapping();
            $string = "{$resolvMap->count()} entries";
            #PH::ACTIONlog( $context, $string );


            foreach( $resolvMap->getMapArray() as &$resolvRecord )
            {
                //Todo: swaschkut 20210421 - long2ip not working with IPv6 use cidr::inet_itop
                $string = str_pad(long2ip($resolvRecord['start']), 14) . " - " . long2ip($resolvRecord['end']);
                PH::ACTIONlog( $context, $string );
            }
            $unresolvedCount = count($resolvMap->unresolved);
            $string = "unresolved: {$unresolvedCount} entries";
            if( $unresolvedCount > 0 )
            {
                #PH::print_stdout();
                #PH::ACTIONlog( $context, $string );

                foreach($resolvMap->unresolved as &$resolvRecord)
                {
                    if( get_class( $resolvRecord ) == "AddressGroup" )
                        $type = "AddressGroup";
                    else
                        $type = $resolvRecord->type();
                    $string ="UNRESOLVED: objname: '{$resolvRecord->name()}' of type: ".$type;
                    PH::ACTIONlog( $context, $string );
                }
            }
        }
        elseif( $object->isRegion() )
        {
            $string = "UNSUPPORTED";
            PH::ACTIONlog( $context, $string );
        }
        else
        {
            $type = $object->type();

            if( $type == 'ip-netmask' || $type == 'ip-range' )
            {
                $resolvMap = $object->getIP4Mapping()->getMapArray();
                $resolvMap = reset($resolvMap);
                //Todo: swaschkut 20210421 - long2ip not working with IPv6 use cidr::inet_itop
                $string = str_pad(long2ip($resolvMap['start']), 14) . " - " . long2ip($resolvMap['end']);
                PH::ACTIONlog($context, $string);
            }
            else
            {
                $string = "UNSUPPORTED";
                PH::ACTIONlog( $context, $string );
            }
        }
    }
);


AddressCallContext::$supportedActions[] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        $object->display_references(7);
    },
);


AddressCallContext::$supportedActions[] = array(
    'name' => 'display',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        PH::$JSON_TMP['sub']['object'][$object->name()]['name'] = $object->name();


        if( $object->isGroup() )
        {
            if( $object->isDynamic() )
            {
                $tag_string = "";
                if( count($object->tags->tags()) > 0 )
                {
                    $toStringInline = $object->tags->toString_inline();
                    TAG::revertreplaceNamewith( $toStringInline );
                    $tag_string = "tag: '".$toStringInline."'";
                }


                $tmpFilter = $object->filter;
                TAG::revertreplaceNamewith( $tmpFilter );
                PH::print_stdout( $context->padding . "* " . get_class($object) . " '{$object->name()}' (DYNAMIC)  ({$object->count()} members)  desc: '{$object->description()}' $tag_string filter: '{$tmpFilter}" );
                PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object)." (DYNAMIC)";

                PH::$JSON_TMP['sub']['object'][$object->name()]['tag'] = $tag_string;
                PH::$JSON_TMP['sub']['object'][$object->name()]['filter'] = $object->filter;
            }
            else
            {
                PH::print_stdout( $context->padding . "* " . get_class($object) . " '{$object->name()}' ({$object->count()} members)   desc: '{$object->description()}'" );
                PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);
            }

            PH::$JSON_TMP['sub']['object'][$object->name()]['memberscount'] = $object->count();
            PH::$JSON_TMP['sub']['object'][$object->name()]['description'] = $object->description();

            foreach( $object->members() as $member )
            {
                PH::$JSON_TMP['sub']['object'][$object->name()]['members'][$member->name()]['name'] = $member->name();
                PH::$JSON_TMP['sub']['object'][$object->name()]['members'][$member->name()]['type'] = get_class( $member );

                if( $member->isAddress() )
                {
                    PH::print_stdout( "          - {$member->name()}  value: '{$member->value()}'" );
                    PH::$JSON_TMP['sub']['object'][$object->name()]['members'][$member->name()]['value'] = $member->value();
                }
                else
                    PH::print_stdout( "          - {$member->name()}" );
            }
        }
        elseif( $object->isAddress() )
        {
            $tag_string = "";
            if( count($object->tags->tags()) > 0 )
            {
                $toStringInline = $object->tags->toString_inline();
                TAG::revertreplaceNamewith( $toStringInline );
                $tag_string = "tag: '".$toStringInline."'";
            }

            PH::print_stdout( $context->padding . "* " . get_class($object) . " '{$object->name()}'  type: '{$object->type()}'  value: '{$object->value()}'  desc: '{$object->description()}' IPcount: '{$object->getIPcount()}' $tag_string" );
            PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = $object->type();
            PH::$JSON_TMP['sub']['object'][$object->name()]['value'] = $object->value();
            PH::$JSON_TMP['sub']['object'][$object->name()]['tag'] = $tag_string;
            PH::$JSON_TMP['sub']['object'][$object->name()]['description'] = $object->description();
            PH::$JSON_TMP['sub']['object'][$object->name()]['ipcount'] = $object->getIPcount();
        }
        elseif( $object->isRegion() )
        {
            PH::print_stdout( $context->padding . "* " . get_class($object) . " '{$object->name()}' " );
            PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);
            foreach( $object->members() as $member )
            {
                PH::$JSON_TMP['sub']['object'][$object->name()][$member]['value'] = $member;
                PH::print_stdout( "          - '{$member}'" );
            }

        }

        if( PH::$shadow_displayxmlnode )
        {
            PH::print_stdout(  "" );
            DH::DEBUGprintDOMDocument($context->object->xmlroot);
        }

        PH::print_stdout(  "" );
    },
);
/*

 */
AddressCallContext::$supportedActions[] = array(
    'name' => 'display_upper_level_object',
    'MainFunction' => function (AddressCallContext $context) {
        $location = PH::findLocationObjectOrDie($context->object);
        if( $location->isFirewall() || $location->isPanorama() || $location->isVirtualSystem() )
            return FALSE;

        $store = $context->object->owner;

        if( isset($store->parentCentralStore) && $store->parentCentralStore !== null )
        {
            $store = $store->parentCentralStore;
            $find = $store->find($context->object->name());

            if( $find !== null )
            {
                if( get_class($store->owner) == "PanoramaConf" )
                    PH::print_stdout( $context->padding." * DG: 'SHARED'" );
                else
                    PH::print_stdout( $context->padding." * DG: '".$store->owner->name()."'");
            }
        }
    }
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'display_lower_level_object',
    'MainFunction' => function (AddressCallContext $context) {
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
            $tmp_obj = $deviceGroup->addressStore->find($object->name(), null, FALSE);
            if( $tmp_obj !== null )
                PH::print_stdout( $context->padding." * DG: '".$deviceGroup->name()."'");
        }

    }
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'description-Append',
    'MainFunction' => function (AddressCallContext $context) {
        $address = $context->object;

        if( $address->isTmpAddr() )
        {
            $string = "object is of type TMP";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $address->isRegion() )
        {
            $string = "object is of type Region";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $description = $address->description();

        $textToAppend = "";
        if( $description != "" )
            $textToAppend = " ";


        $newName = $context->arguments['stringFormula'];

        if( strpos($newName, '$$current.name$$') !== FALSE )
        {
            $textToAppend .= str_replace('$$current.name$$', $address->name(), $newName);
        }
        else
        {
            $textToAppend .= $newName;
        }


        if( $context->object->owner->owner->version < 71 )
            $max_length = 253;
        else
            $max_length = 1020;

        if( strlen($description) + strlen($textToAppend) > $max_length )
        {
            $string = "resulting description is too long";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $text = $context->padding . " - new description will be: '{$description}{$textToAppend}' ... ";

        if( $context->isAPI )
            $address->API_setDescription($description . $textToAppend);
        else
            $address->setDescription($description . $textToAppend);
        $text .= "OK";
        PH::ACTIONlog( $context, $text );
    },
    'args' => array(
        'stringFormula' => array(
            'type' => 'string',
            'default' => '*nodefault*',
            'help' =>
                "This string is used to compose a name. You can use the following aliases :\n" .
                "  - \$\$current.name\$\$ : current name of the object\n")
    ),
    'help' => ''
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'description-Delete',
    'MainFunction' => function (AddressCallContext $context) {
        $address = $context->object;

        if( $address->isTmpAddr() )
        {
            $string = "object is of type TMP";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $address->isRegion() )
        {
            $string = "object is of type Region";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $description = $address->description();
        if( $description == "" )
        {
            $string = "no description available";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $text = $context->padding . " - new description will be: '' ... ";
        if( $context->isAPI )
            $address->API_setDescription("");
        else
            $address->setDescription("");
        $text .= "OK";
        PH::ACTIONlog( $context, $text );
    },
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'description-Replace-Character',
    'MainFunction' => function (AddressCallContext $context) {

        $object = $context->object;

        $characterToreplace = $context->arguments['search'];
        if( strpos($characterToreplace, '$$comma$$') !== FALSE )
            $characterToreplace = str_replace('$$comma$$', ",", $characterToreplace);
        if( strpos($characterToreplace, '$$forwardslash$$') !== FALSE )
            $characterToreplace = str_replace('$$forwardslash$$', "/", $characterToreplace);
        if( strpos($characterToreplace, '$$colon$$') !== FALSE )
            $characterToreplace = str_replace('$$colon$$', ":", $characterToreplace);
        if( strpos($characterToreplace, '$$pipe$$') !== FALSE )
            $characterToreplace = str_replace('$$pipe$$', "|", $characterToreplace);
        if( strpos($characterToreplace, '$$space$$') !== FALSE )
            $characterToreplace = str_replace('$$space$$', " ", $characterToreplace);

        $characterForreplace = $context->arguments['replace'];
        if( strpos($characterForreplace, '$$comma$$') !== FALSE )
            $characterForreplace = str_replace('$$comma$$', ",", $characterForreplace);
        if( strpos($characterForreplace, '$$forwardslash$$') !== FALSE )
            $characterForreplace = str_replace('$$forwardslash$$', "/", $characterForreplace);
        if( strpos($characterForreplace, '$$colon$$') !== FALSE )
            $characterForreplace = str_replace('$$colon$$', ":", $characterForreplace);
        if( strpos($characterForreplace, '$$pipe$$') !== FALSE )
            $characterForreplace = str_replace('$$pipe$$', "|", $characterForreplace);
        if( strpos($characterForreplace, '$$space$$') !== FALSE )
            $characterForreplace = str_replace('$$space$$', " ", $characterForreplace);

        $description = $object->description();

        $newDescription = str_replace($characterToreplace, $characterForreplace, $description);
        //todo add regex replacement 20210305
        //$desc = preg_replace('/appRID#[0-9]+/', '', $rule->description());

        if( $description == $newDescription )
        {
            $string = "new and old description are the same" ;
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new description will be '{$newDescription}'";
        PH::ACTIONlog( $context, $string );

        if( $context->isAPI )
            $object->API_setDescription($newDescription);
        else
            $object->setDescription($newDescription);


    },
    'args' => array(
        'search' => array('type' => 'string', 'default' => '*nodefault*'),
        'replace' => array('type' => 'string', 'default' => '')
    ),
    'help' => 'possible variable $$comma$$ or $$forwardslash$$ or $$colon$$ or $$pipe$$  or $$pipe$$; example "actions=description-Replace-Character:$$comma$$word1"'
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'value-host-object-add-netmask-m32',
    'MainFunction' => function (AddressCallContext $context) {
        $address = $context->object;

        if( $address->isGroup() )
        {
            $string = "object is of type GROUP";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $address->isRegion() )
        {
            $string = "object is of type Region";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( !$address->isType_ipNetmask() )
        {
            $string = "object is not IP netmask";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $value = $address->value();

        if( strpos($value, "/") !== FALSE )
        {
            $string = "object: " . $address->name() . " with value: " . $value . " is not a host object.";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( strpos( $value, ":") !== false )
        {
            $string = "object: " . $address->name() . " with value: " . $value . " is of type IPv6.";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        //if(filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
            //$new_value = $value . "/128";
        //else
            $new_value = $value . "/32";

        $text = $context->padding . " - new value will be: '" . $new_value . "'";
        if( $context->isAPI )
            $address->API_editValue($new_value);
        else
            $address->setValue($new_value);
        $text .= "OK";
        PH::ACTIONlog( $context, $text );
    }
);


AddressCallContext::$supportedActions[] = array(
    'name' => 'value-set-reverse-dns',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isGroup() )
        {
            $string = "object is of type GROUP";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $object->isRegion() )
        {
            $string = "object is of type Region";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( !$object->isType_ipNetmask() )
        {
            $string = "'value-set-reverse-dns' alias is compatible with ip-netmask type objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( $object->getNetworkMask() != 32 )
        {
            $string = "'value-set-reverse-dns' actions only works on /32 addresses";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $ip = $object->getNetworkValue();
        $reverseDns = gethostbyaddr($ip);

        if( $ip == $reverseDns )
        {
            $string = "'value-set-reverse-dns' could not be resolved";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $text = $context->padding . " - new value will be: '" . $reverseDns . " with type: fqdn'";
        $object->setType( 'fqdn' );
        $object->setValue($reverseDns);

        if( $context->isAPI )
            $object->API_sync();

        $text .= "OK";
        PH::ACTIONlog( $context, $text );
    }
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'value-set-ip-for-fqdn',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isGroup() )
        {
            $string = "object is of type GROUP";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $object->isRegion() )
        {
            $string = "object is of type Region";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( !$object->isType_FQDN() )
        {
            $string = "object is NOT of type FQDN";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }


        $fqdn = $object->value();

        $reverseDns = gethostbynamel($fqdn);
        if( $reverseDns === FALSE || count( $reverseDns ) == 0 )
        {
            $string = "'value-set-ip-for-fqdn' could not be resolved";
            return;
        }
        elseif( count( $reverseDns ) > 1 )
        {
            $string = "'value-set-ip-for-fqdn' resolved more than one IP-Address [".implode(",",$reverseDns)."]";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $text = $context->padding . " - new value will be: '" . $reverseDns[0] . " with type: ip-netmask'";

        $object->setType( 'ip-netmask' );
        $object->setValue($reverseDns[0]);

        if( $context->isAPI )
            $object->API_sync();

        $text .= "OK";
        PH::ACTIONlog( $context, $text );
    }
);
AddressCallContext::$supportedActions[] = array(
    'name' => 'value-replace',
    'MainFunction' => function (AddressCallContext $context) {
        $address = $context->object;

        if( $address->isGroup() )
        {
            $string = "object is of type GROUP";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( $address->isRegion() )
        {
            $string = "object is of type Region";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( !$address->isType_ipNetmask() )
        {
            $string = "object is not IP netmask";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $value = $address->value();
        $regexValue = $context->arguments['search'];
        $valueToreplace = $context->arguments['replace'];

        if( strpos($regexValue, '$$netmask.32$$') !== FALSE )
            $regexValue = "/32";

        if( strpos($valueToreplace, '$$netmask.blank32$$') !== FALSE )
            $valueToreplace = "";

        if( strpos($regexValue, '$$') !== FALSE or strpos($valueToreplace, '$$') !== FALSE )
            derr( "this argument variable with '$$' is not supported", null, False );


        if( strpos($regexValue, "*nodefault*") !== FALSE )
        {
            $string = "search value not set";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( strpos($valueToreplace, "*nodefault*") !== FALSE )
        {
            $string = "replace value not set";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }


        if( strpos($value, $regexValue) === FALSE )
        {
            $string = "object value does not contain: " . $regexValue;
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        //todo: if $regexValue start with . or :
        // - replace in between
        // - if not replace at start
        $new_value = str_replace( $regexValue, $valueToreplace, $value );

        if( !filter_var($new_value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && filter_var($new_value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) )
        {
            $string = "object value is not a valid IP: " . $new_value;
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        elseif( filter_var($new_value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) )
        {
            //Todo: check if count of . is same on $regexValue and also on $valueToreplace
        }
        elseif( filter_var($new_value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) )
        {
            //Todo: check if count of : is same on $regexValue and also on $valueToreplace
        }

        $text = $context->padding . " - old value is: '" . $value . "'";
        PH::ACTIONlog( $context, $text );

        $text = $context->padding . " - new value will be: '" . $new_value . "'";
        if( $context->isAPI )
            $address->API_editValue($new_value);
        else
            $address->setValue($new_value);
        $text .= "OK";
        PH::ACTIONlog( $context, $text );
    },
    'args' => array(
        'search' => array(
            'type' => 'string',
            'default' => '*nodefault*',
            'help' => '1.1.1.'
        ),
        'replace' => array('type' => 'string', 'default' => '*nodefault*',
            'help' => '2.2.2.'
        )
    ),
    'help' => 'search for a full or partial value and replace; example "actions=value-replace:1.1.1.,2.2.2." it is recommend to use additional filter: "filter=(value string.regex /^1.1.1./)"
                "actions=value-replace:$$netmask.32$$,$$netmask.blank32$$"
    '
);

//starting with 7.0 PAN-OS support max. 2500 members per group, former 500
AddressCallContext::$supportedActions[] = array(
    'name' => 'split-large-address-groups',
    'MainFunction' => function (AddressCallContext $context) {
        $largeGroupsCount = $context->arguments['largeGroupsCount'];
        $splitCount = $largeGroupsCount - 1;

        $group = $context->object;


        if( $group->isGroup() )
        {
            $membersCount = $group->count();

            // if this group has more members than $largeGroupsCount then we must split it
            if( $membersCount > $largeGroupsCount )
            {
                $string = "AddressGroup named '" . $group->name() . "' with $membersCount members";
                PH::ACTIONlog( $context, $string );

                // get member list in $members
                $members = $group->members();

                $i = 0;

                if( isset($newGroup) ) unset($newGroup);

                // loop move every member to a new subgroup
                foreach( $members as $member )
                {
                    // Condition to detect if previous sub-group is full
                    // so we have to create a new one
                    if( $i % $splitCount == 0 )
                    {
                        if( isset($newGroup) )
                        { // now we can rewrite XML
                            $newGroup->rewriteXML();
                        }

                        // create a new sub-group with name 'original--1'
                        if( $context->isAPI )
                            $newGroup = $group->owner->API_newAddressGroup($group->name() . '--' . ($i / $splitCount));
                        else
                            $newGroup = $group->owner->newAddressGroup($group->name() . '--' . ($i / $splitCount));
                        $string = "New AddressGroup object created with name: " . $newGroup->name();
                        PH::ACTIONlog( $context, $string );

                        // add this new sub-group to the original one. Don't rewrite XML for performance reasons.
                        if( $context->isAPI )
                            $group->API_addMember($newGroup, FALSE);
                        else
                            $group->addMember($newGroup, FALSE);
                    }

                    // remove current group member from old group, don't rewrite XML yet for performance savings
                    if( $context->isAPI )
                        $group->API_removeMember($member, FALSE);
                    else
                        $group->removeMember($member, FALSE);

                    // we add current group member to new subgroup
                    if( $context->isAPI )
                        $newGroup->API_addMember($member, FALSE);
                    else
                        $newGroup->addMember($member, FALSE);

                    $i++;
                }
                if( isset($newGroup) )
                { // now we can rewrite XML
                    $newGroup->rewriteXML();
                }

                // Now we can rewrite XML
                $group->rewriteXML();

                $string = "AddressGroup count after split: " . $group->count();
                PH::ACTIONlog( $context, $string );
                PH::print_stdout();
            }
            else
            {

                $string = "ADDRESS GROUP members count is smaller as largeGroupsCount argument is set: " . $largeGroupsCount;
                PH::ACTIONstatus( $context, "SKIPPED", $string );
            }
        }
        else
        {
            $string = "address object is not a ADDRESS GROUP.";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
        }


    },
    'args' => array('largeGroupsCount' => array('type' => 'string', 'default' => '2490')
    )
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'replace-Object-by-IP',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            $string = "because object is already tmp address";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $object->isGroup() || $object->isRegion() )
        {
            $string = "because object is or GROUP or REGION";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( !$object->isType_ipRange() && !$object->isType_ipNetmask() && !$object->isAddress() )
        {
            $string = "because object is not an IP address/netmask";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $rangeDetected = FALSE;

        /*
        if( !$object->nameIsValidRuleIPEntry() )
        {
            PH::print_stdout( $context->padding . "     *  SKIPPED because object is not an IP address/netmask or range" );
            return;
        }
        */

        $objectRefs = $object->getReferences();
        $clearForAction = TRUE;
        foreach( $objectRefs as $objectRef )
        {
            $class = get_class($objectRef);
            if( $class != 'AddressRuleContainer' && $class != 'NatRule' )
            {
                $clearForAction = FALSE;
                $string = "because its used in unsupported class $class";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }
        }

        $pan = PH::findRootObjectOrDie($object->owner);

        if( !$object->isType_ipRange() )
        {
            //$explode = explode('/',$object->getNetworkValue());
            $explode = explode('/', $object->value());

            if( count($explode) > 1 )
            {
                $name = $explode[0];
                $mask = $explode[1];
            }
            else
            {
                $name = $object->value();
                $mask = 32;
            }

            if( $mask > 32 || $mask < 0 )
            {
                $string = "because of invalid mask detected : '$mask'";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }

            if( filter_var($name, FILTER_VALIDATE_IP) === FALSE )
            {
                $string = "because of invalid IP detected : '$name'";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }

            if( $mask == 32 )
            {
                $newName = $name;
            }
            else
            {
                $newName = $name . '/' . $mask;
            }
        }
        else
        {
            $rangeDetected = TRUE;
            $explode = explode('-', $object->value());
            $newName = $explode[0] . '-' . $explode[1];
        }

        $string = "new object name will be $newName";
        PH::ACTIONlog( $context, $string );


        $objToReplace = $object->owner->find($newName, null, false );
        if( $objToReplace === null )
        {
            if( $context->isAPI )
            {
                $objToReplace = $object->owner->createTmp($newName);

                /*
                if( $rangeDetected)
                    $objToReplace = $object->owner->API_newAddress($newName, 'ip-range', $explode[0].'-'.$explode[1] );
                else
                    $objToReplace = $object->owner->API_newAddress($newName, 'ip-netmask', $name.'/'.$mask);
                */
            }
            else
            {
                $objToReplace = $object->owner->createTmp($newName);
            }
        }
        else
        {
            if( !$object->isType_ipRange() )
            {
                $objMap = IP4Map::mapFromText($name . '/' . $mask);
                if( !$objMap->equals($objToReplace->getIP4Mapping()) )
                {
                    $string = "because an object with same name exists but has different value";
                    PH::ACTIONstatus( $context, "SKIPPED", $string );
                    return;
                }
            }
            //TODO: same valdiation for IP Range

        }

        if( $clearForAction )
        {
            foreach( $objectRefs as $objectRef )
            {
                $class = get_class($objectRef);

                if( $class == 'AddressRuleContainer' )
                {
                    /** @var AddressRuleContainer $objectRef */
                    $string = "replacing in {$objectRef->toString()}";
                    PH::ACTIONlog( $context, $string );

                    if( $objectRef->owner->isNatRule()
                        && $objectRef->name == 'snathosts'
                        && $objectRef->owner->sourceNatTypeIs_DIPP()
                        && $objectRef->owner->snatinterface !== null )
                    {
                        $string = "because it's a SNAT with Interface IP address";
                        PH::ACTIONstatus( $context, "SKIPPED", $string );
                        continue;
                    }


                    if( $context->isAPI )
                        $objectRef->API_add($objToReplace);
                    else
                        $objectRef->addObject($objToReplace);

                    if( $context->isAPI )
                        $objectRef->API_remove($object, FALSE, $context);
                    else
                        $objectRef->remove($object, TRUE, FALSE, $context);
                }
                elseif( $class == 'NatRule' )
                {
                    /** @var NatRule $objectRef */
                    $string = "replacing in {$objectRef->toString()}";
                    PH::ACTIONlog( $context, $string );

                    if( $context->isAPI )
                        $objectRef->API_setDNAT($objToReplace, $objectRef->dnatports);
                    else
                        $objectRef->replaceReferencedObject($object, $objToReplace);
                }
                else
                {
                    derr("unsupported class '$class'");
                }

            }
        }

        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);

    },
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'display-NAT-usage',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            $string = "because object is temporary";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $objectRefs = $object->getReferences();



        $clearForAction = TRUE;
        foreach( $objectRefs as $objectRef )
        {
            $class = get_class($objectRef);
            if( $class != 'AddressRuleContainer' && $class != 'NatRule' )
            #if( $class != 'NatRule' )
            {
                $clearForAction = FALSE;
                $string = "it is not used in NAT rule";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }

            #PH::print_stdout( "name: ".$objectRef->name() );


            if( isset($objectRef->owner) && $objectRef->owner !== null )
            {
                $objRef_owner = $objectRef->owner;
                $class = get_class($objRef_owner);
                $class = strtolower($class);
                #PH::print_stdout( "CLASS: ".$class );
                if( $class != "natrule" )
                {
                    $string = "it is not used in NAT rule";
                    PH::ACTIONstatus( $context, "SKIPPED", $string );
                    return;
                }

                PH::print_stdout();

                if( $objRef_owner->sourceNatIsEnabled() )
                {
                    //SNAT

                    $text = $context->padding . $objRef_owner->source->toString_inline()."";
                    $text .= " => ".$objRef_owner->snathosts->toString_inline()."";
                    PH::ACTIONlog( $context, $text );

                    $text = "";
                    foreach( $objRef_owner->source->members() as $key =>$member )
                    {
                        if( $object === $member )
                        {
                            if( $member->isAddress() )
                                $text .= $context->padding . PH::boldText( $member->value() );
                            else
                                $text .= $context->padding . "GROUP: ".$member->name()." missing IPv4";
                        }

                        else
                        {
                            if( $member->isAddress() )
                                $text .= $context->padding . $member->value();
                            else
                                $text .= $context->padding . "GROUP: ".$member->name()." missing IPv4";
                        }

                    }
                    foreach( $objRef_owner->snathosts->members() as $key => $member )
                    {
                        $text .= " => ";
                        if( $object === $member )
                            if( $member->isAddress() )
                                $text .= PH::boldText( $member->value() );
                            else
                                $text .= " GROUP: ".$member->name()." missing IPv4";
                        else
                        {
                            if( $member->isAddress() )
                                $text .= $member->value();
                            else
                                $text .= " GROUP: ".$member->name()." missing IPv4";
                        }
                    }


                    if( $objRef_owner->isBiDirectional() )
                    {
                        //Bidir
                        $text .= $context->padding . "rule is bidir-NAT";
                        $text .= $context->padding . "name: ".$objRef_owner->name();
                    }
                    PH::ACTIONlog( $context, $text );
                }
                elseif( $objRef_owner->destinationNatIsEnabled() )
                {
                    //DNAT

                    $text = $context->padding . $objRef_owner->destination->toString_inline()."";
                    $text .= " => ".$objRef_owner->dnathost->name()."";
                    PH::ACTIONlog( $context, $text );

                    $text = "";
                    foreach( $objRef_owner->destination->members() as $key => $member )
                    {
                        if( $object === $member )
                            $text .= $context->padding . PH::boldText( $member->value() );
                        else
                            $text .= $context->padding .  $member->value();
                    }
                    $text .= " => ";
                    $text .= $objRef_owner->dnathost->value();
                    PH::ACTIONlog( $context, $text );
                }
            }
        }
    },
);

AddressCallContext::$supportedActions[] = array(
    'name' => 'display-xpath-usage',
    'MainFunction' => function (AddressCallContext $context) {
        /** @var Address $object */
        $object = $context->object;

        //------------------------
        $qualifiedNodeName = '//*[text()="'.$object->name().'"]';

        //
        if( get_class($object->owner->owner) == "PanoramaConf" || get_class($object->owner->owner) == "PANConf" )
            $xmlDoc = $object->owner->owner->xmldoc;
        elseif( get_class($object->owner->owner) == "VirtualSystem" )
        {
            if( get_class($object->owner->owner->owner ) == "PANConf" )
            {
                if( !isset( $object->owner->owner->owner->owner ) )
                    $xmlDoc = $object->owner->owner->owner->xmldoc;
                else
                {
                    //Template ??? but there is no AddressStore
                }
            }
        }
        elseif( get_class($object->owner->owner) == "DeviceGroup" )
        {
            if( get_class($object->owner->owner->owner) == "PanoramaConf" )
                $xmlDoc = $object->owner->owner->owner->xmldoc;
        }

        $string1 = "";
        DH::getXpathDisplay( $string1, $xmlDoc, $qualifiedNodeName, "test", false, "display" );


        //------------------------
        $fullxpath = false;
        $displayAPIcommand = false;
        $displayXMLlineno = false;
        $displayAttributeName = false;
        $pan = false;

        $displayXMLnode = true;
        $qualifiedNodeName = "entry";
        $nameattribute = $object->name();

        $own_xpath = $object->getXPath();

        $xpath = null;
        $string2 = "";
        DH::getXpathDisplayMain( $string2, $xmlDoc, $qualifiedNodeName, $nameattribute, $xpath, $displayXMLnode, $displayAttributeName, $displayXMLlineno, $fullxpath, $displayAPIcommand, $pan, $own_xpath );

        //------------------------
        if( !empty($string1) )
            $context->objectList[$object->name()]['text'] = $string1;
        if( !empty($string2) )
            $context->objectList[$object->name()]['nameattribute'] = $string2;
    },
    'GlobalFinishFunction' => function (AddressCallContext $context)
    {
        $remove_known_references = false;

        //optimise array
        foreach( $context->objectList as $key => &$object )
        {
            if( isset( $object['text'] ) )
            {
                $tmp_array = explode( "* XPATH:", $object['text'] );
                foreach( $tmp_array as $key2 => $value2 )
                {
                    $tmp_array2 = preg_split("/\r\n|\n|\r/", $value2);
                    $tmp_array2 = array_map('trim', $tmp_array2);
                    $tmp_array[$key2] = array_filter($tmp_array2);
                }
                $tmp_array = array_filter($tmp_array);
                unset( $tmp_array[1] );
                $object['text'] = $tmp_array;
            }
            if( isset( $object['nameattribute'] ) )
            {
                $tmp_array = explode( "* XPATH:", $object['nameattribute'] );
                unset( $tmp_array[0] );
                foreach( $tmp_array as $key2 => $value2 )
                {
                    $tmp_array2 = preg_split("/\r\n|\n|\r/", $value2);
                    $tmp_array2 = array_map('trim', $tmp_array2);
                    foreach( $tmp_array2 as $key3 => $value3 )
                    {
                        if( strpos( $value3, "TEMPLATE" ) !== FALSE )
                            unset( $tmp_array2[$key3] );
                    }
                    $tmp_array[$key2] = array_filter($tmp_array2);
                }

                $object['nameattribute'] = $tmp_array;
                if( empty($tmp_array) )
                    unset( $context->objectList[$key] );
            }
        }

        //remove already know reference:
        if( $remove_known_references )
        {
            foreach( $context->objectList as $key => &$object )
            {
                if( isset( $object['text'] ) )
                {
                    foreach( $object['text'] as $key2 => $value2 )
                    {
                        if( strpos( $value2[0], "device-group" ) !== FALSE || strpos( $value2[0], "vsys" ) !== FALSE )
                        {
                            if( strpos( $value2[0], "address" ) !== FALSE )
                            {
                                unset( $object['text'][$key2] );
                            }
                            if( strpos( $value2[0], "-rulebase" ) !== FALSE || strpos( $value2[0], "rules" ) !== FALSE )
                            {
                                unset( $object['text'][$key2] );
                            }
                            if( strpos( $value2[0], "tag" ) !== FALSE )
                            {
                                unset( $object['text'][$key2] );
                            }
                        }
                        if( strpos( $value2[0], "shared" ) !== FALSE )
                        {
                            if( strpos( $value2[0], "tag" ) !== FALSE )
                            {
                                unset( $object['text'][$key2] );
                            }
                        }
                    }
                    if( empty($object['text']) )
                        unset( $object['text'] );
                }

                if( isset( $object['nameattribute'] ) )
                {
                    foreach( $object['nameattribute'] as $key2 => $value2 )
                    {
                        if( strpos( $value2[0], "device-group" ) !== FALSE || strpos( $value2[0], "vsys" ) !== FALSE )
                        {
                            if( strpos( $value2[0], "address" ) !== FALSE )
                            {
                                unset( $object['nameattribute'][$key2] );
                            }
                            if( strpos( $value2[0], "-rulebase" ) !== FALSE || strpos( $value2[0], "rules" ) !== FALSE )
                            {
                                unset( $object['nameattribute'][$key2] );
                            }
                            if( strpos( $value2[0], "tag" ) !== FALSE )
                            {
                                unset( $object['nameattribute'][$key2] );
                            }
                        }
                        if( strpos( $value2[0], "shared" ) !== FALSE )
                        {
                            if( strpos( $value2[0], "tag" ) !== FALSE )
                            {
                                unset( $object['nameattribute'][$key2] );
                            }
                        }

                    }
                    if( empty($object['nameattribute']) )
                        unset( $object['nameattribute'] );
                }
                if( empty($object) )
                    unset( $context->objectList[$key] );
            }
        }


        //print_r( $context->objectList );
        $padding = "  ";
        foreach( $context->objectList as $object_name => $object )
        {
            PH::print_stdout( $padding."* ".$object_name );
            //key -> 'text' || 'nameattribute'
            foreach( $object as $key2 => $value2 )
            {

                foreach( $value2 as $key3 => $value3 )
                {
                    $xmlfound = false;
                    $xmlString = "";
                    foreach( $value3 as $key4 => $value4 )
                    {
                        if ($key4 == 0)
                            PH::print_stdout($padding.$padding."- XPATH: " . $value4);
                        elseif (strpos($value4, "VALUE") !== FALSE) {
                            $xmlfound = true;
                        } elseif ($xmlfound) {
                            $xmlString .= $value4;
                        } else
                            PH::print_stdout($padding.$padding."  ".$value4);
                    }

                    DH::XMLstringToPrettyDOMDocument($xmlString);

                    $padding2 = $padding.$padding.$padding."   ";
                    $xmlString = str_replace( "\n", "\n".$padding2, $xmlString );
                    PH::print_stdout($padding2.$xmlString);


                }
            }
            PH::print_stdout( );
        }
    }
);

AddressCallContext::$supportedActions['create-Address'] = array(
    'name' => 'create-address',
    'MainFunction' => function (AddressCallContext $context) {
    },
    'GlobalFinishFunction' => function (AddressCallContext $context) {

        $addressStore = $context->subSystem->addressStore;

        $newName = $context->arguments['name'];

        $value = $context->arguments['value'];
        $type = $context->arguments['type'];
        $description = $context->arguments['description'];

        if( !in_array( $type, Address::$AddressTypes) )
        {
            $string = "Address named '" . $newName . "' cannot create as type: ".$type." is not allowed";
            derr($string, null, false);
            PH::ACTIONlog( $context, $string );
            return;
        }

        /** @var Address $tmpAddress */
        $tmpAddress = $addressStore->find( $newName );
        if( $tmpAddress === null )
        {
            $string = "create Address object : '" . $newName . "'";
            PH::ACTIONlog( $context, $string );

            if( $context->isAPI )
                $addressStore->API_newAddress($newName, $type, $value, $description);
            else
                $addressStore->newAddress( $newName, $type, $value, $description);
        }
        else
        {
            if( $tmpAddress->isType_TMP() )
            {
                $prefix = array();
                $prefix['host'] = "";

                $prefix['network'] = "";
                $prefix['networkmask'] = "m";

                $prefix['range'] = "";
                $prefix['rangeseparator'] = "-";

                $tmpAddress->replaceIPbyObject( $context, $prefix );
            }
            else
            {
                $string = "Address named '" . $newName . "' already exists, cannot create";
                PH::ACTIONlog( $context, $string );
            }
        }

    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => '*nodefault*'),
        'value' => array('type' => 'string', 'default' => '*nodefault*'),
        'type' => array(
            'type' => 'string',
            'default' => '*nodefault*',
            'help' =>
                implode( ", ", Address::$AddressTypes )
        ),
        'description' => array('type' => 'string', 'default' => '-')
    )
);

AddressCallContext::$supportedActions[] = Array(
    'name' => 'create-address-from-file',
    'GlobalInitFunction' => function(AddressCallContext $context){},
    'MainFunction' => function(AddressCallContext $context){},
    'GlobalFinishFunction' => function(AddressCallContext $context)
    {
        /*

        file syntax:
            AddressObjectName,IP-Address,Address-group

        example:
            h-192.168.0.1,192.168.0.1/32,private-network-AddressGroup
            n-192.168.2.0m24,192.168.2.0/24,private-network-AddressGroup

        */
        $create_addressGroup = false;
        $address_addressgroup = "";

        $object = $context->object;
        if( !is_object( $object ) )
        {
            derr( 'addressStore is empty - create first an address object via the Palo Alto Networks GUI' );
            #how to access the addressstore????
        }

        $addressStore = $object->owner;

        $forceAddToGroup = $context->arguments['force-add-to-group'];
        $forceChangeValue = $context->arguments['force-change-value'];

        if( !isset($context->cachedList) )
        {
            $text = file_get_contents( $context->arguments['file'] );

            if( $text === false )
                derr("cannot open file '{$context->arguments['file']}");

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


        if( count( $list ) == 0 )
            derr( 'called file: '.$context->arguments['file'].' is empty' );


        foreach( $list as $key => $item )
        {
            $create_addressGroup = false;

            $address_information = explode(",", $key);

            $address_name = $address_information[0];
            $address_value = $address_information[1];
            if( count($address_information) == 3 )
            {
                $create_addressGroup = true;
                $address_addressgroup = $address_information[2];
            }


            $key = $address_value;

            $addressstring = "";
            $networkvalue = "";
            //VALIDATION for $key
            if( substr_count($key, '.') == 3 )
            {
                $testvalue = CIDR::stringToStartEnd( $key );
                $range = CIDR::range2network( $testvalue['start'], $testvalue['end'] );

                $networkvalue = long2ip( $range['network'] );
                $networkmask = $range['mask'];
                $addressstring = $range['string'];
            }
            elseif( strpos( $key, ":") !== false )
            {
                /*
                if( substr_count($key, '/') == 0 )
                    $key = $key."/64";

                $test = Ipv6_Prefix2Range( $key );
                if( $test === false )
                    print "FALSE\n";
                else
                {
                    print "TRUE\n";
                    print_r( $test );
                }
                */

                derr( "IPv6 addresses are not supported yet." );
            }
            else
                derr( "not a valid IPv4 or IPv6 address." );


            $new_address_name = $address_name;
            $new_address_value = $addressstring;

            $new_address = $addressStore->find( $new_address_name );
            if( $new_address == null )
            {
                $string = $context->padding."- object: '{$new_address_name}'\n";
                $string .= $context->padding.$context->padding." *** create addressobject with name: '{$new_address_name}' and value: '{$new_address_value}'\n";
                PH::ACTIONlog( $context, $string );

                if( $context->isAPI )
                    $newObj = $addressStore->API_newAddress( $new_address_name, 'ip-netmask', $new_address_value );
                else
                    $newObj = $addressStore->newAddress( $new_address_name, 'ip-netmask', $new_address_value );
            }
            else
            {
                if( $new_address->isGroup() )
                {
                    $string = $context->padding.$context->padding." *** SKIPPED creating; addressobject with name: '{$new_address_name}' already available as an address-group";
                    PH::ACTIONlog( $context, $string );
                    mwarning( "*** SKIPPED *** existing address object is group\n", null, false);
                    continue;
                }

                if( $new_address->isType_TMP() )
                {
                    $prefix = array();
                    $prefix['host'] = "";

                    $prefix['network'] = "";
                    $prefix['networkmask'] = "m";

                    $prefix['range'] = "";
                    $prefix['rangeseparator'] = "-";

                    $new_address->replaceIPbyObject( $context, $prefix );
                }
                else
                {
                    $string = $context->padding."- object: '{$new_address_name}'\n";
                    $string .= $context->padding.$context->padding." *** SKIPPED creating; addressobject with name: '{$new_address_name}' already available. old-value: '{$new_address->value()}' - new-value:'{$new_address_value}'\n\n";
                    PH::ACTIONlog( $context, $string );

                    if( $new_address_value != $new_address->value() )
                    {
                        if( $forceChangeValue )
                        {
                            $string = "force change value is used. set value to: ".$new_address_value;
                            PH::ACTIONlog($context, $string );
                            if( $context->isAPI )
                                $new_address->API_setValue( $new_address_value );
                            else
                                $new_address->setValue( $new_address_value );
                        }
                        if( $forceAddToGroup )
                        {
                            $string = "force adding to address-Group as argument is used";
                            PH::ACTIONlog($context, $string );
                        }
                        else
                        {
                            $create_addressGroup = false;
                            mwarning( "address value differ from existing address object: existing-value: '{$new_address->value()}' - new-value:'{$new_address_value}'\n", null, false);
                            continue;
                        }
                    }
                }

                $newObj = $new_address;
            }

            if( $create_addressGroup )
            {
                $newAddressGroup = $addressStore->find( $address_addressgroup );
                if( $newAddressGroup == null )
                {
                    $string = $context->padding."- object: '{$address_addressgroup}'\n";
                    $string .= $context->padding.$context->padding." *** create addressgroup with name: '{$address_addressgroup}'\n";
                    PH::ACTIONlog( $context, $string );
                    if( $context->isAPI )
                        $addressStore->API_newAddressGroup( $address_addressgroup );
                    else
                        $addressStore->newAddressGroup( $address_addressgroup );
                }
                else
                {
                    $string = $context->padding . "- object: '{$address_addressgroup}'\n";
                    $string .= $context->padding . $context->padding . " *** SKIPPED addressgroup name: '{$address_addressgroup}' already available\n";
                    PH::ACTIONlog( $context, $string );
                    #maybe print out the members of the group
                }

                $newgrpObj = $addressStore->find( $address_addressgroup );
                if( $newgrpObj != null )
                {
                    if( $newgrpObj->has( $newObj ) == false )
                    {
                        $string = $context->padding.$context->padding." *** add addressobject with name: '{$new_address_name}' as member to addressgroup: '{$address_addressgroup}'\n\n";
                        PH::ACTIONlog( $context, $string );
                        if( $context->isAPI )
                            $newgrpObj->API_addMember( $newObj );
                        else
                            $newgrpObj->addMember( $newObj );
                    }
                }
                else
                {
                    $string = "addressgroup: ".$address_addressgroup." not available";
                    PH::ACTIONstatus( $context, 'SKIPPED', $string);
                }
            }
        }

    },
    'args' => Array(
        'file' => Array( 'type' => 'string',
            'default' => '*nodefault*',
            'help' =>
                "file syntax:   AddressObjectName,IP-Address,Address-group

example:
    h-192.168.0.1,192.168.0.1/32,private-network-AddressGroup
    n-192.168.2.0m24,192.168.2.0/24,private-network-AddressGroup\n"
        ),
        'force-add-to-group' => array('type' => 'bool', 'default' => FALSE),
        'force-change-value' => array('type' => 'bool', 'default' => FALSE)
    ),
);

AddressCallContext::$supportedActions['create-AddressGroup'] = array(
    'name' => 'create-addressgroup',
    'MainFunction' => function (AddressCallContext $context) {
    },
    'GlobalFinishFunction' => function (AddressCallContext $context) {

        $addressStore = $context->subSystem->addressStore;

        $newName = $context->arguments['name'];


        if( $addressStore->find( $newName ) === null )
        {
            $string = "create AddressGroup object : '" . $newName . "'";
            PH::ACTIONlog( $context, $string );

            if( $context->isAPI )
            {
                if( $context->isSaseAPI )
                {
                    $tmp_address = $addressStore->API_newAddress("dummy", "ip-netmask", "127.0.0.1", "dummy");
                    $tmp_group = $addressStore->newAddressGroup( $newName);
                    $tmp_group->addMember( $tmp_address );
                    $tmp_group->API_sync();
                }
                else
                    $addressStore->API_newAddressGroup($newName);
            }

            else
                $addressStore->newAddressGroup( $newName);
        }
        else
        {
            $string = "AddressGroup named '" . $newName . "' already exists, cannot create";
            PH::ACTIONlog( $context, $string );
        }

    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => '*nodefault*')
    )
);

AddressCallContext::$supportedActions['move-range2network'] = array(
    'name' => 'move-range2network',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isGroup() || $object->isRegion() || !$object->isType_ipRange() )
        {
            $string = "Address object is not of type ip-range";
            PH::ACTIONstatus( $context, 'skipped', $string);
            return false;
        }


        $array = explode( "-", $object->value() );
        $start = ip2long( $array[0] );
        $end = ip2long( $array[1] );

        $range = CIDR::range2network( $start, $end );

        if( $range !== false )
        {
            //network' => $start, 'mask' => $netmask, 'string' => long2ip($start) . '/' . $netmask
            $object->setType( "ip-netmask" );
            $object->setValue( $range['string'] );

            if( $context->isAPI )
                $object->API_sync();
            $string = "moved to type ip-netmask with value: ".$range['string'];
            PH::ACTIONlog( $context, $string );
        }
        else
        {
            $string = "Address object of type ip-range named '" . $object->name() . "' cannot moved to an ip-netmask object type. value: ".$object->value();
            PH::ACTIONlog( $context, $string );
        }

    }
);

AddressCallContext::$supportedActions['move-wildcard2network'] = array(
    'name' => 'move-wildcard2network',
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;

        if( $object->isGroup() || $object->isRegion() || !$object->isType_ipWildcard() )
        {
            $string = "Address object is not of type ip-wildcard";
            PH::ACTIONstatus( $context, 'skipped', $string);
            return false;
        }


        $array = explode( "/", $object->value() );
        $address = $array[0];
        $wildcardmask = $array[1];

        $cidr_array = explode(".", $wildcardmask);
        $tmp_hostCidr = "";
        foreach( $cidr_array as $key => &$entry )
        {
            $final_entry = 255 - (int)$entry;
            if( $key == 0 )
                $tmp_hostCidr .= $final_entry;
            else
                $tmp_hostCidr .= ".".$final_entry;
        }

        $cidr = CIDR::netmask2cidr($tmp_hostCidr);

        if( is_int( $cidr ) )
        {
            //network' => $start, 'mask' => $netmask, 'string' => long2ip($start) . '/' . $netmask
            $object->setType( "ip-netmask" );
            $value = $address."/".$cidr;
            $object->setValue( $value );

            if( $context->isAPI )
                $object->API_sync();
            $string = "moved to type ip-netmask with value: ".$value;
            PH::ACTIONlog( $context, $string );
        }
        else
        {
            $string = "Address object of type ip-wildcard named '" . $object->name() . "' cannot moved to an ip-netmask object type. value: ".$object->value();
            PH::ACTIONlog( $context, $string );
        }
    }
);


AddressCallContext::$supportedActions['upload-Address-2CloudManager'] = array(
    'name' => 'upload-address-2cloudmanager',
    'GlobalInitFunction' => function (AddressCallContext $context) {
        //get Panorama config
        //possible: XML file / XML API
        //including DG

        if( $context->isSaseAPI === False )
            derr( "only Strata Cloud manager is supported for this type=address action", null, False );

        $filename = $context->arguments['panorama_file'];
        $DGname = $context->arguments['dg_name'];
        $context->objectList = array();

        ##########################################

        $argv2 = array();
        $argc2 = array();
        PH::$args = array();
        PH::$argv = array();
        $argv2[0] = "test";

        if( file_exists( $filename ) )
                $argv2[] = "in=".$filename;
        else
            derr("cannot open file '{$filename}", null, False);

        //create new UTIL with Panorama config in
        $util2 = new UTIL("custom", $argv2, $argc2, "actions=upload-address-2cloudmanager");
        $util2->utilInit();
        $util2->load_config();

##########################################
##########################################

        $pan = $util2->pan;

        //check that load config file is Panorama
        if( $pan->isPanorama() )
        {
            //find DG name
            $sub = $pan->findDeviceGroup( $DGname );
            if( $sub === null )
                $util2->locationNotFound($DGname);
        }

        else
            derr( "only Panorama config file is supported", null, False );

        ##########################################

        foreach( $sub->addressStore->all( "!(object is.group) and !(object is.tmp)" ) as $obj )
        {
            $context->objectList[] = $obj;
            #print $obj->name()."\n";
        }

    },
    'MainFunction' => function (AddressCallContext $context) {

    },
    'GlobalFinishFunction' => function (AddressCallContext $context) {

        $addressStore = $context->subSystem->addressStore;

        foreach( $context->objectList as $object )
        {
            if( $object->isGroup() || $object->isTmpAddr() )
            {
                $string = "Address object is Group or TMP - not supported";
                PH::ACTIONstatus( $context, 'skipped', $string);
                continue;
            }

            $newName = $object->name();
            $value = $object->value();
            $type = $object->type();

            $tmpAddr = $addressStore->find( $newName );
            if( $tmpAddr === null )
            {
                $string = "upload Address object : '" . $newName . "' - type: ".$type." - value: ".$value;
                PH::ACTIONlog( $context, $string );

                if( $context->isAPI )
                    $addressStore->API_newAddress($newName, $type, $value);
                else
                    derr( "only API supported" );
            }
            else
                mwarning( "objectname: ".$newName." is already available", null, false );
        }
    },
    'args' => array(
        'panorama_file' => Array( 'type' => 'string', 'default' => '*nodefault*'),
        'dg_name' => array('type' => 'string', 'default' => '*nodefault*')
    )
);

AddressCallContext::$supportedActions['upload-AddressGroup-2CloudManager'] = array(
    'name' => 'upload-addressgroup-2cloudmanager',
    'GlobalInitFunction' => function (AddressCallContext $context) {
        //get Panorama config
        //possible: XML file / XML API
        //including DG

        if( $context->isSaseAPI === False )
            derr( "only Strata Cloud manager is supported for this type=address action", null, False );

        $filename = $context->arguments['panorama_file'];
        $DGname = $context->arguments['dg_name'];
        $context->objectList = array();

        ##########################################

        $argv2 = array();
        $argc2 = array();
        PH::$args = array();
        PH::$argv = array();
        $argv2[0] = "test";

        if( file_exists( $filename ) )
            $argv2[] = "in=".$filename;
        else
            derr("cannot open file '{$filename}", null, False);

        //create new UTIL with Panorama config in
        $util2 = new UTIL("custom", $argv2, $argc2, "actions=upload-address-2cloudmanager");
        $util2->utilInit();
        $util2->load_config();

##########################################
##########################################

        $pan = $util2->pan;

        //check that load config file is Panorama
        if( $pan->isPanorama() )
        {
            //find DG name
            $sub = $pan->findDeviceGroup( $DGname );
            if( $sub === null )
                $util2->locationNotFound($DGname);
        }
        else
            derr( "only Panorama config file is supported", null, False );

        ##########################################

        foreach( $sub->addressStore->all( "(object is.group)" ) as $obj )
        {
            #print $obj->name()."\n";
            /** @var $obj AddressGroup */
            $context->objectList[$obj->name()]['obj'] = $obj;
        }
    },
    'MainFunction' => function (AddressCallContext $context) {
    },
    'GlobalFinishFunction' => function (AddressCallContext $context) {

        $addressStore = $context->subSystem->addressStore;

        foreach( $context->objectList as $object_entry )
        {
            $object = $object_entry['obj'];
            if( !$object->isGroup() )
            {
                $string = "Address object is not Group - not supported";
                PH::ACTIONstatus( $context, 'skipped', $string);
                continue;
            }

            $newName = $object->name();

            $adrGrp = $addressStore->find( $newName );
            if( $adrGrp === null )
            {
                $string = "upload AddressGroup object : '" . $newName;
                PH::ACTIONlog( $context, $string );

                //check that addressgroup and all members are available
                //then API sync if possible

                $adrGrp = $addressStore->newAddressGroup( $newName );
                foreach( $object->members() as $member2 )
                {
                    if( $object->owner === $member2->owner )
                        $adrGrp->addMember( $member2 );
                    else
                        mwarning( "this objectname: ".$member2->name()." is part of another DG: ".$member2->owner->owner->name() );
                }


                if( $context->isAPI )
                    $adrGrp->API_sync( true );
            }
            else
                mwarning( "objectname: ".$newName." is already available", null, false );
        }
    },
    'args' => array(
        'panorama_file' => Array( 'type' => 'string', 'default' => '*nodefault*'),
        'dg_name' => array('type' => 'string', 'default' => '*nodefault*')
    )
);

AddressCallContext::$supportedActions['combine-addressgroups'] = array(
    'name' => 'combine-addressgroups',
    'GlobalInitFunction' => function (AddressCallContext $context) {

        $new_addressgroup_name = $context->arguments['new_addressgroup_name'];

        $obj = $context->subSystem->addressStore->find($new_addressgroup_name);
        if( $obj !== null )
        {
            derr("this action is only working if no addressgroup with name: ".$new_addressgroup_name." is not already available", null, False);
        }


        $context->objectList = array();
    },
    'MainFunction' => function (AddressCallContext $context) {
        $object = $context->object;
        if( !$object->isAddress() )
            $context->objectList[] = $object;
    },
    'GlobalFinishFunction' => function (AddressCallContext $context) {
        $new_addressgroup_name = $context->arguments['new_addressgroup_name'];
        $replace_groups = $context->arguments['replace_groups'];

        PH::print_stdout("   - create AddressGroup: ". $new_addressgroup_name );

        if( $context->isAPI )
            $obj = $context->subSystem->addressStore->API_newAddressGroup($new_addressgroup_name);
        else
            $obj = $context->subSystem->addressStore->newAddressGroup($new_addressgroup_name);

        foreach( $context->objectList as $group )
        {
            /** @var AddressGroup $group*/
            foreach( $group->members() as $member )
            {
                PH::print_stdout("     - add address as member: ". $member->name());
                if( $context->isAPI )
                    $obj->API_addMember($member);
                else
                    $obj->addMember($member);
            }

            foreach($group->tags->getAll() as $tag)
            {
                PH::print_stdout("     - add tag: ". $tag->name());
                if( $context->isAPI )
                    $obj->tags->API_addTag($tag);
                else
                    $obj->tags->addTag($tag);
            }

            if( $replace_groups )
            {
                PH::print_stdout( " replace addressgroup: ". $group->name() . " with new addressgroup: ". $obj->name());
                if( $context->isAPI )
                    $group->replaceMeGlobally($obj,true);
                else
                    $group->replaceMeGlobally($obj);
            }
        }
    },
    'args' => array(
        'new_addressgroup_name' => Array( 'type' => 'string', 'default' => '*nodefault*'),
        'replace_groups' => array('type' => 'bool', 'default' => FALSE)
    )
);

AddressCallContext::$supportedActions['address-group-create-EDL-IP'] = array(
    'name' => 'address-group-create-edl-ip',
    'GlobalInitFunction' => function (AddressCallContext $context) {
        $filename = $context->arguments['filename'];
        if (file_exists($filename))
            unlink($filename);
    },
    'MainFunction' => function (AddressCallContext $context) {
        $f = AddressCallContext::$commonActionFunctions['edl-create-list']['function'];
        $f($context, 'ip-netmask');
    },
    'args' => array(
        'filename' => Array( 'type' => 'string', 'default' => '*nodefault*')
    )
);

AddressCallContext::$supportedActions['address-group-create-EDL-FQDN'] = array(
    'name' => 'address-group-create-edl-fqdn',
    'GlobalInitFunction' => function (AddressCallContext $context) {
        $filename = $context->arguments['filename'];
        if (file_exists($filename))
            unlink($filename);
    },
    'MainFunction' => function (AddressCallContext $context) {
        $f = AddressCallContext::$commonActionFunctions['edl-create-list']['function'];
        $f($context, 'fqdn');
    },
    'args' => array(
        'filename' => Array( 'type' => 'string', 'default' => '*nodefault*')
    )
);
