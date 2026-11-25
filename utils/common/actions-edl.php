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

EDLCallContext::$supportedActions['delete'] = array(
    'name' => 'delete',
    'MainFunction' => function (EDLCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            $string = "this object is used by other objects and cannot be deleted (use deleteForce to try anyway)";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( $object->isUsedViaSameNameOverride() )
        {
            $string = "this object has no direct reference, but through a same-name object in another device-group level (Shared / ancestor / descendant) Panorama pushes this object and firewalls use it (use delete-Force to try anyway)";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( $context->isAPI )
        {
            mwarning("action delete via API not available yet");
            # $object->owner->API_removeZone($object);
        }
        else
        {
            mwarning("action delete not available yet");
            #$object->owner->removeZone($object);
        }
    },
);

EDLCallContext::$supportedActions['delete-force'] = array(
    'name' => 'delete-Force',
    'MainFunction' => function (EDLCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            $string = "this object seems to be used so deletion may fail.";
            PH::ACTIONstatus( $context, "WARNING", $string );
        }
        if( $object->isUsedViaSameNameOverride() )
        {
            $string = "firewalls use this object through a same-name object in another device-group level: deleting it changes what Panorama pushes";
            PH::ACTIONstatus( $context, "WARNING", $string );
        }
        if( $context->isAPI )
        {
            mwarning("action delete via API not available yet");
            # $object->owner->API_removeZone($object);
        }
        else
        {
            mwarning("action delete not available yet");
            #$object->owner->removeZone($object);
        }
    },
);
EDLCallContext::$supportedActions['deleteforce'] = array_merge(EDLCallContext::$supportedActions['delete-force'], 
    array(
        'name' => 'deleteForce',
        'deprecated' => 'this action "deleteForce" is deprecated, you should use "delete-Fore" instead!',
        'help' => 'this action "deleteForce" is deprecated, you should use "delete-Fore" instead!'
    )
);

EDLCallContext::$supportedActions['name-addprefix'] = array(
    'name' => 'name-addPrefix',
    'MainFunction' => function (EDLCallContext $context) {
        $object = $context->object;
        $newName = $context->arguments['prefix'] . $object->name();

        if( $object->isTmp() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        if( strlen($newName) > 127 )
        {
            $string = "resulting name is too long";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, FALSE) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, TRUE) !== null )
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
EDLCallContext::$supportedActions['name-addsuffix'] = array(
    'name' => 'name-addSuffix',
    'MainFunction' => function (EDLCallContext $context) {
        $object = $context->object;
        $newName = $object->name() . $context->arguments['suffix'];

        if( $object->isTmp() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "new name will be '{$newName}'";
        PH::ACTIONlog( $context, $string );

        if( strlen($newName) > 127 )
        {
            $string = "resulting name is too long";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, FALSE) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, TRUE) !== null )
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
EDLCallContext::$supportedActions['name-removeprefix'] = array(
    'name' => 'name-removePrefix',
    'MainFunction' => function (EDLCallContext $context) {
        $object = $context->object;
        $prefix = $context->arguments['prefix'];

        if( $object->isTmp() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

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

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, FALSE) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, TRUE) !== null )
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
EDLCallContext::$supportedActions['name-removesuffix'] = array(
    'name' => 'name-removeSuffix',
    'MainFunction' => function (EDLCallContext $context) {
        $object = $context->object;
        $suffix = $context->arguments['suffix'];
        $suffixStartIndex = strlen($object->name()) - strlen($suffix);

        if( $object->isTmp() )
        {
            $string = "not applicable to TMP objects";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

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

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, FALSE) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, TRUE) !== null )
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

EDLCallContext::$supportedActions['name-touppercase'] = array(
    'name' => 'name-toUpperCase',
    'MainFunction' => function (EDLCallContext $context) {
        $object = $context->object;
        #$newName = $context->arguments['prefix'].$object->name();
        $newName = mb_strtoupper($object->name(), 'UTF8');

        if( $object->isTmp() )
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
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else

            $object->setName($newName);
    }
);
EDLCallContext::$supportedActions['name-tolowercase'] = array(
    'name' => 'name-toLowerCase',
    'MainFunction' => function (EDLCallContext $context) {
        $object = $context->object;
        #$newName = $context->arguments['prefix'].$object->name();
        $newName = mb_strtolower($object->name(), 'UTF8');

        if( $object->isTmp() )
        {
            $string = "not applicable to TMP objects";
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
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else

            $object->setName($newName);
    }
);
EDLCallContext::$supportedActions['name-toucwords'] = array(
    'name' => 'name-toUCWords',
    'MainFunction' => function (EDLCallContext $context) {
        $object = $context->object;
        #$newName = $context->arguments['prefix'].$object->name();
        $newName = mb_strtolower($object->name(), 'UTF8');
        $newName = ucwords($newName);

        if( $object->isTmp() )
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
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else

            $object->setName($newName);
    }
);

EDLCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (EDLCallContext $context) {
        $object = $context->object;

        $object->display_references(7);
    },
);

EDLCallContext::$supportedActions['display'] = array(
    'name' => 'display',
    'MainFunction' => function (EDLCallContext $context) {
        $object = $context->object;
        $tmp_txt = "     * " . get_class($object) . " '{$object->name()}'  ";

        PH::print_stdout( $tmp_txt );
        PH::$JSON_TMP['sub']['object'][$object->name()]['name'] = $object->name();
        PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);

        if( $object->recurring == null )
            $tmp_recurring = "---";
        else
            $tmp_recurring = $object->recurring;
        $string = "type: ".$object->type." | recurring: ".$tmp_recurring. " | url: ".$object->url;
        PH::print_stdout( "       - ".$string );
        // the same as data (shadow-json, config viewer): before only name and class - the viewer showed no list type,
        // recurring and URL
        PH::$JSON_TMP['sub']['object'][$object->name()]['edl-type'] = $object->type;
        PH::$JSON_TMP['sub']['object'][$object->name()]['recurring'] = $object->recurring;
        PH::$JSON_TMP['sub']['object'][$object->name()]['url'] = $object->url;


    },
);


EDLCallContext::$supportedActions[] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (EDLCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (EDLCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (EDLCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;

        $lines = '';


        $addWhereUsed = FALSE;
        $addUsedInLocation = FALSE;

        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = TRUE;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = TRUE;


        $headers = '<th>ID</th><th>location</th><th>name</th><th>type</th><th>recurring</th><th>url</th>';

        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';

        $count = 0;
        if( isset($context->objectList) )
        {
            foreach( $context->objectList as $object )
            {
                $count++;

                /** @var Tag $object */
                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $context->encloseFunction( (string)$count );

                $lines .= $context->encloseFunction(PH::getLocationString($object));

                $lines .= $context->encloseFunction($object->name());

                $lines .= $context->encloseFunction($object->type());

                $lines .= $context->encloseFunction($object->recurring());

                $lines .= $context->encloseFunction($object->url());


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

                $lines .= "</tr>\n";
            }
        }

        require_once dirname(__FILE__) . '/../lib/ExportToHtmlHelper.php';
        ExportToHtmlHelper::writeHtmlExport($filename, $headers, $lines);
    },
    'args' => array('filename' => array('type' => 'string', 'default' => '*nodefault*'),
        'additionalFields' =>
            array('type' => 'pipeSeparatedList',
                'subtype' => 'string',
                'default' => '*NONE*',
                'choices' => array('WhereUsed', 'UsedInLocation'),
                'help' =>
                    "pipe(|) separated list of additional field to include in the report. The following is available:\n" .
                    "  - WhereUsed : list places where object is used (rules, groups ...)\n" .
                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n")
    )
);
EDLCallContext::$supportedActions[] = array_merge(EDLCallContext::$supportedActions[array_key_last(EDLCallContext::$supportedActions)], array('name' => 'exportToHtml'));

EDLCallContext::$supportedActions[] = array(
    'name' => 'move',
    'MainFunction' => function (EDLCallContext $context) {
        $object = $context->object;

        $localLocation = 'shared';

        if( !$object->owner->owner->isPanorama() && !$object->owner->owner->isFirewall() )
            $localLocation = $object->owner->owner->name();

        $targetLocation = $context->arguments['location'];
        $targetStore = null;

        if( $localLocation == $targetLocation )
        {
            $string = "because original and target destinations are the same: $targetLocation";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        $spStore = get_class($object)."Store";
        if( $targetLocation == 'shared' )
        {
            $findSubSystem = $rootObject;

            $targetStore = $rootObject->$spStore;
        }
        else
        {
            $findSubSystem = $rootObject->findSubSystemByName($targetLocation);
            if( $findSubSystem === null )
                derr("cannot find VSYS/DG named '$targetLocation'");

            $targetStore = $findSubSystem->$spStore;
        }

        if( $localLocation == 'shared' )
        {
            $reflocations = $object->getReferencesLocation();

            foreach( $object->getReferences() as $ref )
            {
                if( PH::getLocationString($ref) != $targetLocation )
                {
                    $skipped = TRUE;
                    //check if targetLocation is parent of reflocation
                    if( $findSubSystem->owner->isPanorama() )
                        $locations = $findSubSystem->childDeviceGroups(TRUE);
                    elseif( $findSubSystem->owner->isFirewall() )
                    {
                        $locations = array();
                        $skipped = TRUE;
                    }

                    foreach( $locations as $childloc )
                    {
                        if( PH::getLocationString($ref) == $childloc->name() )
                            $skipped = FALSE;
                    }

                    if( $skipped )
                    {
                        $string = "moving from SHARED to sub-level is NOT possible because of references";
                        PH::ACTIONstatus( $context, "SKIPPED", $string );
                        return;
                    }
                }
            }
        }

        if( $localLocation != 'shared' && $targetLocation != 'shared' )
        {
            if( $context->baseObject->isFirewall() )
            {
                $string = "moving between VSYS is not supported";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }

            foreach( $object->getReferences() as $ref )
            {
                if( PH::getLocationString($ref) != $targetLocation )
                {
                    $skipped = TRUE;
                    //check if targetLocation is parent of reflocation
                    $locations = $findSubSystem->childDeviceGroups(TRUE);
                    foreach( $locations as $childloc )
                    {
                        if( PH::getLocationString($ref) == $childloc->name() )
                            $skipped = FALSE;
                    }

                    if( $skipped )
                    {
                        $string = "moving between 2 VSYS/DG is not possible because of references on higher DG level";
                        PH::ACTIONstatus( $context, "SKIPPED", $string );
                        return;
                    }
                }
            }
        }

        $conflictObject = $targetStore->find($object->name(), null, FALSE);
        if( $conflictObject === null )
        {
            $string = "moved, no conflict";
            PH::ACTIONlog( $context, $string );

            //Todo: update remove and add SP object
            if( $context->isAPI )
            {
                $oldXpath = $object->getXPath();
                $object->owner->API_removeEDL($object);
                $targetStore->API_addEDL($object);

                $object->API_sync();
                $context->connector->sendDeleteRequest($oldXpath);
            }
            else
            {
                $object->owner->removeEDL($object);
                $targetStore->addEDL($object);
            }
            return;
        }

        if( $context->arguments['mode'] == 'skipifconflict' )
        {
            $string = "there is an object with same name. Choose another mode to to resolve this conflict";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "there is a conflict with an object of same name";
        PH::ACTIONlog( $context, $string );

        if( $object->equals($conflictObject) )
        {
            $string = "Removed because target has same content";
            PH::ACTIONlog( $context, $string );
            $object->replaceMeGlobally($conflictObject);

            if( $context->isAPI )
                $object->owner->API_removeSecurityProfile($object);
            else
                $object->owner->removeSecurityProfile($object);
        }

    },
    'args' => array('location' => array('type' => 'string', 'default' => '*nodefault*'),
        'mode' => array('type' => 'string', 'default' => 'skipIfConflict', 'choices' => array('skipIfConflict', 'removeIfMatch'))
    ),
);
// <editor-fold desc=" ***** EDL fields (offline) *****" defaultstate="collapsed" >
// the source URL and every text: the aliases $$comma$$ $$colon$$ $$forwardslash$$ $$pipe$$ (':' '/' ',' separate actions / arguments)

EDLCallContext::$supportedActions[] = array(
    'name' => 'type-set',
    'MainFunction' => function (EDLCallContext $context) {
        $context->runEdit( function( EDL $o, $a ) {
            $src = $a['source'] === '*nodefault*' ? '' : PH::textAliases( $a['source'] );
            $o->editTypeSet( $a['type'], $src );
            return "type '" . $o->type() . "', source '" . $o->url() . "'";
        } );
    },
    'args' => array(
        'type' => array( 'type' => 'string', 'default' => '*nodefault*', 'choices' => EDL::EDL_TYPES ),
        'source' => array( 'type' => 'string', 'default' => '*nodefault*', 'help' => 'needed when the source does not fit the new type (URL / name of a predefined list)' ),
    ),
    'help' => "the type of the list: ip, domain, url, imsi, imei, predefined-ip, predefined-url. Example: 'actions=type-set:domain' or " .
        "'actions=type-set:predefined-ip,panw-bulletproof-ip-list'"
);

EDLCallContext::$supportedActions[] = array(
    'name' => 'source-set',
    'MainFunction' => function (EDLCallContext $context) {
        $context->runEdit( function( EDL $o, $a ) {
            $o->editSourceSet( PH::textAliases( $a['source'] ) );
            return "source '" . $o->url() . "'";
        } );
    },
    'args' => array( 'source' => array( 'type' => 'string', 'default' => '*nodefault*' ) ),
    'help' => "the URL of the list (predefined types: the name of the predefined list). ':' and '/' as aliases. Example: " .
        "'actions=source-set:https\$\$colon\$\$\$\$forwardslash\$\$\$\$forwardslash\$\$lists.example.com\$\$forwardslash\$\$ip.txt'"
);

EDLCallContext::$supportedActions[] = array(
    'name' => 'recurring-set',
    'MainFunction' => function (EDLCallContext $context) {
        $context->runEdit( function( EDL $o, $a ) {
            $at = $a['at'] === '*nodefault*' ? '' : (string)$a['at'];
            $day = $a['day'] === '*nodefault*' ? '' : (string)$a['day'];
            $o->editRecurringSet( $a['interval'], $at, $day );
            return "update '" . $a['interval'] . "'" . ( $at !== '' ? ' at ' . $at : '' ) . ( $day !== '' ? ', day ' . $day : '' );
        } );
    },
    'args' => array(
        'interval' => array( 'type' => 'string', 'default' => '*nodefault*', 'choices' => EDL::EDL_RECURRING ),
        'at' => array( 'type' => 'string', 'default' => '*nodefault*', 'help' => 'daily / weekly / monthly: the hour 0-23' ),
        'day' => array( 'type' => 'string', 'default' => '*nodefault*', 'help' => 'weekly: monday … sunday; monthly: 1-31' ),
    ),
    'help' => "how often the firewall reads the list. Example: 'actions=recurring-set:hourly', 'actions=recurring-set:weekly,3,monday'"
);

EDLCallContext::$supportedActions[] = array(
    'name' => 'description-set',
    'MainFunction' => function (EDLCallContext $context) {
        $context->runEdit( function( EDL $o, $a ) {
            $text = $a['description'] === '*nodefault*' ? '' : PH::textAliases( (string)$a['description'] );
            $o->editDescriptionSet( $text );
            return "description '" . $text . "'";
        } );
    },
    'args' => array( 'description' => array( 'type' => 'string', 'default' => '' ) ),
    'help' => "the description of the list (empty: removed); in the type element of the EDL"
);

EDLCallContext::$supportedActions[] = array(
    'name' => 'certificate-profile-set',
    'MainFunction' => function (EDLCallContext $context) {
        $context->runEdit( function( EDL $o, $a ) {
            $o->editCertificateProfileSet( (string)$a['profile'] );
            return "certificate profile '" . $a['profile'] . "'";
        } );
    },
    'args' => array( 'profile' => array( 'type' => 'string', 'default' => '*nodefault*', 'help' => 'name of the certificate profile, none: removed' ) ),
    'help' => "the certificate profile that checks the server of an https source. Example: 'actions=certificate-profile-set:none'"
);

EDLCallContext::$supportedActions[] = array(
    'name' => 'exception-add',
    'MainFunction' => function (EDLCallContext $context) {
        $context->runEdit( function( EDL $o, $a ) {
            $o->editExceptionAdd( PH::textAliases( (string)$a['entry'] ) );
            return "exception '" . PH::textAliases( (string)$a['entry'] ) . "' added";
        } );
    },
    'args' => array( 'entry' => array( 'type' => 'string', 'default' => '*nodefault*' ) ),
    'help' => "an entry of the list the firewall ignores (IP, domain, URL). Example: 'actions=exception-add:192.0.2.10'"
);

EDLCallContext::$supportedActions[] = array(
    'name' => 'exception-remove',
    'MainFunction' => function (EDLCallContext $context) {
        $context->runEdit( function( EDL $o, $a ) {
            $o->editExceptionRemove( PH::textAliases( (string)$a['entry'] ) );
            return "exception '" . PH::textAliases( (string)$a['entry'] ) . "' removed";
        } );
    },
    'args' => array( 'entry' => array( 'type' => 'string', 'default' => '*nodefault*' ) ),
    'help' => "removes an entry of the exception list"
);

EDLCallContext::$supportedActions[] = array(
    'name' => 'expand-domain-set',
    'MainFunction' => function (EDLCallContext $context) {
        $context->runEdit( function( EDL $o, $a ) {
            $o->editExpandDomainSet( (bool)$a['enable'] );
            return "expand domain " . ( $a['enable'] ? 'yes' : 'no' );
        } );
    },
    'args' => array( 'enable' => array( 'type' => 'bool', 'default' => '*nodefault*' ) ),
    'help' => "type domain: also the subdomains of every entry. Example: 'actions=expand-domain-set:true'"
);

EDLCallContext::$supportedActions[] = array(
    'name' => 'name-rename',
    'MainFunction' => function (EDLCallContext $context) {
        $context->runEdit( function( EDL $o, $a ) {
            $old = $o->name();
            $n = $o->editRename( (string)$a['newname'] );
            return "renamed '" . $old . "' -> '" . $o->name() . "' (users updated: " . $n . ")";
        } );
    },
    'args' => array( 'newname' => array( 'type' => 'string', 'default' => '*nodefault*' ) ),
    'help' => "renames the list and every rule that uses it (as source / destination)"
);
// </editor-fold>
