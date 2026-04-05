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


LogProfileCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (LogProfileCallContext $context) {
        $object = $context->object;

        $object->display_references(7);
    },
);

LogProfileCallContext::$supportedActions['display'] = array(
    'name' => 'display',
    'MainFunction' => function (LogProfileCallContext $context) {
        /** @var LogProfile $object */
        $object = $context->object;
        $tmp_txt = "     * " . get_class($object) . " '{$object->name()}'   ";


        if( !empty( $object->type() ) )
        {
            foreach( $object->type() as $key => $name )
            {
                if( isset($name['notSet']))
                {
                    $tmp_txt = "       - ".str_pad( $key, 12 );
                    $tmp_txt .= " | NOT SET";
                }
                else
                {
                    foreach ($name as $name_key => $type)
                    {
                        $tmp_txt = "       - " . str_pad($key, 12)." | ".str_pad($name_key, 12)."";
                        foreach ($type as $type_key => $type_value)
                        {
                            $tmp_txt .= " |" . $type_key . "->" . $type_value;
                        }
                    }
                }
                PH::print_stdout($tmp_txt);
            }
        }

        if( PH::$shadow_displayxmlnode )
            DH::DEBUGprintDOMDocument($object->xmlroot);

    },
);

LogProfileCallContext::$supportedActions[] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (LogProfileCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (LogProfileCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (LogProfileCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;

        $lines = '';


        $addWhereUsed = FALSE;
        $addUsedInLocation = FALSE;
        $addTotalUse = FALSE;

        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = TRUE;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = TRUE;
        if( isset($optionalFields['TotalUse']) )
            $addTotalUse = TRUE;

        #$headers = '<th>ID</th><th>location</th><th>name</th><th>color</th><th>description</th>';
        $headers = '<th>ID</th><th>location</th><th>name</th><th>content</th>';

        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';
        if( $addTotalUse )
            $headers .= '<th>total use</th>';

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

                if( !empty( $object->type() ) )
                {
                    $tmp_array = array();
                    foreach( $object->type() as $key => $name )
                    {
                        if( isset($name['notSet']))
                        {
                            $tmp_txt = "       - ".str_pad( $key, 12 );
                            $tmp_txt .= " | NOT SET";
                        }
                        else
                        {
                            foreach ($name as $name_key => $type)
                            {
                                $tmp_txt = "       - " . str_pad($key, 12)." | ".str_pad($name_key, 12)."";
                                foreach ($type as $type_key => $type_value)
                                {
                                    $tmp_txt .= " |" . $type_key . "->" . $type_value;
                                }
                            }
                        }
                        $tmp_array[] = $tmp_txt;


                    }
                    $lines .= $context->encloseFunction($tmp_array);
                }
                else
                {
                    $lines .= $context->encloseFunction("---");
                }
                /*
                //information for log-profile needed
                if( $object->isTag() )
                {
                    if( $object->isTmp() )
                    {
                        $lines .= $context->encloseFunction('unknown');
                        $lines .= $context->encloseFunction('');

                    }
                    else
                    {
                        $lines .= $context->encloseFunction($object->color);
                        $lines .= $context->encloseFunction($object->getComments());
                    }
                }
                */

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
                if( $addTotalUse)
                {
                    $refCount = $object->countReferences();
                    if( $refCount == 0 )
                        $refCount = "---";
                    else
                        $refCount = (string)$refCount ;
                    $lines .= $context->encloseFunction( $refCount );
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
                'choices' => array('WhereUsed', 'UsedInLocation', 'TotalUse'),
                'help' =>
                    "pipe(|) separated list of additional field to include in the report. The following is available:\n" .
                    "  - WhereUsed : list places where object is used (rules, groups ...)\n" .
                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n" .
                    "  - TotalUse : list a counter how often this object is used\n"
            )
    )
);
LogProfileCallContext::$supportedActions[] = array_merge(LogProfileCallContext::$supportedActions[array_key_last(LogProfileCallContext::$supportedActions)], array('name' => 'exportToHtml'));

LogProfileCallContext::$supportedActions['create'] = array(
    'name' => 'create',
    'MainFunction' => function (LogProfileCallContext $context) {
    },
    'GlobalFinishFunction' => function (LogProfileCallContext $context)
    {
        $object = $context->object;

        $args = &$context->arguments;
        $log_name = $args['logprofile-name'];

        $log_prof_obj = $context->subSystem->LogProfileStore->createLogProfile($log_name);

        if( $context->isAPI || $context->isSCMAPI )
            $log_prof_obj->API_sync(true);
    },
    'args' => array('logprofile-name' => array('type' => 'string', 'default' => '*nodefault*') )
);
LogProfileCallContext::$supportedActions[] = array(
    'name' => 'move',
    'MainFunction' => function (LogProfileCallContext $context) {
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

        if( $targetLocation == 'shared' )
        {
            $findSubSystem = $rootObject;
            $targetStore = $rootObject->LogProfileStore;
        }
        else
        {
            $findSubSystem = $rootObject->findSubSystemByName($targetLocation);
            if( $findSubSystem === null )
                derr("cannot find VSYS/DG named '$targetLocation'");

            $targetStore = $findSubSystem->LogProfileStore;
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

            if( $context->isAPI )
            {
                $oldXpath = $object->getXPath();
                $object->owner->removeLogProfile($object);
                $targetStore->addLogProfile($object);
                if( $context->isSaseAPI || $context->isSCMAPI )
                {
                    $object->API_sync(true);

                    $context->connector->sendDELETERequest($object);
                }
                else
                {
                    $object->API_sync();
                    $context->connector->sendDeleteRequest($oldXpath);
                }

            }
            else
            {
                $object->owner->removeLogProfile($object);
                $targetStore->addLogProfile($object);
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
                $object->owner->API_removeLogProfile($object);
            else
                $object->owner->removeLogProfile($object);
            return;
        }

    },
    'args' => array('location' => array('type' => 'string', 'default' => '*nodefault*'),
        'mode' => array('type' => 'string', 'default' => 'skipIfConflict', 'choices' => array('skipIfConflict', 'removeIfMatch'))
    ),
);
LogProfileCallContext::$supportedActions['delete'] = array(
    'name' => 'delete',
    'MainFunction' => function (LogProfileCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            $string = "this object is used by other objects and cannot be deleted (use deleteForce to try anyway)";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( $context->isAPI )
            $object->owner->API_removeLogProfile($object);
        else
            $object->owner->removeLogProfile($object);
    },
);