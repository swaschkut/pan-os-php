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

SecurityProfileCallContext::$supportedActions['delete'] = array(
    'name' => 'delete',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            $string = "this object is used by other objects and cannot be deleted (use deleteForce to try anyway)";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        //Todo: continue improvement for SecProf

        if( get_class($object) == "customURLProfile" )
        {
            #$string = "object of class customURLProfile can not yet be checked if unused";
            #PH::ACTIONstatus( $context, "SKIPPED", $string );
            #return;
        }
        elseif( get_class( $object ) === "PredefinedSecurityProfileURL" )
        {
            $string = "object of class PredefinedSecurityProfileURL can not be deleted";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $context->isAPI )
            $object->owner->API_removeSecurityProfile( $object );
        else
            $object->owner->removeSecurityProfile($object);
    },
);

SecurityProfileCallContext::$supportedActions['delete-force'] = array(
    'name' => 'delete-Force',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            $string = "this object seems to be used so deletion may fail.";
            PH::ACTIONstatus($context, "WARNING", $string);
        }
        //Todo: continue improvement for SecProf

        if( get_class($object) == "customURLProfile" )
        {
            #$string = "object of class customURLProfile can not yet be checked if unused";
            #PH::ACTIONstatus( $context, "SKIPPED", $string );
            #return;
        }
        elseif( get_class( $object ) === "PredefinedSecurityProfileURL" )
        {
            $string = "object of class PredefinedSecurityProfileURL can not be deleted";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $context->isAPI )
            $object->owner->API_removeSecurityProfile( $object );
        else
            $object->owner->removeSecurityProfile($object);

    },
);
SecurityProfileCallContext::$supportedActions['deleteforce'] = array_merge(
    SecurityProfileCallContext::$supportedActions['delete-force'],
    array(
        'name' => 'deleteForce',
        'deprecated' => 'this action "deleteForce" is deprecated, you should use "delete-Fore" instead!',
        'help' => 'this action "deleteForce" is deprecated, you should use "delete-Fore" instead!'
    )
);

SecurityProfileCallContext::$supportedActions['name-addprefix'] = array(
    'name' => 'name-addPrefix',
    'MainFunction' => function (SecurityProfileCallContext $context) {
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
SecurityProfileCallContext::$supportedActions['name-addsuffix'] = array(
    'name' => 'name-addSuffix',
    'MainFunction' => function (SecurityProfileCallContext $context) {
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
SecurityProfileCallContext::$supportedActions['name-removeprefix'] = array(
    'name' => 'name-removePrefix',
    'MainFunction' => function (SecurityProfileCallContext $context) {
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
SecurityProfileCallContext::$supportedActions['name-removesuffix'] = array(
    'name' => 'name-removeSuffix',
    'MainFunction' => function (SecurityProfileCallContext $context) {
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

SecurityProfileCallContext::$supportedActions['name-touppercase'] = array(
    'name' => 'name-toUpperCase',
    'MainFunction' => function (SecurityProfileCallContext $context) {
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
SecurityProfileCallContext::$supportedActions['name-tolowercase'] = array(
    'name' => 'name-toLowerCase',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;
        #$newName = $context->arguments['prefix'].$object->name();
        $newName = mb_strtolower($object->name(), 'UTF8');

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
SecurityProfileCallContext::$supportedActions['name-toucwords'] = array(
    'name' => 'name-toUCWords',
    'MainFunction' => function (SecurityProfileCallContext $context) {
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

SecurityProfileCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        $object->display_references(7);
    },
);

SecurityProfileCallContext::$supportedActions['display'] = array(
    'name' => 'display',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $context->object->display(7);

        if( PH::$shadow_displayxmlnode )
        {
            PH::print_stdout(  "" );
            DH::DEBUGprintDOMDocument($context->object->xmlroot);
        }
    },
);

SecurityProfileCallContext::$supportedActions['display-xml'] = array(
    'name' => 'display-xml',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        DH::DEBUGprintDOMDocument($object->xmlroot);
    },
);
SecurityProfileCallContext::$supportedActions['url-filtering-action-set'] = array(
    'name' => 'url-filtering-action-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if( get_class( $object) !== "URLProfile")
            return null;

        $category = $context->arguments['url-category'];
        $custom = $object->owner->owner->customURLProfileStore->find( $category );
        if( !in_array( $category, $object->predefined ) and $custom == null )
        {
            mwarning( "url-filtering category: ".$category. " not supported", null, false );
            return false;
        }


        $action = $context->arguments['action'];

        if( !in_array( $action, $object->tmp_url_prof_array ) )
        {
            mwarning( "url-filtering action support only: ".implode($object->tmp_url_prof_array). " action: ".$action. " not supported", null, false );
            return false;
        }


        $object->setAction( $action, $category );

        if( $context->isAPI )
            $object->API_sync();
    },
    'args' => array(
        'action' => array('type' => 'string', 'default' => 'false'),
        'url-category' => array('type' => 'string', 'default' => 'false'),
    ),
);
SecurityProfileCallContext::$supportedActions['url.action-set'] = array(
    'name' => 'url.action-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;
        $action = $context->arguments['action'];
        $filter = $context->arguments['filter'];

        if (get_class($object) !== "URLProfile")
            return null;

        //Todo:
        //how to set new action

        $object->setAction($action, $filter);

        if( $context->isAPI )
            $object->API_sync();

        PH::print_stdout( "\n" );
    },
    'args' => array(
        'action' => array('type' => 'string', 'default' => '*nodefault*',
            'help' => 'allow, alert, block, continue, override'),
        'filter' => array('type' => 'string', 'default' => 'all',
            'help' => "all / all-[action] / category"),
    ),
);
SecurityProfileCallContext::$supportedActions['url.user-credential-detection.action-set'] = array(
    'name' => 'url.action-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;
        $action = $context->arguments['action'];
        $filter = $context->arguments['filter'];

        if (get_class($object) !== "URLProfile")
            return null;

        //Todo:
        //how to set new action

        $object->setAction($action, $filter, "user-credential-detection");

        if( $context->isAPI )
            $object->API_sync();

        PH::print_stdout( "\n" );
    },
    'args' => array(
        'action' => array('type' => 'string', 'default' => '*nodefault*',
            'help' => 'allow, alert, block, continue, override'),
        'filter' => array('type' => 'string', 'default' => 'all',
            'help' => "all / all-[action] / category"),
    ),
);

SecurityProfileCallContext::$supportedActions[] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (SecurityProfileCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (SecurityProfileCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;

        $addWhereUsed = FALSE;
        $addUsedInLocation = FALSE;
        $addTotalUse = FALSE;
        $addCountDisabledRules = FALSE;
        $bestPractice = FALSE;
        $visibility = FALSE;
        $adoption = FALSE;
        $addURLmembers = FALSE;

        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = TRUE;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = TRUE;

        if( isset($optionalFields['TotalUse']) )
        {
            $addTotalUse = TRUE;
            $addCountDisabledRules = TRUE;
        }

        if( isset($optionalFields['BestPractice']) )
            $bestPractice = TRUE;

        if( isset($optionalFields['Visibility']) )
            $visibility = TRUE;

        if( isset($optionalFields['Adoption']) )
            $adoption = TRUE;

        $headers = '<th>ID</th><th>location</th><th>name</th>';
        if( $bestPractice )
            $headers .= '<th>BP SP</th>';
        if( $visibility )
            $headers .= '<th>visibility SP</th>';
        if( $adoption )
            $headers .= '<th>adoption SP</th>';

        $headers .= '<th>store</th><th>type</th><th>rules</th>';
        if( $bestPractice )
            $headers .= '<th>BP rules</th>';
        if( $visibility )
            $headers .= '<th>visibility rules</th>';
        if( $adoption )
            $headers .= '<th>adoption rules</th>';

        $headers .= '<th>exception</th>';
        if( $bestPractice )
            $headers .= '<th>BP exception</th>';
        if( $visibility )
            $headers .= '<th>visibility exception</th>';

        $headers .= '<th>DNS lists</th>';
        if( $bestPractice )
            $headers .= '<th>BP DNS lists</th>';
        if( $visibility )
            $headers .= '<th>visibility DNS lists</th>';

        $headers .= '<th>DNS sinkhole</th><th>DNS security</th>';
        if( $bestPractice )
            $headers .= '<th>BP DNS security</th>';
        if( $visibility )
            $headers .= '<th>visibility DNS security</th>';

        $headers .= '<th>DNS whitelist</th><th>mica-engine</th>';
        if( $bestPractice )
            $headers .= '<th>BP mica-engine</th>';
        if( $visibility )
            $headers .= '<th>visibility mica-engine</th>';



        if( $bestPractice )
        {
            $headers .= '<th>URL BP</th>';
            $headers .= '<th>URL BP details</th>';

            $headers .= '<th>URL credentials BP</th>';

            $headers .= '<th>URL credentials BP details</th>';

            $headers .= '<th>URL credentials BP TAB details</th>';
        }

        if( $visibility )
        {
            $headers .= '<th>URL visibility</th>';
            $headers .= '<th>URL visibility details</th>';

            $headers .= '<th>URL credentials visibility</th>';
            $headers .= '<th>URL credentials visibility details</th>';

            $headers .= '<th>URL credentials visibility TAB details</th>';
        }
        if( $adoption )
        {
            $headers .= '<th>URL adoption</th>';
        }

        if( $addURLmembers or ( !$bestPractice and !$visibility ) or $context->debug )
            $headers .= '<th>URL members</th>';


        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';
        if( $addTotalUse )
            $headers .= '<th>total use</th>';
        if( $addCountDisabledRules )
            $headers .= '<th>count disabled Rules</th>';


        $lines = '';
        $bp_text_yes = "yes";
        $bp_text_no = "no";
        $bp_NOT_sign = " | **NOT BP**";
        $visible_NOT_sign = " | **NOT VISIBLE**";

        $count = 0;
        if( isset($context->objectList) )
        {
            foreach( $context->objectList as $object )
            {
                $count++;

                /** @var AntiVirusProfile|AntiSpywareProfile|customURLProfile|DataFilteringProfile|FileBlockingProfile|PredefinedSecurityProfileURL|URLProfile|VulnerabilityProfile|WildfireProfile|DNSSecurityProfile|VirusAndWildfireProfile $object */
                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $context->encloseFunction( (string)$count );

                $lines .= $context->encloseFunction(PH::getLocationString($object));


                $lines .= $context->encloseFunction($object->name());
                if( $bestPractice || $visibility || $adoption )
                {
                    if( get_class($object) == "AntiVirusProfile" )
                    {
                        if( $bestPractice )
                        {
                            if( $object->is_best_practice() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }

                        if( $visibility )
                        {
                            if( $object->is_visibility() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }

                        if( $adoption )
                        {
                            if( $object->is_adoption() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }

                    }
                    elseif( get_class($object) == "AntiSpywareProfile")
                    {
                        if( $bestPractice )
                        {
                            if( $object->is_best_practice()  )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }

                        if( $visibility )
                        {
                            if ($object->is_visibility() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }

                        if( $adoption )
                        {
                            if( $object->is_adoption() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }
                    }
                    elseif( get_class($object) == "DNSSecurityProfile")
                    {
                        if( $bestPractice )
                        {
                            if( $object->is_best_practice()  )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }

                        if( $visibility )
                        {
                            if ($object->is_visibility() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }

                        if( $adoption )
                        {
                            if( $object->is_adoption() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }
                    }
                    elseif( get_class($object) == "VulnerabilityProfile")
                    {
                        if( $bestPractice )
                        {
                            if( $object->is_best_practice() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }

                        if( $visibility )
                        {
                            if( $object->is_visibility() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }

                        if( $adoption )
                        {
                            if( $object->is_adoption() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }
                    }
                    elseif( get_class($object) == "WildfireProfile")
                    {
                        if( $bestPractice )
                        {
                            if( $object->is_best_practice() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }

                        if( $visibility )
                        {
                            if( $object->is_visibility() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }

                        if( $adoption )
                        {
                            if( $object->is_adoption() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }
                    }
                    elseif( get_class($object) == "VirusAndWildfireProfile")
                    {
                        if( $bestPractice )
                        {
                            if( $object->is_best_practice() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }

                        if( $visibility )
                        {
                            if( $object->is_visibility() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }

                        if( $adoption )
                        {
                            if( $object->is_adoption() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }
                    }
                    elseif( get_class($object) == "FileBlockingProfile")
                    {
                        if( $bestPractice )
                        {
                            if( $object->is_best_practice() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }

                        if( $visibility )
                        {
                            if( $object->is_visibility() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }

                        if( $adoption )
                        {
                            if( $object->is_adoption() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }
                    }
                    elseif( get_class($object) == "URLProfile")
                    {
                        if( $bestPractice )
                        {
                            if( $object->is_best_practice() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }

                        if( $visibility )
                        {
                            if( $object->is_visibility() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }

                        if( $adoption )
                        {
                            if( $object->is_adoption() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }
                    }
                    else
                    {
                        if( $bestPractice )
                            $lines .= $context->encloseFunction('---');
                        if( $visibility )
                            $lines .= $context->encloseFunction('---');
                        if( $adoption )
                            $lines .= $context->encloseFunction('---');
                    }

                }
                $lines .= $context->encloseFunction( $object->owner->name() );


                if( isset($object->secprof_type) )
                    $lines .= $context->encloseFunction($object->secprof_type);
                else
                    $lines .= $context->encloseFunction(get_class($object) );

                $tmp_array = array();
                if( !empty( $object->rules_obj ) )
                {
                    foreach( $object->rules_obj as $rulename => $rule )
                    {
                        $stringSeverity = "";
                        if( !empty($rule->severity) )
                            $stringSeverity = " - severity:'". implode( ",", $rule->severity )."'";
                        $stringApplication = "";
                        if( !empty($rule->application) )
                            $stringApplication = " - application:'". implode( ",", $rule->application )."'";
                        $stringFileType = "";
                        if( !empty($rule->filetype) )
                            $stringFileType = " - filetype:'". implode( ",", $rule->filetype )."'";
                        $stringPacketCapture = "";
                        if( $rule->packetCapture() !== null )
                            $stringPacketCapture = " - packetCapture:'".$rule->packetCapture()."'";
                        $stringCategory = "";
                        if( $rule->category() !== null )
                            $stringCategory = " - category:'".$rule->category()."'";
                        $stringHost = "";
                        if( $rule->host() !== null )
                            $stringHost = " - host:'".$rule->host()."'";
                        $stringThreatName = "";
                        if( $rule->threatname !== null )
                            $stringThreatName = " - threat-name:'".$rule->threatName()."'";
                        $stringAction = "";
                        if( $rule->action() !== null )
                            $stringAction = " - action:'".$rule->action()."'";
                        $stringDirection = "";
                        if( $rule->direction() !== null )
                            $stringDirection = " - direction:'".$rule->direction()."'";
                        $stringAnalysis = "";
                        if( $rule->analysis() !== null )
                            $stringAnalysis = " - analysis:'".$rule->analysis()."'";

                        $tmp_string = "'".$rule->name()."' | ".$stringSeverity.$stringThreatName.$stringAction.$stringApplication.$stringFileType.$stringPacketCapture.$stringCategory.$stringHost.$stringDirection.$stringAnalysis;
                        if( get_class($rule ) == "ThreatPolicySpyware" )
                        {
                            if( !$rule->spyware_rule_best_practice() && $bestPractice )
                                $tmp_string .= $bp_NOT_sign;
                            if( !$rule->spyware_rule_visibility() && $visibility )
                                $tmp_string .= $visible_NOT_sign;
                        }

                        elseif( get_class($rule ) == "ThreatPolicyVulnerability" )
                        {
                            if( !$rule->vulnerability_rule_best_practice() && $bestPractice )
                                $tmp_string .= $bp_NOT_sign;
                            if( !$rule->vulnerability_rule_visibility() && $visibility )
                                $tmp_string .= $visible_NOT_sign;
                        }
                        elseif( get_class($rule ) == "ThreatPolicyWildfire" )
                        {
                            if( !$rule->wildfire_rule_best_practice() && $bestPractice )
                                $tmp_string .= $bp_NOT_sign;
                            if( !$rule->wildfire_rule_visibility() && $visibility )
                                $tmp_string .= $visible_NOT_sign;
                        }
                        elseif( get_class($rule ) == "ThreatPolicyFileBlocking" )
                        {
                            if( !$rule->fileblocking_rule_best_practice() && $bestPractice )
                            {
                                $check_array = $rule->fileblocking_rule_bp_visibility_JSON( "bp", "file-blocking" );
                                $not_block = $rule->show_missing_bp_json( $check_array );
                                if( !empty( $not_block ) )
                                    $tmp_string .= $bp_NOT_sign."[".implode(", ", $not_block)."]";
                                else
                                    $tmp_string .= $bp_NOT_sign;
                            }

                            if( !$rule->fileblocking_rule_visibility() && $visibility )
                                $tmp_string .= $visible_NOT_sign;
                        }
                        $tmp_array[] = $tmp_string;
                    }
                }

                $array = array();
                if( !empty( $object->tmp_virus_prof_array ) )
                {
                    foreach( $object->tmp_virus_prof_array as $key => $type )
                    {
                        $string = $type;

                        $actionTypeArray = array('action', 'wildfire-action', 'mlav-action');

                        foreach( $actionTypeArray as $actionType )
                        {
                            if( isset( $object->$type[$actionType] ) )
                            {
                                $string .= "          - ".$actionType.":          '" . $object->$type[$actionType] . "'";
                                if( $bestPractice )
                                {
                                    $check_array = PH::$shadow_bp_jsonfile['virus']['rule']['bp'][$actionType];
                                    if( in_array( $type, $check_array['type'] ) )
                                    {
                                        if( !in_array( $object->$type[$actionType], $check_array['action'] ) )
                                            $string .= $bp_NOT_sign;
                                    }
                                    else
                                    {
                                        if( !in_array( $object->$type[$actionType], $check_array['action-not-matching-type'] ) )
                                            $string .= $bp_NOT_sign;
                                    }
                                }
                                if( $visibility )
                                {
                                    //Todo: to get same output as BP; change JSON and validate what is needed
                                    $check_array = PH::$shadow_bp_jsonfile['virus']['rule']['visibility'][$actionType];
                                    if( in_array( "!".$object->$type[$actionType], $check_array ) )
                                        $string .= $visible_NOT_sign;
                                }
                            }
                        }

                        $array[] = $string;
                    }

                }

                if( !empty( $object->rules_obj ) || !empty( $object->tmp_virus_prof_array ) )
                {
                    $tmp_array2 = array_merge( $tmp_array, $array );
                    $lines .= $context->encloseFunction($tmp_array2);
                }
                else
                    $lines .= $context->encloseFunction('');

                if( $bestPractice || $visibility || $adoption )
                {

                    if( get_class($object) == "AntiVirusProfile" )
                    {
                        if( $bestPractice )
                        {
                            if( $object->av_action_best_practice() && $object->av_wildfireaction_best_practice() && $object->av_mlavaction_best_practice() )
                                $lines .= $context->encloseFunction($bp_text_yes.' BP AV actions set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO BP AV actions');
                        }
                        if( $visibility )
                        {
                            if( $object->av_action_visibility() && $object->av_wildfireaction_visibility() && $object->av_mlavaction_visibility() )
                                $lines .= $context->encloseFunction($bp_text_yes.' Visibility AV actions set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO Visibility AV actions');
                        }
                        if( $adoption )
                        {
                            $lines .= $context->encloseFunction($bp_text_yes.' Adoption AV set');
                        }
                    }
                    elseif( get_class($object) == "AntiSpywareProfile" )
                    {
                        if( $bestPractice )
                        {
                            if( $object->spyware_rules_best_practice() )
                                $lines .= $context->encloseFunction($bp_text_yes.' BP AS rules set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO BP AS rules');
                        }
                        if( $visibility )
                        {
                            if( $object->spyware_rules_visibility() )
                                $lines .= $context->encloseFunction($bp_text_yes.' Visibility AS rules set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO Visibility AS rules');
                        }
                        if( $adoption )
                        {
                            if( $object->is_adoption() )
                                $lines .= $context->encloseFunction($bp_text_yes.' Adoption AS set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO Adoption AS set');
                        }
                    }
                    elseif( get_class($object) == "VulnerabilityProfile" )
                    {
                        if( $bestPractice )
                        {
                            if( $object->vulnerability_rules_best_practice() )
                                $lines .= $context->encloseFunction($bp_text_yes.' BP VP rules set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO BP VP rules');
                        }
                        if( $visibility )
                        {
                            if( $object->vulnerability_rules_visibility() )
                                $lines .= $context->encloseFunction($bp_text_yes.' Visibility VP rules set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO Visibility VP rules');
                        }
                        if( $adoption )
                        {
                            if( $object->is_adoption() )
                                $lines .= $context->encloseFunction($bp_text_yes.' Adoption VP set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO Adoption VP set');
                        }
                    }
                    elseif( get_class($object) == "FileBlockingProfile" )
                    {
                        if( $bestPractice )
                        {
                            if( $object->fileblocking_rules_best_practice() )
                                $lines .= $context->encloseFunction($bp_text_yes.' BP FB rules set');
                            else
                            {
                                $lines .= $context->encloseFunction($bp_text_no.' NO BP FB rules');
                            }

                        }
                        if( $visibility )
                        {
                            if( $object->fileblocking_rules_visibility() )
                                $lines .= $context->encloseFunction($bp_text_yes.' Visibility FB rules set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO Visibility FB rules');
                        }
                        if( $adoption )
                        {
                            if( $object->is_adoption() )
                                $lines .= $context->encloseFunction($bp_text_yes.' Adoption FB set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO Adoption FB set');
                        }
                    }
                    elseif( get_class($object) == "WildfireProfile" )
                    {
                        if( $bestPractice )
                        {
                            if( $object->wildfire_rules_best_practice() )
                                $lines .= $context->encloseFunction($bp_text_yes.' BP WF rules set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO BP WF rules');
                        }
                        if( $visibility )
                        {
                            if( $object->wildfire_rules_visibility() )
                                $lines .= $context->encloseFunction($bp_text_yes.' Visibility WF rules set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO Visibility WF rules');
                        }
                        if( $adoption )
                        {
                            if( $object->is_adoption() )
                                $lines .= $context->encloseFunction($bp_text_yes.' Adoption WF set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO Adoption WF set');
                        }
                    }
                    elseif( get_class($object) == "VirusAndWildfireProfile" )
                    {
                        if( $bestPractice )
                        {
                            if( $object->av_action_best_practice() && $object->av_wildfireaction_best_practice()
                                && $object->av_mlavaction_best_practice() && $object->wildfire_rules_best_practice() )
                                $lines .= $context->encloseFunction($bp_text_yes.' BP AV/WF rules set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO BP AV/WF rules');
                        }
                        if( $visibility )
                        {
                            if( $object->av_action_visibility() && $object->av_wildfireaction_visibility()
                                && $object->av_mlavaction_visibility() && $object->wildfire_rules_visibility() )
                                $lines .= $context->encloseFunction($bp_text_yes.' Visibility AV/WF rules set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO Visibility AV/WF rules');
                        }
                        if( $adoption )
                        {
                            if( $object->is_adoption() )
                                $lines .= $context->encloseFunction($bp_text_yes.' Adoption AV/WF set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO Adoption AV/WF set');
                        }
                    }
                    else
                    {
                        if( $bestPractice )
                            $lines .= $context->encloseFunction('---');
                        if( $visibility )
                            $lines .= $context->encloseFunction('---');
                        if( $adoption )
                            $lines .= $context->encloseFunction('---');
                    }
                }

                #$lines .= $context->encloseFunction($object->value());
                if( !empty( $object->threatException ) )
                {
                    $tmp_array = array();
                    foreach( $object->threatException as $threatname => $threat )
                    {
                        $string = $threat['name'];
                        if( isset( $threat['action'] ) )
                            $string .= " | ".$threat['action'];
                        if( isset( $threat['default-action'] ) )
                            $string .= " [default:".$threat['default-action']."]";
                        if( isset( $threat['exempt-ip'] ) and count($threat['exempt-ip']) > 0 )
                            $string .= " | ".implode( ",", $threat['exempt-ip'] );
                        $tmp_array[] = $string;
                    }

                    #$string = implode( ",", $tmp_array);
                    #$lines .= $context->encloseFunction( $string );
                    $lines .= $context->encloseFunction( $tmp_array );
                }
                else
                    $lines .= $context->encloseFunction('');

                if( $bestPractice || $visibility)
                {
                    if( get_class($object) == "AntiSpywareProfile" )
                    {
                        if( $bestPractice )
                            $lines .= $context->encloseFunction('BP_AS_exception_dummy');
                        if( $visibility )
                            $lines .= $context->encloseFunction('Visibility_AS_exception_dummy');
                    }
                    elseif( get_class($object) == "VulnerabilityProfile" )
                    {
                        if( $bestPractice )
                            $lines .= $context->encloseFunction('BP_VP_exception_dummy');
                        if( $visibility )
                            $lines .= $context->encloseFunction('Visibility_VP_exception_dummy');
                    }
                    else
                    {
                        if( $bestPractice )
                            $lines .= $context->encloseFunction('---');
                        if( $visibility )
                            $lines .= $context->encloseFunction('---');
                    }
                }

                $string_dns_list = array();
                $string_dns_sinkhole = array();
                $string_dns_security = array();
                $string_dns_whitelist = array();
                $string_mica_engine = array();
                if( !empty( $object->additional ) )
                {
                    if( !empty( $object->additional['botnet-domain'] ) )
                    {
                        foreach( $object->additional['botnet-domain'] as $type => $threat )
                        {
                            if( $type == "lists" )
                            {
                                foreach( $object->additional['botnet-domain']['lists'] as $name => $rule )
                                {
                                    //$string = $name." -  action: ".$value['action'];
                                    $string = "";
                                    $string .= $rule->name();

                                    $string .= " - action: '".$rule->action."'";
                                    $string .= " - packet-capture: '".$rule->packetCapture()."'";

                                    /** @var DNSPolicy $rule */
                                    if( $bestPractice && !$rule->spyware_lists_bestpractice() )
                                        $string .= $bp_NOT_sign;
                                    if( $visibility && !$rule->spyware_lists_visibility() )
                                        $string .= $visible_NOT_sign;



                                    $string_dns_list[] =  $string;
                                }

                            }
                            elseif( $type == "sinkhole" )
                            {
                                foreach( $object->additional['botnet-domain'][$type] as $name => $value )
                                    $string_dns_sinkhole[] = $name.": ".$value;
                            }
                            elseif( $type == "dns-security-categories" )
                            {
                                foreach( $object->additional['botnet-domain'][$type] as $name => $rule )
                                {
                                    $string = "";
                                    $string .= $rule->name();

                                    $string .= " - log-level: '".$rule->logLevel()."'";
                                    $string .= " - action: '".$rule->action."'";
                                    $string .= " - packet-capture: '".$rule->packetCapture()."'";
                                    /** @var DNSPolicy $rule */
                                    if( $bestPractice && !$rule->spyware_dns_security_rule_bestpractice() )
                                        $string .= $bp_NOT_sign;
                                    if( $visibility && !$rule->spyware_dns_security_rule_visibility() )
                                        $string .= $visible_NOT_sign;
                                    $string_dns_security[] = $string;
                                }
                            }
                            elseif( $type == "advanced-dns-security-categories" )
                            {
                                $string_dns_security[] = "";
                                $string_dns_security[] = "---Advanced DNS Security Categories";
                                foreach( $object->additional['botnet-domain'][$type] as $name => $rule )
                                {
                                    $string = "";
                                    $string .= $rule->name();

                                    $string .= " - log-level: '".$rule->logLevel()."'";
                                    $string .= " - action: '".$rule->action."'";
                                    #adns does not have packet-capture
                                    //$string .= " - packet-capture: '".$rule->packetCapture()."'";
                                    /** @var DNSPolicy $rule */
                                    //Todo: TBD
                                    if( $bestPractice && !$rule->spyware_advanced_dns_security_rule_bestpractice() )
                                        $string .= $bp_NOT_sign;
                                    if( $visibility && !$rule->spyware_advanced_dns_security_rule_visibility() )
                                        $string .= $visible_NOT_sign;
                                    $string_dns_security[] = $string;
                                }
                            }
                            elseif( $type == "whitelist" )
                            {
                                foreach( $object->additional['botnet-domain'][$type] as $name => $value )
                                {
                                    $string = $value['name'];
                                    if( isset($value['description']) )
                                        $string .= "' | description:'".$value['description'];
                                    $string_dns_whitelist[] = $string;
                                }
                            }

                        }
                    }

                    if( !empty( $object->additional['mica-engine-spyware-enabled'] ) )
                    {
                        $enabled = "[no]";

                        if( $object->cloud_inline_analysis_enabled )
                            $enabled = "[yes]";
                        else
                        {
                            if( $bestPractice )
                                $enabled .= $bp_NOT_sign;
                            if( $visibility )
                                $enabled .= $visible_NOT_sign;
                        }

                        $string_mica_engine[] = "mica-engine-spyware-enabled: ". $enabled;

                        foreach ($object->additional['mica-engine-spyware-enabled'] as $type => $array)
                        {
                            $tmp_string = $type . " - inline-policy-action :" . $object->additional['mica-engine-spyware-enabled'][$type]['inline-policy-action'];
                            if( $bestPractice )
                            {
                                if( isset(PH::$shadow_bp_jsonfile['spyware']['cloud-inline']['bp']) )
                                {
                                    $check_array = PH::$shadow_bp_jsonfile['spyware']['cloud-inline']['bp'];
                                    if( isset($check_array['inline-policy-action']) )
                                    {
                                        $bp_set = TRUE;
                                        foreach( $check_array['inline-policy-action'] as $detailed_check )
                                        {
                                            if ($detailed_check['type'][0] == "any") {
                                                if ($detailed_check['action'][0] !== $object->additional['mica-engine-spyware-enabled'][$type]['inline-policy-action'])
                                                    $bp_set = FALSE;
                                            }
                                        }
                                        if($bp_set == FALSE)
                                            $tmp_string .= $bp_NOT_sign;
                                    }
                                }
                            }

                            if( $visibility )
                            {
                                if( isset(PH::$shadow_bp_jsonfile['spyware']['cloud-inline']['visibility']) )
                                {
                                    $check_array = PH::$shadow_bp_jsonfile['spyware']['cloud-inline']['visibility'];
                                    if( isset($check_array['inline-policy-action']) )
                                    {
                                        $bp_set = TRUE;
                                        foreach( $check_array['inline-policy-action'] as $detailed_check )
                                        {
                                            if ($detailed_check['type'][0] == "any") {
                                                $validate = $detailed_check['action'][0];
                                                $negate_string = "";
                                                if (strpos($validate, "!") !== FALSE)
                                                    $negate_string = "!";
                                                if ($validate === $negate_string . $object->additional['mica-engine-spyware-enabled'][$type]['inline-policy-action'])
                                                    $bp_set = FALSE;
                                            }
                                        }
                                        if($bp_set == FALSE)
                                            $tmp_string .= $visible_NOT_sign;
                                    }
                                }
                            }

                            //Todo: swaschkut 2025115  LDL missing
                            if( isset($object->additional['mica-engine-spyware-enabled'][$type]['local-deep-learning']) )
                            {
                                $tmp_string .= " - local-deep-learning :".$object->additional['mica-engine-spyware-enabled'][$type]['local-deep-learning'];
                            }

                            $string_mica_engine[] = $tmp_string;
                        }

                    }

                    if( !empty( $object->additional['mica-engine-vulnerability-enabled'] ) )
                    {
                        $enabled = "[no]";
                        if( $object->cloud_inline_analysis_enabled )
                            $enabled = "[yes]";
                        else
                        {
                            if( $bestPractice )
                                $enabled .= $bp_NOT_sign;
                            if( $visibility )
                                $enabled .= $visible_NOT_sign;
                        }

                        $string_mica_engine[] = "mica-engine-vulnerability-enabled: ". $enabled;

                        foreach ($object->additional['mica-engine-vulnerability-enabled'] as $type => $array)
                        {
                            $tmp_string = $type . " - inline-policy-action :" . $object->additional['mica-engine-vulnerability-enabled'][$type]['inline-policy-action'];
                            if( $bestPractice )
                            {
                                if( isset(PH::$shadow_bp_jsonfile['vulnerability']['cloud-inline']['bp']) )
                                {
                                    $check_array = PH::$shadow_bp_jsonfile['vulnerability']['cloud-inline']['bp'];
                                    if( isset($check_array['inline-policy-action']) )
                                    {
                                        $bp_set = TRUE;
                                        foreach( $check_array['inline-policy-action'] as $detailed_check )
                                        {
                                            if( $detailed_check['type'][0] == "any" )
                                            {
                                                if( $detailed_check['action'][0] !== $object->additional['mica-engine-vulnerability-enabled'][$type]['inline-policy-action'] )
                                                    $bp_set = FALSE;
                                            }
                                        }

                                        if($bp_set == FALSE)
                                            $tmp_string .= $bp_NOT_sign;
                                    }
                                }
                            }

                            if( $visibility )
                            {
                                if( isset(PH::$shadow_bp_jsonfile['vulnerability']['cloud-inline']['visibility']) )
                                {
                                    $check_array = PH::$shadow_bp_jsonfile['vulnerability']['cloud-inline']['visibility'];
                                    if( isset($check_array['inline-policy-action']) )
                                    {
                                        $bp_set = TRUE;
                                        foreach( $check_array['inline-policy-action'] as $detailed_check )
                                        {
                                            if ($detailed_check['type'][0] == "any")
                                            {
                                                $validate = $detailed_check['action'][0];
                                                $negate_string = "";
                                                if (strpos($validate, "!") !== FALSE)
                                                    $negate_string = "!";
                                                if ($validate === $negate_string . $object->additional['mica-engine-vulnerability-enabled'][$type]['inline-policy-action'])
                                                    $bp_set = FALSE;
                                            }
                                        }
                                        if($bp_set == FALSE)
                                            $tmp_string .= $visible_NOT_sign;
                                    }
                                }

                            }
                            $string_mica_engine[] = $tmp_string;
                        }

                    }

                    if( !empty( $object->additional['mlav-engine-filebased-enabled'] ) )
                    {
                        $string_mica_engine[] = "mlav-engine-filebased-enabled: ";

                        foreach ($object->additional['mlav-engine-filebased-enabled'] as $type => $array)
                        {
                            $tmp_string = $type . " - mlav-policy-action :" . $object->additional['mlav-engine-filebased-enabled'][$type]['mlav-policy-action'];
                            if( $bestPractice )
                            {
                                if( isset(PH::$shadow_bp_jsonfile['virus']['cloud-inline']['bp']) )
                                {
                                    $check_array = PH::$shadow_bp_jsonfile['virus']['cloud-inline']['bp'];
                                    if( isset($check_array['inline-policy-action']) )
                                    {
                                        $bp_set = TRUE;
                                        foreach( $check_array['inline-policy-action'] as $detailed_check )
                                        {
                                            if ($detailed_check['type'][0] == "any") {
                                                if ($detailed_check['action'][0] !== $object->additional['mlav-engine-filebased-enabled'][$type]['mlav-policy-action'])
                                                    $bp_set = FALSE;
                                            }
                                        }
                                        if($bp_set == FALSE)
                                            $tmp_string .= $bp_NOT_sign;
                                    }
                                }
                            }

                            if( $visibility )
                            {
                                if( isset(PH::$shadow_bp_jsonfile['virus']['cloud-inline']['visibility']) )
                                {
                                    $check_array = PH::$shadow_bp_jsonfile['virus']['cloud-inline']['visibility'];
                                    if( isset($check_array['inline-policy-action']) )
                                    {
                                        $bp_set = TRUE;
                                        foreach( $check_array['inline-policy-action'] as $detailed_check )
                                        {
                                            if ($detailed_check['type'][0] == "any")
                                            {
                                                $validate = $detailed_check['action'][0];
                                                $negate_string = "";
                                                if (strpos($validate, "!") !== FALSE)
                                                    $negate_string = "!";
                                                if ($validate === $negate_string . $object->additional['mlav-engine-filebased-enabled'][$type]['mlav-policy-action'])
                                                    $bp_set = FALSE;
                                            }
                                        }
                                        if($bp_set == FALSE)
                                            $tmp_string .= $visible_NOT_sign;
                                    }
                                }
                            }

                            $string_mica_engine[] = $tmp_string;
                        }

                    }

                    if( !empty( $object->additional['mica-engine-wildfire-rules'] ) )
                    {
                        $enabled = "[no]";
                        if ($object->cloud_inline_analysis_enabled)
                            $enabled = "[yes]";
                        else {
                            #if( $bestPractice )
                            #    $enabled .= $bp_NOT_sign;
                            #if( $visibility )
                            #    $enabled .= $visible_NOT_sign;
                        }

                        $string_mica_engine[] = "mica-engine-wildfire-rules: " . $enabled;

                        foreach( $object->additional['mica-engine-wildfire-rules'] as $rulename => $rule )
                            $string_mica_engine[] = "'".$rulename."' | - application:'".implode(",", $rule['application'])."' - fileType:'".implode(",", $rule['file-type'])."' - direction:'".$rule['direction']."'  - action:'".$rule['action']."'";
                    }
                }
                elseif( get_class($object) == "URLProfile" )
                {
                    if( $object->local_inline_cat !== null )
                        $string_mica_engine[] = "local-inline-cat=".$object->local_inline_cat;
                    if( $object->cloud_inline_cat !== null )
                        $string_mica_engine[] = "cloud-inline-cat=".$object->cloud_inline_cat;
                }

                //<th>DNS lists</th>
                $lines .= $context->encloseFunction($string_dns_list);
                if( $bestPractice || $visibility)
                {
                    if( ( get_class($object) == "AntiSpywareProfile" &&
                            (get_class($object->owner->owner ) == "PanoramaConf"
                                || get_class($object->owner->owner ) == "DeviceGroup"
                                || get_class($object->owner->owner ) == "PANConf"
                                || get_class($object->owner->owner ) == "VirtualSystem")
                        )
                        ||  get_class($object) == "DNSSecurityProfile" )
                    {
                        if( $bestPractice )
                        {
                            if( $object->spyware_dnslist_best_practice() )
                                $lines .= $context->encloseFunction($bp_text_yes.' BP AS dns_list set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO BP AS dns_list');
                        }
                        if( $visibility )
                        {
                            if( $object->spyware_dnslist_visibility() )
                                $lines .= $context->encloseFunction($bp_text_yes.' Visibility AS dns_list set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO Visibility AS dns_list');
                        }
                    }
                    else
                    {
                        if( $bestPractice )
                            $lines .= $context->encloseFunction('---');
                        if( $visibility )
                            $lines .= $context->encloseFunction('---');
                    }
                }
                //<th>DNS sinkhole</th>
                $lines .= $context->encloseFunction($string_dns_sinkhole);
                //<th>DNS security</th>
                $lines .= $context->encloseFunction($string_dns_security);
                if( $bestPractice || $visibility)
                {
                    if( (
                        ( get_class($object) == "AntiSpywareProfile" &&
                            (get_class($object->owner->owner ) == "PanoramaConf"
                                || get_class($object->owner->owner ) == "DeviceGroup"
                                || get_class($object->owner->owner ) == "PANConf"
                                || get_class($object->owner->owner ) == "VirtualSystem")
                        )
                        //Todo: something wrong with the SCM version validation
                            || get_class($object) == "DNSSecurityProfile")
                       // && $object->owner->owner->version >= 102
                    )
                    {
                        if( $bestPractice )
                        {
                            if( $object->spyware_dns_security_best_practice() && $object->spyware_advanced_dns_security_best_practice())
                                $lines .= $context->encloseFunction($bp_text_yes.' BP AS dns_security set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO BP AS dns_security');
                        }
                        if( $visibility )
                        {
                            if( $object->spyware_dns_security_visibility() && $object->spyware_advanced_dns_security_visibility() )
                                $lines .= $context->encloseFunction($bp_text_yes.' Visibility AS dns_security set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO Visibility AS dns_security');
                        }
                    }
                    else
                    {
                        if( $bestPractice )
                            $lines .= $context->encloseFunction('---');
                        if( $visibility )
                            $lines .= $context->encloseFunction('---');
                    }
                }
                //<th>DNS whitelist</th>
                $lines .= $context->encloseFunction($string_dns_whitelist);

                //mica-engine
                $lines .= $context->encloseFunction($string_mica_engine);
                if( $bestPractice || $visibility)
                {
                    if( (get_class($object) == "AntiSpywareProfile" && $object->owner->owner->version >= 102 )
                        || (get_class($object) == "VulnerabilityProfile" && $object->owner->owner->version >= 110 )
                        || (get_class($object) == "WildfireProfile" && $object->owner->owner->version >= 112 )
                        || get_class($object) == "AntiVirusProfile"
                        || (get_class($object) == "URLProfile" && $object->owner->owner->version >= 102 )
                        || get_class($object) == "VirusAndWildfireProfile"
                    )
                    {
                        if( $bestPractice )
                        {
                            if( get_class($object) == "URLProfile" )
                            {
                                if( $object->local_inline_cat !== null
                                    && $object->cloud_inline_cat !== null
                                    && $object->local_inline_cat == "yes"
                                    && $object->cloud_inline_cat == "yes"
                                )
                                    $lines .= $context->encloseFunction($bp_text_yes.' BP mica_engine set');
                                else
                                    $lines .= $context->encloseFunction($bp_text_no.' NO BP mica_engine');
                            }
                            else
                            {
                                if( $object->cloud_inline_analysis_best_practice($object->owner->bp_json_file) )
                                    $lines .= $context->encloseFunction($bp_text_yes.' BP mica_engine set');
                                else
                                    $lines .= $context->encloseFunction($bp_text_no.' NO BP mica_engine');
                            }

                        }
                        if( $visibility )
                        {
                            if( get_class($object) == "URLProfile" )
                            {
                                if( $object->local_inline_cat !== null
                                    && $object->cloud_inline_cat !== null
                                    && $object->local_inline_cat == "yes"
                                    && $object->cloud_inline_cat == "yes"
                                )
                                    $lines .= $context->encloseFunction($bp_text_yes . ' Visibility mica_engine set');
                                else
                                    $lines .= $context->encloseFunction($bp_text_no . ' NO Visibility mica_engine');
                            }
                            else
                            {
                                if ($object->cloud_inline_analysis_visibility($object->owner->bp_json_file))
                                    $lines .= $context->encloseFunction($bp_text_yes . ' Visibility mica_engine set');
                                else
                                    $lines .= $context->encloseFunction($bp_text_no . ' NO Visibility mica_engine');
                            }
                        }
                    }
                    else
                    {
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                    }
                }


                if( get_class($object) == "customURLProfile" )
                {
                    if( $bestPractice )
                    {
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                    }
                    if( $visibility )
                    {
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                    }

                    if( (!$bestPractice and !$visibility ) or $context->debug)
                    {
                        /**
                         * @var $object customURLProfile
                         */
                        $tmp_array = array();
                        foreach ($object->getmembers() as $member)
                            $tmp_array[] = $member;

                        $lines .= $context->encloseFunction($tmp_array);
                    }
                }
                elseif( get_class($object) == "URLProfile" )
                {
                    if( $bestPractice )
                    {
                        if( $object->site_access_is_best_practice() )
                            $lines .= $context->encloseFunction($bp_text_yes);
                        else
                            $lines .= $context->encloseFunction($bp_text_no);
                    }

                    if( $bestPractice )
                    {
                        //URL detail BP
                        $tmp_array = array();
                        $tmp_array = array();
                        $countAllow = count( $object->allow );
                        $countAlert = count( $object->alert );
                        $countBlock = count( $object->block );
                        $tmp_array[] = "Allow (".$countAllow.")";
                        $tmp_array[] = "Alert (".$countAlert.")";
                        $tmp_array[] = "Block (".$countBlock.")";
                        $tmp_array[] = "------------------------";

                        $check_array = $object->url_siteaccess_bp_visibility_JSON( "bp", "url" );
                        #print_r($check_array);
                        $block_categories_to_check = array();
                        $alert_categories_to_check = array();
                        foreach( $check_array as $check )
                        {
                            if( isset( $check['action'] ) )
                            {
                                if( $check['action'] == 'block' )
                                {
                                    if( isset( $check['type'] ) )
                                        $block_categories_to_check = array_merge( $block_categories_to_check, $check['type'] );
                                }
                                elseif( $check['action'] == 'alert' )
                                {
                                    if( isset( $check['type'] ) )
                                        $alert_categories_to_check = array_merge( $alert_categories_to_check, $check['type'] );
                                }
                            }
                        }

                        #if( isset($check_array[0]['type']) )
                        #    $block_categories = $check_array[0]['type'];
                        #else
                        if( empty( $block_categories_to_check ) )
                            $block_categories_to_check = array('command-and-control','compromised-website','grayware','malware','phishing','ransomware','scanning-activity');

                        $notBlock = array();
                        foreach( $block_categories_to_check as $block_category )
                        {
                            if( !in_array( $block_category, $object->block ) )
                                $notBlock[] = $block_category;

                        }
                        if( !empty($notBlock) )
                        {
                            $tmp_array[] = 'BLOCK missing: ';
                            $tmp_array = array_merge( $tmp_array, $notBlock );
                        }
                        $notAlert = array();
                        foreach( $alert_categories_to_check as $alert_category )
                        {
                            if( !in_array( $alert_category, $object->alert ) && !in_array( $alert_category, $object->block ) )
                                $notAlert[] = $alert_category;

                        }
                        if( !empty($notAlert) )
                        {
                            $tmp_array[] = 'ALERT missing: ';
                            $tmp_array = array_merge( $tmp_array, $notAlert );
                        }

                        if( empty($notBlock) && empty($notAlert) )
                            $tmp_array[] = "yes";

                        $lines .= $context->encloseFunction($tmp_array);
                    }
                    if( $bestPractice )
                    {
                        if( $object->url_usercredentialsubmission_best_practice() && $object->url_usercredentialsubmission_best_practice_tab() )
                            $lines .= $context->encloseFunction($bp_text_yes);
                        else
                            $lines .= $context->encloseFunction($bp_text_no);
                    }
                    if( $bestPractice )
                    {
                        //<th>URL credentials</th>
                        $tmp_array = array();
                        $countAllowcredential = count( $object->allow_credential );
                        $countAlertcredential = count( $object->alert_credential );
                        $countBlockcredential = count( $object->block_credential );
                        $tmp_array[] = "Allow (".$countAllowcredential.")";
                        $tmp_array[] = "Alert (".$countAlertcredential.")";
                        $tmp_array[] = "Block (".$countBlockcredential.")";
                        $tmp_array[] = "------------------------";

                        $check_array = $object->url_siteaccess_bp_visibility_JSON( "bp", "url" );

                        $block_categories_to_check = array();
                        $alert_categories_to_check = array();
                        foreach( $check_array as $check )
                        {
                            if( isset( $check['action'] ) )
                            {
                                if( $check['action'] == 'block' )
                                {
                                    if( isset( $check['type'] ) )
                                        $block_categories_to_check = array_merge( $block_categories_to_check, $check['type'] );
                                }
                                elseif( $check['action'] == 'alert' )
                                {
                                    if( isset( $check['type'] ) )
                                        $alert_categories_to_check = array_merge( $alert_categories_to_check, $check['type'] );
                                }
                            }
                        }

                        if( empty( $block_categories_to_check ) )
                            $block_categories_to_check = array('command-and-control','compromised-website','grayware','malware','phishing','ransomware','scanning-activity');

                        $notBlock = array();
                        foreach( $block_categories_to_check as $block_category )
                        {
                            if( !in_array( $block_category, $object->block_credential ) )
                                $notBlock[] = $block_category;

                        }
                        if( !empty($notBlock) )
                        {
                            $tmp_array[] = 'BLOCK missing: ';
                            $tmp_array = array_merge( $tmp_array, $notBlock );
                        }
                        $notAlert = array();
                        foreach( $alert_categories_to_check as $alert_category )
                        {
                            if( !in_array( $alert_category, $object->alert_credential ) && !in_array( $alert_category, $object->block_credential ) )
                                $notAlert[] = $alert_category;

                        }
                        if( !empty($notAlert) )
                        {
                            $tmp_array[] = 'ALERT missing: ';
                            $tmp_array = array_merge( $tmp_array, $notAlert );
                        }

                        if( empty($notBlock) && empty($notAlert) )
                            $tmp_array[] = "yes";

                        $lines .= $context->encloseFunction($tmp_array);
                    }
                    if( $bestPractice )
                    {
                        //<th>URL credentials TAB</th>
                        $tab_config = array();
                        $tab_config[] = "mode: ".$object->credential_mode;
                        $tab_config[] = "log-severity: ".$object->credential_log;
                        $tab_config[] = "----";

                        if( $object->url_usercredentialsubmission_best_practice_tab() )
                            $tab_config[] = $bp_text_yes;
                        else
                            $tab_config[] = $bp_text_no;

                        $lines .= $context->encloseFunction($tab_config);
                    }

                    if( $visibility )
                    {
                        if( $object->site_access_is_visibility() )
                            $lines .= $context->encloseFunction($bp_text_yes);
                        else
                            $lines .= $context->encloseFunction($bp_text_no);
                    }

                    if( $visibility )
                    {
                        //URL detail visibility
                        $tmp_array = array();

                        $sanitized_action = $object->allow;
                        foreach( $sanitized_action as $key => $url_category)
                        {
                            if( isset($object->owner->owner->customURLProfileStore) )
                            {
                                $custom_url_category_obj = $object->owner->owner->customURLProfileStore->find($url_category);
                                if( $custom_url_category_obj !== NULL )
                                    unset( $sanitized_action[$key] );
                            }
                        }

                        if( empty($sanitized_action) )
                            $tmp_array[] = "yes";
                        else
                            $tmp_array[] = 'ALLOW: "set all pre-defined URL-category action to alert"';

                        $lines .= $context->encloseFunction($tmp_array);
                    }

                    if( $visibility )
                    {
                        if( $object->url_usercredentialsubmission_visibility() && $object->url_usercredentialsubmission_visibility_tab() )
                            $lines .= $context->encloseFunction($bp_text_yes);
                        else
                            $lines .= $context->encloseFunction($bp_text_no);
                    }
                    if( $visibility )
                    {
                        //<th>URL credentials</th>
                        $tmp_array = array();

                        $sanitized_action = $object->allow_credential;
                        foreach( $sanitized_action as $key => $url_category)
                        {
                            $custom_url_category_obj = $object->owner->owner->customURLProfileStore->find($url_category);
                            if( $custom_url_category_obj !== NULL )
                                unset( $sanitized_action[$key] );
                        }

                        if( empty($sanitized_action) )
                            $tmp_array[] = "yes";
                        else
                            $tmp_array[] = 'ALLOW: "set all pre-defined URL-category action to alert"';

                        $lines .= $context->encloseFunction($tmp_array);
                    }

                    if( $visibility )
                    {
                        //<th>URL credentials TAB</th>
                        $tab_config = array();
                        $tab_config[] = "mode: ".$object->credential_mode;
                        $tab_config[] = "log-severity: ".$object->credential_log;
                        $tab_config[] = "----";

                        if( $object->url_usercredentialsubmission_visibility_tab() )
                            $tab_config[] = $bp_text_yes;
                        else
                            $tab_config[] = $bp_text_no;

                        $lines .= $context->encloseFunction($tab_config);
                    }

                    if( $adoption )
                    {
                        if( $object->is_adoption() )
                            $lines .= $context->encloseFunction($bp_text_yes.' Adoption URL set');
                        else
                            $lines .= $context->encloseFunction($bp_text_no.' NO Adoption URL set');
                    }

                    if( $addURLmembers or ( !$bestPractice and !$visibility and !$adoption ) or $context->debug )
                    {
                        /**
                         * @var $object URLProfile
                         */
                        $tmp_profile_array = array();
                        $tmp_array = array();
                        foreach( $object->allow as  $member )
                            $tmp_array[] = $member;
                        $tmp_profile_array[] = "allow: ".implode( ",", $tmp_array)."\n";

                        $tmp_array = array();
                        foreach( $object->alert as  $member )
                            $tmp_array[] = $member;
                        $tmp_profile_array[] = "alert: ".implode( ",", $tmp_array)."\n";

                        $tmp_array = array();
                        foreach( $object->block as  $member )
                            $tmp_array[] = $member;

                        $tmp_profile_array[] = "block: ".implode( ",", $tmp_array)."\n";

                        $lines .= $context->encloseFunction( $tmp_profile_array );
                    }
                }
                else
                {
                    if( $bestPractice )
                    {
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                    }
                    if( $visibility )
                    {
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                    }
                    if( $adoption )
                        $lines .= $context->encloseFunction('---');
                    if( $addURLmembers or ( !$bestPractice and !$visibility ) or $context->debug)
                        $lines .= $context->encloseFunction('');
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
                if( $addTotalUse)
                {
                    $refCount = $object->countReferences();
                    if( $refCount == 0 )
                        $refCount = "---";
                    else
                        $refCount = (string)$refCount ;
                    $lines .= $context->encloseFunction( $refCount );
                }
                if( $addCountDisabledRules)
                {
                    if( get_class($object) == "PredefinedSecurityProfileURL" )
                    {
                        $lines .= $context->encloseFunction( "" );
                    }
                    elseif( get_class($object) == "SecurityProfile" )
                    {
                        //Todo: e.g. Decryption rule with URL category exclusion of predefined, are not found as Predefined created as new tmp
                        $lines .= $context->encloseFunction( "" );
                    }
                    else
                    {
                        $refCount = $object->countDisabledRefRule();
                        if( $refCount == 0 )
                            $refCount = "---";
                        else
                            $refCount = (string)$refCount ;
                        $lines .= $context->encloseFunction( $refCount );
                    }
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
                'choices' => array('WhereUsed', 'UsedInLocation', 'TotalUse', 'BestPractice', 'Visibility', 'Adoption', 'URLmembers'),
                'help' =>
                    "pipe(|) separated list of additional fields (ie: Arg1|Arg2|Arg3...) to include in the report. The following is available:\n" .
                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n" .
                    "  - WhereUsed : list places where object is used (rules, groups ...)\n" .
                    "  - TotalUse : list a counter how often this object is used\n" .
                    "  - BestPractice : show if BestPractice is configured\n" .
                    "  - Visibility : show if SP log is configured\n" .
                    "  - Adoption : show if SP log is used\n" .
                    "  - URLmembers : add URL members also if bestpractice or visibility is added\n"
            )
    )

);
SecurityProfileCallContext::$supportedActions[] = array_merge(SecurityProfileCallContext::$supportedActions[array_key_last(SecurityProfileCallContext::$supportedActions)], array('name' => 'exportToHtml'));

SecurityProfileCallContext::$commonActionFunctions['SPR-filter']= array(
    'name' => 'SPR-filter',
    'MainFunction' => function (SecurityProfileCallContext $context, $ruleFilter)
    {
        $ruleCount = 0;
        if( $context->subSystem->isPanorama() )
        {
            $RuleArray = $context->subSystem->securityRules->rules($ruleFilter);
            $ruleCount += count($RuleArray);
            foreach( $context->subSystem->getDeviceGroups() as $dg )
            {
                $RuleArray = $dg->securityRules->rules($ruleFilter);
                $ruleCount += count($RuleArray);
            }
        }
        elseif( $context->subSystem->isDeviceGroup() )
        {
            $panorama = $context->subSystem->owner;

            $RuleArray = $panorama->securityRules->rules($ruleFilter);
            $ruleCount += count($RuleArray);

            foreach( $panorama->getDeviceGroups() as $dg )
            {
                $RuleArray = $dg->securityRules->rules($ruleFilter);
                $ruleCount += count($RuleArray);
            }
        }
        elseif( $context->subSystem->isFirewall() )
        {
            foreach( $context->subSystem->getVirtualSystems() as $dg )
            {
                $RuleArray = $dg->securityRules->rules($ruleFilter);
                $ruleCount += count($RuleArray);
            }
        }
        elseif( $context->subSystem->isVirtualSystem() )
        {
            $firewall = $context->subSystem->owner;

            foreach( $firewall->getVirtualSystems() as $dg )
            {
                $RuleArray = $dg->securityRules->rules($ruleFilter);
                $ruleCount += count($RuleArray);
            }
        }
        elseif( $context->subSystem->isBuckbeak()
            || $context->subSystem->isFawkes()
            || $context->subSystem->isContainer()
            || $context->subSystem->isDeviceCloud()
            || $context->subSystem->isDeviceOnPrem()
            || $context->subSystem->isSnippet()
        )
        {
            /** @var BuckbeakConf $panorama */
            $panorama = $context->subSystem->owner;

            foreach( $panorama->getContainers() as $dg )
            {
                $RuleArray = $dg->securityRules->rules($ruleFilter);
                $ruleCount += count($RuleArray);
            }

            foreach( $panorama->getDeviceClouds() as $dg )
            {
                $RuleArray = $dg->securityRules->rules($ruleFilter);
                $ruleCount += count($RuleArray);
            }

            foreach( $panorama->getDeviceOnPrems() as $dg )
            {
                $RuleArray = $dg->securityRules->rules($ruleFilter);
                $ruleCount += count($RuleArray);
            }

            foreach( $panorama->getSnippets() as $dg )
            {
                //Todo - only if snippet is used - swaschkut 20260614
                $RuleArray = $dg->securityRules->rules($ruleFilter);
                $ruleCount += count($RuleArray);
            }
        }

        return $ruleCount;
    }
);
SecurityProfileCallContext::$commonActionFunctions['bp-stats']= array(
    'name' => 'bp-stats',
    'MainFunction' => function (SecurityProfileCallContext $context, $debug = true, $actions = "display")
    {
        $shadow_json_backup = PH::$shadow_json;
        PH::$shadow_json = true;
        $ruleCount = 0;
        if( $context->subSystem->isPanorama() )
        {
            $context->subSystem->display_bp_statistics( $debug, $actions );

            $dgs = $context->subSystem->getDeviceGroups();
            foreach($dgs as $dg)
                $dg->display_bp_statistics( $debug, $actions );
        }
        elseif( $context->subSystem->isDeviceGroup() )
        {
            $panorama = $context->subSystem->owner;
            $panorama->display_bp_statistics( $debug, $actions );

            $dgs = $panorama->getDeviceGroups();
            foreach($dgs as $dg)
                $dg->display_bp_statistics( $debug, $actions );
        }
        elseif( $context->subSystem->isFirewall() )
        {
            $context->subSystem->display_bp_statistics( $debug, $actions );

            $dgs = $context->subSystem->getVirtualSystems();
            foreach($dgs as $dg)
                $dg->display_bp_statistics( $debug, $actions );
        }
        elseif( $context->subSystem->isVirtualSystem() )
        {
            $firewall = $context->subSystem->owner;

            $firewall->display_bp_statistics( $debug, $actions );
            $dgs = $firewall->getVirtualSystems();
            foreach($dgs as $dg)
                $dg->display_bp_statistics( $debug, $actions );
        }
        elseif( $context->subSystem->isBuckbeak()
            || $context->subSystem->isFawkes()
            || $context->subSystem->isContainer()
            || $context->subSystem->isDeviceCloud()
            || $context->subSystem->isDeviceOnPrem()
            || $context->subSystem->isSnippet()
        )
        {
            /** @var BuckbeakConf $panorama */
            $panorama = $context->subSystem->owner;
            $panorama->display_bp_statistics( $debug, $actions );
        }

        PH::$shadow_json = $shadow_json_backup;

        return PH::$JSON_TMP;
    }
);

SecurityProfileCallContext::$commonActionFunctions['bp-stats_print_table']= array(
    'name' => 'bp-stats_print_table',
    'MainFunction' => function (SecurityProfileCallContext $context, $debug = true, $actions = "display")
    {
        $shadow_json_backup = PH::$shadow_json;
        PH::$shadow_json = true;
        $ruleCount = 0;


        $f = SecurityProfileCallContext::$commonActionFunctions['bp-stats']['MainFunction'];
        $bp_stats_array = $f($context, true );

        $bp_stats_array_visible = $bp_stats_array[0]['percentage']['visibility'];
        $string_check = "visibility";
        $percentageArray_visibility = $bp_stats_array_visible;

        #print_r($percentageArray_visibility);

        $device = $context->subSystem;
        if( $context->subSystem->isPanorama() )
        {
            $device = $context->subSystem;
        }
        elseif( $context->subSystem->isDeviceGroup() )
        {
            $device = $context->subSystem->owner;
        }
        elseif( $context->subSystem->isFirewall() )
        {
            $device = $context->subSystem;
        }
        elseif( $context->subSystem->isVirtualSystem() )
        {
            $device = $context->subSystem->owner;
        }
        elseif( $context->subSystem->isBuckbeak()
            || $context->subSystem->isFawkes()
            || $context->subSystem->isContainer()
            || $context->subSystem->isDeviceCloud()
            || $context->subSystem->isDeviceOnPrem()
            || $context->subSystem->isSnippet()
        )
        {
            /** @var BuckbeakConf $panorama */
            $device = $context->subSystem->owner;
        }

        $device->print_table( $string_check, $percentageArray_visibility);

        PH::$shadow_json = $shadow_json_backup;

        return PH::$JSON_TMP;
    }
);


SecurityProfileCallContext::$supportedActions[] = array(
    'name' => 'exportSPtoHTML_old',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (SecurityProfileCallContext $context) {
        $context->objectList = array();
        $context->first = true;
    },
    'GlobalFinishFunction' => function (SecurityProfileCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        $isSCM = false;

        if( isset( $_SERVER['REQUEST_METHOD'] ) ) {
            $filename = "project/html/".$filename;
        }

        // 1. Report Configuration & Meta Information
        $reportTitle = "Security Profile Review — Visibility & Feature Coverage";
        $sourceMeta  = "configs/spr_html/reports";

        $matchedRulesCount = 0;
        // Security Rules Scope Data Configuration
        $securityRulesScope = [
            'total'          => 0,
            'allow'          => 0,
            'allow_enabled'  => 0,
            'allow_disabled' => 0,
            'enabled'        => 0
        ];

        if( $context->first )
        {
            $ruleFilter = "(action is.allow) and (rule is.enabled)";
            $f = SecurityProfileCallContext::$commonActionFunctions['SPR-filter']['MainFunction'];
            $matchedRulesCount = $f($context, $ruleFilter);

            $av_blank = $f($context, $ruleFilter." and !(secprof av-profile.is.set)");
            $as_blank = $f($context, $ruleFilter." and !(secprof as-profile.is.set)");
            $vp_blank = $f($context, $ruleFilter." and !(secprof vuln-profile.is.set)");
            $url_blank = $f($context, $ruleFilter." and !(secprof url-profile.is.set)");
            $fb_blank = $f($context, $ruleFilter." and !(secprof file-profile.is.set)");
            $wf_blank = $f($context, $ruleFilter." and !(secprof wf-profile.is.set)");

            // SCM related
            $avwf_blank = $f($context, $ruleFilter." and !(secprof avwf-profile.is.set)");
            $dnssec_blank = $f($context, $ruleFilter." and !(secprof dnssec-profile.is.set)");

            $f = SecurityProfileCallContext::$commonActionFunctions['bp-stats']['MainFunction'];
            $bp_stats_array = $f($context, true );

            // Persist summary metadata arrays inside context object state
            $summaryMetrics = isset($bp_stats_array[0]['percentage']['visibility']) ? $bp_stats_array[0]['percentage']['visibility'] : array();
            $bp_stats_raw   = $bp_stats_array;

            $securityRulesScope['total'] = $bp_stats_raw[0]['security rules'];
            $securityRulesScope['allow'] = $bp_stats_raw[0]['security rules allow'];
            $securityRulesScope['allow_enabled'] = $bp_stats_raw[0]['security rules allow enabled'];
            $securityRulesScope['allow_disabled'] = $bp_stats_raw[0]['security rules allow disabled'];
            $securityRulesScope['enabled'] = $bp_stats_raw[0]['security rules enabled'];


            $context->first = false;
        }

        // Fallback: Parse left-side overview metrics if $summaryMetrics was empty due to the flat array layout
        if (empty($summaryMetrics) && !empty($bp_stats_raw[0])) {
            $flatData = $bp_stats_raw[0];
            $overviewMapping = [
                'Antivirus'           => 'av visibility percentage',
                'Anti-Spyware'        => 'as visibility percentage',
                'Vulnerability'       => 'vp visibility percentage',
                'URL Site Access'     => 'url-site-access visibility percentage',
                'URL User Credential' => 'url-credential visibility percentage',
                'File Blocking'       => 'fb visibility percentage',
                'WildFire Analysis'   => 'wf visibility percentage',
            ];
            foreach ($overviewMapping as $label => $flatKey) {
                if (isset($flatData[$flatKey])) {
                    $summaryMetrics[$label] = [
                        'value' => $flatData[$flatKey],
                        'group' => 'Security Profiles'
                    ];
                }
            }
        }

        // 2. Section Map Definitions matching custom requested column fields
        $sections = [
            'sec-av' => [
                'title'    => 'AV — Antivirus Profiles',
                'headers'  => ['Location', 'Antivirus Profile Name', '# of Rules', 'Visible', 'Actions', 'Inline ML'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'actions', 'inline_ml'],
                'numeric'  => ['count', 'visible', 'actions', 'inline_ml'],
                'rows'     => []
            ],
            'sec-as' => [
                'title'    => 'AS — Anti-Spyware Profiles',
                'headers'  => ['Location', 'Anti-Spyware Profile Name', '# of Rules', 'Visible', 'Rules', 'DNS Lists', 'DNS Security', 'Inline ML'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'rules', 'dns_lists', 'dns_security', 'inline_ml'],
                'numeric'  => ['count', 'visible', 'rules', 'dns_lists', 'dns_security', 'inline_ml'],
                'rows'     => []
            ],
            'sec-vp' => [
                'title'    => 'VP — Vulnerability Profiles',
                'headers'  => ['Location', 'Vulnerability Profile Name', '# of Rules', 'Visible', 'Rules', 'Inline ML'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'rules', 'inline_ml'],
                'numeric'  => ['count', 'visible', 'rules', 'inline_ml'],
                'rows'     => []
            ],
            'sec-url' => [
                'title'    => 'URL — URL Filtering Profiles',
                'headers'  => ['Location', 'URL Filtering Profile Name', '# of Rules', 'Visible', 'Site Access', 'User Credential Submission', 'InlineML'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'site_access', 'user_credential', 'inline_ml'],
                'numeric'  => ['count', 'visible', 'site_access', 'user_credential', 'inline_ml'],
                'rows'     => []
            ],
            'sec-fb' => [
                'title'    => 'FB — File Blocking Profiles',
                'headers'  => ['Location', 'File Blocking Profile Name', '# of Rules', 'Visible', 'Rules'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'rules'],
                'numeric'  => ['count', 'visible', 'rules'],
                'rows'     => []
            ],
            'sec-wf' => [
                'title'    => 'WF — WildFire Analysis Profiles',
                'headers'  => ['Location', 'WildFire Analysis Profile Name', '# of Rules', 'Visible', 'Rules', 'Inline ML'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'rules', 'inline_ml'],
                'numeric'  => ['count', 'visible', 'rules', 'inline_ml'],
                'rows'     => []
            ],
        ];

        if( $context->subSystem->isBuckbeak()
            || $context->subSystem->isFawkes()
            || $context->subSystem->isContainer()
            || $context->subSystem->isDeviceCloud()
            || $context->subSystem->isDeviceOnPrem()
            || $context->subSystem->isSnippet()
        )
        {
            $isSCM = true;
            $sections['sec-avwf'] = array(
                'title'    => 'AVWF — VirusAndWildFire Profiles',
                'headers'  => ['Location', 'VirusAndWildFire Profile Name', '# of Rules', 'Visible', 'Rules', 'Inline ML'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'rules', 'inline_ml'],
                'numeric'  => ['count', 'visible', 'rules', 'inline_ml'],
                'rows'     => array()
            );
            $sections['sec-dnssec'] = array(
                'title'    => 'DNSSec — DNSSecurity Profiles',
                'headers'  => ['Location', 'DNSSecurity Profile Name', '# of Rules', 'Visible', 'Rules'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'rules'],
                'numeric'  => ['count', 'visible', 'rules'],
                'rows'     => array()
            );
            unset( $sections['sec-av'] );
            unset( $sections['sec-wf'] );
        }

        // --- MAP PILL LABELS TO FLAT ARRAY SUB-STRINGS ---
        $pillMetaMapping = [
            'sec-av' => [
                'visibility'             => 'av visibility',
                'visibility actions'     => 'av visibility actions',
                'visibility mica-engine' => 'av visibility mica-engine'
            ],
            'sec-as' => [
                'visibility'              => 'as visibility',
                'visibility rules'        => 'as visibility rules',
                'visibility mica-engine'  => 'as visibility mica-engine',
                'dns-list visibility'     => 'dns-list visibility',
                'dns-security visibility' => 'dns-security visibility'
            ],
            'sec-vp' => [
                'visibility'             => 'vp visibility',
                'visibility rules'       => 'vp visibility rules',
                'visibility mica-engine' => 'vp visibility mica-engine'
            ],
            'sec-url' => [
                'site access visibility' => 'url-site-access visibility',
                'credential visibility'  => 'url-credential visibility',
                'visibility mica-engine' => 'url-mica-engine visibility'
            ],
            'sec-fb' => [
                'visibility'       => 'fb visibility'
            ],
            'sec-wf' => [
                'visibility'             => 'wf visibility',
                'visibility rules'       => 'wf visibility rules',
                'visibility mica-engine' => 'wf visibility mica-engine'
            ],
            'sec-avwf' => [
                'visibility'             => 'avwf visibility',
                'visibility rules'       => 'avwf visibility rules',
                'visibility mica-engine' => 'avwf visibility mica-engine'
            ],
            'sec-dnssec' => [
                'visibility'       => 'dnssec visibility',
                'visibility rules' => 'dnssec visibility rules'
            ]
        ];

        // 3. Populate Data & Placeholders
        foreach( $context->objectList as $object )
        {
            if( get_class($object) == "customURLProfile"
                || get_class( $object ) == "PredefinedSecurityProfileURL"
                || get_class( $object ) == "predefined-url"
                || get_class( $object ) == "predefined-url-filtering"
                || get_class( $object ) == "predefined-virus"
                || get_class( $object ) == "predefined-spyware"
                || get_class( $object ) == "predefined-file-blocking"
                || get_class( $object ) == "predefined-vulnerability"
                || get_class( $object ) == "predefined-wildfire-analysis"
            )
                continue;

            $info = array();
            if($object->owner->owner->name() == "")
                $info['location'] = "shared";
            else
                $info['location'] = $object->owner->owner->name();
            $info['profile'] = $object->name();

            $info['count'] = 0;
            foreach( $object->refrules as $rule )
            {
                if( get_class($rule) == "SecurityRule" )
                {
                    if( $rule->isEnabled() && $rule->actionIsAllow() )
                        $info['count']++;
                }
                elseif( get_class($rule) == "SecurityProfileGroup" )
                {
                    foreach( $rule->refrules as $rule2 )
                    {
                        if( get_class($rule2) == "SecurityRule" )
                        {
                            if( $rule2->isEnabled() && $rule2->actionIsAllow() )
                                $info['count']++;
                        }
                    }
                }
            }

            if( $object->is_visibility() )
                $info['visible'] = $info['count'];
            else
                $info['visible'] = 0;

            // --- EXTENDED PARAMETERS ---
            $info['actions']                  = 0;
            $info['inline_ml']                = 0;
            if( get_class($object) == "AntiVirusProfile" )
            {
                if( $object->av_actions_visibility() )
                    $info['actions'] = $info['count'];
            }
            if( ( get_class($object) == "AntiVirusProfile"
                    || get_class($object) == "AntiSpywareProfile"
                    || get_class($object) == "VulnerabilityProfile"
                    || get_class($object) == "WildfireProfile"
                )
                && $object->cloud_inline_analysis_best_practice($object->owner->bp_json_file) )
                $info['inline_ml'] = $info['count'];

            $info['rules_not_visible']        = 0;
            $info['inline_ml_not_visible']    = 0;

            $info['rules']                    = 0;
            if( get_class($object) == "AntiSpywareProfile" && $object->spyware_rules_visibility() )
                $info['rules'] = $info['count'];

            if( get_class($object) == "VulnerabilityProfile" && $object->vulnerability_rules_visibility() )
                $info['rules'] = $info['count'];

            if( get_class($object) == "WildfireProfile" && $object->wildfire_rules_visibility() )
                $info['rules'] = $info['count'];

            $info['dns_lists']                = 0;
            $info['dns_security']             = 0;
            if( get_class($object) == "AntiSpywareProfile" && $object->spyware_dnslist_visibility() )
                $info['dns_lists'] = $info['count'];

            if( get_class($object) == "AntiSpywareProfile" && $object->spyware_dns_security_visibility() )
                $info['dns_security'] = $info['count'];

            $info['site_access']              = 0;
            $info['user_credential']          = 0;
            if( get_class($object) == "URLProfile" && $object->url_siteaccess_visibility())
                $info['site_access'] = $info['count'];

            if( get_class($object) == "URLProfile" && $object->url_usercredentialsubmission_visibility() )
                $info['user_credential'] = $info['count'];

            if( get_class($object) == "URLProfile" && $object->url_usercredentialsubmission_visibility_tab())
                $info['user_credential_tab'] = $info['count'];

            if( get_class($object) == "URLProfile" && $object->url_mica_engine_visibility())
                $info['inline_ml'] = $info['count'];

            if( get_class($object) == "AntiVirusProfile" ) { $sections['sec-av']['rows'][] = $info; }
            elseif( get_class($object) == "AntiSpywareProfile" ) { $sections['sec-as']['rows'][] = $info; }
            elseif( get_class($object) == "VulnerabilityProfile" ) { $sections['sec-vp']['rows'][] = $info; }
            elseif( get_class($object) == "FileBlockingProfile" ) { $sections['sec-fb']['rows'][] = $info; }
            elseif( get_class($object) == "URLProfile" ) { $sections['sec-url']['rows'][] = $info; }
            elseif( get_class($object) == "WildfireProfile" ) { $sections['sec-wf']['rows'][] = $info; }
            elseif( get_class($object) == "VirusAndWildfireProfile" ) { $sections['sec-avwf']['rows'][] = $info; }
            elseif( get_class($object) == "DNSSecurityProfile" ) { $sections['sec-dnssec']['rows'][] = $info; }
        }

        $blankDefaults = [
            'actions' => 0, 'inline_ml' => 0, 'rules_not_visible' => 0, 'inline_ml_not_visible' => 0,
            'rules' => 0, 'dns_lists' => 0, 'dns_security' => 0, 'site_access' => 0, 'user_credential' => 0
        ];

        if( !$isSCM ) {
            $sections['sec-av']['rows'][]  = array_merge(["location" => "N/A", "profile" => "blank", "count" => $av_blank, "visible" => 0], $blankDefaults);
            $sections['sec-wf']['rows'][]  = array_merge(["location" => "N/A", "profile" => "blank", "count" => $wf_blank, "visible" => 0], $blankDefaults);
        } else {
            $sections['sec-avwf']['rows'][]   = array_merge(["location" => "N/A", "profile" => "blank", "count" => $avwf_blank, "visible" => 0], $blankDefaults);
            $sections['sec-dnssec']['rows'][] = array_merge(["location" => "N/A", "profile" => "blank", "count" => $dnssec_blank, "visible" => 0], $blankDefaults);
        }
        $sections['sec-as']['rows'][]  = array_merge(["location" => "N/A", "profile" => "blank", "count" => $as_blank, "visible" => 0], $blankDefaults);
        $sections['sec-vp']['rows'][]  = array_merge(["location" => "N/A", "profile" => "blank", "count" => $vp_blank, "visible" => 0], $blankDefaults);
        $sections['sec-fb']['rows'][]  = array_merge(["location" => "N/A", "profile" => "blank", "count" => $fb_blank, "visible" => 0], $blankDefaults);
        $sections['sec-url']['rows'][] = array_merge(["location" => "N/A", "profile" => "blank", "count" => $url_blank, "visible" => 0], $blankDefaults);

        // --- MOCK INFRAS DATA SET ---
        $network_zone_protection = [
            ['zone' => 'Trust-Internal', 'profile' => 'Strict-Zone-Protection', 'status' => 'Protected', 'drop_count' => 14],
            ['zone' => 'DMZ-External', 'profile' => 'Edge-Protection-Profile', 'status' => 'Protected', 'drop_count' => 142],
            ['zone' => 'Guest-Wifi', 'profile' => 'None', 'status' => 'Unprotected', 'drop_count' => 0]
        ];

        $network_log_forwarding = [
            ['profile_name' => 'Splunk-Forwarding-Default', 'syslog_targets' => '10.0.1.50, 10.0.1.51', 'rules_bound' => 42, 'status' => 'Active'],
            ['profile_name' => 'Critical-Alerts-Email', 'syslog_targets' => 'pagerduty-webhook', 'rules_bound' => 5, 'status' => 'Active']
        ];

        $network_log_settings = [
            ['log_type' => 'System Logs', 'severity_traps' => 'critical, high', 'destination' => 'Syslog-Server', 'status' => 'Configured'],
            ['log_type' => 'Configuration Logs', 'severity_traps' => 'all', 'destination' => 'Syslog-Server', 'status' => 'Configured'],
            ['log_type' => 'Threat Logs', 'severity_traps' => 'all', 'destination' => 'Splunk-Forwarding-Default', 'status' => 'Configured']
        ];

        ob_start();
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title><?php echo htmlspecialchars($reportTitle); ?></title>
            <style>
                :root {
                    --border: #d0d5dd;
                    --header-bg: #1d4ed8;
                    --header-fg: #ffffff;
                    --row-alt: #f8fafc;
                    --muted: #6b7280;
                    --subtotal-bg: #f1f5f9;
                    --net-header: #0f172a;
                    --pill-bg: #f4f4f5;
                    --pill-border: #e4e4e7;
                    --pill-txt: #71717a;
                }
                * { box-sizing: border-box; }
                body {
                    margin: 24px;
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    color: #111827;
                    background-color: #fff;
                }
                header.spr-header {
                    border-bottom: 2px solid var(--border);
                    padding-bottom: 12px;
                    margin-bottom: 24px;
                }
                header.spr-header h1 { margin: 0 0 4px 0; font-size: 22px; }
                header.spr-header .meta { color: var(--muted); font-size: 13px; }

                .spr-header-row {
                    display: flex;
                    gap: 24px;
                    margin-bottom: 24px;
                    align-items: stretch;
                }
                .spr-header-panel {
                    flex: 1;
                    max-height: 480px;
                    overflow-y: auto;
                    border: 1px solid var(--border);
                    padding: 12px;
                    border-radius: 6px;
                    background: #fff;
                }
                .spr-section { margin-bottom: 36px; }
                .spr-section h2 {
                    font-size: 15px;
                    margin: 0 0 12px 0;
                    padding: 6px 10px;
                    background: #f3f4f6;
                    border-left: 4px solid var(--header-bg);
                }

                /* Pill Metric Grid Containers */
                .spr-pill-matrix {
                    display: flex;
                    flex-direction: column;
                    gap: 6px;
                    margin: 4px 0 16px 4px;
                }
                .spr-pill-row {
                    display: flex;
                    gap: 12px;
                    flex-wrap: wrap;
                }
                .spr-pill {
                    background-color: var(--pill-bg);
                    border: 1px solid var(--pill-border);
                    border-radius: 12px;
                    padding: 4px 14px;
                    font-size: 12px;
                    color: var(--pill-txt);
                    display: inline-flex;
                    align-items: center;
                    gap: 6px;
                }
                .spr-pill strong {
                    color: #000000;
                    font-weight: 700;
                }

                .spr-table {
                    border-collapse: collapse;
                    width: 100%;
                    font-size: 13px;
                    margin-bottom: 8px;
                }
                .spr-table th, .spr-table td {
                    border: 1px solid var(--border);
                    padding: 8px 10px;
                    text-align: left;
                }
                .spr-table thead th {
                    background: var(--header-bg);
                    color: var(--header-fg);
                    font-weight: 600;
                }
                .spr-table tbody tr:nth-child(even) { background: var(--row-alt); }
                .spr-table td.num, .spr-table th.num { text-align: right; font-variant-numeric: tabular-nums; }
                .spr-table tr.subtotal td {
                    background: var(--subtotal-bg);
                    font-weight: 600;
                }

                .progress-container {
                    background-color: #e2e8f0;
                    border-radius: 4px;
                    width: 100%;
                    min-width: 120px;
                    height: 14px;
                    display: inline-block;
                    overflow: hidden;
                    vertical-align: middle;
                }
                .progress-bar {
                    background-color: #10b981;
                    height: 100%;
                    border-radius: 4px;
                }
                .progress-bar.low { background-color: #f59e0b; }
                .progress-bar.critical { background-color: #ef4444; }

                .net-container {
                    margin-top: 20px;
                    border: 1px solid var(--border);
                    border-radius: 6px;
                    overflow: hidden;
                }
                .net-section-title {
                    background: var(--net-header);
                    color: #fff;
                    padding: 10px 14px;
                    font-size: 14px;
                    font-weight: 600;
                    margin: 0;
                }
                .net-grid {
                    display: flex;
                    flex-direction: column;
                    gap: 1px;
                    background: var(--border);
                }
                .net-block {
                    background: #fff;
                    padding: 16px;
                }
                .net-block h3 {
                    margin: 0 0 10px 0;
                    font-size: 13px;
                    color: #1e293b;
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                    border-bottom: 1px solid #e2e8f0;
                    padding-bottom: 4px;
                }
                .badge {
                    padding: 2px 6px;
                    border-radius: 4px;
                    font-size: 11px;
                    font-weight: 600;
                }
                .badge-green { background: #dcfce7; color: #15803d; }
                .badge-red { background: #fee2e2; color: #b91c1c; }
            </style>
        </head>
        <body>

        <header class="spr-header">
            <h1><?php echo htmlspecialchars($reportTitle); ?></h1>
            <div class="meta">
                Source Block Matcher: <?php echo htmlspecialchars($sourceMeta); ?> &middot;
                Total Match Assessment Context: <?php echo number_format($matchedRulesCount); ?> rules matched.
            </div>
        </header>

        <div class="spr-header-row">
            <!-- LEFT SIDE PANEL: Coverage Metrics Table -->
            <div class="spr-header-panel">
                <h3 style="font-size: 14px; margin: 0 0 10px 0; text-transform: uppercase; letter-spacing: 0.05em; color: var(--net-header);">
                    Overall Security Profile Coverage &amp; Visibility Status
                </h3>
                <table class="spr-table" style="margin: 0;">
                    <thead>
                    <tr>
                        <th>Group</th>
                        <th>Type</th>
                        <th class="num" style="width: 90px;">Percentage</th>
                        <th style="width: 180px;">% Visual Distribution</th>
                    </tr>
                    </thead>
                    <tbody>
                    <?php if(!empty($summaryMetrics) && is_array($summaryMetrics)): ?>
                        <?php foreach ($summaryMetrics as $type => $info): ?>
                            <?php
                            $pct = isset($info['value']) ? $info['value'] : 0;
                            $group = isset($info['group']) ? $info['group'] : 'General';

                            $colorClass = '';
                            if ($pct == 0) { $colorClass = 'critical'; }
                            elseif ($pct < 70) { $colorClass = 'low'; }
                            ?>
                            <tr>
                                <td style="color: var(--muted); font-size: 12px; font-weight: 500;"><?php echo htmlspecialchars($group); ?></td>
                                <td><strong><?php echo htmlspecialchars($type); ?></strong></td>
                                <td class="num"><strong><?php echo $pct; ?>%</strong></td>
                                <td style="white-space: normal; width: 180px;">
                                    <div class="progress-container">
                                        <div class="progress-bar <?php echo $colorClass; ?>" style="width: <?php echo $pct; ?>%;"></div>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="4" style="color: var(--muted); text-align: center; padding: 20px;">
                                No parameters found inside active environment context array ($summaryMetrics).
                            </td>
                        </tr>
                    <?php endif; ?>
                    </tbody>
                </table>
            </div>

            <!-- RIGHT SIDE PANEL: Security Rules (Scope) Data -->
            <div class="spr-header-panel">
                <h3 style="font-size: 14px; margin: 0 0 10px 0; text-transform: uppercase; letter-spacing: 0.05em; color: var(--net-header);">
                    Security Rules (Scope) Summary
                </h3>
                <table class="spr-table" style="margin: 0;">
                    <thead>
                    <tr>
                        <th>Rule Context Metric Rule Base</th>
                        <th class="num" style="width: 120px;">Rule Count</th>
                    </tr>
                    </thead>
                    <tbody>
                    <tr>
                        <td>Total Security Rules</td>
                        <td class="num" style="font-weight: 600;"><?php echo number_format($securityRulesScope['total']); ?></td>
                    </tr>
                    <tr>
                        <td>Security Rules (Action: Allow)</td>
                        <td class="num"><?php echo number_format($securityRulesScope['allow']); ?></td>
                    </tr>
                    <tr>
                        <td>&nbsp;&nbsp;&bull; Action: Allow &amp; Enabled</td>
                        <td class="num" style="color: #15803d; font-weight: 600;"><?php echo number_format($securityRulesScope['allow_enabled']); ?></td>
                    </tr>
                    <tr>
                        <td>&nbsp;&nbsp;&bull; Action: Allow &amp; Disabled</td>
                        <td class="num" style="color: var(--muted);"><?php echo number_format($securityRulesScope['allow_disabled']); ?></td>
                    </tr>
                    <tr>
                        <td>Total Enabled Firewall Rules</td>
                        <td class="num"><?php echo number_format($securityRulesScope['enabled']); ?></td>
                    </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <hr style="border: 0; border-top: 1px solid var(--border); margin-bottom: 24px;">

        <?php foreach ($sections as $id => $section): ?>
            <section id="<?php echo htmlspecialchars($id); ?>" class="spr-section">
                <h2><?php echo htmlspecialchars($section['title']); ?></h2>

                <!-- CAPSULE METRIC BADGES GRID MATRIX -->
                <?php if (isset($pillMetaMapping[$id]) && !empty($bp_stats_raw[0])): ?>
                    <?php $flatData = $bp_stats_raw[0]; ?>
                    <div class="spr-pill-matrix">
                        <!-- Top Percentage Row -->
                        <div class="spr-pill-row">
                            <?php foreach ($pillMetaMapping[$id] as $label => $baseKey): ?>
                                <?php
                                $pctKey = $baseKey . ' percentage';
                                $pctValue = isset($flatData[$pctKey]) ? $flatData[$pctKey] : 0;
                                ?>
                                <div class="spr-pill">
                                    <?php echo htmlspecialchars($label); ?> (%) <strong><?php echo $pctValue; ?>%</strong>
                                </div>
                            <?php endforeach; ?>
                        </div>
                        <!-- Bottom Numerical Fraction Row -->
                        <div class="spr-pill-row">
                            <?php foreach ($pillMetaMapping[$id] as $label => $baseKey): ?>
                                <?php
                                $calcKey = $baseKey . ' calc';
                                $calcValue = isset($flatData[$calcKey]) ? $flatData[$calcKey] : (isset($flatData[$baseKey]) ? $flatData[$baseKey] : '0');
                                ?>
                                <div class="spr-pill">
                                    <?php echo htmlspecialchars($label); ?> (count) <strong><?php echo htmlspecialchars($calcValue); ?></strong>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endif; ?>

                <table class="spr-table">
                    <thead>
                    <tr>
                        <?php foreach ($section['headers'] as $header): ?>
                            <th class="<?php echo (strpos($header, '#') !== false || strpos($header, 'Visible') !== false || strpos($header, 'ML') !== false) ? 'num' : ''; ?>">
                                <?php echo htmlspecialchars($header); ?>
                            </th>
                        <?php endforeach; ?>
                    </tr>
                    </thead>
                    <tbody>
                    <?php
                    $subtotals = array_fill_keys($section['keys'], 0);

                    foreach ($section['rows'] as $row):
                        ?>
                        <tr>
                            <?php foreach ($section['keys'] as $key): ?>
                                <?php
                                $isNumeric = in_array($key, $section['numeric']);
                                if ($isNumeric) {
                                    $subtotals[$key] += isset($row[$key]) ? $row[$key] : 0;
                                }
                                ?>
                                <td class="<?php echo $isNumeric ? 'num' : ''; ?>">
                                    <?php echo htmlspecialchars(isset($row[$key]) ? $row[$key] : ''); ?>
                                </td>
                            <?php endforeach; ?>
                        </tr>
                    <?php endforeach; ?>

                    <tr class="subtotal">
                        <td>Subtotal</td>
                        <?php
                        for ($i = 1; $i < count($section['keys']); $i++):
                            $key = $section['keys'][$i];
                            $isNumeric = in_array($key, $section['numeric']);
                            ?>
                            <td class="<?php echo $isNumeric ? 'num' : ''; ?>">
                                <?php echo $isNumeric ? $subtotals[$key] : ''; ?>
                            </td>
                        <?php endfor; ?>
                    </tr>
                    </tbody>
                </table>
            </section>
        <?php endforeach; ?>

        <section class="spr-section">
            <div class="net-container">
                <div class="net-section-title">Network Base Infrastructure Configuration Profiles</div>
                <div class="net-grid">

                    <div class="net-block">
                        <h3>Zone Protection Settings</h3>
                        <table class="spr-table" style="margin: 0;">
                            <thead>
                            <tr>
                                <th>Security Target Zone</th>
                                <th>Applied Protection Profile</th>
                                <th>Security Status</th>
                                <th class="num">Drop Counter Action Triggered</th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php foreach($network_zone_protection as $zp): ?>
                                <tr>
                                    <td><strong><?php echo htmlspecialchars($zp['zone']); ?></strong></td>
                                    <td><?php echo htmlspecialchars($zp['profile']); ?></td>
                                    <td>
                                    <span class="badge <?php echo $zp['status'] === 'Protected' ? 'badge-green' : 'badge-red'; ?>">
                                        <?php echo htmlspecialchars($zp['status']); ?>
                                    </span>
                                    </td>
                                    <td class="num"><?php echo $zp['drop_count']; ?></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>

                    <div class="net-block">
                        <h3>Log Forwarding Routing Pipeline</h3>
                        <table class="spr-table" style="margin: 0;">
                            <thead>
                            <tr>
                                <th>Log Forwarding Profile Name</th>
                                <th>Target Destinations / Traps</th>
                                <th class="num">Referenced Security Rules</th>
                                <th>Deployment Status</th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php foreach($network_log_forwarding as $lf): ?>
                                <tr>
                                    <td><strong><?php echo htmlspecialchars($lf['profile_name']); ?></strong></td>
                                    <td><code><?php echo htmlspecialchars($lf['syslog_targets']); ?></code></td>
                                    <td class="num"><?php echo $lf['rules_bound']; ?></td>
                                    <td><span class="badge badge-green"><?php echo htmlspecialchars($lf['status']); ?></span></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>

                    <div class="net-block">
                        <h3>System Engine Log Settings</h3>
                        <table class="spr-table" style="margin: 0;">
                            <thead>
                            <tr>
                                <th>Log Component Class</th>
                                <th>Severity Captures</th>
                                <th>Forwarding Dest Routing Node</th>
                                <th>Operational State</th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php foreach($network_log_settings as $ls): ?>
                                <tr>
                                    <td><strong><?php echo htmlspecialchars($ls['log_type']); ?></strong></td>
                                    <td><?php echo htmlspecialchars($ls['severity_traps']); ?></td>
                                    <td><?php echo htmlspecialchars($ls['destination']); ?></td>
                                    <td><span class="badge badge-green"><?php echo htmlspecialchars($ls['status']); ?></span></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>

                </div>
            </div>
        </section>

        </body>
        </html>
        <?php

        file_put_contents($filename, ob_get_clean());

        return TRUE;
    },
    'args' => array(
        'filename' => array('type' => 'string', 'default' => '*nodefault*')
    )
);

SecurityProfileCallContext::$supportedActions[] = array(
    'name' => 'exportSPtoHTML',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (SecurityProfileCallContext $context) {
        $context->objectList = array();
        $context->first = true;
    },
    'GlobalFinishFunction' => function (SecurityProfileCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        $isSCM = false;

        if( isset( $_SERVER['REQUEST_METHOD'] ) ) {
            $filename = "project/html/".$filename;
        }

        // 1. Report Configuration & Meta Information
        $reportTitle = "Security Profile — Visibility & Feature Coverage";
        $sourceMeta  = "configs/sp_html/reports";

        $matchedRulesCount = 0;
        // Security Rules Scope Data Configuration
        $securityRulesScope = [
            'total'          => 0,
            'allow'          => 0,
            'allow_enabled'  => 0,
            'allow_disabled' => 0,
            'enabled'        => 0
        ];

        if( $context->first )
        {
            $ruleFilter = "(action is.allow) and (rule is.enabled)";
            $f = SecurityProfileCallContext::$commonActionFunctions['SPR-filter']['MainFunction'];
            $matchedRulesCount = $f($context, $ruleFilter);

            $av_blank = $f($context, $ruleFilter." and !(secprof av-profile.is.set)");
            $as_blank = $f($context, $ruleFilter." and !(secprof as-profile.is.set)");
            $vp_blank = $f($context, $ruleFilter." and !(secprof vuln-profile.is.set)");
            $url_blank = $f($context, $ruleFilter." and !(secprof url-profile.is.set)");
            $fb_blank = $f($context, $ruleFilter." and !(secprof file-profile.is.set)");
            $wf_blank = $f($context, $ruleFilter." and !(secprof wf-profile.is.set)");

            // SCM related
            $avwf_blank = $f($context, $ruleFilter." and !(secprof avwf-profile.is.set)");
            $dnssec_blank = $f($context, $ruleFilter." and !(secprof dnssec-profile.is.set)");

            $f = SecurityProfileCallContext::$commonActionFunctions['bp-stats']['MainFunction'];
            $bp_stats_array = $f($context, true );

            // Persist summary metadata arrays inside context object state
            $bp_stats_raw   = $bp_stats_array;

            $securityRulesScope['total'] = $bp_stats_raw[0]['security rules'];
            $securityRulesScope['allow'] = $bp_stats_raw[0]['security rules allow'];
            $securityRulesScope['allow_enabled'] = $bp_stats_raw[0]['security rules allow enabled'];
            $securityRulesScope['allow_disabled'] = $bp_stats_raw[0]['security rules allow disabled'];
            $securityRulesScope['enabled'] = $bp_stats_raw[0]['security rules enabled'];

            $context->first = false;
        }

        // 2. Section Map Definitions matching custom requested column fields
        $sections = [
            'sec-av' => [
                'title'    => 'AV — Antivirus Profiles',
                'headers'  => ['Location', 'Antivirus Profile Name', '# of Rules', 'Visible', 'Actions', 'Inline ML', 'Actions Check Info', 'Inline ML Check Info'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'actions', 'inline_ml', 'actions_detail', 'inline_ml_detail'],
                'numeric'  => ['count', 'visible', 'actions', 'inline_ml'],
                'rows'     => []
            ],
            'sec-as' => [
                'title'    => 'AS — Anti-Spyware Profiles',
                'headers'  => ['Location', 'Anti-Spyware Profile Name', '# of Rules', 'Visible', 'Rules', 'DNS Lists', 'DNS Security', 'Inline ML', 'Rules Check Info', 'DNS Lists Check Info', 'DNS Security Check Info', 'Inline ML Check Info'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'rules', 'dns_lists', 'dns_security', 'inline_ml', 'rules_detail', 'dns_lists_detail', 'dns_security_detail', 'inline_ml_detail'],
                'numeric'  => ['count', 'visible', 'rules', 'dns_lists', 'dns_security', 'adns_security', 'inline_ml'],
                'rows'     => []
            ],
            'sec-vp' => [
                'title'    => 'VP — Vulnerability Profiles',
                'headers'  => ['Location', 'Vulnerability Profile Name', '# of Rules', 'Visible', 'Rules', 'Inline ML', 'Rules Check Info', 'Inline ML Check Info'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'rules', 'inline_ml', 'rules_detail', 'inline_ml_detail'],
                'numeric'  => ['count', 'visible', 'rules', 'inline_ml'],
                'rows'     => []
            ],
            'sec-url' => [
                'title'    => 'URL — URL Filtering Profiles',
                'headers'  => ['Location', 'URL Filtering Profile Name', '# of Rules', 'Visible', 'Site Access', 'User Credential Submission', 'InlineML', 'Site Access Check Info', 'User Credential Check Info', 'Inline ML Check Info'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'site_access', 'user_credential', 'inline_ml', 'site_access_detail', 'user_credential_detail', 'inline_ml_detail'],
                'numeric'  => ['count', 'visible', 'site_access', 'user_credential', 'inline_ml'],
                'rows'     => []
            ],
            'sec-fb' => [
                'title'    => 'FB — File Blocking Profiles',
                'headers'  => ['Location', 'File Blocking Profile Name', '# of Rules', 'Visible', 'Rules', 'Rules Check Info'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'rules', 'rules_detail'],
                'numeric'  => ['count', 'visible', 'rules'],
                'rows'     => []
            ],
            'sec-wf' => [
                'title'    => 'WF — WildFire Analysis Profiles',
                'headers'  => ['Location', 'WildFire Analysis Profile Name', '# of Rules', 'Visible', 'Rules', 'Inline ML', 'Rules Check Info', 'Inline ML Check Info'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'rules', 'inline_ml', 'rules_detail', 'inline_ml_detail'],
                'numeric'  => ['count', 'visible', 'rules', 'inline_ml'],
                'rows'     => []
            ],
        ];

        if( $context->subSystem->isBuckbeak()
            || $context->subSystem->isFawkes()
            || $context->subSystem->isContainer()
            || $context->subSystem->isDeviceCloud()
            || $context->subSystem->isDeviceOnPrem()
            || $context->subSystem->isSnippet()
        )
        {
            $isSCM = true;
            $sections['sec-avwf'] = array(
                'title'    => 'AVWF — VirusAndWildFire Profiles',
                'headers'  => ['Location', 'VirusAndWildFire Profile Name', '# of Rules', 'Visible', 'Rules', 'Inline ML', 'Rules Check Info', 'Inline ML Check Info'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'rules', 'inline_ml', 'rules_detail', 'inline_ml_detail'],
                'numeric'  => ['count', 'visible', 'rules', 'inline_ml'],
                'rows'     => array()
            );
            $sections['sec-dnssec'] = array(
                'title'    => 'DNSSec — DNSSecurity Profiles',
                'headers'  => ['Location', 'DNSSecurity Profile Name', '# of Rules', 'Visible', 'Rules', 'Rules Check Info'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'rules', 'rules_detail'],
                'numeric'  => ['count', 'visible', 'rules'],
                'rows'     => array()
            );
            unset( $sections['sec-av'] );
            unset( $sections['sec-wf'] );
        }

        // --- MAP PILL LABELS TO FLAT ARRAY SUB-STRINGS ---
        // Left intact to retain raw configuration metrics references perfectly while providing tab mutation capabilities
        $pillMetaMapping = [
            'sec-av' => [
                'visibility'             => 'av visibility',
                'visibility actions'     => 'av visibility actions',
                'visibility mica-engine' => 'av visibility mica-engine'
            ],
            'sec-as' => [
                'visibility'              => 'as visibility',
                'visibility rules'        => 'as visibility rules',
                'dns-list visibility'     => 'dns-list visibility',
                'dns-security visibility' => 'dns-security visibility',
                'adns-security visibility'=> 'adns-security visibility',
                'visibility mica-engine'  => 'as visibility mica-engine'
            ],
            'sec-vp' => [
                'visibility'             => 'vp visibility',
                'visibility rules'       => 'vp visibility rules',
                'visibility mica-engine' => 'vp visibility mica-engine'
            ],
            'sec-url' => [
                'site access visibility' => 'url-site-access visibility',
                'credential visibility'  => 'url-credential visibility',
                'visibility mica-engine' => 'url-mica-engine visibility'
            ],
            'sec-fb' => [
                'visibility'       => 'fb visibility'
            ],
            'sec-wf' => [
                'visibility'             => 'wf visibility',
                'visibility rules'       => 'wf visibility rules',
                'visibility mica-engine' => 'wf visibility mica-engine'
            ],
            'sec-avwf' => [
                'visibility'             => 'avwf visibility',
                'visibility rules'       => 'avwf visibility rules',
                'visibility mica-engine' => 'avwf visibility mica-engine'
            ],
            'sec-dnssec' => [
                'visibility'       => 'dnssec visibility',
                'visibility rules' => 'dnssec visibility rules'
            ]
        ];

        // 3. Populate Data & Placeholders
        foreach( $context->objectList as $object )
        {
            /** @var AntiVirusProfile|AntiSpywareProfile|VulnerabilityProfile|WildfireProfile|VirusAndWildfireProfile|DNSSecurityProfile|DataFilteringProfile|URLProfile $object */

            if( get_class($object) == "customURLProfile"
                || get_class( $object ) == "PredefinedSecurityProfileURL"
                || get_class( $object ) == "predefined-url"
                || get_class( $object ) == "predefined-url-filtering"
                || get_class( $object ) == "predefined-virus"
                || get_class( $object ) == "predefined-spyware"
                || get_class( $object ) == "predefined-file-blocking"
                || get_class( $object ) == "predefined-vulnerability"
                || get_class( $object ) == "predefined-wildfire-analysis"
            )
                continue;

            $info = array();
            if($object->owner->owner->name() == "")
                $info['location'] = "shared";
            else
                $info['location'] = $object->owner->owner->name();
            $info['profile'] = $object->name();

            $info['count'] = 0;
            foreach( $object->refrules as $rule )
            {
                /** @var SecurityRule|SecurityProfileGroup $rule */
                if( get_class($rule) == "SecurityRule" )
                {
                    if( $rule->isEnabled() && $rule->actionIsAllow() )
                        $info['count']++;
                }
                elseif( get_class($rule) == "SecurityProfileGroup" )
                {
                    foreach( $rule->refrules as $rule2 )
                    {
                        if( get_class($rule2) == "SecurityRule" )
                        {
                            if( $rule2->isEnabled() && $rule2->actionIsAllow() )
                                $info['count']++;
                        }
                    }
                }
            }

            if( $object->is_visibility() )
                $info['visible'] = $info['count'];
            else
                $info['visible'] = 0;

            if( $object->is_best_practice() )
                $info['bp_pass'] = $info['count'];
            else
                $info['bp_pass'] = 0;

            if( $object->is_adoption() )
                $info['adopted'] = $info['count'];
            else
                $info['adopted'] = 0;

            // --- EXTENDED PARAMETERS ---
            $info['actions']                  = 0;
            $info['inline_ml']                = 0;
            $info['actions_detail']             = 'Compliant';
            $info['inline_ml_detail']             = 'Compliant';
            $info['bp_actions']                  = 0;
            $info['bp_inline_ml']                = 0;
            $info['bp_actions_detail']             = 'BP Compliant';
            $info['bp_inline_ml_detail']             = 'BP Compliant';
            if( get_class($object) == "AntiVirusProfile" )
            {
                if( $object->av_actions_visibility() )
                    $info['actions'] = $info['count'];
                else
                    $info['actions_detail'] = '[Placeholder: visible Actions Detail Text]';

                if( $object->av_actions_best_practice() )
                    $info['bp_actions'] = $info['count'];
                else
                    $info['bp_actions_detail'] = '[Placeholder: BP Actions Detail Text]';
            }
            if( get_class($object) == "AntiVirusProfile"
                || get_class($object) == "AntiSpywareProfile"
                || get_class($object) == "VulnerabilityProfile"
                || get_class($object) == "WildfireProfile"
            )
            {
                if( $object->cloud_inline_analysis_visibility($object->owner->bp_json_file) )
                {
                    $info['inline_ml'] = $info['count'];
                }
                else
                {
                    $notVisibleElements         = $object->build_cloud_inline_comprehensive_array($object->owner->bp_json_file)['all'];
                    $notVisibleElements         = $object->build_cloud_inline_comprehensive_array($object->owner->bp_json_file)['not visible'];
                    $info['inline_ml_detail'] = is_array($notVisibleElements) ? implode("\n", $notVisibleElements) : $notVisibleElements;
                    $info['inline_ml_detail']             = '[Placeholder: In-Line Details]';
                }

                if( $object->cloud_inline_analysis_best_practice($object->owner->bp_json_file) )
                {
                    $info['bp_inline_ml'] = $info['count'];
                }
                else
                {
                    $notVisibleElements         = $object->build_cloud_inline_comprehensive_array($object->owner->bp_json_file)['all'];
                    #$notVisibleElements         = $object->build_cloud_inline_comprehensive_array($object->owner->bp_json_file)['no bp'];
                    $info['bp_inline_ml_detail'] = is_array($notVisibleElements) ? implode("\n", $notVisibleElements) : $notVisibleElements;
                    $info['bp_inline_ml_detail']             = '[Placeholder: bp In-Line Details]';
                }
            }

            $info['rules']                    = 0;
            $info['rules_detail']             = 'Compliant';
            $info['bp_rules']                    = 0;
            $info['bp_rules_detail']             = 'BP Compliant';
            if( get_class($object) == "AntiSpywareProfile" )
            {
                if(  $object->spyware_rules_visibility() )
                    $info['rules'] = $info['count'];
                else
                    $info['rules_detail']             = '[Placeholder: visible Rules Visibility Details]';

                if(  $object->spyware_rules_best_practice() )
                    $info['bp_rules'] = $info['count'];
                else
                    $info['bp_rules_detail']             = '[Placeholder: bp Rules Visibility Details]';
            }

            if( get_class($object) == "VulnerabilityProfile" )
            {
                if( $object->vulnerability_rules_visibility() )
                    $info['rules'] = $info['count'];
                else
                    $info['rules_detail']             = '[Placeholder: visible Rules Visibility Details]';

                if(  $object->vulnerability_rules_best_practice() )
                    $info['bp_rules'] = $info['count'];
                else
                    $info['bp_rules_detail']             = '[Placeholder: bp Rules Visibility Details]';
            }

            if( get_class($object) == "WildfireProfile" )
            {
                if( $object->wildfire_rules_visibility() )
                    $info['rules'] = $info['count'];
                else
                    $info['rules_detail']             = '[Placeholder: visible Rules Visibility Details]';

                if(  $object->wildfire_rules_best_practice() )
                    $info['bp_rules'] = $info['count'];
                else
                    $info['bp_rules_detail']             = '[Placeholder: bp Rules Visibility Details]';
            }

            $info['dns_lists']                = 0;
            $info['dns_security']             = 0;
            $info['dns_lists_detail']             = 'Compliant';
            $info['dns_security_detail']             = 'Compliant';
            $info['bp_dns_lists']                = 0;
            $info['bp_dns_security']             = 0;
            $info['bp_dns_lists_detail']             = 'BP Compliant';
            $info['bp_dns_security_detail']             = 'BP Compliant';
            $info['adns_security']             = 0;
            $info['adns_security_detail']             = 'Compliant';
            $info['bp_adns_security']             = 0;
            $info['bp_adns_security_detail']             = 'BP Compliant';
            if( get_class($object) == "AntiSpywareProfile" )
            {
                if( $object->spyware_dnslist_visibility() )
                    $info['dns_lists'] = $info['count'];
                else
                    $info['dns_lists_detail']         = '[Placeholder: visible DNS Lists Details]';

                if( $object->spyware_dnslist_best_practice() )
                    $info['bp_dns_lists'] = $info['count'];
                else
                    $info['bp_dns_lists_detail']         = '[Placeholder: bp DNS Lists Details]';
            }

            if( get_class($object) == "AntiSpywareProfile" )
            {
                if( $object->spyware_dns_security_visibility() )
                    $info['dns_security'] = $info['count'];
                else
                    $info['dns_security_detail']      = '[Placeholder: DNS Security Details]';

                if( $object->spyware_dns_security_best_practice() )
                    $info['bp_dns_security'] = $info['count'];
                else
                    $info['bp_dns_security_detail']      = '[Placeholder: BP DNS Security Details]';

                if( $object->spyware_advanced_dns_security_visibility() )
                    $info['adns_security'] = $info['count'];
                else
                    $info['adns_security_detail']      = '[Placeholder: DNS Security Details]';

                if( $object->spyware_advanced_dns_security_best_practice() )
                    $info['bp_adns_security'] = $info['count'];
                else
                    $info['bp_adns_security_detail']      = '[Placeholder: BP ADNS Security Details]';
            }

            $info['site_access'] = 0;
            $info['user_credential'] = 0;
            $info['user_credential_tab'] = 0;
            $info['bp_site_access'] = 0;
            $info['bp_user_credential'] = 0;
            $info['bp_user_credential_tab'] = 0;
            if( get_class($object) == "URLProfile" && $object->url_siteaccess_visibility())
                $info['site_access'] = $info['count'];

            if( get_class($object) == "URLProfile" && $object->url_usercredentialsubmission_visibility() )
                $info['user_credential'] = $info['count'];

            if( get_class($object) == "URLProfile" && $object->url_usercredentialsubmission_visibility_tab())
                $info['user_credential_tab'] = $info['count'];

            if( get_class($object) == "URLProfile" && $object->url_mica_engine_visibility())
                $info['inline_ml'] = $info['count'];

            if( get_class($object) == "URLProfile" && $object->url_siteaccess_best_practice())
                $info['bp_site_access'] = $info['count'];

            if( get_class($object) == "URLProfile" && $object->url_usercredentialsubmission_best_practice() )
                $info['bp_user_credential'] = $info['count'];

            if( get_class($object) == "URLProfile" && $object->url_usercredentialsubmission_best_practice_tab())
                $info['bp_user_credential_tab'] = $info['count'];

            if( get_class($object) == "URLProfile" && $object->url_mica_engine_best_practice())
                $info['bp_inline_ml'] = $info['count'];

            $info['site_access_detail']       = ($info['site_access'] < $info['count']) ? '[Placeholder: Site Access Details]' : 'Compliant';
            $info['user_credential_detail']   = ($info['user_credential'] < $info['count']) ? '[Placeholder: User Credential Details]' : 'Compliant';

            $info['bp_site_access_detail']       = ($info['bp_site_access'] < $info['count']) ? '[Placeholder: BP Site Access Details]' : 'BP Compliant';
            $info['bp_user_credential_detail']   = ($info['bp_user_credential'] < $info['count']) ? '[Placeholder: BP User Credential Details]' : 'BP Compliant';


            if( get_class($object) == "AntiVirusProfile" ) { $sections['sec-av']['rows'][] = $info; }
            elseif( get_class($object) == "AntiSpywareProfile" ) { $sections['sec-as']['rows'][] = $info; }
            elseif( get_class($object) == "VulnerabilityProfile" ) { $sections['sec-vp']['rows'][] = $info; }
            elseif( get_class($object) == "FileBlockingProfile" ) { $sections['sec-fb']['rows'][] = $info; }
            elseif( get_class($object) == "URLProfile" ) { $sections['sec-url']['rows'][] = $info; }
            elseif( get_class($object) == "WildfireProfile" ) { $sections['sec-wf']['rows'][] = $info; }
            elseif( get_class($object) == "VirusAndWildfireProfile" ) { $sections['sec-avwf']['rows'][] = $info; }
            elseif( get_class($object) == "DNSSecurityProfile" ) { $sections['sec-dnssec']['rows'][] = $info; }
        }


        $blankDefaults = [
            'actions' => 0, 'inline_ml' => 0, 'rules_not_visible' => 0, 'inline_ml_not_visible' => 0,
            'rules' => 0, 'dns_lists' => 0, 'dns_security' => 0, 'adns_security' => 0, 'site_access' => 0, 'user_credential' => 0,
            'actions_detail' => 'N/A', 'inline_ml_detail' => 'N/A', 'rules_detail' => 'N/A',
            'dns_lists_detail' => 'N/A', 'dns_security_detail' => 'N/A', 'adns_security_detail' => 'N/A', 'site_access_detail' => 'N/A',
            'user_credential_detail' => 'N/A',

            // --- ADD THESE NEW BLANK DEFAULTS ---
            'bp_pass' => 0, 'bp_actions' => 0, 'bp_inline_ml' => 0, 'bp_rules' => 0,
            'bp_dns_lists' => 0, 'bp_dns_security' => 0, 'bp_adns_security' => 0, 'bp_site_access' => 0, 'bp_user_credential' => 0,
            'bp_actions_detail' => 'N/A', 'bp_inline_ml_detail' => 'N/A', 'bp_rules_detail' => 'N/A',
            'bp_dns_lists_detail' => 'N/A', 'bp_dns_security_detail' => 'N/A', 'bp_adns_security_detail' => 'N/A', 'bp_site_access_detail' => 'N/A',
            'bp_user_credential_detail' => 'N/A'
        ];

        if( !$isSCM ) {
            $sections['sec-av']['rows'][]  = array_merge(["location" => "N/A", "profile" => "blank", "count" => $av_blank, "visible" => 0], $blankDefaults);
            $sections['sec-wf']['rows'][]  = array_merge(["location" => "N/A", "profile" => "blank", "count" => $wf_blank, "visible" => 0], $blankDefaults);
        } else {
            $sections['sec-avwf']['rows'][]   = array_merge(["location" => "N/A", "profile" => "blank", "count" => $avwf_blank, "visible" => 0], $blankDefaults);
            $sections['sec-dnssec']['rows'][] = array_merge(["location" => "N/A", "profile" => "blank", "count" => $dnssec_blank, "visible" => 0], $blankDefaults);
        }
        $sections['sec-as']['rows'][]  = array_merge(["location" => "N/A", "profile" => "blank", "count" => $as_blank, "visible" => 0], $blankDefaults);
        $sections['sec-vp']['rows'][]  = array_merge(["location" => "N/A", "profile" => "blank", "count" => $vp_blank, "visible" => 0], $blankDefaults);
        $sections['sec-fb']['rows'][]  = array_merge(["location" => "N/A", "profile" => "blank", "count" => $fb_blank, "visible" => 0], $blankDefaults);
        $sections['sec-url']['rows'][] = array_merge(["location" => "N/A", "profile" => "blank", "count" => $url_blank, "visible" => 0], $blankDefaults);

        // --- MOCK INFRAS DATA SET ---
        $network_zone_protection = [
            ['zone' => 'Trust-Internal', 'profile' => 'Strict-Zone-Protection', 'status' => 'Protected', 'drop_count' => 14],
            ['zone' => 'DMZ-External', 'profile' => 'Edge-Protection-Profile', 'status' => 'Protected', 'drop_count' => 142],
            ['zone' => 'Guest-Wifi', 'profile' => 'None', 'status' => 'Unprotected', 'drop_count' => 0]
        ];

        $network_log_forwarding = [
            ['profile_name' => 'Splunk-Forwarding-Default', 'syslog_targets' => '10.0.1.50, 10.0.1.51', 'rules_bound' => 42, 'status' => 'Active'],
            ['profile_name' => 'Critical-Alerts-Email', 'syslog_targets' => 'pagerduty-webhook', 'rules_bound' => 5, 'status' => 'Active']
        ];

        $network_log_settings = [
            ['log_type' => 'System Logs', 'severity_traps' => 'critical, high', 'destination' => 'Syslog-Server', 'status' => 'Configured'],
            ['log_type' => 'Configuration Logs', 'severity_traps' => 'all', 'destination' => 'Syslog-Server', 'status' => 'Configured'],
            ['log_type' => 'Threat Logs', 'severity_traps' => 'all', 'destination' => 'Splunk-Forwarding-Default', 'status' => 'Configured']
        ];

        ob_start();
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title><?php echo htmlspecialchars($reportTitle); ?></title>
            <style>
                :root {
                    --border: #d0d5dd;
                    --header-bg: #1d4ed8;
                    --header-fg: #ffffff;
                    --row-alt: #f8fafc;
                    --muted: #6b7280;
                    --subtotal-bg: #f1f5f9;
                    --net-header: #0f172a;
                    --pill-bg: #f4f4f5;
                    --pill-border: #e4e4e7;
                    --pill-txt: #71717a;
                    --tab-active-bg: #1d4ed8;
                    --tab-active-fg: #ffffff;
                }
                * { box-sizing: border-box; }
                body {
                    margin: 24px;
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    color: #111827;
                    background-color: #fff;
                }
                header.spr-header {
                    border-bottom: 2px solid var(--border);
                    padding-bottom: 12px;
                    margin-bottom: 24px;
                }
                header.spr-header h1 { margin: 0 0 4px 0; font-size: 22px; }
                header.spr-header .meta { color: var(--muted); font-size: 13px; }

                /* Selector styling */
                .device-selector-box {
                    background: #f8fafc;
                    border: 1px solid var(--border);
                    padding: 16px;
                    border-radius: 8px;
                    margin-bottom: 24px;
                    display: flex;
                    align-items: center;
                    gap: 12px;
                }
                .device-selector-box select {
                    padding: 8px 12px;
                    font-size: 14px;
                    font-weight: 600;
                    border-radius: 6px;
                    border: 1px solid var(--border);
                    background: #fff;
                    color: #0f172a;
                    cursor: pointer;
                    min-width: 250px;
                }

                .spr-header-row {
                    display: flex;
                    gap: 24px;
                    margin-bottom: 24px;
                    align-items: stretch;
                }
                .spr-header-panel {
                    flex: 1;
                    min-height: 380px;
                    border: 1px solid var(--border);
                    padding: 16px;
                    border-radius: 6px;
                    background: #fff;
                    display: flex;
                    flex-direction: column;
                }
                .spr-section { margin-bottom: 36px; }
                .spr-section h2 {
                    font-size: 15px;
                    margin: 0 0 12px 0;
                    padding: 6px 10px;
                    background: #f3f4f6;
                    border-left: 4px solid var(--header-bg);
                }

                /* TAB CONTROLS LAYOUT STYLING */
                .spr-tabs-navigation {
                    display: flex;
                    gap: 4px;
                    border-bottom: 2px solid var(--border);
                    margin-bottom: 16px;
                    padding-top: 4px;
                }
                .spr-tab-btn {
                    padding: 8px 20px;
                    font-size: 13px;
                    font-weight: 600;
                    cursor: pointer;
                    background: #f1f5f9;
                    border: 1px solid var(--border);
                    border-bottom: none;
                    border-top-left-radius: 6px;
                    border-top-right-radius: 6px;
                    color: #475569;
                    transition: all 0.15s ease-in-out;
                    margin-bottom: -2px;
                }
                .spr-tab-btn:hover {
                    background: #e2e8f0;
                    color: #0f172a;
                }
                .spr-tab-btn.active {
                    background: var(--tab-active-bg);
                    color: var(--tab-active-fg);
                    border-color: var(--tab-active-bg);
                }

                /* Pill Metric Grid Containers */
                .spr-pill-matrix {
                    display: flex;
                    flex-direction: column;
                    gap: 6px;
                    margin: 4px 0 16px 4px;
                }
                .spr-pill-row {
                    display: flex;
                    gap: 12px;
                    flex-wrap: wrap;
                }
                .spr-pill {
                    background-color: var(--pill-bg);
                    border: 1px solid var(--pill-border);
                    border-radius: 12px;
                    padding: 4px 14px;
                    font-size: 12px;
                    color: var(--pill-txt);
                    display: inline-flex;
                    align-items: center;
                    gap: 6px;
                }
                .spr-pill strong {
                    color: #000000;
                    font-weight: 700;
                }

                .spr-table {
                    border-collapse: collapse;
                    width: 100%;
                    font-size: 13px;
                    margin-bottom: 8px;
                }
                .spr-table td {
                    white-space: pre-line;
                }
                .spr-table th, .spr-table td {
                    border: 1px solid var(--border);
                    padding: 8px 10px;
                    text-align: left;
                }
                .spr-table thead th {
                    background: var(--header-bg);
                    color: var(--header-fg);
                    font-weight: 600;
                }
                .spr-table tbody tr:nth-child(even) { background: var(--row-alt); }
                .spr-table td.num, .spr-table th.num { text-align: right; font-variant-numeric: tabular-nums; }
                .spr-table tr.subtotal td {
                    background: var(--subtotal-bg);
                    font-weight: 600;
                }

                .progress-container {
                    background-color: #e2e8f0;
                    border-radius: 4px;
                    width: 100%;
                    min-width: 120px;
                    height: 14px;
                    display: inline-block;
                    overflow: hidden;
                    vertical-align: middle;
                }
                .progress-bar {
                    height: 100%;
                    border-radius: 4px;
                    background-color: #10b981;
                }
                .progress-bar.low { background-color: #f59e0b; }
                .progress-bar.critical { background-color: #ef4444; }

                .net-container {
                    margin-top: 20px;
                    border: 1px solid var(--border);
                    border-radius: 6px;
                    overflow: hidden;
                }
                .net-section-title {
                    background: var(--net-header);
                    color: #fff;
                    padding: 10px 14px;
                    font-size: 14px;
                    font-weight: 600;
                    margin: 0;
                }
                .net-grid {
                    display: flex;
                    flex-direction: column;
                    gap: 1px;
                    background: var(--border);
                }
                .net-block {
                    background: #fff;
                    padding: 16px;
                }
                .net-block h3 {
                    margin: 0 0 10px 0;
                    font-size: 13px;
                    color: #1e293b;
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                    border-bottom: 1px solid #e2e8f0;
                    padding-bottom: 4px;
                }
                .badge {
                    padding: 2px 6px;
                    border-radius: 4px;
                    font-size: 11px;
                    font-weight: 600;
                }
                .badge-green { background: #dcfce7; color: #15803d; }
                .badge-red { background: #fee2e2; color: #b91c1c; }
            </style>
        </head>
        <body>

        <header class="spr-header">
            <h1><?php echo htmlspecialchars($reportTitle); ?></h1>
            <div class="meta">
                Source Block Matcher: <?php echo htmlspecialchars($sourceMeta); ?> &middot;
                Total Match Assessment Context: <?php echo number_format($matchedRulesCount); ?> rules matched.
            </div>
        </header>

        <!-- DYNAMIC DEVICE SELECTOR DROPDOWN -->
        <div class="device-selector-box">
            <label for="deviceSelector"><strong>Active Context Dataset / Location:</strong></label>
            <select id="deviceSelector" onchange="changeActiveDeviceContext(this.value)">
                <?php foreach ($bp_stats_raw as $index => $deviceDataInstance): ?>
                    <?php
                    $dropdownLabel = "Dataset Target Location #" . ($index + 1);

                    if (isset($deviceDataInstance['type'])) {
                        $type = $deviceDataInstance['type'];
                        $header = $deviceDataInstance['header'] ?? '';

                        $cleanHeader = preg_replace('/\x1b\[[0-9;]*m/', '', $header);
                        $cleanHeader = preg_replace('/\[[0-9;]*m/', '', $cleanHeader);

                        if ($type === 'PANConf' || $type === 'PanoramaConf') {
                            $dropdownLabel = "FullDevice";
                        }
                        elseif ($type === 'VirtualSystem') {
                            if (preg_match("/VirtualSystem\s+'([^']+)'/", $cleanHeader, $matches)) {
                                $dropdownLabel = $matches[1];
                            } else {
                                $dropdownLabel = "vsys1";
                            }
                        }
                        elseif ($type === 'DeviceGroup') {
                            if (preg_match("/DeviceGroup\s+'([^']+)'/", $cleanHeader, $matches)) {
                                $dropdownLabel = $matches[1];
                            } else {
                                $dropdownLabel = "DeviceGroup Context";
                            }
                        }
                    }
                    ?>
                    <option value="<?php echo $index; ?>">
                        <?php echo htmlspecialchars($dropdownLabel); ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>

        <div class="spr-header-row">
            <!-- RIGHT SIDE PANEL: Security Rules (Scope) Data -->
            <div class="spr-header-panel" style="max-height: 250px; flex: 0 0 350px;">
                <h3 style="font-size: 14px; margin: 0 0 10px 0; text-transform: uppercase; letter-spacing: 0.05em; color: var(--net-header);">
                    Security Rules (Scope) Summary
                </h3>
                <table class="spr-table" style="margin: 0;">
                    <thead>
                    <tr>
                        <th>Rule Context Metric</th>
                        <th class="num" style="width: 100px;">Count</th>
                    </tr>
                    </thead>
                    <tbody>
                    <tr>
                        <td>Total Security Rules</td>
                        <td class="num" id="scope-total" style="font-weight: 600;"><?php echo number_format($securityRulesScope['total']); ?></td>
                    </tr>
                    <tr>
                        <td>Rules (Action: Allow)</td>
                        <td class="num" id="scope-allow"><?php echo number_format($securityRulesScope['allow']); ?></td>
                    </tr>
                    <tr>
                        <td>&nbsp;&nbsp;&bull; Allow &amp; Enabled</td>
                        <td class="num" id="scope-allow-enabled" style="color: #15803d; font-weight: 600;"><?php echo number_format($securityRulesScope['allow_enabled']); ?></td>
                    </tr>
                    <tr>
                        <td>&nbsp;&nbsp;&bull; Allow &amp; Disabled</td>
                        <td class="num" id="scope-allow-disabled" style="color: var(--muted);"><?php echo number_format($securityRulesScope['allow_disabled']); ?></td>
                    </tr>
                    <tr>
                        <td>Total Enabled Rules</td>
                        <td class="num" id="scope-enabled"><?php echo number_format($securityRulesScope['enabled']); ?></td>
                    </tr>
                    </tbody>
                </table>
            </div>

            <!-- LEFT SIDE PANEL WITH TAB SWITCHER ABOVE THE METRICS TABLE -->
            <div class="spr-header-panel">
                <!-- THREE HARDCODED TABS SWITCH -->
                <div class="spr-tabs-navigation">
                    <div class="spr-tab-btn active" onclick="switchMetricsTab('visibility', this)">Visibility</div>
                    <div class="spr-tab-btn" onclick="switchMetricsTab('best-practice', this)">Best-Practice</div>
                    <div class="spr-tab-btn" onclick="switchMetricsTab('adoption', this)">Adoption</div>
                </div>

                <div style="flex: 1; overflow-y: auto;">
                    <table class="spr-table" style="margin: 0;">
                        <thead>
                        <tr>
                            <th>Group</th>
                            <th>Type</th>
                            <th class="num" style="width: 90px;">Percentage</th>
                            <th style="width: 220px;">% Visual Distribution</th>
                        </tr>
                        </thead>
                        <tbody id="overview-metrics-tbody">
                        <!-- Dynamic content is fully handled on load and updates via javascript engine below -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <hr style="border: 0; border-top: 1px solid var(--border); margin-bottom: 24px;">

        <?php foreach ($sections as $id => $section): ?>
            <section id="<?php echo htmlspecialchars($id); ?>" class="spr-section">
                <h2><?php echo htmlspecialchars($section['title']); ?></h2>

                <!-- CAPSULE METRIC BADGES GRID MATRIX WITH DYNAMIC HOOK TEXT INJECTION PIPELINE -->
                <?php if (isset($pillMetaMapping[$id]) && !empty($bp_stats_raw[0])): ?>
                    <div class="spr-pill-matrix">
                        <div class="spr-pill-row">
                            <?php foreach ($pillMetaMapping[$id] as $label => $baseKey): ?>
                                <?php
                                $sluggedLabel = strtolower(preg_replace('/[^a-z0-9-]+/', '-', $label));
                                ?>
                                <div class="spr-pill">
                                    <span id="pill-label-<?php echo $id . '-' . $sluggedLabel; ?>">Visibility</span>:
                                    <strong id="pill-pct-<?php echo $id . '-' . $sluggedLabel; ?>">0%</strong>
                                    <span style="color: var(--muted); margin: 0 2px;">|</span>
                                    <span id="pill-count-<?php echo $id . '-' . $sluggedLabel; ?>" style="font-variant-numeric: tabular-nums;">0/23</span>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endif; ?>

                <table class="spr-table">
                    <thead>
                    <tr>
                        <?php foreach ($section['headers'] as $header): ?>
                            <th class="<?php echo (strpos($header, 'Info') === false && (strpos($header, '#') !== false || strpos($header, 'Visible') !== false || strpos($header, 'ML') !== false || strpos($header, 'Rules') !== false || strpos($header, 'Access') !== false || strpos($header, 'Submission') !== false || strpos($header, 'Lists') !== false || strpos($header, 'Security') !== false || strpos($header, 'Actions') !== false)) ? 'num' : ''; ?>">
                                <?php echo htmlspecialchars($header); ?>
                            </th>
                        <?php endforeach; ?>
                    </tr>
                    </thead>
                    <tbody>
                    <?php
                    $subtotals = array_fill_keys($section['keys'], 0);

                    foreach ($section['rows'] as $row):
                        ?>
                        <tr data-row-json="<?php echo htmlspecialchars(json_encode($row), ENT_QUOTES, 'UTF-8'); ?>">
                            <?php foreach ($section['keys'] as $key): ?>
                                <?php
                                $isNumeric = in_array($key, $section['numeric']);
                                if ($isNumeric) {
                                    $subtotals[$key] += isset($row[$key]) ? (is_numeric($row[$key]) ? $row[$key] : 0) : 0;
                                }
                                ?>
                                <td class="<?php echo $isNumeric ? 'num' : ''; ?>">
                                    <?php
                                    $cellValue = isset($row[$key]) ? $row[$key] : '';
                                    if (is_array($cellValue)) {
                                        $cellValue = implode(', ', $cellValue);
                                    }
                                    echo htmlspecialchars((string)$cellValue);
                                    ?>
                                </td>
                            <?php endforeach; ?>
                        </tr>
                    <?php endforeach; ?>

                    <tr class="subtotal">
                        <td>Subtotal</td>
                        <?php
                        for ($i = 1; $i < count($section['keys']); $i++):
                            $key = $section['keys'][$i];
                            $isNumeric = in_array($key, $section['numeric']);
                            ?>
                            <td class="<?php echo $isNumeric ? 'num' : ''; ?>">
                                <?php echo $isNumeric ? htmlspecialchars((string)$subtotals[$key]) : ''; ?>
                            </td>
                        <?php endfor; ?>
                    </tr>
                    </tbody>
                </table>
            </section>
        <?php endforeach; ?>

        <section class="spr-section">
            <div class="net-container">
                <div class="net-section-title">Network Base Infrastructure Configuration Profiles</div>
                <div class="net-grid">
                    <div class="net-block">
                        <h3>Zone Protection Settings</h3>
                        <table class="spr-table" style="margin: 0;">
                            <thead>
                            <tr>
                                <th>Security Target Zone</th>
                                <th>Applied Protection Profile</th>
                                <th>Security Status</th>
                                <th class="num">Drop Counter Action Triggered</th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php foreach($network_zone_protection as $zp): ?>
                                <tr>
                                    <td><strong><?php echo htmlspecialchars($zp['zone']); ?></strong></td>
                                    <td><?php echo htmlspecialchars($zp['profile']); ?></td>
                                    <td>
                                    <span class="badge <?php echo $zp['status'] === 'Protected' ? 'badge-green' : 'badge-red'; ?>">
                                        <?php echo htmlspecialchars($zp['status']); ?>
                                    </span>
                                    </td>
                                    <td class="num"><?php echo $zp['drop_count']; ?></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>

                    <div class="net-block">
                        <h3>Log Forwarding Routing Pipeline</h3>
                        <table class="spr-table" style="margin: 0;">
                            <thead>
                            <tr>
                                <th>Log Forwarding Profile Name</th>
                                <th>Target Destinations / Traps</th>
                                <th class="num">Referenced Security Rules</th>
                                <th>Deployment Status</th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php foreach($network_log_forwarding as $lf): ?>
                                <tr>
                                    <td><strong><?php echo htmlspecialchars($lf['profile_name']); ?></strong></td>
                                    <td><code><?php echo htmlspecialchars($lf['syslog_targets']); ?></code></td>
                                    <td class="num"><?php echo $lf['rules_bound']; ?></td>
                                    <td><span class="badge badge-green"><?php echo htmlspecialchars($lf['status']); ?></span></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>

                    <div class="net-block">
                        <h3>System Engine Log Settings</h3>
                        <table class="spr-table" style="margin: 0;">
                            <thead>
                            <tr>
                                <th>Log Component Class</th>
                                <th>Severity Captures</th>
                                <th>Forwarding Dest Routing Node</th>
                                <th>Operational State</th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php foreach($network_log_settings as $ls): ?>
                                <tr>
                                    <td><strong><?php echo htmlspecialchars($ls['log_type']); ?></strong></td>
                                    <td><?php echo htmlspecialchars($ls['severity_traps']); ?></td>
                                    <td><?php echo htmlspecialchars($ls['destination']); ?></td>
                                    <td><span class="badge badge-green"><?php echo htmlspecialchars($ls['status']); ?></span></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </section>

        <!-- CONTROLLER AND INTERACTIVE RENDERING ENGINE -->
        <script>
            // Serialize backend dataset globally to client-side JS DOM mapping
            const fullDeviceDatasetArray = <?php echo json_encode($bp_stats_raw); ?>;
            const activePillSectionMapping = <?php echo json_encode($pillMetaMapping); ?>;

            // Unified source of truth schema that defines the layout variations across all 3 tabs
            const detailedSectionsConfiguration = {
                'sec-av': {
                    keys: {
                        'visibility':    ['location', 'profile', 'count', 'visible', 'actions', 'inline_ml', 'actions_detail', 'inline_ml_detail'],
                        'best-practice': ['location', 'profile', 'count', 'bp_pass', 'bp_actions', 'bp_inline_ml', 'bp_actions_detail', 'bp_inline_ml_detail'],
                        'adoption':      ['location', 'profile', 'count', 'adopted']
                    },
                    headers: {
                        'visibility':    ['Location', 'Antivirus Profile Name', '# of Rules', 'Visible', 'Actions', 'Inline ML', 'Actions Check Info', 'Inline ML Check Info'],
                        'best-practice': ['Location', 'Antivirus Profile Name', '# of Rules', 'BP Pass', 'BP Actions', 'BP Inline ML', 'Actions Check Info', 'Inline ML Check Info'],
                        'adoption':      ['Location', 'Antivirus Profile Name', '# of Rules', 'Adopted']
                    },
                    numericIndices: [2, 3, 4, 5]
                },
                'sec-as': {
                    keys: {
                        'visibility':    ['location', 'profile', 'count', 'visible', 'rules', 'dns_lists', 'dns_security', 'adns_security', 'inline_ml', 'rules_detail', 'dns_lists_detail', 'dns_security_detail', 'adns_security_detail', 'inline_ml_detail'],
                        'best-practice': ['location', 'profile', 'count', 'bp_pass', 'bp_rules', 'bp_dns_lists',  'bp_dns_security', 'bp_adns_security', 'bp_inline_ml', 'bp_rules_detail', 'bp_dns_lists_detail', 'bp_dns_security_detail', 'bp_adns_security_detail', 'bp_inline_ml_detail'],
                        'adoption':      ['location', 'profile', 'count', 'adopted']
                    },
                    headers: {
                        'visibility':    ['Location', 'Anti-Spyware Profile Name', '# of Rules', 'Visible', 'Rules', 'DNS Lists', 'DNS Security', 'ADNS Security', 'Inline ML', 'Rules Check Info', 'DNS Lists Check Info', 'DNS Security Check Info', 'ADNS Security Check Info', 'Inline ML Check Info'],
                        'best-practice': ['Location', 'Anti-Spyware Profile Name', '# of Rules', 'BP Pass', 'BP Rules', 'BP DNS Lists', 'BP DNS Security', 'BP ADNS Security', 'BP Inline ML', 'Rules Check Info', 'DNS Lists Check Info', 'DNS Security Check Info', 'ADNS Security Check Info', 'Inline ML Check Info'],
                        'adoption':      ['Location', 'Anti-Spyware Profile Name', '# of Rules', 'Adopted']
                    },
                    numericIndices: [2, 3, 4, 5, 6, 7, 8]
                },
                'sec-vp': {
                    keys: {
                        'visibility':    ['location', 'profile', 'count', 'visible', 'rules', 'inline_ml', 'rules_detail', 'inline_ml_detail'],
                        'best-practice': ['location', 'profile', 'count', 'bp_pass', 'bp_rules', 'bp_inline_ml', 'bp_rules_detail', 'bp_inline_ml_detail'],
                        'adoption':      ['location', 'profile', 'count', 'adopted']
                    },
                    headers: {
                        'visibility':    ['Location', 'Vulnerability Profile Name', '# of Rules', 'Visible', 'Rules', 'Inline ML', 'Rules Check Info', 'Inline ML Check Info'],
                        'best-practice': ['Location', 'Vulnerability Profile Name', '# of Rules', 'BP Pass', 'BP Rules', 'BP Inline ML', 'Rules Check Info', 'Inline ML Check Info'],
                        'adoption':      ['Location', 'Vulnerability Profile Name', '# of Rules', 'Adopted']
                    },
                    numericIndices: [2, 3, 4, 5]
                },
                'sec-url': {
                    keys: {
                        'visibility':    ['location', 'profile', 'count', 'visible', 'site_access', 'user_credential', 'inline_ml', 'site_access_detail', 'user_credential_detail', 'inline_ml_detail'],
                        'best-practice': ['location', 'profile', 'count', 'bp_pass', 'bp_site_access', 'bp_user_credential', 'bp_inline_ml', 'bp_site_access_detail', 'bp_user_credential_detail', 'bp_inline_ml_detail'],
                        'adoption':      ['location', 'profile', 'count', 'adopted']
                    },
                    headers: {
                        'visibility':    ['Location', 'URL Filtering Profile Name', '# of Rules', 'Visible', 'Site Access', 'User Credential Submission', 'InlineML', 'Site Access Check Info', 'User Credential Check Info', 'Inline ML Check Info'],
                        'best-practice': ['Location', 'URL Filtering Profile Name', '# of Rules', 'BP Pass', 'BP Site Access', 'BP User Credential', 'BP InlineML', 'Site Access Check Info', 'User Credential Check Info', 'Inline ML Check Info'],
                        'adoption':      ['Location', 'URL Filtering Profile Name', '# of Rules', 'Adopted']
                    },
                    numericIndices: [2, 3, 4, 5, 6]
                },
                'sec-fb': {
                    keys: {
                        'visibility':    ['location', 'profile', 'count', 'visible', 'rules', 'rules_detail'],
                        'best-practice': ['location', 'profile', 'count', 'bp_pass', 'bp_rules', 'bp_rules_detail'],
                        'adoption':      ['location', 'profile', 'count', 'adopted']
                    },
                    headers: {
                        'visibility':    ['Location', 'File Blocking Profile Name', '# of Rules', 'Visible', 'Rules', 'Rules Check Info'],
                        'best-practice': ['Location', 'File Blocking Profile Name', '# of Rules', 'BP Pass', 'BP Rules', 'Rules Check Info'],
                        'adoption':      ['Location', 'File Blocking Profile Name', '# of Rules', 'Adopted']
                    },
                    numericIndices: [2, 3, 4]
                },
                'sec-wf': {
                    keys: {
                        'visibility':    ['location', 'profile', 'count', 'visible', 'rules', 'inline_ml', 'rules_detail', 'inline_ml_detail'],
                        'best-practice': ['location', 'profile', 'count', 'bp_pass', 'bp_rules', 'bp_inline_ml', 'bp_rules_detail', 'bp_inline_ml_detail'],
                        'adoption':      ['location', 'profile', 'count', 'adopted']
                    },
                    headers: {
                        'visibility':    ['Location', 'WildFire Analysis Profile Name', '# of Rules', 'Visible', 'Rules', 'Inline ML', 'Rules Check Info', 'Inline ML Check Info'],
                        'best-practice': ['Location', 'WildFire Analysis Profile Name', '# of Rules', 'BP Pass', 'BP Rules', 'BP Inline ML', 'Rules Check Info', 'Inline ML Check Info'],
                        'adoption':      ['Location', 'WildFire Analysis Profile Name', '# of Rules', 'Adopted']
                    },
                    numericIndices: [2, 3, 4, 5]
                },
                'sec-avwf': {
                    keys: {
                        'visibility':    ['location', 'profile', 'count', 'visible', 'rules', 'inline_ml', 'rules_detail', 'inline_ml_detail'],
                        'best-practice': ['location', 'profile', 'count', 'bp_pass', 'bp_rules', 'bp_inline_ml', 'bp_rules_detail', 'bp_inline_ml_detail'],
                        'adoption':      ['location', 'profile', 'count', 'adopted']
                    },
                    headers: {
                        'visibility':    ['Location', 'VirusAndWildFire Profile Name', '# of Rules', 'Visible', 'Rules', 'Inline ML', 'Rules Check Info', 'Inline ML Check Info'],
                        'best-practice': ['Location', 'VirusAndWildFire Profile Name', '# of Rules', 'BP Pass', 'BP Rules', 'BP Inline ML', 'Rules Check Info', 'Inline ML Check Info'],
                        'adoption':      ['Location', 'VirusAndWildFire Profile Name', '# of Rules', 'Adopted']
                    },
                    numericIndices: [2, 3, 4, 5]
                },
                'sec-dnssec': {
                    keys: {
                        'visibility':    ['location', 'profile', 'count', 'visible', 'rules', 'rules_detail'],
                        'best-practice': ['location', 'profile', 'count', 'bp_pass', 'bp_rules', 'bp_rules_detail'],
                        'adoption':      ['location', 'profile', 'count', 'adopted']
                    },
                    headers: {
                        'visibility':    ['Location', 'DNSSecurity Profile Name', '# of Rules', 'Visible', 'Rules', 'Rules Check Info'],
                        'best-practice': ['Location', 'DNSSecurity Profile Name', '# of Rules', 'BP Pass', 'BP Rules', 'Rules Check Info'],
                        'adoption':      ['Location', 'DNSSecurity Profile Name', '# of Rules', 'Adopted']
                    },
                    numericIndices: [2, 3, 4]
                }
            };

            // Global engine operational states
            let currentSelectedIndex = 0;
            let currentActiveTab = 'visibility';

            // Tab triggering controller execution entry point
            function switchMetricsTab(tabId, element) {
                const buttons = document.querySelectorAll('.spr-tab-btn');
                buttons.forEach(btn => btn.classList.remove('active'));
                element.classList.add('active');

                currentActiveTab = tabId;

                // 1. Refresh Dynamic Overview layout
                renderMetricsTable();

                // 2. Loop across layout blocks to dynamically mutate tables structure on click
                renderDetailedSectionsLayouts();

                // 3. Trigger context mutations across summary capsule pill fields
                updatePillMatrices();
            }

            /**
             * Iterates over every security profile table block lower down the page,
             * morphing headers, column definitions, and values based on the selected tab state.
             */
            function renderDetailedSectionsLayouts() {
                const activeTab = currentActiveTab;

                for (const sectionId in detailedSectionsConfiguration) {
                    if (!detailedSectionsConfiguration.hasOwnProperty(sectionId)) continue;

                    const config = detailedSectionsConfiguration[sectionId];
                    const sectionEl = document.getElementById(sectionId);
                    if (!sectionEl) continue;

                    const targetKeys = config.keys[activeTab];
                    const targetHeaders = config.headers[activeTab];

                    if (!targetKeys || !targetHeaders) continue;

                    // --- STEP A: REWRITE THE THEAD HEADERS ---
                    const theadRow = sectionEl.querySelector('table thead tr');
                    if (theadRow) {
                        theadRow.innerHTML = '';
                        targetHeaders.forEach((headerText, index) => {
                            const isNumeric = config.numericIndices.includes(index);
                            const th = document.createElement('th');
                            if (isNumeric) th.classList.add('num');
                            th.textContent = headerText;
                            theadRow.appendChild(th);
                        });
                    }

                    // --- STEP B: DYNAMICALLY RE-RENDER TABLE VALUES FROM SEED DATA RETAINING FILTERS ---
                    const selectorEl = document.getElementById('deviceSelector');
                    const selectedLabel = selectorEl ? selectorEl.options[selectorEl.selectedIndex].text.trim() : '';
                    const isFullDevice = (selectedLabel === 'FullDevice');

                    const tableRows = sectionEl.querySelectorAll('table tbody tr:not(.subtotal)');
                    let subtotalAggregates = {};

                    tableRows.forEach(row => {
                        // Retrieve full raw data row structure injected dynamically via data-row-json property
                        const rawDataAttr = row.getAttribute('data-row-json');
                        if (!rawDataAttr) return;

                        const rowData = JSON.parse(rawDataAttr);
                        const rowLocation = rowData['location'] || 'N/A';

                        // Verify display properties visibility status based on active dropdown selector filter
                        const shouldShow = isFullDevice || (rowLocation === selectedLabel);

                        if (shouldShow) {
                            row.style.display = '';
                            row.innerHTML = ''; // Strip column tokens inside row tree

                            targetKeys.forEach((key, index) => {
                                const td = document.createElement('td');
                                const isNumeric = config.numericIndices.includes(index);
                                if (isNumeric) td.classList.add('num');

                                let cellValue = rowData[key] !== undefined ? rowData[key] : '';
                                if (Array.isArray(cellValue)) {
                                    cellValue = cellValue.implode ? cellValue.implode(', ') : cellValue.join(', ');
                                }

                                // Structural cell injection block
                                if (index === 0 || index === 1) {
                                    td.innerHTML = `<strong>${escapeHtml(cellValue)}</strong>`;
                                } else {
                                    td.textContent = cellValue;
                                }

                                // Add running totals to tracking objects matrix
                                if (isNumeric) {
                                    const parsedVal = parseFloat(cellValue) || 0;
                                    subtotalAggregates[index] = (subtotalAggregates[index] || 0) + parsedVal;
                                }

                                row.appendChild(td);
                            });
                        } else {
                            row.style.display = 'none';
                        }
                    });

                    // --- STEP C: RE-COMPUTE THE SUBTOTAL FOR THE SECTION ---
                    const subtotalRow = sectionEl.querySelector('tr.subtotal');
                    if (subtotalRow) {
                        subtotalRow.innerHTML = '';
                        const firstTd = document.createElement('td');
                        firstTd.textContent = 'Subtotal';
                        subtotalRow.appendChild(firstTd);

                        for (let i = 1; i < targetKeys.length; i++) {
                            const td = document.createElement('td');
                            const isNumeric = config.numericIndices.includes(i);
                            if (isNumeric) {
                                td.classList.add('num');
                                td.textContent = subtotalAggregates[i] || 0;
                            } else {
                                td.textContent = '';
                            }
                            subtotalRow.appendChild(td);
                        }
                    }
                }
            }

            /**
             * Dynamic calculation routine that updates unified pill layouts (combining % and count)
             * relative to the active target compliance tab on the fly.
             *
             * For 'adoption', it isolates and displays ONLY the core section/profile adoption info.
             */
            function updatePillMatrices() {
                const dataset = fullDeviceDatasetArray[currentSelectedIndex];
                if (!dataset) return;

                // Map the active UI tab directly to the nomenclature string used in your array keys
                let activeTabString = 'visibility';
                let displayLabelPrefix = 'Visibility';

                if (currentActiveTab === 'best-practice') {
                    activeTabString = 'best-practice';
                    displayLabelPrefix = 'Best-Practice';
                } else if (currentActiveTab === 'adoption') {
                    activeTabString = 'adoption';
                    displayLabelPrefix = 'Adoption';
                }

                for (const sectionId in activePillSectionMapping) {
                    if (!activePillSectionMapping.hasOwnProperty(sectionId)) continue;

                    const labelsConfig = activePillSectionMapping[sectionId];
                    for (const rawLabelName in labelsConfig) {
                        if (!labelsConfig.hasOwnProperty(rawLabelName)) continue;

                        const elementSlug = rawLabelName.toLowerCase().replace(/[^a-z0-9-]+/g, '-');
                        const pillDOMElement = document.getElementById(`pill-label-${sectionId}-${elementSlug}`)?.closest('.spr-pill');

                        // --- ADOPTION TAB FILTER CRITERIA ---
                        // If the active tab is adoption, we only want the main row profile metric.
                        // We hide any pill that represents a sub-component (like rules, inline ml, actions, dns, etc.)
                        if (currentActiveTab === 'adoption' && rawLabelName !== 'visibility' && rawLabelName !== 'site access visibility') {
                            if (pillDOMElement) {
                                pillDOMElement.style.display = 'none';
                            }
                            continue;
                        } else if (pillDOMElement) {
                            pillDOMElement.style.display = ''; // Restore visibility for other tabs
                        }

                        // baseKey is exactly what comes from your mapping config (e.g., "adns-security visibility")
                        const baseKey = labelsConfig[rawLabelName];

                        // 1. Direct Swap Strategy: Replace the literal word "visibility" with the active tab string
                        const targetBaseKey = baseKey.replace('visibility', activeTabString);

                        // 2. Append the exact calculation modifiers your backend expects
                        const percentageKey = `${targetBaseKey} percentage`;
                        const countKey = `${targetBaseKey} calc`;

                        // 3. Clean up UI Label text inside the HTML spans nicely
                        let cleanLabelBody = rawLabelName
                            .replace('visibility', '')
                            .replace('site access', 'Site Access')
                            .replace('credential', 'Credential')
                            .replace('mica-engine', 'Inline ML')
                            .replace('dns-list', 'DNS List')
                            .replace('adns-security', 'Advanced DNS Security')
                            .replace('dns-security', 'DNS Security')
                            .trim();

                        if (cleanLabelBody) {
                            cleanLabelBody = cleanLabelBody.split(' ').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
                        }
                        const finalLabelText = cleanLabelBody ? ` — ${cleanLabelBody}` : '';

                        // 4. Update the Unified Title Label Text
                        const labelElement = document.getElementById(`pill-label-${sectionId}-${elementSlug}`);
                        if (labelElement) {
                            labelElement.textContent = `${displayLabelPrefix}${finalLabelText}`;
                        }

                        // 5. Update Percentage Value Metric
                        const pctElement = document.getElementById(`pill-pct-${sectionId}-${elementSlug}`);
                        if (pctElement) {
                            const pctValue = dataset[percentageKey];
                            pctElement.textContent = pctValue !== undefined ? (isNaN(pctValue) ? pctValue : pctValue + '%') : '0%';
                        }

                        // 6. Update Fractional Count Metric
                        const countElement = document.getElementById(`pill-count-${sectionId}-${elementSlug}`);
                        if (countElement) {
                            countElement.textContent = dataset[countKey] !== undefined ? dataset[countKey] : '0/23';
                        }
                    }
                }
            }

            // Dropdown routing index logic
            function changeActiveDeviceContext(targetIndex) {
                currentSelectedIndex = parseInt(targetIndex);
                const dataset = fullDeviceDatasetArray[currentSelectedIndex];
                if (!dataset) return;

                // 1. Refresh Dynamic Right Panel Global Scope Figures
                updateDOMTextContent('scope-total', formatNumberWithCommas(dataset['security rules'] ?? 0));
                updateDOMTextContent('scope-allow', formatNumberWithCommas(dataset['security rules allow'] ?? 0));
                updateDOMTextContent('scope-allow-enabled', formatNumberWithCommas(dataset['security rules allow enabled'] ?? 0));
                updateDOMTextContent('scope-allow-disabled', formatNumberWithCommas(dataset['security rules allow disabled'] ?? 0));
                updateDOMTextContent('scope-enabled', formatNumberWithCommas(dataset['security rules enabled'] ?? 0));

                // 2. Render Left Panel Table Context Framework based on newly selected device item
                renderMetricsTable();

                // 3. Trigger dynamic pill layout and text calculation updates
                updatePillMatrices();

                // 4. Trigger dynamic table redraw to filter rows by newly selected Location mapping
                renderDetailedSectionsLayouts();
            }

            // Core table rendering manager method parsing the 3-tab layout variations
            function renderMetricsTable() {
                const dataset = fullDeviceDatasetArray[currentSelectedIndex];
                const tbody = document.getElementById('overview-metrics-tbody');
                if (!dataset || !tbody) return;

                tbody.innerHTML = '';

                // Ensure the table header has our new 5th column header title
                const theadRow = document.querySelector('.spr-header-panel table thead tr');
                if (theadRow && theadRow.cells.length === 4) {
                    const th = document.createElement('th');
                    th.classList.add('num');
                    th.style.width = '120px';
                    th.textContent = 'Rule Calculation';
                    theadRow.appendChild(th);
                }

                // Isolate the correct active subset loop array context
                let targetedSubSet = {};
                if (dataset['percentage'] && dataset['percentage'][currentActiveTab]) {
                    targetedSubSet = dataset['percentage'][currentActiveTab];
                }

                for (const displayName in targetedSubSet) {
                    if (!targetedSubSet.hasOwnProperty(displayName)) continue;

                    const matchedData = targetedSubSet[displayName];
                    let pctValue = 0;
                    let groupName = 'Security Profiles';

                    if (matchedData !== null && typeof matchedData === 'object') {
                        pctValue = matchedData['value'] ?? 0;
                        groupName = matchedData['group'] ?? groupName;
                    } else {
                        pctValue = matchedData || 0;
                    }

                    let explicitCalculationValue = 'N/A';

                    // --- 1. HARD FORCED INTERCEPT FOR STATIC KEYS ---
                    if (displayName === 'App-ID' || displayName === 'User-ID' || displayName === 'Service/Port') {
                        let staticKey = 'service port';
                        if (displayName === 'App-ID') staticKey = 'app id';
                        if (displayName === 'User-ID') staticKey = 'user id';

                        const totalRules = dataset[staticKey] || dataset[staticKey.toUpperCase()] || 0;
                        const matchingRules = Math.round((pctValue / 100) * totalRules);

                        explicitCalculationValue = `${matchingRules}/${totalRules}`;
                    } else {
                        // --- 2. DYNAMIC GENERATION FOR STANDARD TABBED PROFILES ---
                        let baseKey = displayName.toLowerCase()
                            .replace('wildfire analysis ', 'wf ')
                            .replace('antivirus ', 'av ')
                            .replace('anti-spyware ', 'as ')
                            .replace('vulnerability ', 'vp ')
                            .replace('file blocking ', 'fb ')
                            .replace('data filtering', 'data')
                            .replace('url filtering profiles', 'url-site-access')
                            .replace('credential theft prevention', 'url-credential')
                            .replace('url inline ml', 'url-mica-engine')
                            .replace('inline ml', 'mica-engine')
                            .replace('dns list', 'dns-list')          // Exact array key fix
                            .replace('dns security', 'dns-security')  // Exact array key fix
                            .replace('advanced dns security', 'adns-security')
                            .replace('profiles', '')
                            .replace('/', ' ')
                            .trim();

                        if (baseKey === 'logging') baseKey = 'log at end';
                        if (baseKey === 'log forwarding') baseKey = 'log prof set';

                        if (`${baseKey} calc` in dataset) {
                            // Flat and tabless (e.g., 'zone protection calc')
                            explicitCalculationValue = dataset[`${baseKey} calc`];
                        } else if (baseKey.startsWith('wf ') || baseKey.startsWith('av ') || baseKey.startsWith('as ') || baseKey.startsWith('vp ')) {
                            // Multi-word profiles (e.g., 'wf visibility rules calc')
                            const keyParts = baseKey.split(' ');
                            const calcLookupKey = `${keyParts[0]} ${currentActiveTab} ${keyParts.slice(1).join(' ')} calc`;
                            explicitCalculationValue = dataset[calcLookupKey] || 'N/A';
                        } else {
                            // Standard tabbed format (e.g., 'fb visibility calc', 'dns-list visibility calc')
                            const calcLookupKey = `${baseKey} ${currentActiveTab} calc`;
                            explicitCalculationValue = dataset[calcLookupKey] || 'N/A';
                        }
                    }

                    let barStatusClass = '';
                    if (parseInt(pctValue) === 0) barStatusClass = 'critical';
                    else if (parseInt(pctValue) < 70) barStatusClass = 'low';

                    const row = document.createElement('tr');

                    row.innerHTML = `
                        <td style="color: var(--muted); font-size: 12px; font-weight: 500;">${escapeHtml(groupName)}</td>
                        <td><strong>${escapeHtml(displayName)}</strong></td>
                        <td class="num"><strong>${pctValue}%</strong></td>
                        <td style="white-space: normal; width: 180px;">
                            <div class="progress-container">
                                <div class="progress-bar"></div>
                            </div>
                        </td>
                        <td class="num" style="font-weight: 600; font-variant-numeric: tabular-nums; color: #0f172a; font-size: 13px;">
                            ${escapeHtml(explicitCalculationValue)}
                        </td>
                    `;

                    const progressBar = row.querySelector('.progress-bar');
                    if (progressBar) {
                        progressBar.style.width = pctValue + '%';
                        if (barStatusClass) progressBar.classList.add(barStatusClass);
                    }

                    tbody.appendChild(row);
                }
            }

            function updateDOMTextContent(elementId, clearTextString) {
                const elementRef = document.getElementById(elementId);
                if (elementRef) elementRef.textContent = clearTextString;
            }

            function formatNumberWithCommas(rawNum) {
                return Number(rawNum).toLocaleString('en-US');
            }

            function escapeHtml(str) {
                return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
            }

            // Run initial bootstrap on screen compile initialization load context execution sequence
            window.addEventListener('DOMContentLoaded', () => {
                const selectorEl = document.getElementById('deviceSelector');
                if (selectorEl) {
                    currentSelectedIndex = parseInt(selectorEl.value) || 0;
                }
                renderMetricsTable();
                updatePillMatrices();
                renderDetailedSectionsLayouts();
            });
        </script>

        </body>
        </html>
        <?php

        file_put_contents($filename, ob_get_clean());

        return TRUE;
    },
    'args' => array(
        'filename' => array('type' => 'string', 'default' => '*nodefault*')
    )
);

SecurityProfileCallContext::$supportedActions[] = array(
    'name' => 'exportSPtoHTML_new',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (SecurityProfileCallContext $context) {
        $context->objectList = array();
        $context->first = true;
    },
    'GlobalFinishFunction' => function (SecurityProfileCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        $isSCM = false;

        if( isset( $_SERVER['REQUEST_METHOD'] ) ) {
            $filename = "project/html/".$filename;
        }

        // 1. Report Configuration & Meta Information
        $reportTitle = "Security Profile — Visibility & Feature Coverage";
        $sourceMeta  = "configs/sp_html/reports";

        $matchedRulesCount = 0;
        // Security Rules Scope Data Configuration
        $securityRulesScope = [
            'total'          => 0,
            'allow'          => 0,
            'allow_enabled'  => 0,
            'allow_disabled' => 0,
            'enabled'        => 0
        ];

        if( $context->first )
        {
            $ruleFilter = "(action is.allow) and (rule is.enabled)";
            $f = SecurityProfileCallContext::$commonActionFunctions['SPR-filter']['MainFunction'];
            $matchedRulesCount = $f($context, $ruleFilter);

            $av_blank = $f($context, $ruleFilter." and !(secprof av-profile.is.set)");
            $as_blank = $f($context, $ruleFilter." and !(secprof as-profile.is.set)");
            $vp_blank = $f($context, $ruleFilter." and !(secprof vuln-profile.is.set)");
            $url_blank = $f($context, $ruleFilter." and !(secprof url-profile.is.set)");
            $fb_blank = $f($context, $ruleFilter." and !(secprof file-profile.is.set)");
            $wf_blank = $f($context, $ruleFilter." and !(secprof wf-profile.is.set)");

            // SCM related
            $avwf_blank = $f($context, $ruleFilter." and !(secprof avwf-profile.is.set)");
            $dnssec_blank = $f($context, $ruleFilter." and !(secprof dnssec-profile.is.set)");

            $f = SecurityProfileCallContext::$commonActionFunctions['bp-stats']['MainFunction'];
            $bp_stats_array = $f($context, true );

            // Persist summary metadata arrays inside context object state
            $bp_stats_raw   = $bp_stats_array;

            $securityRulesScope['total'] = $bp_stats_raw[0]['security rules'];
            $securityRulesScope['allow'] = $bp_stats_raw[0]['security rules allow'];
            $securityRulesScope['allow_enabled'] = $bp_stats_raw[0]['security rules allow enabled'];
            $securityRulesScope['allow_disabled'] = $bp_stats_raw[0]['security rules allow disabled'];
            $securityRulesScope['enabled'] = $bp_stats_raw[0]['security rules enabled'];

            $context->first = false;
        }

        // 2. Section Map Definitions matching custom requested column fields
        $sections = [
            'sec-av' => [
                'title'    => 'AV — Antivirus Profiles',
                'headers'  => ['Location', 'Antivirus Profile Name', '# of Rules', 'Visible', 'Actions', 'Inline ML', 'Actions Check Info', 'Inline ML Check Info'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'actions', 'inline_ml', 'actions_detail', 'inline_ml_detail'],
                'numeric'  => ['count', 'visible', 'actions', 'inline_ml'],
                'rows'     => []
            ],
            'sec-as' => [
                'title'    => 'AS — Anti-Spyware Profiles',
                'headers'  => ['Location', 'Anti-Spyware Profile Name', '# of Rules', 'Visible', 'Rules', 'DNS Lists', 'DNS Security', 'Inline ML', 'Rules Check Info', 'DNS Lists Check Info', 'DNS Security Check Info', 'Inline ML Check Info'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'rules', 'dns_lists', 'dns_security', 'inline_ml', 'rules_detail', 'dns_lists_detail', 'dns_security_detail', 'inline_ml_detail'],
                'numeric'  => ['count', 'visible', 'rules', 'dns_lists', 'dns_security', 'adns_security', 'inline_ml'],
                'rows'     => []
            ],
            'sec-vp' => [
                'title'    => 'VP — Vulnerability Profiles',
                'headers'  => ['Location', 'Vulnerability Profile Name', '# of Rules', 'Visible', 'Rules', 'Inline ML', 'Rules Check Info', 'Inline ML Check Info'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'rules', 'inline_ml', 'rules_detail', 'inline_ml_detail'],
                'numeric'  => ['count', 'visible', 'rules', 'inline_ml'],
                'rows'     => []
            ],
            'sec-url' => [
                'title'    => 'URL — URL Filtering Profiles',
                'headers'  => ['Location', 'URL Filtering Profile Name', '# of Rules', 'Visible', 'Site Access', 'User Credential Submission', 'InlineML', 'Site Access Check Info', 'User Credential Check Info', 'Inline ML Check Info'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'site_access', 'user_credential', 'inline_ml', 'site_access_detail', 'user_credential_detail', 'inline_ml_detail'],
                'numeric'  => ['count', 'visible', 'site_access', 'user_credential', 'inline_ml'],
                'rows'     => []
            ],
            'sec-fb' => [
                'title'    => 'FB — File Blocking Profiles',
                'headers'  => ['Location', 'File Blocking Profile Name', '# of Rules', 'Visible', 'Rules', 'Rules Check Info'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'rules', 'rules_detail'],
                'numeric'  => ['count', 'visible', 'rules'],
                'rows'     => []
            ],
            'sec-wf' => [
                'title'    => 'WF — WildFire Analysis Profiles',
                'headers'  => ['Location', 'WildFire Analysis Profile Name', '# of Rules', 'Visible', 'Rules', 'Inline ML', 'Rules Check Info', 'Inline ML Check Info'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'rules', 'inline_ml', 'rules_detail', 'inline_ml_detail'],
                'numeric'  => ['count', 'visible', 'rules', 'inline_ml'],
                'rows'     => []
            ],
        ];

        if( $context->subSystem->isBuckbeak()
            || $context->subSystem->isFawkes()
            || $context->subSystem->isContainer()
            || $context->subSystem->isDeviceCloud()
            || $context->subSystem->isDeviceOnPrem()
            || $context->subSystem->isSnippet()
        )
        {
            $isSCM = true;
            $sections['sec-avwf'] = array(
                'title'    => 'AVWF — VirusAndWildFire Profiles',
                'headers'  => ['Location', 'VirusAndWildFire Profile Name', '# of Rules', 'Visible', 'Rules', 'Inline ML', 'Rules Check Info', 'Inline ML Check Info'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'rules', 'inline_ml', 'rules_detail', 'inline_ml_detail'],
                'numeric'  => ['count', 'visible', 'rules', 'inline_ml'],
                'rows'     => array()
            );
            $sections['sec-dnssec'] = array(
                'title'    => 'DNSSec — DNSSecurity Profiles',
                'headers'  => ['Location', 'DNSSecurity Profile Name', '# of Rules', 'Visible', 'Rules', 'Rules Check Info'],
                'keys'     => ['location', 'profile', 'count', 'visible', 'rules', 'rules_detail'],
                'numeric'  => ['count', 'visible', 'rules'],
                'rows'     => array()
            );
            unset( $sections['sec-av'] );
            unset( $sections['sec-wf'] );
        }

        // --- MAP PILL LABELS TO FLAT ARRAY SUB-STRINGS ---
        // Left intact to retain raw configuration metrics references perfectly while providing tab mutation capabilities
        $pillMetaMapping = [
            'sec-av' => [
                'visibility'             => 'av visibility',
                'visibility actions'     => 'av visibility actions',
                'visibility mica-engine' => 'av visibility mica-engine'
            ],
            'sec-as' => [
                'visibility'              => 'as visibility',
                'visibility rules'        => 'as visibility rules',
                'dns-list visibility'     => 'dns-list visibility',
                'dns-security visibility' => 'dns-security visibility',
                'adns-security visibility'=> 'adns-security visibility',
                'visibility mica-engine'  => 'as visibility mica-engine'
            ],
            'sec-vp' => [
                'visibility'             => 'vp visibility',
                'visibility rules'       => 'vp visibility rules',
                'visibility mica-engine' => 'vp visibility mica-engine'
            ],
            'sec-url' => [
                'site access visibility' => 'url-site-access visibility',
                'credential visibility'  => 'url-credential visibility',
                'visibility mica-engine' => 'url-mica-engine visibility'
            ],
            'sec-fb' => [
                'visibility'       => 'fb visibility'
            ],
            'sec-wf' => [
                'visibility'             => 'wf visibility',
                'visibility rules'       => 'wf visibility rules',
                'visibility mica-engine' => 'wf visibility mica-engine'
            ],
            'sec-avwf' => [
                'visibility'             => 'avwf visibility',
                'visibility rules'       => 'avwf visibility rules',
                'visibility mica-engine' => 'avwf visibility mica-engine'
            ],
            'sec-dnssec' => [
                'visibility'       => 'dnssec visibility',
                'visibility rules' => 'dnssec visibility rules'
            ]
        ];

        // 3. Populate Data & Placeholders
        foreach( $context->objectList as $object )
        {
            /** @var AntiVirusProfile|AntiSpywareProfile|VulnerabilityProfile|WildfireProfile|VirusAndWildfireProfile|DNSSecurityProfile|DataFilteringProfile|URLProfile $object */

            if( get_class($object) == "customURLProfile"
                || get_class( $object ) == "PredefinedSecurityProfileURL"
                || get_class( $object ) == "predefined-url"
                || get_class( $object ) == "predefined-url-filtering"
                || get_class( $object ) == "predefined-virus"
                || get_class( $object ) == "predefined-spyware"
                || get_class( $object ) == "predefined-file-blocking"
                || get_class( $object ) == "predefined-vulnerability"
                || get_class( $object ) == "predefined-wildfire-analysis"
            )
                continue;

            $info = array();
            if($object->owner->owner->name() == "")
                $info['location'] = "shared";
            else
                $info['location'] = $object->owner->owner->name();
            $info['profile'] = $object->name();

            $info['count'] = 0;
            foreach( $object->refrules as $rule )
            {
                /** @var SecurityRule|SecurityProfileGroup $rule */
                if( get_class($rule) == "SecurityRule" )
                {
                    if( $rule->isEnabled() && $rule->actionIsAllow() )
                        $info['count']++;
                }
                elseif( get_class($rule) == "SecurityProfileGroup" )
                {
                    foreach( $rule->refrules as $rule2 )
                    {
                        if( get_class($rule2) == "SecurityRule" )
                        {
                            if( $rule2->isEnabled() && $rule2->actionIsAllow() )
                                $info['count']++;
                        }
                    }
                }
            }

            if( $object->is_visibility() )
                $info['visible'] = $info['count'];
            else
                $info['visible'] = 0;

            if( $object->is_best_practice() )
                $info['bp_pass'] = $info['count'];
            else
                $info['bp_pass'] = 0;

            if( $object->is_adoption() )
                $info['adopted'] = $info['count'];
            else
                $info['adopted'] = 0;

            // --- EXTENDED PARAMETERS ---
            $info['actions']                  = 0;
            $info['inline_ml']                = 0;
            $info['actions_detail']             = 'Compliant';
            $info['inline_ml_detail']             = 'Compliant';
            $info['bp_actions']                  = 0;
            $info['bp_inline_ml']                = 0;
            $info['bp_actions_detail']             = 'BP Compliant';
            $info['bp_inline_ml_detail']             = 'BP Compliant';
            if( get_class($object) == "AntiVirusProfile" )
            {
                if( $object->av_actions_visibility() )
                    $info['actions'] = $info['count'];
                else
                    $info['actions_detail'] = '[Placeholder: visible Actions Detail Text]';

                if( $object->av_actions_best_practice() )
                    $info['bp_actions'] = $info['count'];
                else
                    $info['bp_actions_detail'] = '[Placeholder: BP Actions Detail Text]';
            }
            if( get_class($object) == "AntiVirusProfile"
                || get_class($object) == "AntiSpywareProfile"
                || get_class($object) == "VulnerabilityProfile"
                || get_class($object) == "WildfireProfile"
            )
            {
                if( $object->cloud_inline_analysis_visibility($object->owner->bp_json_file) )
                {
                    $info['inline_ml'] = $info['count'];
                }
                else
                {
                    $notVisibleElements         = $object->build_cloud_inline_comprehensive_array($object->owner->bp_json_file)['all'];
                    $notVisibleElements         = $object->build_cloud_inline_comprehensive_array($object->owner->bp_json_file)['not visible'];
                    $info['inline_ml_detail'] = is_array($notVisibleElements) ? implode("\n", $notVisibleElements) : $notVisibleElements;
                    #$info['inline_ml_detail']             = '[Placeholder: In-Line Details]';
                }

                if( $object->cloud_inline_analysis_best_practice($object->owner->bp_json_file) )
                {
                    $info['bp_inline_ml'] = $info['count'];
                }
                else
                {
                    $notVisibleElements         = $object->build_cloud_inline_comprehensive_array($object->owner->bp_json_file)['all'];
                    #$notVisibleElements         = $object->build_cloud_inline_comprehensive_array($object->owner->bp_json_file)['no bp'];
                    $info['bp_inline_ml_detail'] = is_array($notVisibleElements) ? implode("\n", $notVisibleElements) : $notVisibleElements;
                    #$info['bp_inline_ml_detail']             = '[Placeholder: bp In-Line Details]';
                }
            }

            $info['rules']                    = 0;
            $info['rules_detail']             = 'Compliant';
            $info['bp_rules']                    = 0;
            $info['bp_rules_detail']             = 'BP Compliant';
            if( get_class($object) == "AntiSpywareProfile" )
            {
                if(  $object->spyware_rules_visibility() )
                    $info['rules'] = $info['count'];
                else
                    $info['rules_detail']             = '[Placeholder: visible Rules Visibility Details]';

                if(  $object->spyware_rules_best_practice() )
                    $info['bp_rules'] = $info['count'];
                else
                    $info['bp_rules_detail']             = '[Placeholder: bp Rules Visibility Details]';
            }

            if( get_class($object) == "VulnerabilityProfile" )
            {
                if( $object->vulnerability_rules_visibility() )
                    $info['rules'] = $info['count'];
                else
                    $info['rules_detail']             = '[Placeholder: visible Rules Visibility Details]';

                if(  $object->vulnerability_rules_best_practice() )
                    $info['bp_rules'] = $info['count'];
                else
                    $info['bp_rules_detail']             = '[Placeholder: bp Rules Visibility Details]';
            }

            if( get_class($object) == "WildfireProfile" )
            {
                if( $object->wildfire_rules_visibility() )
                    $info['rules'] = $info['count'];
                else
                    $info['rules_detail']             = '[Placeholder: visible Rules Visibility Details]';

                if(  $object->wildfire_rules_best_practice() )
                    $info['bp_rules'] = $info['count'];
                else
                    $info['bp_rules_detail']             = '[Placeholder: bp Rules Visibility Details]';
            }

            $info['dns_lists']                = 0;
            $info['dns_security']             = 0;
            $info['dns_lists_detail']             = 'Compliant';
            $info['dns_security_detail']             = 'Compliant';
            $info['bp_dns_lists']                = 0;
            $info['bp_dns_security']             = 0;
            $info['bp_dns_lists_detail']             = 'BP Compliant';
            $info['bp_dns_security_detail']             = 'BP Compliant';
            $info['adns_security']             = 0;
            $info['adns_security_detail']             = 'Compliant';
            $info['bp_adns_security']             = 0;
            $info['bp_adns_security_detail']             = 'BP Compliant';
            if( get_class($object) == "AntiSpywareProfile" )
            {
                if( $object->spyware_dnslist_visibility() )
                    $info['dns_lists'] = $info['count'];
                else
                    $info['dns_lists_detail']         = '[Placeholder: visible DNS Lists Details]';

                if( $object->spyware_dnslist_best_practice() )
                    $info['bp_dns_lists'] = $info['count'];
                else
                    $info['bp_dns_lists_detail']         = '[Placeholder: bp DNS Lists Details]';
            }

            if( get_class($object) == "AntiSpywareProfile" )
            {
                if( $object->spyware_dns_security_visibility() )
                    $info['dns_security'] = $info['count'];
                else
                    $info['dns_security_detail']      = '[Placeholder: DNS Security Details]';

                if( $object->spyware_dns_security_best_practice() )
                    $info['bp_dns_security'] = $info['count'];
                else
                    $info['bp_dns_security_detail']      = '[Placeholder: BP DNS Security Details]';

                if( $object->spyware_advanced_dns_security_visibility() )
                    $info['adns_security'] = $info['count'];
                else
                    $info['adns_security_detail']      = '[Placeholder: DNS Security Details]';

                if( $object->spyware_advanced_dns_security_best_practice() )
                    $info['bp_adns_security'] = $info['count'];
                else
                    $info['bp_adns_security_detail']      = '[Placeholder: BP ADNS Security Details]';
            }

            $info['site_access'] = 0;
            $info['user_credential'] = 0;
            $info['user_credential_tab'] = 0;
            $info['bp_site_access'] = 0;
            $info['bp_user_credential'] = 0;
            $info['bp_user_credential_tab'] = 0;
            if( get_class($object) == "URLProfile" && $object->url_siteaccess_visibility())
                $info['site_access'] = $info['count'];

            if( get_class($object) == "URLProfile" && $object->url_usercredentialsubmission_visibility() )
                $info['user_credential'] = $info['count'];

            if( get_class($object) == "URLProfile" && $object->url_usercredentialsubmission_visibility_tab())
                $info['user_credential_tab'] = $info['count'];

            if( get_class($object) == "URLProfile" && $object->url_mica_engine_visibility())
                $info['inline_ml'] = $info['count'];

            if( get_class($object) == "URLProfile" && $object->url_siteaccess_best_practice())
                $info['bp_site_access'] = $info['count'];

            if( get_class($object) == "URLProfile" && $object->url_usercredentialsubmission_best_practice() )
                $info['bp_user_credential'] = $info['count'];

            if( get_class($object) == "URLProfile" && $object->url_usercredentialsubmission_best_practice_tab())
                $info['bp_user_credential_tab'] = $info['count'];

            if( get_class($object) == "URLProfile" && $object->url_mica_engine_best_practice())
                $info['bp_inline_ml'] = $info['count'];

            $info['site_access_detail']       = ($info['site_access'] < $info['count']) ? '[Placeholder: Site Access Details]' : 'Compliant';
            $info['user_credential_detail']   = ($info['user_credential'] < $info['count']) ? '[Placeholder: User Credential Details]' : 'Compliant';

            $info['bp_site_access_detail']       = ($info['bp_site_access'] < $info['count']) ? '[Placeholder: BP Site Access Details]' : 'BP Compliant';
            $info['bp_user_credential_detail']   = ($info['bp_user_credential'] < $info['count']) ? '[Placeholder: BP User Credential Details]' : 'BP Compliant';


            if( get_class($object) == "AntiVirusProfile" ) { $sections['sec-av']['rows'][] = $info; }
            elseif( get_class($object) == "AntiSpywareProfile" ) { $sections['sec-as']['rows'][] = $info; }
            elseif( get_class($object) == "VulnerabilityProfile" ) { $sections['sec-vp']['rows'][] = $info; }
            elseif( get_class($object) == "FileBlockingProfile" ) { $sections['sec-fb']['rows'][] = $info; }
            elseif( get_class($object) == "URLProfile" ) { $sections['sec-url']['rows'][] = $info; }
            elseif( get_class($object) == "WildfireProfile" ) { $sections['sec-wf']['rows'][] = $info; }
            elseif( get_class($object) == "VirusAndWildfireProfile" ) { $sections['sec-avwf']['rows'][] = $info; }
            elseif( get_class($object) == "DNSSecurityProfile" ) { $sections['sec-dnssec']['rows'][] = $info; }
        }


        $blankDefaults = [
            'actions' => 0, 'inline_ml' => 0, 'rules_not_visible' => 0, 'inline_ml_not_visible' => 0,
            'rules' => 0, 'dns_lists' => 0, 'dns_security' => 0, 'adns_security' => 0, 'site_access' => 0, 'user_credential' => 0,
            'actions_detail' => 'N/A', 'inline_ml_detail' => 'N/A', 'rules_detail' => 'N/A',
            'dns_lists_detail' => 'N/A', 'dns_security_detail' => 'N/A', 'adns_security_detail' => 'N/A', 'site_access_detail' => 'N/A',
            'user_credential_detail' => 'N/A',

            // --- ADD THESE NEW BLANK DEFAULTS ---
            'bp_pass' => 0, 'bp_actions' => 0, 'bp_inline_ml' => 0, 'bp_rules' => 0,
            'bp_dns_lists' => 0, 'bp_dns_security' => 0, 'bp_adns_security' => 0, 'bp_site_access' => 0, 'bp_user_credential' => 0,
            'bp_actions_detail' => 'N/A', 'bp_inline_ml_detail' => 'N/A', 'bp_rules_detail' => 'N/A',
            'bp_dns_lists_detail' => 'N/A', 'bp_dns_security_detail' => 'N/A', 'bp_adns_security_detail' => 'N/A', 'bp_site_access_detail' => 'N/A',
            'bp_user_credential_detail' => 'N/A'
        ];

        if( !$isSCM ) {
            $sections['sec-av']['rows'][]  = array_merge(["location" => "N/A", "profile" => "blank", "count" => $av_blank, "visible" => 0], $blankDefaults);
            $sections['sec-wf']['rows'][]  = array_merge(["location" => "N/A", "profile" => "blank", "count" => $wf_blank, "visible" => 0], $blankDefaults);
        } else {
            $sections['sec-avwf']['rows'][]   = array_merge(["location" => "N/A", "profile" => "blank", "count" => $avwf_blank, "visible" => 0], $blankDefaults);
            $sections['sec-dnssec']['rows'][] = array_merge(["location" => "N/A", "profile" => "blank", "count" => $dnssec_blank, "visible" => 0], $blankDefaults);
        }
        $sections['sec-as']['rows'][]  = array_merge(["location" => "N/A", "profile" => "blank", "count" => $as_blank, "visible" => 0], $blankDefaults);
        $sections['sec-vp']['rows'][]  = array_merge(["location" => "N/A", "profile" => "blank", "count" => $vp_blank, "visible" => 0], $blankDefaults);
        $sections['sec-fb']['rows'][]  = array_merge(["location" => "N/A", "profile" => "blank", "count" => $fb_blank, "visible" => 0], $blankDefaults);
        $sections['sec-url']['rows'][] = array_merge(["location" => "N/A", "profile" => "blank", "count" => $url_blank, "visible" => 0], $blankDefaults);

        // --- MOCK INFRAS DATA SET ---
        $network_zone_protection = [
            ['zone' => 'Trust-Internal', 'profile' => 'Strict-Zone-Protection', 'status' => 'Protected', 'drop_count' => 14],
            ['zone' => 'DMZ-External', 'profile' => 'Edge-Protection-Profile', 'status' => 'Protected', 'drop_count' => 142],
            ['zone' => 'Guest-Wifi', 'profile' => 'None', 'status' => 'Unprotected', 'drop_count' => 0]
        ];

        $network_log_forwarding = [
            ['profile_name' => 'Splunk-Forwarding-Default', 'syslog_targets' => '10.0.1.50, 10.0.1.51', 'rules_bound' => 42, 'status' => 'Active'],
            ['profile_name' => 'Critical-Alerts-Email', 'syslog_targets' => 'pagerduty-webhook', 'rules_bound' => 5, 'status' => 'Active']
        ];

        $network_log_settings = [
            ['log_type' => 'System Logs', 'severity_traps' => 'critical, high', 'destination' => 'Syslog-Server', 'status' => 'Configured'],
            ['log_type' => 'Configuration Logs', 'severity_traps' => 'all', 'destination' => 'Syslog-Server', 'status' => 'Configured'],
            ['log_type' => 'Threat Logs', 'severity_traps' => 'all', 'destination' => 'Splunk-Forwarding-Default', 'status' => 'Configured']
        ];

        ob_start();
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title><?php echo htmlspecialchars($reportTitle); ?></title>
            <style>
                :root {
                    --border: #d0d5dd;
                    --header-bg: #1d4ed8;
                    --header-fg: #ffffff;
                    --row-alt: #f8fafc;
                    --muted: #6b7280;
                    --subtotal-bg: #f1f5f9;
                    --net-header: #0f172a;
                    --pill-bg: #f4f4f5;
                    --pill-border: #e4e4e7;
                    --pill-txt: #71717a;
                    --tab-active-bg: #1d4ed8;
                    --tab-active-fg: #ffffff;
                }
                * { box-sizing: border-box; }
                body {
                    margin: 24px;
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    color: #111827;
                    background-color: #fff;
                }
                header.spr-header {
                    border-bottom: 2px solid var(--border);
                    padding-bottom: 12px;
                    margin-bottom: 24px;
                }
                header.spr-header h1 { margin: 0 0 4px 0; font-size: 22px; }
                header.spr-header .meta { color: var(--muted); font-size: 13px; }

                /* Selector styling */
                .device-selector-box {
                    background: #f8fafc;
                    border: 1px solid var(--border);
                    padding: 16px;
                    border-radius: 8px;
                    margin-bottom: 24px;
                    display: flex;
                    align-items: center;
                    gap: 12px;
                }
                .device-selector-box select {
                    padding: 8px 12px;
                    font-size: 14px;
                    font-weight: 600;
                    border-radius: 6px;
                    border: 1px solid var(--border);
                    background: #fff;
                    color: #0f172a;
                    cursor: pointer;
                    min-width: 250px;
                }

                .spr-header-row {
                    display: flex;
                    gap: 24px;
                    margin-bottom: 24px;
                    align-items: stretch;
                }
                .spr-header-panel {
                    flex: 1;
                    min-height: 380px;
                    border: 1px solid var(--border);
                    padding: 16px;
                    border-radius: 6px;
                    background: #fff;
                    display: flex;
                    flex-direction: column;
                }
                .spr-section { margin-bottom: 36px; }
                .spr-section h2 {
                    font-size: 15px;
                    margin: 0 0 12px 0;
                    padding: 6px 10px;
                    background: #f3f4f6;
                    border-left: 4px solid var(--header-bg);
                }

                /* TAB CONTROLS LAYOUT STYLING */
                .spr-tabs-navigation {
                    display: flex;
                    gap: 4px;
                    border-bottom: 2px solid var(--border);
                    margin-bottom: 16px;
                    padding-top: 4px;
                }
                .spr-tab-btn {
                    padding: 8px 20px;
                    font-size: 13px;
                    font-weight: 600;
                    cursor: pointer;
                    background: #f1f5f9;
                    border: 1px solid var(--border);
                    border-bottom: none;
                    border-top-left-radius: 6px;
                    border-top-right-radius: 6px;
                    color: #475569;
                    transition: all 0.15s ease-in-out;
                    margin-bottom: -2px;
                }
                .spr-tab-btn:hover {
                    background: #e2e8f0;
                    color: #0f172a;
                }
                .spr-tab-btn.active {
                    background: var(--tab-active-bg);
                    color: var(--tab-active-fg);
                    border-color: var(--tab-active-bg);
                }

                /* Pill Metric Grid Containers */
                .spr-pill-matrix {
                    display: flex;
                    flex-direction: column;
                    gap: 6px;
                    margin: 4px 0 16px 4px;
                }
                .spr-pill-row {
                    display: flex;
                    gap: 12px;
                    flex-wrap: wrap;
                }
                .spr-pill {
                    background-color: var(--pill-bg);
                    border: 1px solid var(--pill-border);
                    border-radius: 12px;
                    padding: 4px 14px;
                    font-size: 12px;
                    color: var(--pill-txt);
                    display: inline-flex;
                    align-items: center;
                    gap: 6px;
                }
                .spr-pill strong {
                    color: #000000;
                    font-weight: 700;
                }

                .spr-table {
                    border-collapse: collapse;
                    width: 100%;
                    font-size: 13px;
                    margin-bottom: 8px;
                }
                .spr-table td {
                    white-space: pre-line;
                }
                .spr-table th, .spr-table td {
                    border: 1px solid var(--border);
                    padding: 8px 10px;
                    text-align: left;
                }
                .spr-table thead th {
                    background: var(--header-bg);
                    color: var(--header-fg);
                    font-weight: 600;
                }
                .spr-table tbody tr:nth-child(even) { background: var(--row-alt); }
                .spr-table td.num, .spr-table th.num { text-align: right; font-variant-numeric: tabular-nums; }
                .spr-table tr.subtotal td {
                    background: var(--subtotal-bg);
                    font-weight: 600;
                }

                .progress-container {
                    background-color: #e2e8f0;
                    border-radius: 4px;
                    width: 100%;
                    min-width: 120px;
                    height: 14px;
                    display: inline-block;
                    overflow: hidden;
                    vertical-align: middle;
                }
                .progress-bar {
                    height: 100%;
                    border-radius: 4px;
                    background-color: #10b981;
                }
                .progress-bar.low { background-color: #f59e0b; }
                .progress-bar.critical { background-color: #ef4444; }

                .net-container {
                    margin-top: 20px;
                    border: 1px solid var(--border);
                    border-radius: 6px;
                    overflow: hidden;
                }
                .net-section-title {
                    background: var(--net-header);
                    color: #fff;
                    padding: 10px 14px;
                    font-size: 14px;
                    font-weight: 600;
                    margin: 0;
                }
                .net-grid {
                    display: flex;
                    flex-direction: column;
                    gap: 1px;
                    background: var(--border);
                }
                .net-block {
                    background: #fff;
                    padding: 16px;
                }
                .net-block h3 {
                    margin: 0 0 10px 0;
                    font-size: 13px;
                    color: #1e293b;
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                    border-bottom: 1px solid #e2e8f0;
                    padding-bottom: 4px;
                }
                .badge {
                    padding: 2px 6px;
                    border-radius: 4px;
                    font-size: 11px;
                    font-weight: 600;
                }
                .badge-green { background: #dcfce7; color: #15803d; }
                .badge-red { background: #fee2e2; color: #b91c1c; }
            </style>
        </head>
        <body>

        <header class="spr-header">
            <h1><?php echo htmlspecialchars($reportTitle); ?></h1>
            <div class="meta">
                Source Block Matcher: <?php echo htmlspecialchars($sourceMeta); ?> &middot;
                Total Match Assessment Context: <?php echo number_format($matchedRulesCount); ?> rules matched.
            </div>
        </header>

        <!-- DYNAMIC DEVICE SELECTOR DROPDOWN -->
        <div class="device-selector-box">
            <label for="deviceSelector"><strong>Active Context Dataset / Location:</strong></label>
            <select id="deviceSelector" onchange="changeActiveDeviceContext(this.value)">
                <?php foreach ($bp_stats_raw as $index => $deviceDataInstance): ?>
                    <?php
                    $dropdownLabel = "Dataset Target Location #" . ($index + 1);

                    if (isset($deviceDataInstance['type'])) {
                        $type = $deviceDataInstance['type'];
                        $header = $deviceDataInstance['header'] ?? '';

                        $cleanHeader = preg_replace('/\x1b\[[0-9;]*m/', '', $header);
                        $cleanHeader = preg_replace('/\[[0-9;]*m/', '', $cleanHeader);

                        if ($type === 'PANConf' || $type === 'PanoramaConf') {
                            $dropdownLabel = "FullDevice";
                        }
                        elseif ($type === 'VirtualSystem') {
                            if (preg_match("/VirtualSystem\s+'([^']+)'/", $cleanHeader, $matches)) {
                                $dropdownLabel = $matches[1];
                            } else {
                                $dropdownLabel = "vsys1";
                            }
                        }
                        elseif ($type === 'DeviceGroup') {
                            if (preg_match("/DeviceGroup\s+'([^']+)'/", $cleanHeader, $matches)) {
                                $dropdownLabel = $matches[1];
                            } else {
                                $dropdownLabel = "DeviceGroup Context";
                            }
                        }
                    }
                    ?>
                    <option value="<?php echo $index; ?>">
                        <?php echo htmlspecialchars($dropdownLabel); ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>

        <div class="spr-header-row">
            <!-- RIGHT SIDE PANEL: Security Rules (Scope) Data -->
            <div class="spr-header-panel" style="max-height: 250px; flex: 0 0 350px;">
                <h3 style="font-size: 14px; margin: 0 0 10px 0; text-transform: uppercase; letter-spacing: 0.05em; color: var(--net-header);">
                    Security Rules (Scope) Summary
                </h3>
                <table class="spr-table" style="margin: 0;">
                    <thead>
                    <tr>
                        <th>Rule Context Metric</th>
                        <th class="num" style="width: 100px;">Count</th>
                    </tr>
                    </thead>
                    <tbody>
                    <tr>
                        <td>Total Security Rules</td>
                        <td class="num" id="scope-total" style="font-weight: 600;"><?php echo number_format($securityRulesScope['total']); ?></td>
                    </tr>
                    <tr>
                        <td>Rules (Action: Allow)</td>
                        <td class="num" id="scope-allow"><?php echo number_format($securityRulesScope['allow']); ?></td>
                    </tr>
                    <tr>
                        <td>&nbsp;&nbsp;&bull; Allow &amp; Enabled</td>
                        <td class="num" id="scope-allow-enabled" style="color: #15803d; font-weight: 600;"><?php echo number_format($securityRulesScope['allow_enabled']); ?></td>
                    </tr>
                    <tr>
                        <td>&nbsp;&nbsp;&bull; Allow &amp; Disabled</td>
                        <td class="num" id="scope-allow-disabled" style="color: var(--muted);"><?php echo number_format($securityRulesScope['allow_disabled']); ?></td>
                    </tr>
                    <tr>
                        <td>Total Enabled Rules</td>
                        <td class="num" id="scope-enabled"><?php echo number_format($securityRulesScope['enabled']); ?></td>
                    </tr>
                    </tbody>
                </table>
            </div>

            <!-- LEFT SIDE PANEL WITH TAB SWITCHER ABOVE THE METRICS TABLE -->
            <div class="spr-header-panel">
                <!-- THREE HARDCODED TABS SWITCH -->
                <div class="spr-tabs-navigation">
                    <div class="spr-tab-btn active" onclick="switchMetricsTab('visibility', this)">Visibility</div>
                    <div class="spr-tab-btn" onclick="switchMetricsTab('best-practice', this)">Best-Practice</div>
                    <div class="spr-tab-btn" onclick="switchMetricsTab('adoption', this)">Adoption</div>
                </div>

                <div style="flex: 1; overflow-y: auto;">
                    <table class="spr-table" style="margin: 0;">
                        <thead>
                        <tr>
                            <th>Group</th>
                            <th>Type</th>
                            <th class="num" style="width: 90px;">Percentage</th>
                            <th style="width: 220px;">% Visual Distribution</th>
                        </tr>
                        </thead>
                        <tbody id="overview-metrics-tbody">
                        <!-- Dynamic content is fully handled on load and updates via javascript engine below -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <hr style="border: 0; border-top: 1px solid var(--border); margin-bottom: 24px;">

        <?php foreach ($sections as $id => $section): ?>
            <section id="<?php echo htmlspecialchars($id); ?>" class="spr-section">
                <h2><?php echo htmlspecialchars($section['title']); ?></h2>

                <!-- CAPSULE METRIC BADGES GRID MATRIX WITH DYNAMIC HOOK TEXT INJECTION PIPELINE -->
                <?php if (isset($pillMetaMapping[$id]) && !empty($bp_stats_raw[0])): ?>
                    <div class="spr-pill-matrix">
                        <div class="spr-pill-row">
                            <?php foreach ($pillMetaMapping[$id] as $label => $baseKey): ?>
                                <?php
                                $sluggedLabel = strtolower(preg_replace('/[^a-z0-9-]+/', '-', $label));
                                ?>
                                <div class="spr-pill">
                                    <span id="pill-label-<?php echo $id . '-' . $sluggedLabel; ?>">Visibility</span>:
                                    <strong id="pill-pct-<?php echo $id . '-' . $sluggedLabel; ?>">0%</strong>
                                    <span style="color: var(--muted); margin: 0 2px;">|</span>
                                    <span id="pill-count-<?php echo $id . '-' . $sluggedLabel; ?>" style="font-variant-numeric: tabular-nums;">0/23</span>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endif; ?>

                <table class="spr-table">
                    <thead>
                    <tr>
                        <?php foreach ($section['headers'] as $header): ?>
                            <th class="<?php echo (strpos($header, 'Info') === false && (strpos($header, '#') !== false || strpos($header, 'Visible') !== false || strpos($header, 'ML') !== false || strpos($header, 'Rules') !== false || strpos($header, 'Access') !== false || strpos($header, 'Submission') !== false || strpos($header, 'Lists') !== false || strpos($header, 'Security') !== false || strpos($header, 'Actions') !== false)) ? 'num' : ''; ?>">
                                <?php echo htmlspecialchars($header); ?>
                            </th>
                        <?php endforeach; ?>
                    </tr>
                    </thead>
                    <tbody>
                    <?php
                    $subtotals = array_fill_keys($section['keys'], 0);

                    foreach ($section['rows'] as $row):
                        ?>
                        <tr data-row-json="<?php echo htmlspecialchars(json_encode($row), ENT_QUOTES, 'UTF-8'); ?>">
                            <?php foreach ($section['keys'] as $key): ?>
                                <?php
                                $isNumeric = in_array($key, $section['numeric']);
                                if ($isNumeric) {
                                    $subtotals[$key] += isset($row[$key]) ? (is_numeric($row[$key]) ? $row[$key] : 0) : 0;
                                }
                                ?>
                                <td class="<?php echo $isNumeric ? 'num' : ''; ?>">
                                    <?php
                                    $cellValue = isset($row[$key]) ? $row[$key] : '';
                                    if (is_array($cellValue)) {
                                        $cellValue = implode(', ', $cellValue);
                                    }
                                    echo htmlspecialchars((string)$cellValue);
                                    ?>
                                </td>
                            <?php endforeach; ?>
                        </tr>
                    <?php endforeach; ?>

                    <tr class="subtotal">
                        <td>Subtotal</td>
                        <?php
                        for ($i = 1; $i < count($section['keys']); $i++):
                            $key = $section['keys'][$i];
                            $isNumeric = in_array($key, $section['numeric']);
                            ?>
                            <td class="<?php echo $isNumeric ? 'num' : ''; ?>">
                                <?php echo $isNumeric ? htmlspecialchars((string)$subtotals[$key]) : ''; ?>
                            </td>
                        <?php endfor; ?>
                    </tr>
                    </tbody>
                </table>
            </section>
        <?php endforeach; ?>

        <section class="spr-section">
            <div class="net-container">
                <div class="net-section-title">Network Base Infrastructure Configuration Profiles</div>
                <div class="net-grid">
                    <div class="net-block">
                        <h3>Zone Protection Settings</h3>
                        <table class="spr-table" style="margin: 0;">
                            <thead>
                            <tr>
                                <th>Security Target Zone</th>
                                <th>Applied Protection Profile</th>
                                <th>Security Status</th>
                                <th class="num">Drop Counter Action Triggered</th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php foreach($network_zone_protection as $zp): ?>
                                <tr>
                                    <td><strong><?php echo htmlspecialchars($zp['zone']); ?></strong></td>
                                    <td><?php echo htmlspecialchars($zp['profile']); ?></td>
                                    <td>
                                    <span class="badge <?php echo $zp['status'] === 'Protected' ? 'badge-green' : 'badge-red'; ?>">
                                        <?php echo htmlspecialchars($zp['status']); ?>
                                    </span>
                                    </td>
                                    <td class="num"><?php echo $zp['drop_count']; ?></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>

                    <div class="net-block">
                        <h3>Log Forwarding Routing Pipeline</h3>
                        <table class="spr-table" style="margin: 0;">
                            <thead>
                            <tr>
                                <th>Log Forwarding Profile Name</th>
                                <th>Target Destinations / Traps</th>
                                <th class="num">Referenced Security Rules</th>
                                <th>Deployment Status</th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php foreach($network_log_forwarding as $lf): ?>
                                <tr>
                                    <td><strong><?php echo htmlspecialchars($lf['profile_name']); ?></strong></td>
                                    <td><code><?php echo htmlspecialchars($lf['syslog_targets']); ?></code></td>
                                    <td class="num"><?php echo $lf['rules_bound']; ?></td>
                                    <td><span class="badge badge-green"><?php echo htmlspecialchars($lf['status']); ?></span></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>

                    <div class="net-block">
                        <h3>System Engine Log Settings</h3>
                        <table class="spr-table" style="margin: 0;">
                            <thead>
                            <tr>
                                <th>Log Component Class</th>
                                <th>Severity Captures</th>
                                <th>Forwarding Dest Routing Node</th>
                                <th>Operational State</th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php foreach($network_log_settings as $ls): ?>
                                <tr>
                                    <td><strong><?php echo htmlspecialchars($ls['log_type']); ?></strong></td>
                                    <td><?php echo htmlspecialchars($ls['severity_traps']); ?></td>
                                    <td><?php echo htmlspecialchars($ls['destination']); ?></td>
                                    <td><span class="badge badge-green"><?php echo htmlspecialchars($ls['status']); ?></span></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </section>

        <!-- CONTROLLER AND INTERACTIVE RENDERING ENGINE -->
        <script>
            // Serialize backend dataset globally to client-side JS DOM mapping
            const fullDeviceDatasetArray = <?php echo json_encode($bp_stats_raw); ?>;
            const activePillSectionMapping = <?php echo json_encode($pillMetaMapping); ?>;

            // Unified source of truth schema that defines the layout variations across all 3 tabs
            const detailedSectionsConfiguration = {
                'sec-av': {
                    keys: {
                        'visibility':    ['location', 'profile', 'count', 'visible', 'actions', 'inline_ml', 'actions_detail', 'inline_ml_detail'],
                        'best-practice': ['location', 'profile', 'count', 'bp_pass', 'bp_actions', 'bp_inline_ml', 'bp_actions_detail', 'bp_inline_ml_detail'],
                        'adoption':      ['location', 'profile', 'count', 'adopted']
                    },
                    headers: {
                        'visibility':    ['Location', 'Antivirus Profile Name', '# of Rules', 'Visible', 'Actions', 'Inline ML', 'Actions Check Info', 'Inline ML Check Info'],
                        'best-practice': ['Location', 'Antivirus Profile Name', '# of Rules', 'BP Pass', 'BP Actions', 'BP Inline ML', 'Actions Check Info', 'Inline ML Check Info'],
                        'adoption':      ['Location', 'Antivirus Profile Name', '# of Rules', 'Adopted']
                    },
                    numericIndices: [2, 3, 4, 5]
                },
                'sec-as': {
                    keys: {
                        'visibility':    ['location', 'profile', 'count', 'visible', 'rules', 'dns_lists', 'dns_security', 'adns_security', 'inline_ml', 'rules_detail', 'dns_lists_detail', 'dns_security_detail', 'adns_security_detail', 'inline_ml_detail'],
                        'best-practice': ['location', 'profile', 'count', 'bp_pass', 'bp_rules', 'bp_dns_lists',  'bp_dns_security', 'bp_adns_security', 'bp_inline_ml', 'bp_rules_detail', 'bp_dns_lists_detail', 'bp_dns_security_detail', 'bp_adns_security_detail', 'bp_inline_ml_detail'],
                        'adoption':      ['location', 'profile', 'count', 'adopted']
                    },
                    headers: {
                        'visibility':    ['Location', 'Anti-Spyware Profile Name', '# of Rules', 'Visible', 'Rules', 'DNS Lists', 'DNS Security', 'ADNS Security', 'Inline ML', 'Rules Check Info', 'DNS Lists Check Info', 'DNS Security Check Info', 'ADNS Security Check Info', 'Inline ML Check Info'],
                        'best-practice': ['Location', 'Anti-Spyware Profile Name', '# of Rules', 'BP Pass', 'BP Rules', 'BP DNS Lists', 'BP DNS Security', 'BP ADNS Security', 'BP Inline ML', 'Rules Check Info', 'DNS Lists Check Info', 'DNS Security Check Info', 'ADNS Security Check Info', 'Inline ML Check Info'],
                        'adoption':      ['Location', 'Anti-Spyware Profile Name', '# of Rules', 'Adopted']
                    },
                    numericIndices: [2, 3, 4, 5, 6, 7, 8]
                },
                'sec-vp': {
                    keys: {
                        'visibility':    ['location', 'profile', 'count', 'visible', 'rules', 'inline_ml', 'rules_detail', 'inline_ml_detail'],
                        'best-practice': ['location', 'profile', 'count', 'bp_pass', 'bp_rules', 'bp_inline_ml', 'bp_rules_detail', 'bp_inline_ml_detail'],
                        'adoption':      ['location', 'profile', 'count', 'adopted']
                    },
                    headers: {
                        'visibility':    ['Location', 'Vulnerability Profile Name', '# of Rules', 'Visible', 'Rules', 'Inline ML', 'Rules Check Info', 'Inline ML Check Info'],
                        'best-practice': ['Location', 'Vulnerability Profile Name', '# of Rules', 'BP Pass', 'BP Rules', 'BP Inline ML', 'Rules Check Info', 'Inline ML Check Info'],
                        'adoption':      ['Location', 'Vulnerability Profile Name', '# of Rules', 'Adopted']
                    },
                    numericIndices: [2, 3, 4, 5]
                },
                'sec-url': {
                    keys: {
                        'visibility':    ['location', 'profile', 'count', 'visible', 'site_access', 'user_credential', 'inline_ml', 'site_access_detail', 'user_credential_detail', 'inline_ml_detail'],
                        'best-practice': ['location', 'profile', 'count', 'bp_pass', 'bp_site_access', 'bp_user_credential', 'bp_inline_ml', 'bp_site_access_detail', 'bp_user_credential_detail', 'bp_inline_ml_detail'],
                        'adoption':      ['location', 'profile', 'count', 'adopted']
                    },
                    headers: {
                        'visibility':    ['Location', 'URL Filtering Profile Name', '# of Rules', 'Visible', 'Site Access', 'User Credential Submission', 'InlineML', 'Site Access Check Info', 'User Credential Check Info', 'Inline ML Check Info'],
                        'best-practice': ['Location', 'URL Filtering Profile Name', '# of Rules', 'BP Pass', 'BP Site Access', 'BP User Credential', 'BP InlineML', 'Site Access Check Info', 'User Credential Check Info', 'Inline ML Check Info'],
                        'adoption':      ['Location', 'URL Filtering Profile Name', '# of Rules', 'Adopted']
                    },
                    numericIndices: [2, 3, 4, 5, 6]
                },
                'sec-fb': {
                    keys: {
                        'visibility':    ['location', 'profile', 'count', 'visible', 'rules', 'rules_detail'],
                        'best-practice': ['location', 'profile', 'count', 'bp_pass', 'bp_rules', 'bp_rules_detail'],
                        'adoption':      ['location', 'profile', 'count', 'adopted']
                    },
                    headers: {
                        'visibility':    ['Location', 'File Blocking Profile Name', '# of Rules', 'Visible', 'Rules', 'Rules Check Info'],
                        'best-practice': ['Location', 'File Blocking Profile Name', '# of Rules', 'BP Pass', 'BP Rules', 'Rules Check Info'],
                        'adoption':      ['Location', 'File Blocking Profile Name', '# of Rules', 'Adopted']
                    },
                    numericIndices: [2, 3, 4]
                },
                'sec-wf': {
                    keys: {
                        'visibility':    ['location', 'profile', 'count', 'visible', 'rules', 'inline_ml', 'rules_detail', 'inline_ml_detail'],
                        'best-practice': ['location', 'profile', 'count', 'bp_pass', 'bp_rules', 'bp_inline_ml', 'bp_rules_detail', 'bp_inline_ml_detail'],
                        'adoption':      ['location', 'profile', 'count', 'adopted']
                    },
                    headers: {
                        'visibility':    ['Location', 'WildFire Analysis Profile Name', '# of Rules', 'Visible', 'Rules', 'Inline ML', 'Rules Check Info', 'Inline ML Check Info'],
                        'best-practice': ['Location', 'WildFire Analysis Profile Name', '# of Rules', 'BP Pass', 'BP Rules', 'BP Inline ML', 'Rules Check Info', 'Inline ML Check Info'],
                        'adoption':      ['Location', 'WildFire Analysis Profile Name', '# of Rules', 'Adopted']
                    },
                    numericIndices: [2, 3, 4, 5]
                },
                'sec-avwf': {
                    keys: {
                        'visibility':    ['location', 'profile', 'count', 'visible', 'rules', 'inline_ml', 'rules_detail', 'inline_ml_detail'],
                        'best-practice': ['location', 'profile', 'count', 'bp_pass', 'bp_rules', 'bp_inline_ml', 'bp_rules_detail', 'bp_inline_ml_detail'],
                        'adoption':      ['location', 'profile', 'count', 'adopted']
                    },
                    headers: {
                        'visibility':    ['Location', 'VirusAndWildFire Profile Name', '# of Rules', 'Visible', 'Rules', 'Inline ML', 'Rules Check Info', 'Inline ML Check Info'],
                        'best-practice': ['Location', 'VirusAndWildFire Profile Name', '# of Rules', 'BP Pass', 'BP Rules', 'BP Inline ML', 'Rules Check Info', 'Inline ML Check Info'],
                        'adoption':      ['Location', 'VirusAndWildFire Profile Name', '# of Rules', 'Adopted']
                    },
                    numericIndices: [2, 3, 4, 5]
                },
                'sec-dnssec': {
                    keys: {
                        'visibility':    ['location', 'profile', 'count', 'visible', 'rules', 'rules_detail'],
                        'best-practice': ['location', 'profile', 'count', 'bp_pass', 'bp_rules', 'bp_rules_detail'],
                        'adoption':      ['location', 'profile', 'count', 'adopted']
                    },
                    headers: {
                        'visibility':    ['Location', 'DNSSecurity Profile Name', '# of Rules', 'Visible', 'Rules', 'Rules Check Info'],
                        'best-practice': ['Location', 'DNSSecurity Profile Name', '# of Rules', 'BP Pass', 'BP Rules', 'Rules Check Info'],
                        'adoption':      ['Location', 'DNSSecurity Profile Name', '# of Rules', 'Adopted']
                    },
                    numericIndices: [2, 3, 4]
                }
            };

            // Global engine operational states
            let currentSelectedIndex = 0;
            let currentActiveTab = 'visibility';

            // Tab triggering controller execution entry point
            function switchMetricsTab(tabId, element) {
                const buttons = document.querySelectorAll('.spr-tab-btn');
                buttons.forEach(btn => btn.classList.remove('active'));
                element.classList.add('active');

                currentActiveTab = tabId;

                // 1. Refresh Dynamic Overview layout
                renderMetricsTable();

                // 2. Loop across layout blocks to dynamically mutate tables structure on click
                renderDetailedSectionsLayouts();

                // 3. Trigger context mutations across summary capsule pill fields
                updatePillMatrices();
            }

            /**
             * Iterates over every security profile table block lower down the page,
             * morphing headers, column definitions, and values based on the selected tab state.
             */
            function renderDetailedSectionsLayouts() {
                const activeTab = currentActiveTab;

                for (const sectionId in detailedSectionsConfiguration) {
                    if (!detailedSectionsConfiguration.hasOwnProperty(sectionId)) continue;

                    const config = detailedSectionsConfiguration[sectionId];
                    const sectionEl = document.getElementById(sectionId);
                    if (!sectionEl) continue;

                    const targetKeys = config.keys[activeTab];
                    const targetHeaders = config.headers[activeTab];

                    if (!targetKeys || !targetHeaders) continue;

                    // --- STEP A: REWRITE THE THEAD HEADERS ---
                    const theadRow = sectionEl.querySelector('table thead tr');
                    if (theadRow) {
                        theadRow.innerHTML = '';
                        targetHeaders.forEach((headerText, index) => {
                            const isNumeric = config.numericIndices.includes(index);
                            const th = document.createElement('th');
                            if (isNumeric) th.classList.add('num');
                            th.textContent = headerText;
                            theadRow.appendChild(th);
                        });
                    }

                    // --- STEP B: DYNAMICALLY RE-RENDER TABLE VALUES FROM SEED DATA RETAINING FILTERS ---
                    const selectorEl = document.getElementById('deviceSelector');
                    const selectedLabel = selectorEl ? selectorEl.options[selectorEl.selectedIndex].text.trim() : '';
                    const isFullDevice = (selectedLabel === 'FullDevice');

                    const tableRows = sectionEl.querySelectorAll('table tbody tr:not(.subtotal)');
                    let subtotalAggregates = {};

                    tableRows.forEach(row => {
                        // Retrieve full raw data row structure injected dynamically via data-row-json property
                        const rawDataAttr = row.getAttribute('data-row-json');
                        if (!rawDataAttr) return;

                        const rowData = JSON.parse(rawDataAttr);
                        const rowLocation = rowData['location'] || 'N/A';

                        // Verify display properties visibility status based on active dropdown selector filter
                        const shouldShow = isFullDevice || (rowLocation === selectedLabel);

                        if (shouldShow) {
                            row.style.display = '';
                            row.innerHTML = ''; // Strip column tokens inside row tree

                            targetKeys.forEach((key, index) => {
                                const td = document.createElement('td');
                                const isNumeric = config.numericIndices.includes(index);
                                if (isNumeric) td.classList.add('num');

                                let cellValue = rowData[key] !== undefined ? rowData[key] : '';
                                if (Array.isArray(cellValue)) {
                                    cellValue = cellValue.implode ? cellValue.implode(', ') : cellValue.join(', ');
                                }

                                // Structural cell injection block
                                if (index === 0 || index === 1) {
                                    td.innerHTML = `<strong>${escapeHtml(cellValue)}</strong>`;
                                } else {
                                    td.textContent = cellValue;
                                }

                                // Add running totals to tracking objects matrix
                                if (isNumeric) {
                                    const parsedVal = parseFloat(cellValue) || 0;
                                    subtotalAggregates[index] = (subtotalAggregates[index] || 0) + parsedVal;
                                }

                                row.appendChild(td);
                            });
                        } else {
                            row.style.display = 'none';
                        }
                    });

                    // --- STEP C: RE-COMPUTE THE SUBTOTAL FOR THE SECTION ---
                    const subtotalRow = sectionEl.querySelector('tr.subtotal');
                    if (subtotalRow) {
                        subtotalRow.innerHTML = '';
                        const firstTd = document.createElement('td');
                        firstTd.textContent = 'Subtotal';
                        subtotalRow.appendChild(firstTd);

                        for (let i = 1; i < targetKeys.length; i++) {
                            const td = document.createElement('td');
                            const isNumeric = config.numericIndices.includes(i);
                            if (isNumeric) {
                                td.classList.add('num');
                                td.textContent = subtotalAggregates[i] || 0;
                            } else {
                                td.textContent = '';
                            }
                            subtotalRow.appendChild(td);
                        }
                    }
                }
            }

            /**
             * Dynamic calculation routine that updates unified pill layouts (combining % and count)
             * relative to the active target compliance tab on the fly.
             *
             * For 'adoption', it isolates and displays ONLY the core section/profile adoption info.
             */
            function updatePillMatrices() {
                const dataset = fullDeviceDatasetArray[currentSelectedIndex];
                if (!dataset) return;

                // Map the active UI tab directly to the nomenclature string used in your array keys
                let activeTabString = 'visibility';
                let displayLabelPrefix = 'Visibility';

                if (currentActiveTab === 'best-practice') {
                    activeTabString = 'best-practice';
                    displayLabelPrefix = 'Best-Practice';
                } else if (currentActiveTab === 'adoption') {
                    activeTabString = 'adoption';
                    displayLabelPrefix = 'Adoption';
                }

                for (const sectionId in activePillSectionMapping) {
                    if (!activePillSectionMapping.hasOwnProperty(sectionId)) continue;

                    const labelsConfig = activePillSectionMapping[sectionId];
                    for (const rawLabelName in labelsConfig) {
                        if (!labelsConfig.hasOwnProperty(rawLabelName)) continue;

                        const elementSlug = rawLabelName.toLowerCase().replace(/[^a-z0-9-]+/g, '-');
                        const pillDOMElement = document.getElementById(`pill-label-${sectionId}-${elementSlug}`)?.closest('.spr-pill');

                        // --- ADOPTION TAB FILTER CRITERIA ---
                        // If the active tab is adoption, we only want the main row profile metric.
                        // We hide any pill that represents a sub-component (like rules, inline ml, actions, dns, etc.)
                        if (currentActiveTab === 'adoption' && rawLabelName !== 'visibility' && rawLabelName !== 'site access visibility') {
                            if (pillDOMElement) {
                                pillDOMElement.style.display = 'none';
                            }
                            continue;
                        } else if (pillDOMElement) {
                            pillDOMElement.style.display = ''; // Restore visibility for other tabs
                        }

                        // baseKey is exactly what comes from your mapping config (e.g., "adns-security visibility")
                        const baseKey = labelsConfig[rawLabelName];

                        // 1. Direct Swap Strategy: Replace the literal word "visibility" with the active tab string
                        const targetBaseKey = baseKey.replace('visibility', activeTabString);

                        // 2. Append the exact calculation modifiers your backend expects
                        const percentageKey = `${targetBaseKey} percentage`;
                        const countKey = `${targetBaseKey} calc`;

                        // 3. Clean up UI Label text inside the HTML spans nicely
                        let cleanLabelBody = rawLabelName
                            .replace('visibility', '')
                            .replace('site access', 'Site Access')
                            .replace('credential', 'Credential')
                            .replace('mica-engine', 'Inline ML')
                            .replace('dns-list', 'DNS List')
                            .replace('adns-security', 'Advanced DNS Security')
                            .replace('dns-security', 'DNS Security')
                            .trim();

                        if (cleanLabelBody) {
                            cleanLabelBody = cleanLabelBody.split(' ').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
                        }
                        const finalLabelText = cleanLabelBody ? ` — ${cleanLabelBody}` : '';

                        // 4. Update the Unified Title Label Text
                        const labelElement = document.getElementById(`pill-label-${sectionId}-${elementSlug}`);
                        if (labelElement) {
                            labelElement.textContent = `${displayLabelPrefix}${finalLabelText}`;
                        }

                        // 5. Update Percentage Value Metric
                        const pctElement = document.getElementById(`pill-pct-${sectionId}-${elementSlug}`);
                        if (pctElement) {
                            const pctValue = dataset[percentageKey];
                            pctElement.textContent = pctValue !== undefined ? (isNaN(pctValue) ? pctValue : pctValue + '%') : '0%';
                        }

                        // 6. Update Fractional Count Metric
                        const countElement = document.getElementById(`pill-count-${sectionId}-${elementSlug}`);
                        if (countElement) {
                            countElement.textContent = dataset[countKey] !== undefined ? dataset[countKey] : '0/23';
                        }
                    }
                }
            }

            // Dropdown routing index logic
            function changeActiveDeviceContext(targetIndex) {
                currentSelectedIndex = parseInt(targetIndex);
                const dataset = fullDeviceDatasetArray[currentSelectedIndex];
                if (!dataset) return;

                // 1. Refresh Dynamic Right Panel Global Scope Figures
                updateDOMTextContent('scope-total', formatNumberWithCommas(dataset['security rules'] ?? 0));
                updateDOMTextContent('scope-allow', formatNumberWithCommas(dataset['security rules allow'] ?? 0));
                updateDOMTextContent('scope-allow-enabled', formatNumberWithCommas(dataset['security rules allow enabled'] ?? 0));
                updateDOMTextContent('scope-allow-disabled', formatNumberWithCommas(dataset['security rules allow disabled'] ?? 0));
                updateDOMTextContent('scope-enabled', formatNumberWithCommas(dataset['security rules enabled'] ?? 0));

                // 2. Render Left Panel Table Context Framework based on newly selected device item
                renderMetricsTable();

                // 3. Trigger dynamic pill layout and text calculation updates
                updatePillMatrices();

                // 4. Trigger dynamic table redraw to filter rows by newly selected Location mapping
                renderDetailedSectionsLayouts();
            }

            // Core table rendering manager method parsing the 3-tab layout variations
            function renderMetricsTable() {
                const dataset = fullDeviceDatasetArray[currentSelectedIndex];
                const tbody = document.getElementById('overview-metrics-tbody');
                if (!dataset || !tbody) return;

                tbody.innerHTML = '';

                // Ensure the table header has our new 5th column header title
                const theadRow = document.querySelector('.spr-header-panel table thead tr');
                if (theadRow && theadRow.cells.length === 4) {
                    const th = document.createElement('th');
                    th.classList.add('num');
                    th.style.width = '120px';
                    th.textContent = 'Rule Calculation';
                    theadRow.appendChild(th);
                }

                // Isolate the correct active subset loop array context
                let targetedSubSet = {};
                if (dataset['percentage'] && dataset['percentage'][currentActiveTab]) {
                    targetedSubSet = dataset['percentage'][currentActiveTab];
                }

                for (const displayName in targetedSubSet) {
                    if (!targetedSubSet.hasOwnProperty(displayName)) continue;

                    const matchedData = targetedSubSet[displayName];
                    let pctValue = 0;
                    let groupName = 'Security Profiles';

                    if (matchedData !== null && typeof matchedData === 'object') {
                        pctValue = matchedData['value'] ?? 0;
                        groupName = matchedData['group'] ?? groupName;
                    } else {
                        pctValue = matchedData || 0;
                    }

                    let explicitCalculationValue = 'N/A';

                    // --- 1. HARD FORCED INTERCEPT FOR STATIC KEYS ---
                    if (displayName === 'App-ID' || displayName === 'User-ID' || displayName === 'Service/Port') {
                        let staticKey = 'service port';
                        if (displayName === 'App-ID') staticKey = 'app id';
                        if (displayName === 'User-ID') staticKey = 'user id';

                        const totalRules = dataset[staticKey] || dataset[staticKey.toUpperCase()] || 0;
                        const matchingRules = Math.round((pctValue / 100) * totalRules);

                        explicitCalculationValue = `${matchingRules}/${totalRules}`;
                    } else {
                        // --- 2. DYNAMIC GENERATION FOR STANDARD TABBED PROFILES ---
                        let baseKey = displayName.toLowerCase()
                            .replace('wildfire analysis ', 'wf ')
                            .replace('antivirus ', 'av ')
                            .replace('anti-spyware ', 'as ')
                            .replace('vulnerability ', 'vp ')
                            .replace('file blocking ', 'fb ')
                            .replace('data filtering', 'data')
                            .replace('url filtering profiles', 'url-site-access')
                            .replace('credential theft prevention', 'url-credential')
                            .replace('url inline ml', 'url-mica-engine')
                            .replace('inline ml', 'mica-engine')
                            .replace('dns list', 'dns-list')          // Exact array key fix
                            .replace('dns security', 'dns-security')  // Exact array key fix
                            .replace('advanced dns security', 'adns-security')
                            .replace('profiles', '')
                            .replace('/', ' ')
                            .trim();

                        if (baseKey === 'logging') baseKey = 'log at end';
                        if (baseKey === 'log forwarding') baseKey = 'log prof set';

                        if (`${baseKey} calc` in dataset) {
                            // Flat and tabless (e.g., 'zone protection calc')
                            explicitCalculationValue = dataset[`${baseKey} calc`];
                        } else if (baseKey.startsWith('wf ') || baseKey.startsWith('av ') || baseKey.startsWith('as ') || baseKey.startsWith('vp ')) {
                            // Multi-word profiles (e.g., 'wf visibility rules calc')
                            const keyParts = baseKey.split(' ');
                            const calcLookupKey = `${keyParts[0]} ${currentActiveTab} ${keyParts.slice(1).join(' ')} calc`;
                            explicitCalculationValue = dataset[calcLookupKey] || 'N/A';
                        } else {
                            // Standard tabbed format (e.g., 'fb visibility calc', 'dns-list visibility calc')
                            const calcLookupKey = `${baseKey} ${currentActiveTab} calc`;
                            explicitCalculationValue = dataset[calcLookupKey] || 'N/A';
                        }
                    }

                    let barStatusClass = '';
                    if (parseInt(pctValue) === 0) barStatusClass = 'critical';
                    else if (parseInt(pctValue) < 70) barStatusClass = 'low';

                    const row = document.createElement('tr');

                    row.innerHTML = `
                        <td style="color: var(--muted); font-size: 12px; font-weight: 500;">${escapeHtml(groupName)}</td>
                        <td><strong>${escapeHtml(displayName)}</strong></td>
                        <td class="num"><strong>${pctValue}%</strong></td>
                        <td style="white-space: normal; width: 180px;">
                            <div class="progress-container">
                                <div class="progress-bar"></div>
                            </div>
                        </td>
                        <td class="num" style="font-weight: 600; font-variant-numeric: tabular-nums; color: #0f172a; font-size: 13px;">
                            ${escapeHtml(explicitCalculationValue)}
                        </td>
                    `;

                    const progressBar = row.querySelector('.progress-bar');
                    if (progressBar) {
                        progressBar.style.width = pctValue + '%';
                        if (barStatusClass) progressBar.classList.add(barStatusClass);
                    }

                    tbody.appendChild(row);
                }
            }

            function updateDOMTextContent(elementId, clearTextString) {
                const elementRef = document.getElementById(elementId);
                if (elementRef) elementRef.textContent = clearTextString;
            }

            function formatNumberWithCommas(rawNum) {
                return Number(rawNum).toLocaleString('en-US');
            }

            function escapeHtml(str) {
                return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
            }

            // Run initial bootstrap on screen compile initialization load context execution sequence
            window.addEventListener('DOMContentLoaded', () => {
                const selectorEl = document.getElementById('deviceSelector');
                if (selectorEl) {
                    currentSelectedIndex = parseInt(selectorEl.value) || 0;
                }
                renderMetricsTable();
                updatePillMatrices();
                renderDetailedSectionsLayouts();
            });
        </script>

        </body>
        </html>
        <?php

        file_put_contents($filename, ob_get_clean());

        return TRUE;
    },
    'args' => array(
        'filename' => array('type' => 'string', 'default' => '*nodefault*')
    )
);

SecurityProfileCallContext::$supportedActions['custom-url-category-add-ending-token'] = array(
    'name' => 'custom-url-category-add-ending-token',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if( get_class( $object) !== "customURLProfile")
            return null;

        $newToken = $context->arguments['endingtoken'];

        if( strpos( $newToken, "$$" ) !== FALSE )
            $newToken = str_replace( "$$", "/", $newToken );

        $tokenArray = array( '.', '/', '?', '&', '=', ';', '+', '*', '/*' );

        if( !in_array( $newToken, $tokenArray ) )
        {
            PH::print_stdout(  "skipped! Token: ".$newToken." is not supported. supported endingTokens: ".implode( ",",$tokenArray) );
            return null;
        }

        foreach( $object->getmembers() as $member )
        {
            PH::print_stdout(  "        - " . $member );
            PH::$JSON_TMP['sub']['object'][$object->name()]['members'][] = $member;

            $skiptokenArray = array( '*' );

            $lastChar = substr($member, -1);
            $lasttwoChar = substr($member, -2);
            if( in_array( $lastChar, $tokenArray ) && $newToken != "*" )
                PH::print_stdout(  $context->padding."skipped! endingToken already available: '".$lastChar."'" );
            elseif( $lastChar == $newToken || $lasttwoChar == $newToken )
                PH::print_stdout(  $context->padding."skipped! endingToken already available: '".$member."'" );
            elseif( in_array( $lastChar, $skiptokenArray ) )
            {
                if( $lasttwoChar == "/*" )
                    PH::print_stdout(  $context->padding."skipped! following token available at lastChar: '".$lasttwoChar."'" );
                else
                {
                    PH::print_stdout(  $context->padding."something needs to be done before: '".$lastChar."'" );
                    $member2 = str_replace( "*", "/*", $member );
                    $object->addMember( $member2 );
                    $object->deleteMember( $member );

                    if( $context->isAPI )
                        $object->API_sync();
                }
            }
            else
            {
                if( $newToken == "*" and $lastChar !== "/" )
                {
                    PH::print_stdout(  $context->padding."skipped! as token: '".$newToken."' - lastchar must be '/' - but this is available: '".$lastChar."'" );
                    continue;
                }

                $object->addMember( $member.$newToken );
                $object->deleteMember( $member );

                if( $context->isAPI )
                    $object->API_sync();
            }
        }
    },
    'args' => array('endingtoken' =>
        array('type' => 'string', 'default' => '/',
            'help' =>
                "supported ending token: '.', '/', '?', '&', '=', ';', '+', '*', '/*' - please be aware for '/*' please use '$$*'\n\n".
                "'actions=custom-url-category-add-ending-token:/' is the default value, it can NOT be run directly\n".
                "please use: 'actions=custom-url-category-add-ending-token' to avoid problems like: '**ERROR** unsupported Action:\"\"'"

        )
    )
);

SecurityProfileCallContext::$supportedActions['custom-url-category-remove-ending-token'] = array(
    'name' => 'custom-url-category-remove-ending-token',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if( get_class( $object) !== "customURLProfile")
            return null;

        $newToken = $context->arguments['endingtoken'];

        if( strpos( $newToken, "$$" ) !== FALSE )
            $newToken = str_replace( "$$", "/", $newToken );

        $tokenArray = array( '.', '/', '?', '&', '=', ';', '+', '*', '/*' );

        if( !in_array( $newToken, $tokenArray ) )
        {
            PH::print_stdout(  "skipped! Token: ".$newToken." is not supported. supported endingTokens: ".implode( ",",$tokenArray) );
            return null;
        }

        foreach( $object->getmembers() as $member )
        {
            PH::print_stdout(  "        - " . $member );
            PH::$JSON_TMP['sub']['object'][$object->name()]['members'][] = $member;

            $lastChar = substr($member, -1);
            if( in_array( $lastChar, $tokenArray ) )
            {
                $tmp = rtrim($member, $lastChar);
                $object->addMember( $tmp );
                $object->deleteMember( $member );

                if( $context->isAPI )
                    $object->API_sync();
            }
        }
    },
    'args' => array('endingtoken' =>
        array('type' => 'string', 'default' => '/',
            'help' =>
                "supported ending token: '.', '/', '?', '&', '=', ';', '+', '*', '/*' - please be aware for '/*' please use '$$*'\n\n".
                "'actions=custom-url-category-add-ending-token:/' is the default value, it can NOT be run directly\n".
                "please use: 'actions=custom-url-category-add-ending-token' to avoid problems like: '**ERROR** unsupported Action:\"\"'"

        )
    )
);

SecurityProfileCallContext::$supportedActions['custom-url-category-fix-leading-dot'] = array(
    'name' => 'custom-url-category-fix-leading-dot',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if( get_class( $object) !== "customURLProfile")
            return null;

        foreach( $object->getmembers() as $member )
        {
            PH::print_stdout(  "        - " . $member );
            PH::$JSON_TMP['sub']['object'][$object->name()]['members'][] = $member;


            $fristChar = substr($member, 0, 1);
            if( $fristChar === "." )
            {
                PH::print_stdout(  "following token available at firstChar: '".$fristChar."' adding '*' at beginning" );
                $object->addMember( "*".$member );
                $object->deleteMember( $member );

                if( $context->isAPI )
                    $object->API_sync();
            }
        }
    }
);

SecurityProfileCallContext::$supportedActions['virus.decoder.best-practice-set'] = array(
    'name' => 'virus.decoder.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "AntiVirusProfile")
            return null;

        $tmp_decoder = DH::findFirstElement('decoder', $object->xmlroot);
        foreach($object->tmp_virus_prof_array as $decoder )
        {
            $xmlNode = DH::findFirstElementByNameAttr("entry", $decoder, $tmp_decoder);

            $actionTypeArray = array( "action", "wildfire-action", "mlav-action" );

            if( $decoder == "http" || $decoder == "https" || $decoder == "ftp" || $decoder == "smb" )
            {
                foreach( $actionTypeArray as $actionType )
                {
                    if( $object->$decoder[$actionType] != "default" && $object->$decoder[$actionType] != "reset-both"  )
                    {
                        $object->$decoder[$actionType] = "reset-both";
                        $action_xmlNode = DH::findFirstElement($actionType, $xmlNode);
                        $action_xmlNode->textContent = "reset-both";
                    }
                }
            }
            else
            {
                foreach( $actionTypeArray as $actionType )
                {
                    if( $object->$decoder[$actionType] != "reset-both"  )
                    {
                        $object->$decoder[$actionType] = "reset-both";
                        $action_xmlNode = DH::findFirstElement($actionType, $xmlNode);
                        $action_xmlNode->textContent = "reset-both";
                    }
                }
            }
        }
    }
);

SecurityProfileCallContext::$supportedActions['virus.inline-ml.best-practice-set'] = array(
    'name' => 'virus.inline-ml.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "AntiVirusProfile")
            return null;

        $tmp_mlav_engine = DH::findFirstElement('mlav-engine-filebased-enabled', $object->xmlroot);
        if( $tmp_mlav_engine !== False )
        {
            foreach ($tmp_mlav_engine->childNodes as $mlav_engine_entry)
            {
                if( $mlav_engine_entry->nodeType != XML_ELEMENT_NODE )
                    continue;

                $name = DH::findAttribute( "name", $mlav_engine_entry);

                $action_xmlNode = DH::findFirstElement("mlav-policy-action", $mlav_engine_entry);
                $action_xmlNode->textContent = "enable";

                $object->additional['mlav-engine-filebased-enabled'][$name]['mlav-policy-action'] = "enable";
            }
        }
    }
);

SecurityProfileCallContext::$supportedActions['virus.best-practice-set'] = array(
    'name' => 'virus.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if( get_class( $object) !== "AntiVirusProfile")
            return null;

        ////////////////////////////////////////////
        $f = SecurityProfileCallContext::$supportedActions['virus.decoder.best-practice-set']['MainFunction'];
        $f($context);

        ////////////////////////////////////////////
        $f = SecurityProfileCallContext::$supportedActions['virus.inline-ml.best-practice-set']['MainFunction'];
        $f($context);


        if( $context->isAPI )
        {
            $object->API_sync();
        }

    },
);

SecurityProfileCallContext::$supportedActions['virus.decoder.alert-only-set'] = array(
    'name' => 'virus.decoder.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "AntiVirusProfile" && get_class( $object) !== "VirusAndWildfireProfile" )
            return null;

        $tmp_decoder = DH::findFirstElement('decoder', $object->xmlroot);
        if( $tmp_decoder === False)
            return null;

        foreach($object->tmp_virus_prof_array as $decoder )
        {
            $xmlNode = DH::findFirstElementByNameAttr("entry", $decoder, $tmp_decoder);

            $actionTypeArray = array( "action", "wildfire-action", "mlav-action" );

            foreach( $actionTypeArray as $actionType )
            {
                $check_array = $object->virus_bp_visibility_JSON( "visibility", "virus", $actionType );

                foreach( $check_array as $check )
                {
                    $final_check = $check;
                    if( str_contains( $final_check, "!" ) )
                        $final_check = str_replace("!", "", $final_check);

                    if (isset($object->$decoder[$actionType]) && $object->$decoder[$actionType] == $final_check)
                    {
                        $object->$decoder[$actionType] = "alert";
                        $action_xmlNode = DH::findFirstElement($actionType, $xmlNode);
                        $action_xmlNode->textContent = "alert";
                    }
                }
            }
        }
    }
);

SecurityProfileCallContext::$supportedActions['virus.inline-ml.alert-only-set'] = array(
    'name' => 'virus.inline-ml.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context)
    {
        $object = $context->object;

        if (get_class($object) !== "AntiVirusProfile" && get_class( $object) !== "VirusAndWildfireProfile" )
            return null;

        $tmp_mlav_engine = DH::findFirstElement('mlav-engine-filebased-enabled', $object->xmlroot);
        if( $tmp_mlav_engine !== False )
        {
            foreach ($tmp_mlav_engine->childNodes as $mlav_engine_entry)
            {
                if( $mlav_engine_entry->nodeType != XML_ELEMENT_NODE )
                    continue;

                $check_array = $object->bp_visibility_JSON( "visibility", "virus");

                if( isset($check_array['inline-policy-action'] ) )
                {
                    foreach ($check_array['inline-policy-action'] as $validate)
                    {
                        foreach( $validate['type'] as $type )
                        {
                            if( $type == 'any' || $type == $mlav_engine_entry )
                            {
                                $final_check = $validate['action'][0];
                                if( str_contains( $final_check, "!" ) )
                                    $final_check = str_replace("!", "", $final_check);

                                $name = DH::findAttribute( "name", $mlav_engine_entry);

                                $action_xmlNode = DH::findFirstElement("mlav-policy-action", $mlav_engine_entry);
                                if( $action_xmlNode->textContent == $final_check )
                                {
                                    $action_xmlNode->textContent = "enable(alert-only)";
                                    $object->additional['mlav-engine-filebased-enabled'][$name]['mlav-policy-action'] = "enable(alert-only)";
                                }
                            }
                        }
                    }
                }
            }
        }
    }
);

SecurityProfileCallContext::$supportedActions['virus.alert-only-set'] = array(
    'name' => 'virus.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if( get_class( $object) !== "AntiVirusProfile")
            return null;

        ///////////////////////////////////////////////////////////////
        $f = SecurityProfileCallContext::$supportedActions['virus.decoder.alert-only-set']['MainFunction'];
        $f($context);


        ///////////////////////////////////////////////////////////////
        $f = SecurityProfileCallContext::$supportedActions['virus.inline-ml.alert-only-set']['MainFunction'];
        $f($context);


        if( $context->isAPI )
        {
            $object->API_sync();
        }

    },
);

SecurityProfileCallContext::$supportedActions['spyware.inline-ml.best-practice-set'] = array(
    'name' => 'spyware.inline-ml.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "AntiSpywareProfile")
            return null;

        $tmp_mlav_engine = DH::findFirstElement('mica-engine-spyware-enabled', $object->xmlroot);
        if( $tmp_mlav_engine !== False )
        {
            $tmp_mlav_engine_enable = DH::findFirstElementOrCreate('cloud-inline-analysis', $object->xmlroot);
            $tmp_mlav_engine_enable->textContent = "yes";

            foreach ($tmp_mlav_engine->childNodes as $mlav_engine_entry)
            {
                if( $mlav_engine_entry->nodeType != XML_ELEMENT_NODE )
                    continue;

                $name = DH::findAttribute( "name", $mlav_engine_entry);

                $action_xmlNode = DH::findFirstElement("inline-policy-action", $mlav_engine_entry);
                $action_xmlNode->textContent = "reset-both";

                $object->additional['mica-engine-spyware-enabled'][$name]['inline-policy-action'] = "reset-both";
            }
        }
        else
        {
            $xmlString = '   <mica-engine-spyware-enabled>
  <entry name="HTTP Command and Control detector">
     <inline-policy-action>reset-both</inline-policy-action>
  </entry>
  <entry name="HTTP2 Command and Control detector">
     <inline-policy-action>reset-both</inline-policy-action>
  </entry>
  <entry name="SSL Command and Control detector">
     <inline-policy-action>reset-both</inline-policy-action>
  </entry>
  <entry name="Unknown-TCP Command and Control detector">
     <inline-policy-action>reset-both</inline-policy-action>
  </entry>
  <entry name="Unknown-UDP Command and Control detector">
     <inline-policy-action>reset-both</inline-policy-action>
  </entry>
</mica-engine-spyware-enabled>';

            if( $object->owner->owner->version >= 102 )
            {
                $xmlElement = DH::importXmlStringOrDie($object->xmlroot->ownerDocument, $xmlString);
                $object->xmlroot->appendChild($xmlElement);

                $tmp_mlav_engine = DH::findFirstElementOrCreate('cloud-inline-analysis', $object->xmlroot);
                $tmp_mlav_engine->textContent = "yes";
                $object->cloud_inline_analysis_enabled = true;

                $object->additional['mica-engine-spyware-enabled']['HTTP Command and Control detector']['inline-policy-action'] = "reset-both";
                $object->additional['mica-engine-spyware-enabled']['HTTP2 Command and Control detector']['inline-policy-action'] = "reset-both";
                $object->additional['mica-engine-spyware-enabled']['SSL Command and Control detector']['inline-policy-action'] = "reset-both";

                $object->additional['mica-engine-spyware-enabled']['Unknown-TCP Command and Control detector']['inline-policy-action'] = "reset-both";
                $object->additional['mica-engine-spyware-enabled']['Unknown-UDP Command and Control detector']['inline-policy-action'] = "reset-both";
            }
        }
    }
);

SecurityProfileCallContext::$supportedActions['spyware.rules.best-practice-set'] = array(
    'name' => 'spyware.rules.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context)
    {
        $object = $context->object;

        if (get_class($object) !== "AntiSpywareProfile")
            return null;

        foreach( $object->rules_obj as $rule )
        {
            /** @var ThreatPolicy $rule */
            if( in_array("high", $rule->severity()) || in_array("critical", $rule->severity()) || in_array("medium", $rule->severity()) )
            {
                if( !in_array("low", $rule->severity()) && !in_array("informational", $rule->severity()) )
                {
                    if( $rule->category() != "brute-force" && $rule->category() != "app-id-change")
                    {
                        $rule->action = "reset-both";

                        //move this to threatPolicyvulnerability create method "setAction($name)"
                        $tmp = DH::findFirstElement("action", $rule->xmlroot);
                        if( $tmp !== FALSE )
                        {
                            $tmp_action = DH::firstChildElement($tmp);
                            if( $tmp_action !== FALSE )
                            {
                                $tmp->removeChild($tmp_action);

                                $xmlString = '<reset-both/>';
                                $xmlElement = DH::importXmlStringOrDie($rule->xmlroot->ownerDocument, $xmlString);
                                $tmp->appendChild($xmlElement);
                            }
                        }

                        $tmp_packet_capture = DH::findFirstElementOrCreate("packet-capture", $rule->xmlroot);
                        $tmp_packet_capture->textContent = "single-packet";
                        $rule->packetCapture = "single-packet";
                    }
                }
            }
        }
    }
);

SecurityProfileCallContext::$supportedActions['spyware.dns.best-practice-set'] = array(
    'name' => 'spyware.dns.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context)
    {
        $object = $context->object;

        if (get_class($object) !== "AntiSpywareProfile" && get_class($object) !== "DNSSecurityProfile")
            return null;

        $rootObject = PH::findRootObjectOrDie($context->object->owner->owner);
        if ( get_class($object) == "AntiSpywareProfile" && $rootObject->isBuckbeak() )
            return null;

        $hasDNSlicense = $context->arguments['has-DNS-license'];
        foreach( $object->dns_rules_obj as $rule )
        {
            $tmp_action = DH::findFirstElementOrCreate("action", $rule->xmlroot);

            if( !$rule->advanced )
            {
                $tmp_packet_capture = DH::findFirstElement("packet-capture", $rule->xmlroot);
                if( $tmp_packet_capture === FALSE )
                    $tmp_packet_capture = DH::findFirstElementOrCreate("packet-capture", $rule->xmlroot);
            }

            $tmp_log_level = DH::findFirstElement("log-level", $rule->xmlroot);
            /** @var DNSPolicy $rule */
            if( $rule->name() == "pan-dns-sec-adtracking"
                || $rule->name() == "pan-dns-sec-ddns"
                || $rule->name() == "pan-dns-sec-recent"
            )
            {
                if( $hasDNSlicense )
                {
                    if( $tmp_action->textContent == "" )
                        $tmp_action->textContent = "allow";
                    if( $tmp_packet_capture->textContent == "" )
                        $tmp_packet_capture->textContent = "single-packet";
                }
                else
                {
                    $tmp_action->textContent = "allow";
                    $tmp_packet_capture->textContent = "disable";
                    $tmp_log_level->textContent = "none";
                }
            }
            elseif( $rule->name() == "pan-dns-sec-parked" )
            {
                if( $hasDNSlicense )
                {
                    if( $tmp_action->textContent == "" )
                        $tmp_action->textContent = "allow";
                    if( $tmp_packet_capture->textContent == "" )
                        $tmp_packet_capture->textContent = "disable";
                }
                else
                {
                    $tmp_action->textContent = "allow";
                    $tmp_packet_capture->textContent = "disable";
                    $tmp_log_level->textContent = "none";
                }
            }
            elseif( $rule->name() == "pan-dns-sec-cc" )
            {
                if( $hasDNSlicense )
                {
                    $tmp_action->textContent = "sinkhole";
                    $tmp_packet_capture->textContent = "extended-capture";
                }
                else
                {
                    $tmp_action->textContent = "allow";
                    $tmp_packet_capture->textContent = "disable";
                    $tmp_log_level->textContent = "none";
                }
            }
            else
            {
                if( $hasDNSlicense )
                {
                    $tmp_action->textContent = "sinkhole";
                    $tmp_packet_capture->textContent = "single-packet";
                }
                else
                {
                    $tmp_action->textContent = "allow";
                    $tmp_packet_capture->textContent = "disable";
                    $tmp_log_level->textContent = "none";
                }
            }
        }
    },
    'args' => array('has-DNS-license' =>
        array('type' => 'bool', 'default' => 'true',
            'help' => "[has-DNS-license] 'spyware.best-practice-set:FALSE' - define correct AS Profile setting if License is NOT available"
        )
    )
);

SecurityProfileCallContext::$supportedActions['spyware.botnet.best-practice-set'] = array(
    'name' => 'spyware.botnet.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "AntiSpywareProfile" && get_class($object) !== "DNSSecurityProfile")
            return null;

        $rootObject = PH::findRootObjectOrDie($context->object->owner->owner);
        if ( get_class($object) == "AntiSpywareProfile" && $rootObject->isBuckbeak() )
            return null;

        $hasDNSlicense = $context->arguments['has-DNS-license'];
        $tmp_rule = DH::findFirstElement('botnet-domains', $object->xmlroot);
        if( $tmp_rule !== FALSE )
        {
            $tmp_lists = DH::findFirstElement('lists', $tmp_rule);
            if ($tmp_lists !== FALSE)
            {
                foreach ($tmp_lists->childNodes as $tmp_entry1)
                {
                    if ($tmp_entry1->nodeType != XML_ELEMENT_NODE)
                        continue;

                    $name = DH::findAttribute("name", $tmp_entry1);
                    $tmp_dnsobj = $object->additional['botnet-domain']['lists'][$name];
                    if( $name == "default-paloalto-dns" )
                    {
                        $tmp = DH::findFirstElement("action", $tmp_entry1);
                        if ($tmp !== FALSE)
                        {
                            $tmp_action = DH::firstChildElement($tmp);
                            if ($tmp_action !== FALSE) {
                                $tmp->removeChild($tmp_action);

                                if( $hasDNSlicense )
                                {
                                    //swaschkut 20251109 - clarified with roland
                                    //this should be kept as sinkhole - also if block is set, change it to sinkhole
                                    $tmp_actionString = "sinkhole";
                                }
                                else
                                    $tmp_actionString = "allow";
                                $xmlString = '<'.$tmp_actionString.'/>';
                                $xmlElement = DH::importXmlStringOrDie($object->xmlroot->ownerDocument, $xmlString);
                                $tmp->appendChild($xmlElement);

                                $tmp_dnsobj->action = $tmp_actionString;
                            }
                        }
                        $tmp = DH::findFirstElement("packet-capture", $tmp_entry1);
                        if ($tmp !== FALSE)
                        {
                            if( $hasDNSlicense )
                            {
                                #$tmp->textContent = "single-packet";
                                $tmp->textContent = "extended-capture";
                            }
                            else
                                $tmp->textContent = "disable";
                        }
                    }
                }
            }
        }
    },
    'args' => array('has-DNS-license' =>
        array('type' => 'bool', 'default' => 'true',
            'help' => "[has-DNS-license] 'spyware.best-practice-set:FALSE' - define correct AS Profile setting if License is NOT available"
        )
    )
);

SecurityProfileCallContext::$supportedActions['spyware.best-practice-set'] = array(
    'name' => 'spyware.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "AntiSpywareProfile")
            return null;

        ////////////////////////////////////////
        //inline
        $f = SecurityProfileCallContext::$supportedActions['spyware.inline-ml.best-practice-set']['MainFunction'];
        $f($context);

        ////////////////////////////////////////
        //rules
        $f = SecurityProfileCallContext::$supportedActions['spyware.rules.best-practice-set']['MainFunction'];
        $f($context);

        ////////////////////////////////////////
        //dns
        $f = SecurityProfileCallContext::$supportedActions['spyware.dns.best-practice-set']['MainFunction'];
        $f($context);

        ////////////////////////////////////////
        //botnet
        $f = SecurityProfileCallContext::$supportedActions['spyware.botnet.best-practice-set']['MainFunction'];
        $f($context);

        if( $context->isAPI )
        {
            $object->API_sync();
        }
    },
    'args' => array('has-DNS-license' =>
        array('type' => 'bool', 'default' => 'true',
            'help' => "[has-DNS-license] 'spyware.best-practice-set:FALSE' - define correct AS Profile setting if License is NOT available"
        )
    )
);
SecurityProfileCallContext::$supportedActions['dns-security.best-practice-set'] = array(
    'name' => 'dns-security.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "DNSSecurityProfile")
            return null;


        ////////////////////////////////////////
        //dns
        $f = SecurityProfileCallContext::$supportedActions['spyware.dns.best-practice-set']['MainFunction'];
        $f($context);

        ////////////////////////////////////////
        //botnet
        $f = SecurityProfileCallContext::$supportedActions['spyware.botnet.best-practice-set']['MainFunction'];
        $f($context);

        if( $context->isAPI )
        {
            $object->API_sync();
        }
    },
    'args' => array('has-DNS-license' =>
        array('type' => 'bool', 'default' => 'true',
            'help' => "[has-DNS-license] 'dns-security.best-practice-set:FALSE' - define correct AS Profile setting if License is NOT available"
        )
    )
);
SecurityProfileCallContext::$supportedActions['spyware.inline-ml.alert-only-set'] = array(
    'name' => 'spyware.inline-ml.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context )
    {
        /** @var AntiSpywareProfile $object */
        $object = $context->object;

        if (get_class($object) !== "AntiSpywareProfile")
        {
            PH::print_stdout("skipped");
            return null;
        }

        $tmp_mlav_engine = DH::findFirstElement('mica-engine-spyware-enabled', $object->xmlroot);
        if( $tmp_mlav_engine !== False )
        {
            $action_other_then_allow_alert = false;
            foreach ($tmp_mlav_engine->childNodes as $mlav_engine_entry)
            {
                if( $mlav_engine_entry->nodeType != XML_ELEMENT_NODE )
                    continue;

                $name = DH::findAttribute( "name", $mlav_engine_entry);

                $action_xmlNode = DH::findFirstElement("inline-policy-action", $mlav_engine_entry);

                if( $action_xmlNode->textContent == "allow" )
                {
                    $action_xmlNode->textContent = "alert";
                    $object->additional['mica-engine-spyware-enabled'][$name]['inline-policy-action'] = "alert";
                }
                elseif( $action_xmlNode->textContent == "alert" )
                {
                }
                elseif( !$object->cloud_inline_analysis_enabled )
                {
                    //explanation:
                    //inline analysis is disabled -> but action is set to block -> not enabled, will not help
                    $action_xmlNode->textContent = "alert";
                    $object->additional['mica-engine-spyware-enabled'][$name]['inline-policy-action'] = "alert";
                }
                else
                {
                    $action_other_then_allow_alert = true;
                }
            }

            if( !$action_other_then_allow_alert )
            {
                $tmp_mlav_engine = DH::findFirstElementOrCreate('cloud-inline-analysis', $object->xmlroot);
                $tmp_mlav_engine->textContent = "yes";
                $object->cloud_inline_analysis_enabled = true;
            }
        }
        else
        {
            $xmlString = '   <mica-engine-spyware-enabled>
  <entry name="HTTP Command and Control detector">
     <inline-policy-action>alert</inline-policy-action>
  </entry>
  <entry name="HTTP2 Command and Control detector">
     <inline-policy-action>alert</inline-policy-action>
  </entry>
  <entry name="SSL Command and Control detector">
     <inline-policy-action>alert</inline-policy-action>
  </entry>
  <entry name="Unknown-TCP Command and Control detector">
     <inline-policy-action>alert</inline-policy-action>
  </entry>
  <entry name="Unknown-UDP Command and Control detector">
     <inline-policy-action>alert</inline-policy-action>
  </entry>
</mica-engine-spyware-enabled>';

            if( $object->owner->owner->version >= 102 )
            {
                $xmlElement = DH::importXmlStringOrDie($object->xmlroot->ownerDocument, $xmlString);
                $object->xmlroot->appendChild($xmlElement);

                $tmp_mlav_engine = DH::findFirstElementOrCreate('cloud-inline-analysis', $object->xmlroot);
                $tmp_mlav_engine->textContent = "yes";
                $object->cloud_inline_analysis_enabled = true;

                $object->additional['mica-engine-spyware-enabled']['HTTP Command and Control detector']['inline-policy-action'] = "alert";
                $object->additional['mica-engine-spyware-enabled']['HTTP2 Command and Control detector']['inline-policy-action'] = "alert";
                $object->additional['mica-engine-spyware-enabled']['SSL Command and Control detector']['inline-policy-action'] = "alert";

                $object->additional['mica-engine-spyware-enabled']['Unknown-TCP Command and Control detector']['inline-policy-action'] = "alert";
                $object->additional['mica-engine-spyware-enabled']['Unknown-UDP Command and Control detector']['inline-policy-action'] = "alert";
            }
        }
    }
);

SecurityProfileCallContext::$supportedActions['spyware.rules.alert-only-set'] = array(
    'name' => 'spyware.rules.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context )
    {
        /** @var AntiSpywareProfile $object */
        $object = $context->object;

        if (get_class($object) !== "AntiSpywareProfile")
        {
            PH::print_stdout("skipped");
            return null;
        }

        $sp_severity = array();
        foreach( $object->rules_obj as $rule )
        {
            /** @var ThreatPolicySpyware $rule */
            $sp_severity = array_merge( $sp_severity, $rule->severity());

            /** @var ThreatPolicy $rule */
            if( $rule->action() == "allow" )
            {
                $rule->action = "alert";

                //move this to threatPolicyvulnerability create method "setAction($name)"
                $tmp = DH::findFirstElement("action", $rule->xmlroot);
                if( $tmp !== FALSE )
                {
                    $tmp_action = DH::firstChildElement($tmp);
                    if( $tmp_action !== FALSE )
                    {
                        $tmp->removeChild($tmp_action);

                        $xmlString = '<alert/>';
                        $xmlElement = DH::importXmlStringOrDie($rule->xmlroot->ownerDocument, $xmlString);
                        $tmp->appendChild($xmlElement);
                    }
                }
            }
        }
        $sp_severity_default = array( "any", "critical", "high", "medium", "low", "informational" );
        $result = array_diff($sp_severity_default, $sp_severity);

        if( !in_array("any", $sp_severity) )
        {
            if( !empty($result) )
            {
                if( in_array("any", $result) )
                {
                    foreach( $result as $rule )
                    {
                        if( $rule == "any" )
                            continue;


                        $threadPolicy_obj = new ThreatPolicySpyware( $rule, $object);
                        $threadPolicy_obj->type = "ThreatPolicySpyware";

                        if( $rule == "critical" || $rule == "high" || $rule == "medium" )
                            $threadPolicy_obj->action = "alert";
                        elseif( $rule == "low" || $rule == "informational" )
                            $threadPolicy_obj->action = "default";

                        $object->rules_obj[] = $threadPolicy_obj;
                        $threadPolicy_obj->addReference( $object );

                        $object->owner->owner->ThreatPolicyStore->add($threadPolicy_obj);

                        $threadPolicy_obj->newThreatPolicyXML($object->xmlroot, $rule, $rule, $threadPolicy_obj->action);
                    }
                }
            }
        }
    }
);

SecurityProfileCallContext::$supportedActions['spyware.dns.alert-only-set'] = array(
    'name' => 'spyware.dns.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context )
    {
        /** @var AntiSpywareProfile $object */
        $object = $context->object;

        if (get_class($object) !== "AntiSpywareProfile" && get_class($object) !== "DNSSecurityProfile")
        {
            PH::print_stdout("skipped");
            return null;
        }

        $rootObject = PH::findRootObjectOrDie($context->object->owner->owner);
        if ( get_class($object) == "AntiSpywareProfile" && $rootObject->isBuckbeak() )
            return null;

        $hasDNSlicense = $context->arguments['has-DNS-license'];
        foreach( $object->dns_rules_obj as $rule )
        {
            $tmp_action = DH::findFirstElement("action", $rule->xmlroot);

            if( !$rule->advanced )
            {
                $tmp_packet_capture = DH::findFirstElement("packet-capture", $rule->xmlroot);
                if( $tmp_packet_capture === FALSE )
                    $tmp_packet_capture = DH::findFirstElementOrCreate("packet-capture", $rule->xmlroot);
            }

            $tmp_log_level = DH::findFirstElement("log-level", $rule->xmlroot);
            if( $tmp_log_level === FALSE )
                $tmp_log_level = DH::findFirstElementOrCreate("log-level", $rule->xmlroot);

            /** @var DNSPolicy $rule */
            if( $rule->action() == "allow" )
            {
                $rule->action = "allow";

                //move this to DNSPolicy create method "setAction($name)"
                if( $hasDNSlicense )
                {
                    if( $tmp_action->textContent == "" )
                        $tmp_action->textContent = "allow";
                    if( $tmp_packet_capture->textContent == "" )
                        $tmp_packet_capture->textContent = "disable";
                    if( $tmp_log_level->textContent == "" || $tmp_log_level->textContent == "none" )
                        $tmp_log_level->textContent = "default";

                }
                else
                {
                    $tmp_action->textContent = "allow";
                    $tmp_packet_capture->textContent = "disable";
                    $tmp_log_level->textContent = "none";
                }
            }
            elseif( $rule->action() == "default" )
            {
                if( $rule->name() == "pan-dns-sec-adtracking"
                    || $rule->name() == "pan-dns-sec-ddns"
                    || $rule->name() == "pan-dns-sec-parked"
                    || $rule->name() == "pan-dns-sec-recent"
                )
                {
                    if( $hasDNSlicense )
                    {
                        if( $tmp_action->textContent == "" )
                            $tmp_action->textContent = "allow";
                        if( $tmp_packet_capture->textContent == "" )
                            $tmp_packet_capture->textContent = "disable";
                        if( $tmp_log_level->textContent == "" || $tmp_log_level->textContent == "none" )
                            $tmp_log_level->textContent = "default";
                    }
                    else
                    {
                        $tmp_action->textContent = "allow";
                        $tmp_packet_capture->textContent = "disable";
                        $tmp_log_level->textContent = "none";
                    }
                }
                else
                {
                    if( $hasDNSlicense )
                    {
                        if( $tmp_action->textContent == "" )
                            $tmp_action->textContent = "allow";
                        if( $tmp_packet_capture->textContent == "" )
                            $tmp_packet_capture->textContent = "disable";
                        if( $tmp_log_level->textContent == "" || $tmp_log_level->textContent == "none" )
                            $tmp_log_level->textContent = "default";
                    }
                    else
                    {
                        $tmp_action->textContent = "allow";
                        $tmp_packet_capture->textContent = "disable";
                        $tmp_log_level->textContent = "none";
                    }
                }
            }
            elseif( $rule->action() == "sinkhole" )
            {
                if( $hasDNSlicense )
                {
                    if( $tmp_action->textContent == "" )
                        $tmp_action->textContent = "sinkhole";
                    if( $tmp_packet_capture->textContent == "" )
                        $tmp_packet_capture->textContent = "disable";
                    if( $tmp_log_level->textContent == "" || $tmp_log_level->textContent == "none" )
                        $tmp_log_level->textContent = "default";
                }
                else
                {
                    $tmp_action->textContent = "allow";
                    $tmp_packet_capture->textContent = "disable";
                    $tmp_log_level->textContent = "none";
                }
            }
        }
    },
    'args' => array('has-DNS-license' =>
        array('type' => 'bool', 'default' => 'true',
            'help' => "[has-DNS-license] 'spyware.best-practice-set:FALSE' - define correct AS Profile setting if License is NOT available"
        )
    )
);

SecurityProfileCallContext::$supportedActions['spyware.botnet.alert-only-set'] = array(
    'name' => 'spyware.botnet.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context )
    {
        /** @var AntiSpywareProfile $object */
        $object = $context->object;

        if (get_class($object) !== "AntiSpywareProfile" && get_class($object) !== "DNSSecurityProfile")
        {
            PH::print_stdout("skipped");
            return null;
        }

        $rootObject = PH::findRootObjectOrDie($context->object->owner->owner);
        if ( get_class($object) == "AntiSpywareProfile" && $rootObject->isBuckbeak() )
            return null;

        $hasDNSlicense = $context->arguments['has-DNS-license'];
        $tmp_rule = DH::findFirstElement('botnet-domains', $object->xmlroot);
        if( $tmp_rule !== FALSE )
        {
            $tmp_lists = DH::findFirstElement('lists', $tmp_rule);
            if ($tmp_lists !== FALSE)
            {
                foreach ($tmp_lists->childNodes as $tmp_entry1)
                {
                    if ($tmp_entry1->nodeType != XML_ELEMENT_NODE)
                        continue;

                    $name = DH::findAttribute("name", $tmp_entry1);
                    /** @var DNSPolicy $tmp_dnsobj */
                    $tmp_dnsobj = $object->additional['botnet-domain']['lists'][$name];
                    if( $tmp_dnsobj->action() == "allow" )
                    {
                        $tmp = DH::findFirstElement("action", $tmp_entry1);
                        if ($tmp !== FALSE)
                        {
                            $tmp_action = DH::firstChildElement($tmp);
                            if ($tmp_action !== FALSE) {
                                $tmp->removeChild($tmp_action);

                                if( $hasDNSlicense )
                                    $tmp_actionString = "alert";
                                else
                                    $tmp_actionString = "allow";

                                $xmlString = '<'.$tmp_actionString.'/>';
                                $xmlElement = DH::importXmlStringOrDie($object->xmlroot->ownerDocument, $xmlString);
                                $tmp->appendChild($xmlElement);

                                $tmp_dnsobj->action = $tmp_actionString;
                            }
                        }
                        $tmp = DH::findFirstElement("packet-capture", $tmp_entry1);
                        if ($tmp !== FALSE)
                        {
                            if( $hasDNSlicense )
                            {
                                //keep what is there before!!!!
                                //$tmp->textContent = "disable";
                            }
                            else
                                $tmp->textContent = "disable";
                        }
                    }
                }
            }
        }
    },
    'args' => array('has-DNS-license' =>
        array('type' => 'bool', 'default' => 'true',
            'help' => "[has-DNS-license] 'spyware.best-practice-set:FALSE' - define correct AS Profile setting if License is NOT available"
        )
    )
);

SecurityProfileCallContext::$supportedActions['spyware.alert-only-set'] = array(
    'name' => 'spyware.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        /** @var AntiSpywareProfile $object */
        $object = $context->object;

        if (get_class($object) !== "AntiSpywareProfile")
        {
            PH::print_stdout("skipped");
            return null;
        }


        /////////////////////////////////////////////////////////
        /// InlineML
        $f = SecurityProfileCallContext::$supportedActions['spyware.inline-ml.alert-only-set']['MainFunction'];
        $f($context);


        /////////////////////////////////////////////////////////
        /// Rules
        $f = SecurityProfileCallContext::$supportedActions['spyware.rules.alert-only-set']['MainFunction'];
        $f($context);


        /////////////////////////////////////////////////////////
        $f = SecurityProfileCallContext::$supportedActions['spyware.dns.alert-only-set']['MainFunction'];
        $f($context);


        /////////////////////////////////////////////////////////
        $f = SecurityProfileCallContext::$supportedActions['spyware.botnet.alert-only-set']['MainFunction'];
        $f($context );


        if( $context->isAPI )
        {
            $object->API_sync();
        }
    },
    'args' => array('has-DNS-license' =>
        array('type' => 'bool', 'default' => 'true',
            'help' => "[has-DNS-license] 'spyware.alert-only-set:FALSE' - define correct AS Profile setting if License is NOT available"
        )
    )
);
SecurityProfileCallContext::$supportedActions['dns-security.alert-only-set'] = array(
    'name' => 'dns-security.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        /** @var DNSSecurityProfile $object */
        $object = $context->object;

        if (get_class($object) !== "DNSSecurityProfile")
        {
            PH::print_stdout("skipped");
            return null;
        }



        /////////////////////////////////////////////////////////
        $f = SecurityProfileCallContext::$supportedActions['spyware.dns.alert-only-set']['MainFunction'];
        $f($context);


        /////////////////////////////////////////////////////////
        $f = SecurityProfileCallContext::$supportedActions['spyware.botnet.alert-only-set']['MainFunction'];
        $f($context );


        if( $context->isAPI )
        {
            $object->API_sync();
        }
    },
    'args' => array('has-DNS-license' =>
        array('type' => 'bool', 'default' => 'true',
            'help' => "[has-DNS-license] 'dns-security.alert-only-set:FALSE' - define correct DNSSecurity Profile setting if License is NOT available"
        )
    )
);
SecurityProfileCallContext::$supportedActions['vulnerability.inline-ml.best-practice-set'] = array(
    'name' => 'vulnerability.inline-ml.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "VulnerabilityProfile")
            return null;

        $tmp_mlav_engine = DH::findFirstElement('cloud-inline-analysis', $object->xmlroot);
        if( $object->owner->owner->version >= 110 )
        {
            if( $tmp_mlav_engine === False )
                $tmp_mlav_engine = DH::findFirstElementOrCreate('cloud-inline-analysis', $object->xmlroot);

            $tmp_mlav_engine->textContent = "yes";
        }


        $tmp_mlav_engine = DH::findFirstElement('mica-engine-vulnerability-enabled', $object->xmlroot);
        if( $object->owner->owner->version >= 110 )
        {
            if ($tmp_mlav_engine === False)
                $tmp_mlav_engine = DH::findFirstElementOrCreate('mica-engine-vulnerability-enabled', $object->xmlroot);
        }
        if( $tmp_mlav_engine !== False )
        {
            if( !$tmp_mlav_engine->hasChildNodes() )
            {
                $xmlString1 = '<entry name="SQL Injection">
  <inline-policy-action>reset-both</inline-policy-action>
</entry>';
                $xmlString2 = '<entry name="Command Injection">
  <inline-policy-action>reset-both</inline-policy-action>
</entry>';
                $xmlElement = DH::importXmlStringOrDie($object->xmlroot->ownerDocument, $xmlString1);
                $tmp_mlav_engine->appendChild($xmlElement);

                $xmlElement = DH::importXmlStringOrDie($object->xmlroot->ownerDocument, $xmlString2);
                $tmp_mlav_engine->appendChild($xmlElement);
            }

            foreach ($tmp_mlav_engine->childNodes as $mlav_engine_entry)
            {
                if( $mlav_engine_entry->nodeType != XML_ELEMENT_NODE )
                    continue;

                $name = DH::findAttribute( "name", $mlav_engine_entry);

                $action_xmlNode = DH::findFirstElementOrCreate("inline-policy-action", $mlav_engine_entry);
                $action_xmlNode->textContent = "reset-both";

                $object->additional['mica-engine-vulnerability-enabled'][$name]['inline-policy-action'] = "reset-both";
            }
        }
    }
);
SecurityProfileCallContext::$supportedActions['vulnerability.rules.best-practice-set'] = array(
    'name' => 'vulnerability.rules.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "VulnerabilityProfile")
            return null;

        foreach( $object->rules_obj as $rule )
        {
            /** @var ThreatPolicy $rule */
            if( in_array("high", $rule->severity()) || in_array("critical", $rule->severity()) || in_array("medium", $rule->severity()) )
            {
                if( !in_array("low", $rule->severity()) && !in_array("informational", $rule->severity()) )
                {
                    $rule->action = "reset-both";

                    //move this to threatPolicyvulnerability create method "setAction($name)"
                    $tmp = DH::findFirstElement("action", $rule->xmlroot);
                    if( $tmp !== FALSE )
                    {
                        $tmp_action = DH::firstChildElement($tmp);
                        if( $tmp_action !== FALSE )
                        {
                            $tmp->removeChild($tmp_action);

                            $xmlString = '<reset-both/>';
                            $xmlElement = DH::importXmlStringOrDie($rule->xmlroot->ownerDocument, $xmlString);
                            $tmp->appendChild($xmlElement);
                        }
                    }

                    $tmp_packet_capture = DH::findFirstElementOrCreate("packet-capture", $rule->xmlroot);
                    $tmp_packet_capture->textContent = "single-packet";
                    $rule->packetCapture = "single-packet";
                }
            }
        }
    }
);
SecurityProfileCallContext::$supportedActions['vulnerability.best-practice-set'] = array(
    'name' => 'vulnerability.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "VulnerabilityProfile")
            return null;

        //////////////////////////////////////////////////////////////////
        /// inline
        $f = SecurityProfileCallContext::$supportedActions['vulnerability.inline-ml.best-practice-set']['MainFunction'];
        $f($context);

        //////////////////////////////////////////////////////////////////
        /// rules
        $f = SecurityProfileCallContext::$supportedActions['vulnerability.rules.best-practice-set']['MainFunction'];
        $f($context);

        if( $context->isAPI )
        {
            $object->API_sync();
        }
    },
);


SecurityProfileCallContext::$supportedActions['vulnerability.inline-ml.alert-only-set'] = array(
    'name' => 'vulnerability.inline-ml.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context )
    {
        $object = $context->object;

        if (get_class($object) !== "VulnerabilityProfile")
            return null;

        $sendAPI = false;
        $tmp_mlav_engine = DH::findFirstElement('cloud-inline-analysis', $object->xmlroot);
        if( $object->owner->owner->version >= 110 )
        {
            if( $tmp_mlav_engine === False )
                $tmp_mlav_engine = DH::findFirstElementOrCreate('cloud-inline-analysis', $object->xmlroot);

            $tmp_mlav_engine->textContent = "yes";
            $sendAPI = true;
        }


        $tmp_mlav_engine = DH::findFirstElement('mica-engine-vulnerability-enabled', $object->xmlroot);
        if( $object->owner->owner->version >= 110 )
        {
            if ($tmp_mlav_engine === False)
                $tmp_mlav_engine = DH::findFirstElementOrCreate('mica-engine-vulnerability-enabled', $object->xmlroot);
        }
        if( $tmp_mlav_engine !== False )
        {
            if( !$tmp_mlav_engine->hasChildNodes() )
            {
                $xmlString1 = '<entry name="SQL Injection">
  <inline-policy-action>alert</inline-policy-action>
</entry>';
                $xmlString2 = '<entry name="Command Injection">
  <inline-policy-action>alert</inline-policy-action>
</entry>';
                $xmlElement = DH::importXmlStringOrDie($object->xmlroot->ownerDocument, $xmlString1);
                $tmp_mlav_engine->appendChild($xmlElement);

                $xmlElement = DH::importXmlStringOrDie($object->xmlroot->ownerDocument, $xmlString2);
                $tmp_mlav_engine->appendChild($xmlElement);

                $sendAPI = true;
            }

            $action_other_then_allow_alert = false;
            foreach ($tmp_mlav_engine->childNodes as $mlav_engine_entry)
            {
                if( $mlav_engine_entry->nodeType != XML_ELEMENT_NODE )
                    continue;

                $name = DH::findAttribute( "name", $mlav_engine_entry);

                $action_xmlNode = DH::findFirstElementOrCreate("inline-policy-action", $mlav_engine_entry);
                if( $action_xmlNode->textContent == "allow" )
                {
                    $action_xmlNode->textContent = "alert";
                    $object->additional['mica-engine-vulnerability-enabled'][$name]['inline-policy-action'] = "alert";

                    $sendAPI = true;
                }
                elseif( $action_xmlNode->textContent == "alert" )
                {

                }
                else
                {
                    $action_other_then_allow_alert = true;
                }
            }

            if( !$action_other_then_allow_alert )
            {
                $tmp_mlav_engine = DH::findFirstElementOrCreate('cloud-inline-analysis', $object->xmlroot);
                $tmp_mlav_engine->textContent = "yes";

                $sendAPI = true;
            }
        }
    }
);

SecurityProfileCallContext::$supportedActions['vulnerability.rules.alert-only-set_OLD'] = array(
    'name' => 'vulnerability.rules.alert-only-set_OLD',
    'MainFunction' => function (SecurityProfileCallContext $context )
    {
        $object = $context->object;

        if (get_class($object) !== "VulnerabilityProfile")
            return null;

        $object->vulnerability_rules_coverage();

        #print_r($object->rule_coverage);

        $sp_severity = array();
        foreach( $object->rules_obj as $rule )
        {
            /** @var ThreatPolicy $rule */
            $sp_severity = array_merge( $sp_severity, $rule->severity());

            if( $rule->action() == "allow" )
            {
                $rule->action = "alert";

                //move this to threatPolicyvulnerability create method "setAction($name)"
                $tmp = DH::findFirstElement("action", $rule->xmlroot);
                if( $tmp !== FALSE )
                {
                    $tmp_action = DH::firstChildElement($tmp);
                    if( $tmp_action !== FALSE )
                    {
                        $tmp->removeChild($tmp_action);

                        $xmlString = '<alert/>';
                        $xmlElement = DH::importXmlStringOrDie($rule->xmlroot->ownerDocument, $xmlString);
                        $tmp->appendChild($xmlElement);

                        $sendAPI = true;
                    }
                }
            }
        }
        $sp_severity_default = array( "any", "critical", "high", "medium", "low", "informational" );
        $result = array_diff($sp_severity_default, $sp_severity);

        if( !in_array("any", $sp_severity) ||
            ( isset($object->rule_coverage["any"]['any'] ) && $object->rule_coverage["any"]['any']['threat-name'] != "any"  ||
              isset($object->rule_coverage["any"]['client'] ) && $object->rule_coverage["any"]['client']['threat-name'] != "any"  ||
              isset($object->rule_coverage["any"]['server'] ) && $object->rule_coverage["any"]['server']['threat-name'] != "any"
            )
        )
        {
            if( !empty($result) )
            {
                if( in_array("any", $result) )
                {
                    foreach ($result as $severity)
                    {
                        //Todo: bug if threat-name != any
                        if ($severity == "any")
                        {
                            print "continue\n";
                            continue;
                        }


                        $threadPolicy_obj = new ThreatPolicyVulnerability($rule, $object);
                        $threadPolicy_obj->type = "ThreatPolicyVulnerability";

                        if( $severity == "critical" || $severity == "high" || $severity == "medium" )
                            $threadPolicy_obj->action = "alert";
                        elseif( $severity == "low" || $severity == "informational" )
                            $threadPolicy_obj->action = "default";

                        $object->rules_obj[] = $threadPolicy_obj;
                        $threadPolicy_obj->addReference($object);

                        $object->owner->owner->ThreatPolicyStore->add($threadPolicy_obj);

                        $threadPolicy_obj->newThreatPolicyXML($object->xmlroot, $severity, $severity, $threadPolicy_obj->action);

                        $sendAPI = true;
                    }
                }
            }
            foreach( $sp_severity_default as $severity )
            {
                if ($severity == "any")
                    continue;

                $object->vulnerability_rules_coverage();
                if( !isset($object->rule_coverage[$severity]['any']) ||
                    ( isset($object->rule_coverage[$severity]['any'] ) && $object->rule_coverage[$severity]['any']['category'] != "any"  ||
                        isset($object->rule_coverage[$severity]['client'] ) && $object->rule_coverage[$severity]['client']['category'] != "any"  ||
                        isset($object->rule_coverage[$severity]['server'] ) && $object->rule_coverage[$severity]['server']['category'] != "any"
                    )
                )
                {
                    $host_types = array("client", "server");
                    foreach($host_types as $host_type)
                    {
                        if( !isset($object->rule_coverage[$severity][$host_type]) ||
                            isset($object->rule_coverage[$severity][$host_type]) && $object->rule_coverage[$severity][$host_type]['category'] != "any"
                        )
                        {
                            $threadPolicy_obj = new ThreatPolicyVulnerability($severity."_".$host_type, $object);
                            $threadPolicy_obj->type = "ThreatPolicyVulnerability";

                            if( $severity == "critical" || $severity == "high" || $severity == "medium" )
                                $threadPolicy_obj->action = "alert";
                            elseif( $severity == "low" || $severity == "informational" )
                                $threadPolicy_obj->action = "default";

                            $threadPolicy_obj->host = $host_type;

                            $object->rules_obj[] = $threadPolicy_obj;
                            $threadPolicy_obj->addReference($object);

                            $object->owner->owner->ThreatPolicyStore->add($threadPolicy_obj);

                            $threadPolicy_obj->newThreatPolicyXML($object->xmlroot, $severity."_".$host_type, $severity, $threadPolicy_obj->action, $threadPolicy_obj->host);

                            $sendAPI = true;
                        }
                        #else
                        #    print "severity already set: ".$severity."\n";
                    }
                }
            }
        }
        #else
        #    print "exit as any is available as severity\n";
    }
);

SecurityProfileCallContext::$supportedActions['vulnerability.rules.alert-only-set_NEW1'] = array(
    'name' => 'vulnerability.rules.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context)
    {
        /** @var VulnerabilityProfile $object */
        $object = $context->object;

        if (get_class($object) !== "VulnerabilityProfile")
            return null;

        $sendAPI = false;

        // 1. Normalize existing rules to "alert" if they are set to "allow"
        $sp_severity = array();
        foreach ($object->rules_obj as $rule)
        {
            /** @var ThreatPolicy $rule */
            $sp_severity = array_merge($sp_severity, $rule->severity());

            if ($rule->action() === "allow")
            {
                $rule->action = "alert";

                $tmp = DH::findFirstElement("action", $rule->xmlroot);
                if ($tmp !== false)
                {
                    $tmp_action = DH::firstChildElement($tmp);
                    if ($tmp_action !== false)
                    {
                        $tmp->removeChild($tmp_action);
                        $xmlElement = DH::importXmlStringOrDie($rule->xmlroot->ownerDocument, '<alert/>');
                        $tmp->appendChild($xmlElement);
                        $sendAPI = true;
                    }
                }
            }
        }

        // Calculate initial rule coverage once action normalizations are complete
        $object->vulnerability_rules_coverage();

        // 2. Check if a valid global 'any' severity threat catch-all rule exists
        $hasValidAnySeverity = false;
        if (in_array("any", $sp_severity))
        {
            $anyCoverage = $object->rule_coverage['any'] ?? [];
            $hasInvalidAnyThreat = false;

            foreach (['any', 'client', 'server'] as $hostType)
            {
                if (isset($anyCoverage[$hostType]))
                {
                    $cfg = $anyCoverage[$hostType];

                    // Global layer validation: check threat-name, cve, and vendor-id safely
                    if (($cfg['threat-name'] ?? 'any') !== 'any' ||
                        ($cfg['cve'] ?? 'any')         !== 'any' ||
                        ($cfg['vendor-id'] ?? 'any')   !== 'any')
                    {
                        $hasInvalidAnyThreat = true;
                        break;
                    }
                }
            }
            if (!$hasInvalidAnyThreat)
                $hasValidAnySeverity = true;
        }

        // 3. Process missing coverages ONLY if a global 'any' catch-all doesn't already handle it
        if (!$hasValidAnySeverity)
        {
            $requiredSeverities = ["critical", "high", "medium", "low", "informational"];
            $actionMap = [
                "critical"      => "alert",
                "high"          => "alert",
                "medium"        => "alert",
                "low"           => "default",
                "informational" => "default"
            ];

            foreach ($requiredSeverities as $severity)
            {
                $coverage = $object->rule_coverage[$severity] ?? [];

                // If a host 'any' rule exists for this specific severity and passes all catch-all checks, skip
                $anyHost = $coverage['any'] ?? null;
                if ($anyHost !== null &&
                    ($anyHost['category'] ?? 'any')  === 'any' &&
                    ($anyHost['cve'] ?? 'any')       === 'any' &&
                    ($anyHost['vendor-id'] ?? 'any') === 'any')
                {
                    continue;
                }

                // Check specific client/server profiles if no host 'any' catch-all is present
                foreach (['client', 'server'] as $host_type)
                {
                    $hostCfg = $coverage[$host_type] ?? null;

                    // Trigger rule creation if the specific host configuration is missing,
                    // or if it exists but narrows down by category, cve, or vendor-id.
                    if ($hostCfg === null ||
                        ($hostCfg['category'] ?? 'any')  !== 'any' ||
                        ($hostCfg['cve'] ?? 'any')       !== 'any' ||
                        ($hostCfg['vendor-id'] ?? 'any') !== 'any')
                    {
                        $ruleName = $severity . "_" . $host_type;
                        $action = $actionMap[$severity] ?? 'default';

                        $threadPolicy_obj = new ThreatPolicyVulnerability($ruleName, $object);
                        $threadPolicy_obj->type = "ThreatPolicyVulnerability";
                        $threadPolicy_obj->action = $action;
                        $threadPolicy_obj->host = $host_type;

                        $object->rules_obj[] = $threadPolicy_obj;
                        $threadPolicy_obj->addReference($object);
                        $object->owner->owner->ThreatPolicyStore->add($threadPolicy_obj);

                        $threadPolicy_obj->newThreatPolicyXML(
                            $object->xmlroot,
                            $ruleName,
                            $severity,
                            $action,
                            $host_type
                        );

                        $sendAPI = true;
                    }
                }
            }

            // Refresh coverage mapping one final time to update cache state
            $object->vulnerability_rules_coverage();

            #if( $sendAPI && $context->isAPI )
            #    $object->API_sync();
        }
    }
);

SecurityProfileCallContext::$supportedActions['vulnerability.rules.alert-only-set'] = array(
    'name' => 'vulnerability.rules.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context)
    {
        /** @var VulnerabilityProfile $object */
        $object = $context->object;

        if (get_class($object) !== "VulnerabilityProfile")
            return null;

        $sendAPI = false;

        // 1. Normalize existing rules to "alert" if they are set to "allow"
        $sp_severity = array();
        foreach ($object->rules_obj as $rule)
        {
            /** @var ThreatPolicy $rule */
            $sp_severity = array_merge($sp_severity, $rule->severity());

            if ($rule->action() === "allow")
            {
                $rule->action = "alert";

                $tmp = DH::findFirstElement("action", $rule->xmlroot);
                if ($tmp !== false)
                {
                    $tmp_action = DH::firstChildElement($tmp);
                    if ($tmp_action !== false)
                    {
                        $tmp->removeChild($tmp_action);
                        $xmlElement = DH::importXmlStringOrDie($rule->xmlroot->ownerDocument, '<alert/>');
                        $tmp->appendChild($xmlElement);
                        $sendAPI = true;
                    }
                }
            }
        }

        // Calculate initial rule coverage once action normalizations are complete
        $object->vulnerability_rules_coverage();

        // 2. Check if a valid global 'any' severity threat catch-all rule exists
        $hasValidAnySeverity = false;
        if (in_array("any", $sp_severity))
        {
            $anyCoverage = $object->rule_coverage['any'] ?? [];
            $hasInvalidAnyThreat = false;

            foreach (['any', 'client', 'server'] as $hostType)
            {
                if (isset($anyCoverage[$hostType]))
                {
                    $cfg = $anyCoverage[$hostType];

                    // Global layer validation: check threat-name, cve, and vendor-id safely
                    if (($cfg['threat-name'] ?? 'any') !== 'any' ||
                        ($cfg['cve'] ?? 'any')         !== 'any' ||
                        ($cfg['vendor-id'] ?? 'any')   !== 'any')
                    {
                        $hasInvalidAnyThreat = true;
                        break;
                    }
                }
            }
            if (!$hasInvalidAnyThreat)
                $hasValidAnySeverity = true;
        }

        // 3. Process missing coverages ONLY if a global 'any' catch-all doesn't already handle it
        if (!$hasValidAnySeverity)
        {
            $requiredSeverities = ["critical", "high", "medium", "low", "informational"];
            $actionMap = [
                "critical"      => "alert",
                "high"          => "alert",
                "medium"        => "alert",
                "low"           => "default",
                "informational" => "default"
            ];

            foreach ($requiredSeverities as $severity)
            {
                $coverage = $object->rule_coverage[$severity] ?? [];

                // A. If a host 'any' rule already exists and passes all catch-all checks, skip entirely
                $anyHost = $coverage['any'] ?? null;
                if ($anyHost !== null &&
                    ($anyHost['category'] ?? 'any')  === 'any' &&
                    ($anyHost['cve'] ?? 'any')       === 'any' &&
                    ($anyHost['vendor-id'] ?? 'any') === 'any')
                {
                    continue;
                }

                // B. OPTIMIZATION: If this severity is completely missing,
                // create ONE clean catch-all rule with host = any.
                if (empty($coverage))
                {
                    $ruleName = $severity;
                    $action = $actionMap[$severity] ?? 'default';

                    $threadPolicy_obj = new ThreatPolicyVulnerability($ruleName, $object);
                    $threadPolicy_obj->type = "ThreatPolicyVulnerability";
                    $threadPolicy_obj->action = $action;
                    $threadPolicy_obj->host = "any";

                    $object->rules_obj[] = $threadPolicy_obj;
                    $threadPolicy_obj->addReference($object);
                    $object->owner->owner->ThreatPolicyStore->add($threadPolicy_obj);

                    $threadPolicy_obj->newThreatPolicyXML(
                        $object->xmlroot,
                        $ruleName,
                        $severity,
                        $action,
                        "any"
                    );

                    $sendAPI = true;
                    continue; // Skip the client/server split loop below
                }

                // C. Fallback: If partial custom rules exist, evaluate client/server individually
                foreach (['client', 'server'] as $host_type)
                {
                    $hostCfg = $coverage[$host_type] ?? null;

                    if ($hostCfg === null ||
                        ($hostCfg['category'] ?? 'any')  !== 'any' ||
                        ($hostCfg['cve'] ?? 'any')       !== 'any' ||
                        ($hostCfg['vendor-id'] ?? 'any') !== 'any')
                    {
                        $ruleName = $severity . "_" . $host_type;
                        $action = $actionMap[$severity] ?? 'default';

                        $threadPolicy_obj = new ThreatPolicyVulnerability($ruleName, $object);
                        $threadPolicy_obj->type = "ThreatPolicyVulnerability";
                        $threadPolicy_obj->action = $action;
                        $threadPolicy_obj->host = $host_type;

                        $object->rules_obj[] = $threadPolicy_obj;
                        $threadPolicy_obj->addReference($object);
                        $object->owner->owner->ThreatPolicyStore->add($threadPolicy_obj);

                        $threadPolicy_obj->newThreatPolicyXML(
                            $object->xmlroot,
                            $ruleName,
                            $severity,
                            $action,
                            $host_type
                        );

                        $sendAPI = true;
                    }
                }
            }

            // Refresh coverage mapping one final time to update cache state
            $object->vulnerability_rules_coverage();

            if( $sendAPI && $context->isAPI )
                $object->API_sync();
        }
    }
);

SecurityProfileCallContext::$supportedActions['vulnerability.alert-only-set'] = array(
    'name' => 'vulnerability.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "VulnerabilityProfile")
            return null;


        ///////////////////////////////////////////////////////////////////////////////////////
        /// InlineML
        $f = SecurityProfileCallContext::$supportedActions['vulnerability.inline-ml.alert-only-set']['MainFunction'];
        $f($context );


        ///////////////////////////////////////////////////////////////////////////////////////
        /// rules
        $f = SecurityProfileCallContext::$supportedActions['vulnerability.rules.alert-only-set']['MainFunction'];
        $f($context );


        //if( $sendAPI && $context->isAPI )
        if( $context->isAPI )
        {
            $object->API_sync();
        }
    },
);

SecurityProfileCallContext::$supportedActions['wildfire.inline-ml.alert-only-set'] = array(
    'name' => 'wildfire.inline-ml.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context )
    {
        $object = $context->object;

        if (get_class($object) !== "WildfireProfile" && get_class( $object) !== "VirusAndWildfireProfile" )
            return null;

        $sendAPI = false;
        $tmp_mlav_engine = DH::findFirstElement('cloud-inline-analysis', $object->xmlroot);
        if ($object->owner->owner->version >= 112)
        {
            if ($tmp_mlav_engine === False)
                $tmp_mlav_engine = DH::findFirstElementOrCreate('cloud-inline-analysis', $object->xmlroot);

            $tmp_mlav_engine->textContent = "yes";
            $sendAPI = true;
        }


        $tmp_mlav_engine = DH::findFirstElement('mica-engine-wildfire-rules', $object->xmlroot);
        if ($object->owner->owner->version >= 112)
        {
            if ($tmp_mlav_engine === False)
                $tmp_mlav_engine = DH::findFirstElementOrCreate('mica-engine-wildfire-rules', $object->xmlroot);
        }
        if ($tmp_mlav_engine !== False)
        {
            if (!$tmp_mlav_engine->hasChildNodes())
            {
                $xmlString1 = '<entry name="wf_inline_alert">
   <application>
    <member>any</member>
   </application>
   <file-type>
    <member>any</member>
   </file-type>
   <direction>both</direction>
   <action>alert</action>
  </entry>';
                $xmlString2 = '<entry name="wf_inline_allow">
   <application>
    <member>any</member>
   </application>
   <file-type>
    <member>any</member>
   </file-type>
   <direction>both</direction>
   <action>allow</action>
  </entry>';
                //if ($object->owner->owner->version == 111 )
                //    $xmlElement = DH::importXmlStringOrDie($object->xmlroot->ownerDocument, $xmlString2);
                //else
                if ($object->owner->owner->version >= 112 )
                    $xmlElement = DH::importXmlStringOrDie($object->xmlroot->ownerDocument, $xmlString1);

                $tmp_mlav_engine->appendChild($xmlElement);

                $sendAPI = true;
            }

            $action_other_then_allow_alert = false;
            foreach ($tmp_mlav_engine->childNodes as $mlav_engine_entry)
            {
                if ($mlav_engine_entry->nodeType != XML_ELEMENT_NODE)
                    continue;

                $name = DH::findAttribute("name", $mlav_engine_entry);

                $action_xmlNode = DH::findFirstElementOrCreate("action", $mlav_engine_entry);
                if ($action_xmlNode->textContent == "allow")
                {
                    if ($object->owner->owner->version >= 112)
                    {
                        $action_xmlNode->textContent = "alert";
                        $object->additional['mica-engine-wildfire-rules'][$name]['action'] = "alert";

                        $sendAPI = true;
                    }
                }
                elseif ($action_xmlNode->textContent == "alert")
                {

                }
                else
                {
                    $action_other_then_allow_alert = true;
                }
            }

            if (!$action_other_then_allow_alert)
            {
                $tmp_mlav_engine = DH::findFirstElementOrCreate('cloud-inline-analysis', $object->xmlroot);
                $tmp_mlav_engine->textContent = "yes";

                $sendAPI = true;
            }
        }
    }
);

SecurityProfileCallContext::$supportedActions['wildfire.rules.alert-only-set'] = array(
    'name' => 'wildfire.rules.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context )
    {
        /** @var WildfireProfile $object */
        $object = $context->object;

        if (get_class($object) !== "WildfireProfile" && get_class( $object) !== "VirusAndWildfireProfile" )
        {
            PH::print_stdout("skipped");
            return null;
        }

        $add_WF_alert = true;
        foreach( $object->rules_obj as $rule )
        {
            /** @var ThreatPolicyWildfire $rule */
            if( ($rule->analysis() == "public-cloud" || $rule->analysis() == "private-cloud" )
                && $rule->direction() == "both"
                && in_array("any", $rule->application() )
                && in_array("any", $rule->filetype() )
            )
            {
                $add_WF_alert = false;
                break;
            }


        }

        if( $add_WF_alert )
        {
            $tmp_name = "alert_vcp";
            $threadPolicy_obj = new ThreatPolicyWildfire( $tmp_name, $object);
            $threadPolicy_obj->type = "ThreatPolicyWildfire";

            $threadPolicy_obj->analysis = "public-cloud";
            $threadPolicy_obj->direction = "both";
            $threadPolicy_obj->filetype[] = "any";
            $threadPolicy_obj->application[] = "any";

            $object->rules_obj[] = $threadPolicy_obj;
            $threadPolicy_obj->addReference( $object );

            $object->owner->owner->ThreatPolicyStore->add($threadPolicy_obj);

            $threadPolicy_obj->newThreatPolicyXML($object->xmlroot, $tmp_name, null, $threadPolicy_obj->action);

            if( $context->isAPI )
                $object->API_sync();
        }

    }
);

SecurityProfileCallContext::$supportedActions['wildfire.alert-only-set'] = array(
    'name' => 'wildfire.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context)
    {
        $object = $context->object;

        if (get_class($object) !== "WildfireProfile")
            return null;

        ///////////////////////////////////////////////////////////////////////////////////////
        /// InlineML
        $f = SecurityProfileCallContext::$supportedActions['wildfire.inline-ml.alert-only-set']['MainFunction'];
        $f($context );


        ///////////////////////////////////////////////////////////////////////////////////////
        /// Rules
        $f = SecurityProfileCallContext::$supportedActions['wildfire.rules.alert-only-set']['MainFunction'];
        $f($context );


        if( $context->isAPI )
        {
            $object->API_sync();
        }
    }
);

SecurityProfileCallContext::$supportedActions['wildfire.inline-ml.best-practice-set'] = array(
    'name' => 'wildfire.inline-ml.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "WildfireProfile" && get_class( $object) !== "VirusAndWildfireProfile" )
            return null;

        $tmp_mlav_engine = DH::findFirstElement('cloud-inline-analysis', $object->xmlroot);
        if( $object->owner->owner->version >= 111 )
        {
            if( $tmp_mlav_engine === False )
                $tmp_mlav_engine = DH::findFirstElementOrCreate('cloud-inline-analysis', $object->xmlroot);

            $tmp_mlav_engine->textContent = "yes";
        }


        $tmp_mlav_engine = DH::findFirstElement('mica-engine-wildfire-rules', $object->xmlroot);
        if( $object->owner->owner->version >= 111 )
        {
            if ($tmp_mlav_engine === False)
                $tmp_mlav_engine = DH::findFirstElementOrCreate('mica-engine-wildfire-rules', $object->xmlroot);
        }
        if( $tmp_mlav_engine !== False )
        {
            if( !$tmp_mlav_engine->hasChildNodes() )
            {
                $xmlString1 = '<entry name="wf_inline_block">
   <application>
    <member>any</member>
   </application>
   <file-type>
    <member>any</member>
   </file-type>
   <direction>both</direction>
   <action>block</action>
  </entry>';
                $xmlElement = DH::importXmlStringOrDie($object->xmlroot->ownerDocument, $xmlString1);
                $tmp_mlav_engine->appendChild($xmlElement);
            }

            foreach ($tmp_mlav_engine->childNodes as $mlav_engine_entry)
            {
                if( $mlav_engine_entry->nodeType != XML_ELEMENT_NODE )
                    continue;

                $name = DH::findAttribute( "name", $mlav_engine_entry);

                $action_xmlNode = DH::findFirstElementOrCreate("action", $mlav_engine_entry);
                $action_xmlNode->textContent = "block";

                $object->additional['mica-engine-wildfire-rules'][$name]['action'] = "block";
            }
        }
    }
);
SecurityProfileCallContext::$supportedActions['wildfire.best-practice-set'] = array(
    'name' => 'wildfire.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "WildfireProfile")
            return null;

        //////////////////////////////////////////////////////////////////////
        /// inline
        $f = SecurityProfileCallContext::$supportedActions['wildfire.inline-ml.best-practice-set']['MainFunction'];
        $f($context );

        if( $context->isAPI )
        {
            $object->API_sync();
        }
    },
);

SecurityProfileCallContext::$supportedActions['virus-and-wildfire.alert-only-set'] = array(
    'name' => 'virus-and-wildfire.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if( get_class( $object) !== "VirusAndWildfireProfile")
            return null;

        ///////////////////////////////////////////////////////////////
        $f = SecurityProfileCallContext::$supportedActions['virus.decoder.alert-only-set']['MainFunction'];
        $f($context);


        ///////////////////////////////////////////////////////////////
        $f = SecurityProfileCallContext::$supportedActions['virus.inline-ml.alert-only-set']['MainFunction'];
        $f($context);

        ///////////////////////////////////////////////////////////////////////////////////////
        /// InlineML
        $f = SecurityProfileCallContext::$supportedActions['wildfire.inline-ml.alert-only-set']['MainFunction'];
        $f($context );


        ///////////////////////////////////////////////////////////////////////////////////////
        /// Rules
        $f = SecurityProfileCallContext::$supportedActions['wildfire.rules.alert-only-set']['MainFunction'];
        $f($context );

        #if( $context->isAPI )
        #    $object->API_sync();

    },
);
SecurityProfileCallContext::$supportedActions['virus-and-wildfire.best-practice-set'] = array(
    'name' => 'wildfire.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "VirusAndWildfireProfile")
            return null;

        //AV
        ////////////////////////////////////////////
        $f = SecurityProfileCallContext::$supportedActions['virus.decoder.best-practice-set']['MainFunction'];
        $f($context);

        ////////////////////////////////////////////
        $f = SecurityProfileCallContext::$supportedActions['virus.inline-ml.best-practice-set']['MainFunction'];
        $f($context);

        //WF
        //////////////////////////////////////////////////////////////////////
        /// inline
        $f = SecurityProfileCallContext::$supportedActions['wildfire.inline-ml.best-practice-set']['MainFunction'];
        $f($context );

        if( $context->isAPI )
        {
            $object->API_sync();
        }
    },
);
SecurityProfileCallContext::$supportedActions['url.alert-only-set'] = array(
    'name' => 'url.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "URLProfile")
            return null;

        /////////////////
        $object->url_siteaccess_set_alertonly();

        /////////////////
        $object->url_credential_set_alertonly();

        ////////////////////////////
        $object->url_inline_cat_set(true);

        ////////////
        $object->url_credential_mode_alertonly();


        if( $context->isAPI )
        {
            $object->API_sync();
        }
    },
);

SecurityProfileCallContext::$supportedActions['url.siteaccess.alert-only-set'] = array(
    'name' => 'url.siteaccess.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "URLProfile")
            return null;

        $object->url_siteaccess_set_alertonly();

        if( $context->isAPI )
        {
            $object->API_sync();
        }
    },
);

SecurityProfileCallContext::$supportedActions['url.credential-enforcement.alert-only-set'] = array(
    'name' => 'url.credential-enforcement.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "URLProfile")
            return null;

        $object->url_credential_set_alertonly();

        if( $context->isAPI )
        {
            $object->API_sync();
        }
    },
);

SecurityProfileCallContext::$supportedActions['url.credential-enforcement.mode.alert-only-set'] = array(
    'name' => 'url.credential-enforcement.mode.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "URLProfile")
            return null;

        $object->url_credential_mode_alertonly();

        if( $context->isAPI )
        {
            $object->API_sync();
        }
    },
);

SecurityProfileCallContext::$supportedActions['url.inline-ml.alert-only-set'] = array(
    'name' => 'url.inline-ml.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "URLProfile")
            return null;

        $object->url_inline_cat_set(true);

        if( $context->isAPI )
        {
            $object->API_sync();
        }
    },
);

SecurityProfileCallContext::$supportedActions['url.best-practice-set'] = array(
    'name' => 'url.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        /** @var URLProfile $object */
        $object = $context->object;

        if (get_class($object) !== "URLProfile")
            return null;

        //call alert-only-set from above
        $f = SecurityProfileCallContext::$supportedActions['url.alert-only-set']['MainFunction'];
        $f($context);


        $alert_xmlnode = DH::findFirstElementOrCreate("alert", $object->xmlroot);

        $check_array = $object->url_siteaccess_bp_visibility_JSON( "bp", "url" );
        if( isset($check_array[0]['type']) )
            $block_categories = $check_array[0]['type'];
        else
            $block_categories = array('command-and-control','compromised-website','grayware','malware','phishing','ransomware','scanning-activity');

        $block_xmlnode = DH::findFirstElementOrCreate("block", $object->xmlroot);
        foreach( $block_categories as $block_category )
        {
            if( !in_array( $block_category, $object->block ) )
            {
                if( in_array( $block_category, $object->alert ) )
                {
                    $key = array_search ($block_category, $object->alert);
                    unset( $object->alert[$key] );
                    $alert_category_xmlnode = DH::findFirstElementByValue("member", $block_category, $alert_xmlnode );
                    $alert_xmlnode->removeChild($alert_category_xmlnode);

                    $object->block[$block_category] = $block_category;

                    $xmlString = '<member>'.$block_category.'</member>';
                    $xmlElement = DH::importXmlStringOrDie($object->xmlroot->ownerDocument, $xmlString);
                    $block_xmlnode->appendChild($xmlElement);
                }
            }
        }

        //credential all from alert to block
        $credential_xmlnode = DH::findFirstElementOrCreate("credential-enforcement", $object->xmlroot);

        $alert_credential_xmlnode = DH::findFirstElementOrCreate("alert", $credential_xmlnode);
        $block_credential_xmlnode = DH::findFirstElementOrCreate("block", $credential_xmlnode);

        if( $alert_credential_xmlnode !== False )
        {
            foreach( $alert_credential_xmlnode->childNodes as $alert_node )
            {
                if( $alert_node->nodeType != XML_ELEMENT_NODE )
                    continue;

                $tmp_name = $alert_node->textContent;

                $clone_node = $alert_node->cloneNode(true);
                if( !in_array($tmp_name, $object->block_credential) )
                {
                    $block_credential_xmlnode->appendChild($clone_node);
                    $object->block_credential[$tmp_name] = $tmp_name;
                }

                $alert_credential_xmlnode->removeChild($alert_node);


                $key = array_search ($tmp_name, $object->allow_credential);
                unset($object->alert_credential[$key]);
            }
            $credential_xmlnode->removeChild($alert_credential_xmlnode);
        }


        foreach( $object->alert_credential as $alert )
        {
            if( !in_array($alert, $object->block_credential) )
            {
                $object->block_credential[$alert] = $alert;

                $xmlString = '<member>'.$alert.'</member>';
                $xmlElement = DH::importXmlStringOrDie($object->xmlroot->ownerDocument, $xmlString);
                $block_credential_xmlnode->appendChild($xmlElement);
            }
        }
        $object->alert_credential = array();


        if( $context->isAPI )
        {
            $object->API_sync();
        }
    },
);
SecurityProfileCallContext::$supportedActions['url.credential-enforcement.mode'] = array(
    'name' => 'url.credential-enforcement.mode',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;
        $modeToSet = $context->arguments['mode'];

        $modeArray = array("disabled", "ip-user","domain-credentials","group-mapping");
        if( !in_array($modeToSet, $modeArray) )
            derr( "mode $modeToSet is not a supported mode. supported: '".implode(",", $modeArray)."'", null, FALSE );

        if (get_class($object) !== "URLProfile")
            return null;

        #$modeToSet = "ip-user";

        $credentialEnforcement_Node = DH::findFirstElementOrCreate("credential-enforcement", $object->xmlroot);
        $mode_Node = DH::findFirstElementOrCreate("mode", $credentialEnforcement_Node);
        DH::clearDomNodeChilds($mode_Node);
        $modeToSet_Node = DH::findFirstElementOrCreate($modeToSet, $mode_Node);

        if( $modeToSet == "group-mapping" )
        {
            //<group-mapping>any</group-mapping>
            $modeToSet_Node->textContent = "any";
        }


        if( $context->isAPI )
            $object->api_sync();
    },
    'args' => array(
        'mode' => array('type' => 'string', 'default' => '*nodefault*',
            'help' => '"disabled", "ip-user","domain-credentials","group-mapping"'),
    ),
);
SecurityProfileCallContext::$supportedActions['url.credential-enforcement.log-severity'] = array(
    'name' => 'url.credential-enforcement.log-severity',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;
        $severityToSet = $context->arguments['severity'];;

        $severityArray = array("critical", "high","medium","low","informational");
        if( !in_array($severityToSet, $severityArray) )
            derr( "severity $severityToSet is not a supported mode. supported: '".implode(",", $severityArray)."'", null, FALSE );

        if (get_class($object) !== "URLProfile")
            return null;

        $credentialEnforcement_Node = DH::findFirstElementOrCreate("credential-enforcement", $object->xmlroot);
        $severity_Node = DH::findFirstElementOrCreate("log-severity", $credentialEnforcement_Node);
        $severity_Node->textContent = $severityToSet;

        if( $context->isAPI )
            $object->api_sync();
    },
    'args' => array(
        'severity' => array('type' => 'string', 'default' => '*nodefault*',
            'help' => '"critical", "high","medium","low","informational"'),
    ),
);

SecurityProfileCallContext::$supportedActions[] = array(
    'name' => 'move',
    'MainFunction' => function (SecurityProfileCallContext $context) {
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
                $object->owner->API_removeSecurityProfile($object);
                $targetStore->API_addSecurityProfile($object);

                $object->API_sync();
                $context->connector->sendDeleteRequest($oldXpath);
            }
            else
            {
                $object->owner->removeSecurityProfile($object);
                $targetStore->addSecurityProfile($object);
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

SecurityProfileCallContext::$supportedActions['file-blocking.rules.alert-only-set'] = array(
    'name' => 'file-blocking.rules.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context )
    {
        /** @var FileBlockingProfile $object */
        $object = $context->object;

        if (get_class($object) !== "FileBlockingProfile")
        {
            PH::print_stdout("skipped");
            return null;
        }

        $add_FB_alert = true;
        foreach( $object->rules_obj as $rule )
        {
            /** @var ThreatPolicyFileBlocking $rule */
            if( $rule->action() == "alert"
                && $rule->direction() == "both"
                && in_array("any", $rule->application() )
                && in_array("any", $rule->filetype() )
            )
            {
                $add_FB_alert = false;
                break;
            }

        }

        if( $add_FB_alert )
        {
            $tmp_name = "alert_vcp";
            $threadPolicy_obj = new ThreatPolicyFileBlocking( $tmp_name, $object);
            $threadPolicy_obj->type = "ThreatPolicyFileBlocking";

            $threadPolicy_obj->action = "alert";
            $threadPolicy_obj->direction = "both";
            $threadPolicy_obj->filetype[] = "any";
            $threadPolicy_obj->application[] = "any";

            $object->rules_obj[] = $threadPolicy_obj;
            $threadPolicy_obj->addReference( $object );

            $object->owner->owner->ThreatPolicyStore->add($threadPolicy_obj);

            $threadPolicy_obj->newThreatPolicyXML($object->xmlroot, $tmp_name, null, $threadPolicy_obj->action);

            if( $context->isAPI )
                $object->API_sync();
        }

    }
);

SecurityProfileCallContext::$supportedActions['file-blocking.alert-only-set'] = array(
    'name' => 'file-blocking.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if( get_class( $object) !== "FileBlockingProfile")
            return null;

        ///////////////////////////////////////////////////////////////
        $f = SecurityProfileCallContext::$supportedActions['file-blocking.rules.alert-only-set']['MainFunction'];
        $f($context);


        if( $context->isAPI )
        {
            $object->API_sync();
        }

    },
);


SecurityProfileCallContext::$supportedActions[] = array(
    'name' => 'move_from-shared_to_lowest_possible_DG',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        $localLocation = 'shared';

        if( !$object->owner->owner->isPanorama() && !$object->owner->owner->isFirewall() )
            $localLocation = $object->owner->owner->name();

        if( $localLocation !== 'shared' )
        {
            $string = "because original location is NOT shared";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
        }


        $reflocations = $object->getReferencesLocation();
        $rootObject = PH::findRootObjectOrDie($object->owner->owner);
        $spStore = get_class($object)."Store";

        if( count($reflocations) > 1 )
        {
            //calculate foreach reflocation the DG hierarchy array;
            $data = array();
            foreach( $reflocations as $reflocation )
            {
                /** @var DeviceGroup $findSubSystem */
                $findSubSystem = $rootObject->findSubSystemByName($reflocation);
                if( $findSubSystem === null )
                    derr("cannot find VSYS/DG named '$reflocation'");

                if( get_class($findSubSystem) == "DeviceGroup" )
                {
                    $parentDGS = $findSubSystem->parentDeviceGroups();
                    $parentDGS['shared'] = $findSubSystem->owner;


                    $tmp_padding = "";

                    $data[] = array_reverse(array_keys($parentDGS));
                }
            }

            $common = array_values(array_intersect(...$data));
            $lastKey = array_key_last($common);
            $lastValue = $common[$lastKey];

            PH::print_stdout("       * targetLocation: ".$lastValue);

            $targetLocation = $lastValue;
            $targetStore = null;

            if( $localLocation == $targetLocation )
            {
                $string = "because original and target destinations are the same: $targetLocation";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }

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
        }
        elseif( count($reflocations) == 1 )
        {
            $targetLocation = array_key_last($reflocations);

            PH::print_stdout("       * targetLocation: ".$targetLocation);

            if( $localLocation == $targetLocation )
            {
                $string = "because original and target destinations are the same: $targetLocation";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }

            $findSubSystem = $rootObject->findSubSystemByName($targetLocation);
            if( $findSubSystem === null )
                derr("cannot find VSYS/DG named '$targetLocation'");

            $targetStore = $findSubSystem->$spStore;
        }
        elseif( count($reflocations) == 0 )
        {
            $string = "because object is NOT used - can be deleted";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }




        /////////////////////////////////////////////////
        if( $localLocation == 'shared' )
        {
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

        /////////////////////////////////////////////////////////
        //Todo - move action from there

        $conflictObject = $targetStore->find($object->name(), null, FALSE);
        if( $conflictObject === null )
        {
            $string = "moved, no conflict";
            PH::ACTIONlog( $context, $string );

            //Todo: update remove and add SP object
            if( $context->isAPI )
            {
                $oldXpath = $object->getXPath();
                $object->owner->API_removeSecurityProfile($object);
                $targetStore->API_addSecurityProfile($object);

                $object->API_sync();
                $context->connector->sendDeleteRequest($oldXpath);
            }
            else
            {
                $object->owner->removeSecurityProfile($object);
                $targetStore->addSecurityProfile($object);
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

    }
);