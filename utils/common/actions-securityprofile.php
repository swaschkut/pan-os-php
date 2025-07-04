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

SecurityProfileCallContext::$supportedActions['deleteforce'] = array(
    'name' => 'deleteForce',
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
            $headers .= '<th>BP</th>';
        if( $visibility )
            $headers .= '<th>visibility</th>';
        if( $adoption )
            $headers .= '<th>adoption</th>';

        $headers .= '<th>exception</th>';
        if( $bestPractice )
            $headers .= '<th>BP</th>';
        if( $visibility )
            $headers .= '<th>visibility</th>';

        $headers .= '<th>DNS lists</th>';
        if( $bestPractice )
            $headers .= '<th>BP</th>';
        if( $visibility )
            $headers .= '<th>visibility</th>';

        $headers .= '<th>DNS sinkhole</th><th>DNS security</th>';
        if( $bestPractice )
            $headers .= '<th>BP</th>';
        if( $visibility )
            $headers .= '<th>visibility</th>';

        $headers .= '<th>DNS whitelist</th><th>mica-engine</th>';
        if( $bestPractice )
            $headers .= '<th>BP</th>';
        if( $visibility )
            $headers .= '<th>visibility</th>';



        if( $bestPractice )
        {
            $headers .= '<th>URL BP</th>';
            $headers .= '<th>URL BP details</th>';

            $headers .= '<th>URL credentials BP details</th>';

            $headers .= '<th>URL credentials BP TAB details</th>';
        }

        if( $visibility )
        {
            $headers .= '<th>URL visibility</th>';
            $headers .= '<th>URL visibility details</th>';

            $headers .= '<th>URL credentials visibility details</th>';

            $headers .= '<th>URL credentials visibility TAB details</th>';
        }
        if( $adoption )
        {
            $headers .= '<th>URL adoption</th>';
        }

        if( $addURLmembers or ( !$bestPractice and !$visibility ) )
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

                /** @var AntiVirusProfile|AntiSpywareProfile|customURLProfile|DataFilteringProfile|FileBlockingProfile|PredefinedSecurityProfileURL|URLProfile|VulnerabilityProfile|WildfireProfile $object */
                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $context->encloseFunction( (string)$count );

                if( $object->owner->owner === null )
                {
                    $lines .= $context->encloseFunction('predefined');
                }
                else
                {
                    if( $object->owner->owner !== null && ( $object->owner->owner->isPanorama() || $object->owner->owner->isFirewall() ) )
                        $lines .= $context->encloseFunction('shared');
                    else
                        $lines .= $context->encloseFunction($object->owner->owner->name());
                }


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
                            if( $object->is_best_practice() && $object->spyware_dns_security_best_practice() && $object->spyware_dnslist_best_practice() )
                                $lines .= $context->encloseFunction($bp_text_yes);
                            else
                                $lines .= $context->encloseFunction($bp_text_no);
                        }

                        if( $visibility )
                        {
                            if( $object->is_visibility() && $object->spyware_dns_security_visibility() && $object->spyware_dnslist_visibility() )
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

                if( !empty( $object->rules_obj ) )
                {
                    $tmp_array = array();
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
                                $tmp_string .= $bp_NOT_sign;
                            if( !$rule->fileblocking_rule_visibility() && $visibility )
                                $tmp_string .= $visible_NOT_sign;
                        }
                        $tmp_array[] = $tmp_string;
                    }


                    $lines .= $context->encloseFunction( $tmp_array );
                }
                elseif( !empty( $object->tmp_virus_prof_array ) )
                {
                    $array = array();
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
                    $lines .= $context->encloseFunction($array);
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
                            if( $object->av_action_visibility() && $object->av_wildfireaction_visibility() && $object->av_mlavaction_is_visibility() )
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
                                $lines .= $context->encloseFunction($bp_text_no.' NO BP FB rules');
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
                                foreach( $object->additional['botnet-domain']['lists'] as $name => $value )
                                {
                                    $string = $name." -  action: ".$value['action'];
                                    if( isset($value['packet-capture']) )
                                    {
                                        //Todo: this is still hardcoded - how to use BP JSON file???
                                        //PH::$shadow_bp_jsonfile
                                        $string .= " -  packet-capture: ".$value['packet-capture'];
                                        if( $bestPractice && $name == "default-paloalto-dns" )
                                        {
                                            if( $value['action'] != "sinkhole" && ($value['packet-capture'] != "single-packet" || $value['packet-capture'] != "extended-capture" ) )
                                                $string .= $bp_NOT_sign;
                                        }
                                        if( $visibility && $name == "default-paloalto-dns" )
                                        {
                                            if( $value['action'] == "allow" )
                                                $string .= $visible_NOT_sign;
                                        }
                                    }

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
                                        foreach( $check_array['inline-policy-action'] as $validate )
                                            $bp_set = $object->bp_stringValidation($array, 'inline-policy-action', $validate);
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
                                        foreach( $check_array['inline-policy-action'] as $validate )
                                            $bp_set = $object->visibility_stringValidation($array, 'inline-policy-action', $validate);
                                        if($bp_set == FALSE)
                                            $tmp_string .= $visible_NOT_sign;
                                    }
                                }
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
                                        foreach( $check_array['inline-policy-action'] as $validate )
                                            $bp_set = $object->bp_stringValidation($array, 'inline-policy-action', $validate);
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
                                        foreach( $check_array['inline-policy-action'] as $validate )
                                            $bp_set = $object->visibility_stringValidation($array, 'inline-policy-action', $validate);
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
                                        foreach( $check_array['inline-policy-action'] as $validate )
                                            $bp_set = $object->bp_stringValidation($array, 'mlav-policy-action', $validate);
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
                                        foreach( $check_array['inline-policy-action'] as $validate )
                                            $bp_set = $object->visibility_stringValidation($array, 'mlav-policy-action', $validate);
                                        if($bp_set == FALSE)
                                            $tmp_string .= $visible_NOT_sign;
                                    }
                                }
                            }

                            $string_mica_engine[] = $tmp_string;
                        }

                    }
                }

                //<th>DNS lists</th>
                $lines .= $context->encloseFunction($string_dns_list);
                if( $bestPractice || $visibility)
                {
                    if( get_class($object) == "AntiSpywareProfile" )
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
                    if( get_class($object) == "AntiSpywareProfile" && $object->owner->owner->version >= 102 )
                    {
                        if( $bestPractice )
                        {
                            if( $object->spyware_dns_security_best_practice() )
                                $lines .= $context->encloseFunction($bp_text_yes.' BP AS dns_security set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO BP AS dns_security');
                        }
                        if( $visibility )
                        {
                            if( $object->spyware_dns_security_visibility() )
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

                $lines .= $context->encloseFunction($string_mica_engine);
                if( $bestPractice || $visibility)
                {
                    if( (get_class($object) == "AntiSpywareProfile" && $object->owner->owner->version >= 102 ) || (get_class($object) == "VulnerabilityProfile" && $object->owner->owner->version >= 110 ) || get_class($object) == "AntiVirusProfile" )
                    {
                        if( $bestPractice )
                        {
                            if( $object->cloud_inline_analysis_best_practice($object->owner->bp_json_file) )
                                $lines .= $context->encloseFunction($bp_text_yes.' BP mica_engine set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO BP mica_engine');
                        }
                        if( $visibility )
                        {
                            if( $object->cloud_inline_analysis_visibility($object->owner->bp_json_file) )
                                $lines .= $context->encloseFunction($bp_text_yes.' Visibility mica_engine set');
                            else
                                $lines .= $context->encloseFunction($bp_text_no.' NO Visibility mica_engine');
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
                    }
                    if( $visibility )
                    {
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                    }

                    if( !$bestPractice and !$visibility )
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
                        if( isset($check_array[0]['type']) )
                            $block_categories = $check_array[0]['type'];
                        else
                            $block_categories = array('command-and-control','compromised-website','grayware','malware','phishing','ransomware','scanning-activity');

                        $notBlock = array();
                        foreach( $block_categories as $block_category )
                        {
                            if( !in_array( $block_category, $object->block ) )
                                $notBlock[] = $block_category;

                        }
                        if( !empty($notBlock) )
                        {
                            $tmp_array[] = 'BLOCK missing: ';
                            $tmp_array = array_merge( $tmp_array, $notBlock );
                        }
                        else
                            $tmp_array[] = "yes";

                        $lines .= $context->encloseFunction($tmp_array);
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
                        if( isset($check_array[0]['type']) )
                            $block_categories = $check_array[0]['type'];
                        else
                            $block_categories = array('command-and-control','compromised-website','grayware','malware','phishing','ransomware','scanning-activity');

                        $notBlock = array();
                        foreach( $block_categories as $block_category )
                        {
                            if( !in_array( $block_category, $object->block_credential ) )
                                $notBlock[] = $block_category;

                        }
                        if( !empty($notBlock) )
                        {
                            $tmp_array[] = 'BLOCK missing: ';
                            $tmp_array = array_merge( $tmp_array, $notBlock );
                        }
                        else
                            $tmp_array[] = "yes";

                        $lines .= $context->encloseFunction($tmp_array);
                    }
                    if( $bestPractice )
                    {
                        //<th>URL credentials TAB</th>
                        if( $object->url_usercredentialsubmission_best_practice_tab() )
                            $lines .= $context->encloseFunction($bp_text_yes);
                        else
                            $lines .= $context->encloseFunction($bp_text_no);
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
                        if( $object->url_usercredentialsubmission_visibility_tab() )
                            $lines .= $context->encloseFunction($bp_text_yes);
                        else
                            $lines .= $context->encloseFunction($bp_text_no);
                    }

                    if( $adoption )
                    {
                        if( $object->is_adoption() )
                            $lines .= $context->encloseFunction($bp_text_yes.' Adoption URL set');
                        else
                            $lines .= $context->encloseFunction($bp_text_no.' NO Adoption URL set');
                    }

                    if( $addURLmembers or ( !$bestPractice and !$visibility and !$adoption ) )
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
                    }
                    if( $visibility )
                    {
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                        $lines .= $context->encloseFunction('---');
                    }
                    if( $adoption )
                        $lines .= $context->encloseFunction('---');
                    if( $addURLmembers or ( !$bestPractice and !$visibility ) )
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

        $content = file_get_contents(dirname(__FILE__) . '/html/export-template.html');
        $content = str_replace('%TableHeaders%', $headers, $content);

        $content = str_replace('%lines%', $lines, $content);

        $jscontent = file_get_contents(dirname(__FILE__) . '/html/jquery.min.js');
        $jscontent .= "\n";
        $jscontent .= file_get_contents(dirname(__FILE__) . '/html/jquery.stickytableheaders.min.js');
        $jscontent .= "\n\$('table').stickyTableHeaders();\n";

        $content = str_replace('%JSCONTENT%', $jscontent, $content);

        file_put_contents($filename, $content);


        file_put_contents($filename, $content);
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
SecurityProfileCallContext::$supportedActions['virus.best-practice-set'] = array(
    'name' => 'virus.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if( get_class( $object) !== "AntiVirusProfile")
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


        if( $context->isAPI )
        {
            $object->API_sync();
        }

    },
);
SecurityProfileCallContext::$supportedActions['virus.alert-only-set'] = array(
    'name' => 'virus.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if( get_class( $object) !== "AntiVirusProfile")
            return null;

        $tmp_decoder = DH::findFirstElement('decoder', $object->xmlroot);
        foreach($object->tmp_virus_prof_array as $decoder )
        {
            $xmlNode = DH::findFirstElementByNameAttr("entry", $decoder, $tmp_decoder);

            $actionTypeArray = array( "action", "wildfire-action", "mlav-action" );

            foreach( $actionTypeArray as $actionType )
            {
                if ($object->$decoder[$actionType] == "allow") {
                    $object->$decoder[$actionType] = "alert";
                    $action_xmlNode = DH::findFirstElement($actionType, $xmlNode);
                    $action_xmlNode->textContent = "alert";
                }
            }
        }

        $tmp_mlav_engine = DH::findFirstElement('mlav-engine-filebased-enabled', $object->xmlroot);
        if( $tmp_mlav_engine !== False )
        {
            foreach ($tmp_mlav_engine->childNodes as $mlav_engine_entry)
            {
                if( $mlav_engine_entry->nodeType != XML_ELEMENT_NODE )
                    continue;

                $name = DH::findAttribute( "name", $mlav_engine_entry);

                $action_xmlNode = DH::findFirstElement("mlav-policy-action", $mlav_engine_entry);
                if( $action_xmlNode->textContent == "disable" )
                {
                    $action_xmlNode->textContent = "enable(alert-only)";
                    $object->additional['mlav-engine-filebased-enabled'][$name]['mlav-policy-action'] = "enable(alert-only)";
                }
            }
        }


        if( $context->isAPI )
        {
            $object->API_sync();
        }

    },
);
SecurityProfileCallContext::$supportedActions['spyware.best-practice-set'] = array(
    'name' => 'spyware.best-practice-set',
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

        $hasDNSlicense = $context->arguments['has-DNS-license'];
        foreach( $object->dns_rules_obj as $rule )
        {
            $tmp_action = DH::findFirstElementOrCreate("action", $rule->xmlroot);
            $tmp_packet_capture = DH::findFirstElementOrCreate("packet-capture", $rule->xmlroot);
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
                    if( $name == "default-paloalto-dns" )
                    {
                        $tmp = DH::findFirstElement("action", $tmp_entry1);
                        if ($tmp !== FALSE)
                        {
                            $tmp_action = DH::firstChildElement($tmp);
                            if ($tmp_action !== FALSE) {
                                $tmp->removeChild($tmp_action);

                                if( $hasDNSlicense )
                                    $tmp_actionString = "sinkhole";
                                else
                                    $tmp_actionString = "allow";
                                $xmlString = '<'.$tmp_actionString.'/>';
                                $xmlElement = DH::importXmlStringOrDie($rule->xmlroot->ownerDocument, $xmlString);
                                $tmp->appendChild($xmlElement);

                                $object->additional['botnet-domain']['lists'][$name]['action'] = $tmp_actionString;
                            }
                        }
                        $tmp = DH::findFirstElement("packet-capture", $tmp_entry1);
                        if ($tmp !== FALSE)
                        {
                            if( $hasDNSlicense )
                                #$tmp->textContent = "single-packet";
                                $tmp->textContent = "extended-packet";
                            else
                                $tmp->textContent = "disable";
                        }
                    }
                }
            }
        }

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


        $hasDNSlicense = $context->arguments['has-DNS-license'];
        foreach( $object->dns_rules_obj as $rule )
        {
            $tmp_action = DH::findFirstElement("action", $rule->xmlroot);
            $tmp_packet_capture = DH::findFirstElement("packet-capture", $rule->xmlroot);
            if( $tmp_packet_capture === FALSE )
                $tmp_packet_capture = DH::findFirstElementOrCreate("packet-capture", $rule->xmlroot);
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
                    }
                    else
                    {
                        $tmp_action->textContent = "allow";
                        $tmp_packet_capture->textContent = "disable";
                        $tmp_log_level->textContent = "none";
                    }
                }
            }
        }

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
                    if( $object->additional['botnet-domain']['lists'][$name]['action'] == "allow" )
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
                                $xmlElement = DH::importXmlStringOrDie($rule->xmlroot->ownerDocument, $xmlString);
                                $tmp->appendChild($xmlElement);

                                $object->additional['botnet-domain']['lists'][$name]['action'] = $tmp_actionString;
                            }
                        }
                        $tmp = DH::findFirstElement("packet-capture", $tmp_entry1);
                        if ($tmp !== FALSE)
                        {
                            if( $hasDNSlicense )
                                $tmp->textContent = "disable";
                            else
                                $tmp->textContent = "disable";
                        }
                    }
                }
            }
        }

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
SecurityProfileCallContext::$supportedActions['vulnerability.best-practice-set'] = array(
    'name' => 'vulnerability.best-practice-set',
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

        if( $context->isAPI )
        {
            $object->API_sync();
        }
    },
);
SecurityProfileCallContext::$supportedActions['vulnerability.alert-only-set'] = array(
    'name' => 'vulnerability.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
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

        if( !in_array("any", $sp_severity) )
        {
            if( !empty($result) )
            {
                if( in_array("any", $result) )
                {
                    foreach ($result as $rule)
                    {
                        if ($rule == "any")
                            continue;

                        $threadPolicy_obj = new ThreatPolicyVulnerability($rule, $object);
                        $threadPolicy_obj->type = "ThreatPolicyVulnerability";

                        if( $rule == "critical" || $rule == "high" || $rule == "medium" )
                            $threadPolicy_obj->action = "alert";
                        elseif( $rule == "low" || $rule == "informational" )
                            $threadPolicy_obj->action = "default";

                        $object->rules_obj[] = $threadPolicy_obj;
                        $threadPolicy_obj->addReference($object);

                        $object->owner->owner->ThreatPolicyStore->add($threadPolicy_obj);

                        $threadPolicy_obj->newThreatPolicyXML($object->xmlroot, $rule, $rule, $threadPolicy_obj->action);

                        $sendAPI = true;
                    }
                }
            }
            foreach( $sp_severity_default as $severity )
            {
                if ($severity == "any")
                    continue;

                $object->vulnerability_rules_coverage();
                if( !isset($object->rule_coverage[$severity]['any']) )
                {
                    $host_types = array("client", "server");
                    foreach($host_types as $host_type)
                    {
                        if( !isset($object->rule_coverage[$severity][$host_type]))
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
                    }
                }
            }
        }


        if( $sendAPI && $context->isAPI )
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

        $allow_xmlnode = DH::findFirstElement("allow", $object->xmlroot);
        $alert_xmlnode = DH::findFirstElementOrCreate("alert", $object->xmlroot);
        if( $allow_xmlnode !== False )
        {
            foreach( $allow_xmlnode->childNodes as $allow_node )
            {
                if( $allow_node->nodeType != XML_ELEMENT_NODE )
                    continue;

                $tmp_name = $allow_node->textContent;

                $custom_url_category_obj = $object->owner->owner->customURLProfileStore->find($tmp_name);
                if( $custom_url_category_obj !== NULL )
                    continue;


                $clone_node = $allow_node->cloneNode(true);
                $alert_xmlnode->appendChild($clone_node);
                $allow_xmlnode->removeChild($allow_node);


                $key = array_search ($tmp_name, $object->allow);
                unset($object->allow[$key]);
            }
            if( empty($object->allow) )
                $object->xmlroot->removeChild($allow_xmlnode);
        }

        foreach( $object->allow as $allow )
        {
            $custom_url_category_obj = $object->owner->owner->customURLProfileStore->find($allow);
            if( $custom_url_category_obj !== NULL )
                continue;


            $object->alert[] = $allow;

            $xmlString = '<member>'.$allow.'</member>';
            $xmlElement = DH::importXmlStringOrDie($object->xmlroot->ownerDocument, $xmlString);
            $alert_xmlnode->appendChild($xmlElement);
        }
        $object->allow = array();

        $credential_xmlnode = DH::findFirstElementOrCreate("credential-enforcement", $object->xmlroot);
        $allow_credential_xmlnode = DH::findFirstElement("allow", $credential_xmlnode);
        $alert_credential_xmlnode = DH::findFirstElementOrCreate("alert", $credential_xmlnode);
        if( $allow_credential_xmlnode !== False )
        {
            foreach( $allow_credential_xmlnode->childNodes as $allow_node )
            {
                if( $allow_node->nodeType != XML_ELEMENT_NODE )
                    continue;

                $tmp_name = $allow_node->textContent;

                $custom_url_category_obj = $object->owner->owner->customURLProfileStore->find($tmp_name);
                if( $custom_url_category_obj !== NULL )
                    continue;

                $clone_node = $allow_node->cloneNode(true);
                $alert_credential_xmlnode->appendChild($clone_node);
                $allow_credential_xmlnode->removeChild($allow_node);

                $key = array_search ($tmp_name, $object->allow_credential);
                unset($object->allow_credential[$key]);
            }
            if( empty($object->allow_credential) )
                $credential_xmlnode->removeChild($allow_credential_xmlnode);
        }

        foreach( $object->allow_credential as $allow )
        {
            $custom_url_category_obj = $object->owner->owner->customURLProfileStore->find($allow);
            if( $custom_url_category_obj !== NULL )
                continue;

            $object->alert_credential[] = $allow;

            $xmlString = '<member>'.$allow.'</member>';
            $xmlElement = DH::importXmlStringOrDie($object->xmlroot->ownerDocument, $xmlString);
            $alert_credential_xmlnode->appendChild($xmlElement);
        }
        $object->allow_credential = array();

        if( $context->object->owner->owner->version >= 102 )
        {
            $xmlnode = DH::findFirstElementOrCreate("local-inline-cat", $object->xmlroot);
            $xmlnode->textContent = "yes";

            $xmlnode = DH::findFirstElementOrCreate("cloud-inline-cat", $object->xmlroot);
            $xmlnode->textContent = "yes";
        }

        $credential_xmlnode = DH::findFirstElementOrCreate("credential-enforcement", $object->xmlroot);
        $mode_credential_xmlnode = DH::findFirstElementOrCreate("mode", $credential_xmlnode);
        $mode_child_xmlnode = DH::firstChildElement($mode_credential_xmlnode);
        if( $mode_child_xmlnode->nodeName == "disabled" )
        {
            DH::findFirstElementOrCreate("ip-user", $mode_credential_xmlnode);
            $logseverity_credential_xmlnode = DH::findFirstElementOrCreate("log-severity", $credential_xmlnode);
            $logseverity_credential_xmlnode->textContent = "medium";
            $mode_credential_xmlnode->removeChild($mode_child_xmlnode);
        }

        if( $context->isAPI )
        {
            $object->API_sync();
        }
    },
);

SecurityProfileCallContext::$supportedActions['url.best-practice-set'] = array(
    'name' => 'url.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
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