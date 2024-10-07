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

SecurityProfileCallContext::$supportedActions['action-set'] = array(
    'name' => 'action-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;
        $action = $context->action;
        $filter = $context->filter;

        if (get_class($object) !== "URLProfile")
            return null;

        //Todo:
        //how to set new action

        $object->setAction($action, $filter);

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
        $bestPractice = FALSE;

        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = TRUE;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = TRUE;

        if( isset($optionalFields['TotalUse']) )
            $addTotalUse = TRUE;

        if( isset($optionalFields['BestPractice']) )
            $bestPractice = TRUE;


        $headers = '<th>ID</th><th>location</th><th>name</th><th>store</th><th>type</th><th>rules</th>';
        if( $bestPractice )
            $headers .= '<th>BP</th>';

        $headers .= '<th>exception</th>';
        if( $bestPractice )
            $headers .= '<th>BP</th>';

        $headers .= '<th>DNS lists</th>';
        if( $bestPractice )
            $headers .= '<th>BP</th>';

        $headers .= '<th>DNS sinkhole</th><th>DNS security</th>';
        if( $bestPractice )
            $headers .= '<th>BP</th>';

        $headers .= '<th>DNS whitelist</th><th>mica-engine</th>';
        if( $bestPractice )
            $headers .= '<th>BP</th>';

        $headers .= '<th>URL members</th>';


        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';
        if( $addTotalUse )
            $headers .= '<th>total use</th>';


        $lines = '';

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
                        $tmp_array[] = "'".$rule->name()."' | severity:'". implode( ",", $rule->severity )."' - action:'".$rule->action()."' - packetCapture:'".$rule->packetCapture()."' - category:'".$rule->category()."' - host:'".$rule->host()."'";
                    }


                    $lines .= $context->encloseFunction( $tmp_array );
                }
                elseif( !empty( $object->tmp_virus_prof_array ) )
                {
                    $array = array();
                    foreach( $object->tmp_virus_prof_array as $key => $type )
                    {
                        $string = $type;
                        if( isset( $object->$type['action'] ) )
                            $string .= "          - action:          '" . $object->$type['action'] . "'";

                        if( isset( $object->$type['wildfire-action'] ) )
                            $string .=  "          - wildfire-action: '" . $object->$type['wildfire-action'] . "'";

                        if( isset( $object->$type['mlav-action'] ) )
                            $string .= "          - mlav-action: '" . $object->$type['mlav-action'] . "'";
                        $array[] = $string;
                    }
                    $lines .= $context->encloseFunction($array);
                }
                else
                    $lines .= $context->encloseFunction('');

                if( $bestPractice )
                {
                    if( get_class($object) == "AntiSpywareProfile" || get_class($object) == "VulnerabilityProfile" )
                    {
                        $lines .= $context->encloseFunction('BP');
                    }
                    else
                        $lines .= $context->encloseFunction('');
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
                if( $bestPractice )
                {
                    if( get_class($object) == "AntiSpywareProfile" || get_class($object) == "VulnerabilityProfile" )
                    {
                        $lines .= $context->encloseFunction('BP');
                    }
                    else
                        $lines .= $context->encloseFunction('---');
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
                                        $string .= " -  packet-capture: ".$value['packet-capture'];
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
                        $string_mica_engine[] = "mica-engine-spyware-enabled: ". $enabled;

                        foreach ($object->additional['mica-engine-spyware-enabled'] as $name => $threat)
                            $string_mica_engine[] = $name . " - inline-policy-action :" . $object->additional['mica-engine-spyware-enabled'][$name]['inline-policy-action'];
                    }

                    if( !empty( $object->additional['mica-engine-vulnerability-enabled'] ) )
                    {
                        $enabled = "[no]";
                        if( $object->cloud_inline_analysis_enabled )
                            $enabled = "[yes]";
                        $string_mica_engine[] = "mica-engine-vulnerability-enabled: ". $enabled;

                        foreach ($object->additional['mica-engine-vulnerability-enabled'] as $name => $threat)
                            $string_mica_engine[] = $name . " - inline-policy-action :" . $object->additional['mica-engine-vulnerability-enabled'][$name]['inline-policy-action'];
                    }

                    if( !empty( $object->additional['mlav-engine-filebased-enabled'] ) )
                    {
                        $string_mica_engine[] = "mlav-engine-filebased-enabled: ";

                        foreach ($object->additional['mlav-engine-filebased-enabled'] as $name => $threat)
                            $string_mica_engine[] = $name . " - mlav-policy-action :" . $object->additional['mlav-engine-filebased-enabled'][$name]['mlav-policy-action'];
                    }
                }

                //<th>DNS lists</th>
                $lines .= $context->encloseFunction($string_dns_list);
                if( $bestPractice )
                {
                    if( get_class($object) == "AntiSpywareProfile" )
                    {
                        $lines .= $context->encloseFunction('BP');
                    }
                    else
                        $lines .= $context->encloseFunction('---');
                }
                //<th>DNS sinkhole</th>
                $lines .= $context->encloseFunction($string_dns_sinkhole);
                //<th>DNS security</th>
                $lines .= $context->encloseFunction($string_dns_security);
                if( $bestPractice )
                {
                    if( get_class($object) == "AntiSpywareProfile" )
                    {
                        $lines .= $context->encloseFunction('BP');
                    }
                    else
                        $lines .= $context->encloseFunction('---');
                }
                //<th>DNS whitelist</th>
                $lines .= $context->encloseFunction($string_dns_whitelist);

                $lines .= $context->encloseFunction($string_mica_engine);
                if( $bestPractice )
                {
                    if( get_class($object) == "AntiSpywareProfile" || get_class($object) == "VulnerabilityProfile" )
                    {
                        $lines .= $context->encloseFunction('BP');
                    }
                    else
                        $lines .= $context->encloseFunction('---');
                }

                if( get_class($object) == "customURLProfile" )
                {
                    /**
                     * @var $object customURLProfile
                     */
                    $tmp_array = array();
                    foreach( $object->getmembers() as  $member )
                        $tmp_array[] = $member;

                    $string = implode( ",", $tmp_array);
                    $lines .= $context->encloseFunction( $tmp_array );
                }
                else
                {
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
                'choices' => array('WhereUsed', 'UsedInLocation', 'TotalUse', 'BestPractice'),
                'help' =>
                    "pipe(|) separated list of additional fields (ie: Arg1|Arg2|Arg3...) to include in the report. The following is available:\n" .
                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n" .
                    "  - WhereUsed : list places where object is used (rules, groups ...)\n" .
                    "  - TotalUse : list a counter how often this object is used\n" .
                    "  - BestPractice : show if BestPractice is configured\n"
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

            if( $decoder == "http" || $decoder == "https" || $decoder == "ftp" || $decoder == "smb" )
            {
                if( $object->$decoder['action'] != "default" && $object->$decoder['action'] != "reset-both"  )
                {
                    $object->$decoder['action'] = "reset-both";
                    $action_xmlNode = DH::findFirstElement("action", $xmlNode);
                    $action_xmlNode->textContent = "reset-both";
                }

                if( $object->$decoder['wildfire-action'] != "default" && $object->$decoder['wildfire-action'] != "reset-both"  )
                {
                    $object->$decoder['wildfire-action'] = "reset-both";
                    $action_xmlNode = DH::findFirstElement("wildfire-action", $xmlNode);
                    $action_xmlNode->textContent = "reset-both";
                }

                if( $object->$decoder['mlav-action'] != "default" && $object->$decoder['mlav-action'] != "reset-both"  )
                {
                    $object->$decoder['mlav-action'] = "reset-both";
                    $action_xmlNode = DH::findFirstElement("mlav-action", $xmlNode);
                    $action_xmlNode->textContent = "reset-both";
                }
            }
            else
            {
                if( $object->$decoder['action'] != "reset-both"  )
                {
                    $object->$decoder['action'] = "reset-both";
                    $action_xmlNode = DH::findFirstElement("action", $xmlNode);
                    $action_xmlNode->textContent = "reset-both";
                }

                if( $object->$decoder['wildfire-action'] != "reset-both"  )
                {
                    $object->$decoder['wildfire-action'] = "reset-both";
                    $action_xmlNode = DH::findFirstElement("wildfire-action", $xmlNode);
                    $action_xmlNode->textContent = "reset-both";
                }

                if( $object->$decoder['mlav-action'] != "reset-both"  )
                {
                    $object->$decoder['mlav-action'] = "reset-both";
                    $action_xmlNode = DH::findFirstElement("mlav-action", $xmlNode);
                    $action_xmlNode->textContent = "reset-both";
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
            derr( "API mode is not supported yet" );
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

            if( $decoder == "http" || $decoder == "https" || $decoder == "ftp" || $decoder == "smb" )
            {
                if( $object->$decoder['action'] == "allow" )
                {
                    $object->$decoder['action'] = "alert";
                    $action_xmlNode = DH::findFirstElement("action", $xmlNode);
                    $action_xmlNode->textContent = "alert";
                }

                if( $object->$decoder['wildfire-action'] == "allow" )
                {
                    $object->$decoder['wildfire-action'] = "alert";
                    $action_xmlNode = DH::findFirstElement("wildfire-action", $xmlNode);
                    $action_xmlNode->textContent = "alert";
                }

                if( $object->$decoder['mlav-action'] == "allow" )
                {
                    $object->$decoder['mlav-action'] = "alert";
                    $action_xmlNode = DH::findFirstElement("mlav-action", $xmlNode);
                    $action_xmlNode->textContent = "alert";
                }
            }
            else
            {
                if( $object->$decoder['action'] == "allow"  )
                {
                    $object->$decoder['action'] = "alert";
                    $action_xmlNode = DH::findFirstElement("action", $xmlNode);
                    $action_xmlNode->textContent = "alert";
                }

                if( $object->$decoder['wildfire-action'] == "allow"  )
                {
                    $object->$decoder['wildfire-action'] = "alert";
                    $action_xmlNode = DH::findFirstElement("wildfire-action", $xmlNode);
                    $action_xmlNode->textContent = "alert";
                }

                if( $object->$decoder['mlav-action'] == "allow"  )
                {
                    $object->$decoder['mlav-action'] = "alert";
                    $action_xmlNode = DH::findFirstElement("mlav-action", $xmlNode);
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
            derr( "API mode is not supported yet" );
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

            if( $this->owner->owner->version >= 102 )
            {
                $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $xmlString);
                $object->xmlroot->appendChild($xmlElement);

                $tmp_mlav_engine = DH::findFirstElementOrCreate('cloud-inline-analysis', $object->xmlroot);
                $tmp_mlav_engine->textContent = "yes";
            }
        }

        if( $context->isAPI )
        {
            derr( "API mode is not supported yet" );
            $object->API_sync();
        }
    },
);
SecurityProfileCallContext::$supportedActions['spyware.alert-only-set'] = array(
    'name' => 'spyware.alert-only-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "AntiSpywareProfile")
            return null;

        $tmp_mlav_engine = DH::findFirstElementOrCreate('mica-engine-spyware-enabled', $object->xmlroot);
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

            if( $this->owner->owner->version >= 102 )
            {
                $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $xmlString);
                $object->xmlroot->appendChild($xmlElement);

                $tmp_mlav_engine = DH::findFirstElementOrCreate('cloud-inline-analysis', $object->xmlroot);
                $tmp_mlav_engine->textContent = "yes";
            }
        }

        if( $context->isAPI )
        {
            derr( "API mode is not supported yet" );
            $object->API_sync();
        }
    },
);
SecurityProfileCallContext::$supportedActions['vulnerability.best-practice-set'] = array(
    'name' => 'vulnerability.best-practice-set',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        if (get_class($object) !== "VulnerabilityProfile")
            return null;

        $tmp_mlav_engine = DH::findFirstElementOrCreate('cloud-inline-analysis', $object->xmlroot);
        $tmp_mlav_engine->textContent = "yes";

        $tmp_mlav_engine = DH::findFirstElementOrCreate('mica-engine-vulnerability-enabled', $object->xmlroot);
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

        if( $context->isAPI )
        {
            derr( "API mode is not supported yet" );
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



        $tmp_mlav_engine = DH::findFirstElementOrCreate('mica-engine-vulnerability-enabled', $object->xmlroot);
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
            }
        }

        if( $context->isAPI )
        {
            derr( "API mode is not supported yet" );
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
        $alert_xmlnode = DH::findFirstElement("alert", $object->xmlroot);
        if( $allow_xmlnode !== False )
        {
            foreach( $allow_xmlnode->childNodes as $allow_node )
            {
                if( $allow_node->nodeType != XML_ELEMENT_NODE )
                    continue;

                $alert_xmlnode->appendChild($allow_node);
            }
        }

        foreach( $object->allow as $allow )
        {
            $object->alert[] = $allow;
        }
        $object->allow = array();

        if( $context->object->owner->owner->version >= 102 )
        {
            $xmlnode = DH::findFirstElementOrCreate("local-inline-cat", $object->xmlroot);
            $xmlnode->textContent = "yes";

            $xmlnode = DH::findFirstElementOrCreate("cloud-inline-cat", $object->xmlroot);
            $xmlnode->textContent = "yes";
        }

        if( $context->isAPI )
        {
            derr( "API mode is not supported yet" );
            $object->API_sync();
        }
    },
);