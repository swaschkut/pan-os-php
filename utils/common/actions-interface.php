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

InterfaceCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( InterfaceCallContext $context )
    {
        /** @var EthernetInterface $object */
        $object = $context->object;

        $linkstate = "";
        if( method_exists($object, 'getLinkState') )
            $linkstate = "[".$object->getLinkState()."]";

        $mgmtProfile = "";
        if( method_exists($object, 'getMgmtProfile') )
        {
            if( $object->getMgmtProfile() !== null )
            {
                $mgmtProfile = " mgmtProfile:[".$object->getMgmtProfile()."]";
                PH::$JSON_TMP['sub']['object'][$object->name()]['interface-management-profile'] = $object->getMgmtProfile();
            }
            else
            {
                $mgmtProfile = " mgmtProfile:[---]";
            }
        }

        PH::print_stdout("     * ".get_class($object)." '{$object->name()}' {$linkstate}".$mgmtProfile );
        PH::$JSON_TMP['sub']['object'][$object->name()]['name'] = $object->name();
        PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);
        PH::$JSON_TMP['sub']['object'][$object->name()]['linkstate'] = $linkstate;

        //Todo: optimization needed, same process as for other utiles

        $text = "       - " . $object->type . " - ";

        if( $object->type == "layer3" || $object->type == "virtual-wire" || $object->type == "layer2" )
        {
            if( $object->isSubInterface() )
            {
                $text .= "subinterface - ";
                PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['subinterface'] = "yes";
                PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['subinterfacecount'] = "0";
            }

            else
            {
                $text .= "count subinterface: " . $object->countSubInterfaces() . " - ";
                PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['subinterface'] = "false";
                PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['subinterfacecount'] = $object->countSubInterfaces();
            }

        }
        elseif( $object->type == "aggregate-group" )
        {
            $text .= "".$object->ae()." - ";
            PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ae'] = $object->ae();
        }


        if( $object->type == "layer3" )
        {
            $text .= "ip-addresse(s): ";
            foreach( $object->getLayer3IPv4Addresses() as $ip_address )
            {
                if( strpos( $ip_address, "." ) !== false )
                {
                    $text .= $ip_address . ",";
                    PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ipaddress'][] = $ip_address;
                }
                else
                {
                    #$object = $sub->addressStore->find( $ip_address );
                    #PH::print_stdout( $ip_address." ({$object->value()}) ,");
                    $text .= $ip_address . ",";
                    PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ipaddress'][] = $ip_address;
                }
            }
            foreach( $object->getLayer3IPv6Addresses() as $ip_address )
            {
                if( strpos( $ip_address, ":" ) !== false )
                {
                    $text .= $ip_address . ",";
                    PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ipaddress'][] = $ip_address;
                }
                else
                {
                    #$object = $sub->addressStore->find( $ip_address );
                    #PH::print_stdout( $ip_address." ({$object->value()}) ,");
                    $text .= $ip_address . ",";
                    PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ipaddress'][] = $ip_address;
                }
            }
        }
        elseif( $object->type == "tunnel" || $object->type == "loopback" || $object->type == "vlan"  )
        {
            $text .= ", ip-addresse(s): ";
            foreach( $object->getIPv4Addresses() as $ip_address )
            {
                if( strpos( $ip_address, "." ) !== false )
                {
                    $text .= $ip_address . ",";
                    PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ipaddress'][] = $ip_address;
                }
                else
                {
                    #$object = $sub->addressStore->find( $ip_address );
                    #PH::print_stdout($text); $ip_address." ({$object->value()}) ,");
                    $text .= $ip_address . ",";
                    PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ipaddress'][] = $ip_address;
                }
            }
            foreach( $object->getIPv6Addresses() as $ip_address )
            {
                if( strpos( $ip_address, ":" ) !== false )
                {
                    $text .= $ip_address . ",";
                    PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ipaddress'][] = $ip_address;
                }
                else
                {
                    #$object = $sub->addressStore->find( $ip_address );
                    #PH::print_stdout($text); $ip_address." ({$object->value()}) ,");
                    $text .= $ip_address . ",";
                    PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ipaddress'][] = $ip_address;
                }
            }
        }
        elseif( $object->type == "auto-key" )
        {
            $text .= " - IPsec config";
            $text .= " - IKE gateway: " . $object->gateway;
            $text .= " - interface: " . $object->interface;
            PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ike']['gw'] = $object->gateway;
            PH::$JSON_TMP['sub']['object'][$object->name()][$object->type]['ike']['interface'] = $object->interface;
        }

        PH::print_stdout( $text );

    },
);
InterfaceCallContext::$supportedActions['displayreferences'] = Array(
    'name' => 'displayreferences',
    'MainFunction' => function ( InterfaceCallContext $context ) {
        /** @var EthernetInterface $object */
        $object = $context->object;
        PH::print_stdout("     * " . get_class($object) . " '{$object->name()}'");

        $object->display_references();
    }
);

InterfaceCallContext::$supportedActions['exportToExcel'] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (InterfaceCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (InterfaceCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (InterfaceCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;

        $addWhereUsed = FALSE;
        $addUsedInLocation = FALSE;
        $addResolveGroupIPCoverage = FALSE;
        $addNestedMembers = FALSE;

        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = TRUE;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = TRUE;


        $headers = '<th>ID</th><th>template</th><th>location</th><th>name</th><th>class</th><th>type</th><th>subinterfaces</th><th>IP-addresses</th><th>IPv6-addresses</th><th>mgmt-profile</th>';

        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';

        $lines = '';

        $count = 0;
        if( isset($context->objectList) )
        {
            foreach( $context->objectList as $object )
            {
                $count++;

                /** @var Zone $object */
                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $context->encloseFunction( (string)$count );

                if( get_class($object->owner->owner) == "PANConf" )
                {
                    if( isset($object->owner->owner->owner) && $object->owner->owner->owner !== null && (get_class($object->owner->owner->owner) == "Template" || get_class($context->subSystem->owner) == "TemplateStack" ) )
                    {
                        $lines .= $context->encloseFunction($object->owner->owner->owner->name());
                        $lines .= $context->encloseFunction($object->owner->owner->name());
                    }
                    else
                    {
                        $lines .= $context->encloseFunction("---");
                        $lines .= $context->encloseFunction($object->owner->owner->name());
                    }
                }


                $lines .= $context->encloseFunction($object->name());

                if( $object->type == "tmp" )
                {
                    $lines .= $context->encloseFunction('unknown');
                    $lines .= $context->encloseFunction('');
                    $lines .= $context->encloseFunction('');
                    $lines .= $context->encloseFunction('');
                    $lines .= $context->encloseFunction('');
                    $lines .= $context->encloseFunction('');
                }
                else
                {
                    $lines .= $context->encloseFunction(get_class($object));

                    $lines .= $context->encloseFunction($object->type);

                    //subinterfaces
                    if( $object->type == "layer3" || $object->type == "virtual-wire" || $object->type == "layer2" )
                    {
                        if( $object->isSubInterface() )
                            $lines .= $context->encloseFunction("subinterface");
                        else
                            $lines .= $context->encloseFunction("count: " . $object->countSubInterfaces());
                    }
                    elseif( $object->type == "aggregate-group" )
                    {
                        $lines .= $context->encloseFunction($object->ae());
                    }
                    else
                        $lines .= $context->encloseFunction("----");

                    //IP-addresses
                    if( $object->type == "layer3" )
                    {
                        $lines .= $context->encloseFunction($object->getLayer3IPv4Addresses());
                        $lines .= $context->encloseFunction($object->getLayer3IPv6Addresses());
                    }
                    elseif( $object->type == "tunnel" || $object->type == "loopback" || $object->type == "vlan"  )
                    {
                        $lines .= $context->encloseFunction($object->getIPv4Addresses());
                        $lines .= $context->encloseFunction($object->getIPv6Addresses());
                    }
                    else
                    {
                        $lines .= $context->encloseFunction("----");
                        $lines .= $context->encloseFunction("----");
                    }


                    //mgmt-profile
                    if( method_exists($object, 'getMgmtProfile') )
                    {
                        if( $object->getMgmtProfile() !== null )
                            $lines .= $context->encloseFunction($object->getMgmtProfile());
                        else
                            $lines .= $context->encloseFunction("----");
                    }
                    else
                        $lines .= $context->encloseFunction("----");
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
                'choices' => array('WhereUsed', 'UsedInLocation', 'ResolveIP', 'NestedMembers'),
                'help' =>
                    "pipe(|) separated list of additional fields (ie: Arg1|Arg2|Arg3...) to include in the report. The following is available:\n" .
                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n" .
                    "  - WhereUsed : list places where object is used (rules, groups ...)\n"
            )
    )

);

InterfaceCallContext::$supportedActions['name-Rename'] = array(
    'name' => 'name-Rename',
    'MainFunction' => function (InterfaceCallContext $context) {
        $object = $context->object;

        $newName = $context->arguments['newName'];

        $newName = str_replace("$$", "/", $newName);

        //Todo: only working for offline config
        if( $context->isAPI )
            derr( "changing interface is not supported in API mode" );

        /** @VAR EthernetInterface $object */
        $object->setName($newName);

    },
    'args' => array(
        'newName' => array(
            'type' => 'string',
            'default' => '*nodefault*',
            'help' => "instead of '/' use '$$' => 'actions=name-rename:ethernet1/1' please use 'actions=name-rename:ethernet1$$1'")
    )
);

InterfaceCallContext::$supportedActions['display-migration-warning'] = array(
    'name' => 'display-migration-warning',
    'MainFunction' => function (InterfaceCallContext $context) {
        $object = $context->object;

        /** @var EthernetInterface $object */
        $int_warning = $object->xmlroot->getAttribute('warning');

        PH::print_stdout( "    - ".htmlspecialchars_decode($int_warning) );


    }
);

InterfaceCallContext::$supportedActions['replace_IPv4_objects_by_value'] = Array(
    'name' => 'replace_IPv4_objects_by_value',
    'MainFunction' => function ( InterfaceCallContext $context )
    {
        /** @var EthernetInterface|VlanInterface|TunnelInterface|LoopbackInterface $object */
        $object = $context->object;

        /** @var VirtualSystem $vsys */
        $vsys = $object->importedByVSYS;

        if( $object->type == "layer3" )
        {
            foreach( $object->getLayer3IPv4Addresses() as $ip_address )
            {
                if( strpos( $ip_address, "." ) === FALSE )
                {
                    $pan_object = $object->owner->owner;
                    if( isset( $pan_object->owner ) )
                    {
                        //Panorama Template
                        if( get_class($pan_object->owner) == "Template" || get_class($pan_object->owner) == "TemplateStack" )
                        {
                            $template_object = $pan_object->owner;
                            $panorama_object = $template_object->owner;
                            $address_obj = $panorama_object->addressStore->find($ip_address);

                            $object->replaceIPv4ObjectByValue($context, $address_obj);
                        }
                    }
                    else
                    {
                        //NGFW
                        /** @var Address $address */
                        $address_obj = $vsys->addressStore->find($ip_address);

                        $object->replaceIPv4ObjectByValue($context, $address_obj);
                    }
                }
                else
                {
                    //valid IPv4 Interface address - nothing to replace
                }
            }
        }
        elseif( $object->type == "tunnel" || $object->type == "loopback" || $object->type == "vlan"  )
        {
            foreach( $object->getIPv4Addresses() as $ip_address )
            {
                if( strpos( $ip_address, "." ) === FALSE )
                {
                    $pan_object = $object->owner->owner;
                    if( isset( $pan_object->owner ) )
                    {
                        //Panorama Template
                        if( get_class($pan_object->owner) == "Template" || get_class($pan_object->owner) == "TemplateStack" )
                        {
                            $template_object = $pan_object->owner;
                            $panorama_object = $template_object->owner;
                            $address_obj = $panorama_object->addressStore->find($ip_address);

                            $object->replaceIPv4ObjectByValue( $context, $address_obj );
                        }
                    }
                    else
                    {
                        //NGFW
                        /** @var Address $address */
                        $address_obj = $vsys->addressStore->find($ip_address);

                        $object->replaceIPv4ObjectByValue( $context, $address_obj );
                    }
                }
                else
                {
                    //valid IPv4 Interface address - nothing to replace
                }
            }
        }
    }
);

InterfaceCallContext::$supportedActions['replace_IPv6_objects_by_value'] = Array(
    'name' => 'replace_IPv6_objects_by_value',
    'MainFunction' => function ( InterfaceCallContext $context )
    {
        /** @var EthernetInterface|VlanInterface|TunnelInterface|LoopbackInterface $object */
        $object = $context->object;

        /** @var VirtualSystem $vsys */
        $vsys = $object->importedByVSYS;

        if( $object->type == "layer3" )
        {
            foreach( $object->getLayer3IPv6Addresses() as $ip_address )
            {
                if( strpos( $ip_address, ":" ) === false )
                {
                    $pan_object = $object->owner->owner;
                    if( isset( $pan_object->owner ) )
                    {
                        //Panorama Template
                        if( get_class($pan_object->owner) == "Template" || get_class($pan_object->owner) == "TemplateStack" )
                        {
                            $template_object = $pan_object->owner;
                            $panorama_object = $template_object->owner;
                            $address_obj = $panorama_object->addressStore->find($ip_address);

                            $object->replaceIPv6ObjectByValue($context, $address_obj);
                        }
                    }
                    else
                    {
                        //NGFW
                        /** @var Address $address */
                        $address_obj = $vsys->addressStore->find($ip_address);

                        $object->replaceIPv6ObjectByValue( $context, $address_obj );
                    }
                }
                else
                {
                    //valid IPv6 Interface address - nothing to replace
                }
            }
        }
        elseif( $object->type == "tunnel" || $object->type == "loopback" || $object->type == "vlan"  )
        {
            foreach( $object->getIPv6Addresses() as $ip_address )
            {
                if( strpos( $ip_address, ":" ) === false )
                {
                    $pan_object = $object->owner->owner;
                    if( isset( $pan_object->owner ) )
                    {
                        //Panorama Template
                        if( get_class($pan_object->owner) == "Template" || get_class($pan_object->owner) == "TemplateStack" )
                        {
                            $template_object = $pan_object->owner;
                            $panorama_object = $template_object->owner;
                            $address_obj = $panorama_object->addressStore->find($ip_address);

                            $object->replaceIPv6ObjectByValue( $context, $address_obj );
                        }
                    }
                    else
                    {
                        //NGFW
                        /** @var Address $address */
                        $address_obj = $vsys->addressStore->find($ip_address);

                        $object->replaceIPv6ObjectByValue( $context, $address_obj );
                    }
                }
                else
                {
                    //valid IPv6 Interface address - nothing to replace
                }
            }
        }
    }
);

InterfaceCallContext::$supportedActions['ae-group-set'] = array(
    'name' => 'ae-group-set',
    'MainFunction' => function (InterfaceCallContext $context) {
        $object = $context->object;

        if( get_class($object) !== "EthernetInterface" )
        {
            mwarning( "SKIPPED: set AE number is only working Interface of type EthernetInterface. provided: ".get_class($object), null, false );
            return false;
        }

        $newAE = $context->arguments['newAE'];

        //Todo: only working for offline config
        if( $context->isAPI )
            derr( "changing AE is not supported in API mode" );

        if( $object->type != 'aggregate-group' )
        {
            //Todo: swaschkut 20250512
            //validate if references are available which can cause issues,
            //there should be no references available, then change type
            if( count($object->refrules) > 0 )
            {
                foreach( $object->refrules as $rule )
                {
                    if( get_class($rule) !== "InterfaceContainer" )
                    {
                        PH::print_stdout( "    " . '  - ' . $rule->toString() );
                        mwarning( "SKIPPED: interface Type EthernetInterface found, but change to 'aggreagte-group not possible due to references.", null, false );
                        return false;
                    }
                }
            }

            if( count( $object->subInterfaces()) > 0 )
            {
                mwarning( "SKIPPED: interface Type EthernetInterface found, but interface has sub-interfaces", null, false );
                return false;
            }

            $object->type = 'aggregate-group';
        }

        $tmp_description = $object->description();
        foreach( $object->xmlroot->childNodes as $child )
            $object->xmlroot->removeChild($child);

        /** @VAR EthernetInterface $object */
        $object->setAE($newAE);
        $object->setDescription( $tmp_description );

    },
    'args' => array('newAE' => array('type' => 'string', 'default' => '*nodefault*') )
);

InterfaceCallContext::$supportedActions['type-aggregate-ethernet-set'] = array(
    'name' => 'type-aggregate-ethernet-set',
    'MainFunction' => function (InterfaceCallContext $context) {
        $object = $context->object;

        /** @var EthernetInterface $object */

        /*
        PH::print_stdout( "    " . '  - ' . $object->toString() );
        PH::print_stdout( "    " . '  - ' . $object->type() );
        PH::print_stdout( "    " . '  - ' . get_class($object) );
        */

        if( get_class($object) !== "EthernetInterface" )
        {
            mwarning( "SKIPPED: Interface of type NOT EthernetInterface. provided: ".get_class($object), null, false );
            #return false;
        }


        $newName = $context->arguments['name'];
        //Todo: validate name - only allowed 'ae' followed by a one or two digit number [1-32]

        $newMainInterface = $object->owner->owner->network->aggregateEthernetIfStore->find($newName);
        if( $newMainInterface !== null )
        {
            mwarning( "Interface: ".$newName." already exists", null, false );
            return false;
        }

        //Todo: only working for offline config
        if( $context->isAPI )
            derr( "changing to class AggregateEthernetInterface is not supported in API mode" );



        $vsys_obj = $object->importedByVSYS;

        $newMainInterface = $object->owner->owner->network->aggregateEthernetIfStore->newEthernetIf( $newName );
        $vsys_obj->importedInterfaces->addInterface($newMainInterface);

        foreach( $object->getLayer3IPv4Addresses() as $ip_address )
            $newMainInterface->addIPv4Address($ip_address);

        //Todo: update reference of old Main Interface

        if( count($object->refrules) > 0 )
        {
            foreach( $object->refrules as $rule )
            {
                if( get_class($rule) !== "InterfaceContainer" )
                    $rule->referencedObjectRenamed( $newMainInterface, $object);
            }
        }
        $vsys_obj->importedInterfaces->removeInterface($object);
        if( get_class($object) === "EthernetInterface" )
            $object->owner->owner->network->ethernetIfStore->removeEthernetIf($object);
        elseif( get_class($object) === "AggregateEthernetInterface" )
            $object->owner->owner->network->aggregateEthernetIfStore->removeEthernetIf($object);
        else
        {
            mwarning( "SKIPPED: Interface of type ".get_class($object).". not yet supported", null, false );
            return false;
        }

        if( count( $object->subInterfaces()) > 0 )
        {
            foreach( $object->subInterfaces() as $subinterface )
            {
                $newSubInterface = $newMainInterface->addSubInterface($subinterface->tag());

                $vsys_obj->importedInterfaces->addInterface($newSubInterface);
                $vsys_obj->importedInterfaces->removeInterface($subinterface);
                foreach( $subinterface->getLayer3IPv4Addresses() as $ip_address )
                    $newSubInterface->addIPv4Address($ip_address);

                //Todo: update references of old Main subinterfaces
                if( count($subinterface->refrules) > 0 )
                {
                    foreach( $subinterface->refrules as $rule )
                    {
                        /** @var StaticRoute $rule */
                        if( get_class($rule) !== "InterfaceContainer" )
                            $rule->referencedObjectRenamed( $newSubInterface, $subinterface);
                    }
                }
            }
        }
    },
    'args' => array('name' => array('type' => 'string', 'default' => '*nodefault*') )
);

InterfaceCallContext::$supportedActions['remove'] = array(
    'name' => 'remove',
    'MainFunction' => function (InterfaceCallContext $context) {
        $object = $context->object;

        /** @var EthernetInterface $object */

        //Todo: only working for offline config
        if( $context->isAPI )
            derr( "changing to class AggregateEthernetInterface is not supported in API mode" );

        $newMainInterface = $object->owner->owner->network->ethernetIfStore->find($object->name());
        if( $newMainInterface === null )
        {
            #mwarning( "Interface: ".$object->name()." not/no longer available", null, false );
            return false;
        }

        $vsys_obj = $object->importedByVSYS;

        if( count($object->refrules) > 0 )
        {
            foreach( $object->refrules as $rule )
            {
                if( get_class($rule) !== "InterfaceContainer" )
                {
                    PH::print_stdout( "    " . '  - ' . $rule->toString() );
                    mwarning( "SKIPPED: interface can not be removed, because it has references", null, false );
                    return false;
                }
            }
        }

        $vsys_obj->importedInterfaces->removeInterface($object);
        $object->owner->owner->network->ethernetIfStore->removeEthernetIf($object);
    }
);