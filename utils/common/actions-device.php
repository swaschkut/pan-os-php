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

//Todo:
// - create template-stack ( add to FW device (serial#))
// - create template (incl adding to template-stack)
// - add devicegroup to FW device serial#
// - container-create / devicecloud-create
// - devicegroupe-setparent / container-setparent / deviceloud-setparent
// - template-movesharedtovsys
// - templatestack-movetofirsttemplate
// - delete manageddevice with decommission reference on DG, template-stack

DeviceCallContext::$supportedActions['display'] = array(
    'name' => 'display',
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        PH::print_stdout( "     * " . get_class($object) . " '{$object->name()}'" );
        PH::$JSON_TMP['sub']['object'][$object->name()]['name'] = $object->name();
        PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);

        if( get_class($object) == "TemplateStack" )
        {
            /** @var TemplateStack $object */

            $padding = "       ";
            //Todo: PH::print_stdout( where this template is used // full templateStack hierarchy

            $vsyses = $object->deviceConfiguration->getVirtualSystems();
            foreach( $vsyses as $vsys )
                PH::print_stdout( $padding."  - ".get_class($vsys).": name: ".$vsys->name());

            PH::print_stdout( $padding."----------");

            $used_templates = $object->templates;
            foreach( $used_templates as $template )
            {
                PH::print_stdout( $context->padding." - " . get_class($template) . " '{$template->name()}'" );
                PH::$JSON_TMP['sub']['object'][$object->name()]['template'][] = $template->name();
            }
            //Todo: PH::print_stdout( where this TemplateStack is used SERIAL

            foreach( $object->FirewallsSerials as $serial => $managedFirewall )
            {
                if( $managedFirewall !== null )
                    PH::print_stdout( $context->padding." - serial: ".$serial." - DG: ".$managedFirewall->devicegroup);
            }
        }
        elseif( get_class($object) == "VirtualSystem" )
        {
            /** @var VirtualSystem $object */
            PH::print_stdout( $context->padding." - Name: '{$object->alternativeName()}'" );
            PH::$JSON_TMP['sub']['object'][$object->name()]['alternativename'] = $object->alternativeName();
        }
        elseif( get_class($object) == "DeviceGroup" )
        {
            $parentDGS = $object->parentDeviceGroups();
            $parentDGS['shared'] = $object->owner;


            $tmp_padding = "";
            foreach( array_reverse( $parentDGS ) as $key => $DG)
            {
                PH::print_stdout( $context->padding.$tmp_padding."- ".$key );
                $tmp_padding .= "  ";
                PH::$JSON_TMP['sub']['object'][$object->name()]['hierarchy'][] = $key;
            }
            foreach( $object->getDevicesInGroup() as $key => $device )
            {
                #PH::print_stdout( $context->padding."- ".$key );
                $managedFirewall = $object->owner->managedFirewallsStore->find($key);
                if( $managedFirewall !== null )
                    PH::print_stdout( $context->padding." - serial: ".$key." - Template-Stack: ".$managedFirewall->template_stack);

                if( isset($device['vsyslist']) )
                    PH::print_stdout($context->padding."  - virtualsystem: '".array_keys($device['vsyslist'])[0]."'");
                else
                    PH::print_stdout($context->padding."   - virtualsystem: 'vsys1'");

                PH::$JSON_TMP['sub']['object'][$object->name()]['devices'][] = $key;
            }


        }
        elseif( get_class($object) == "ManagedDevice" )
        {
            $managedDevice = $context->object;
            $device = $managedDevice->owner->owner;

            $padding = "       ";
            /** @var ManagedDevice $managedDevice */

            if( $device->isPanorama() )
            {
                if( $managedDevice->getDeviceGroup() != null )
                {
                    PH::print_stdout( $padding."DG: ".$managedDevice->getDeviceGroup() );
                    PH::$JSON_TMP['sub']['object'][$object->name()]['dg'] = $managedDevice->getDeviceGroup();
                }


                if( $managedDevice->getTemplate() != null )
                {
                    PH::print_stdout( $padding."Template: ".$managedDevice->getTemplate() );
                    PH::$JSON_TMP['sub']['object'][$object->name()]['template'] = $managedDevice->getTemplate();
                }


                if( $managedDevice->getTemplateStack() != null )
                {
                    PH::print_stdout( $padding."TemplateStack: ".$managedDevice->getTemplateStack() );
                    PH::$JSON_TMP['sub']['object'][$object->name()]['templatestack'][$managedDevice->getTemplateStack()]['name'] = $managedDevice->getTemplateStack();

                    $templatestack = $device->findTemplateStack( $managedDevice->getTemplateStack() );
                    foreach( $templatestack->templates as $template )
                    {
                        $template_obj = $device->findTemplate( $template );
                        if( $template_obj !== null )
                        {
                            PH::print_stdout( " - ".$template_obj->name() );
                            PH::$JSON_TMP['sub']['object'][$object->name()]['templatestack'][$managedDevice->getTemplateStack()]['templates'][] = $template_obj->name();
                        }

                    }
                }

                if( $managedDevice->isConnected )
                {
                    PH::print_stdout( $padding."connected" );
                    PH::print_stdout( $padding."IP-Address: ".$managedDevice->mgmtIP );
                    PH::print_stdout( $padding."Hostname: ".$managedDevice->hostname );
                    PH::print_stdout( $padding."PAN-OS: ".$managedDevice->version );
                    PH::print_stdout( $padding."Model: ".$managedDevice->model );

                    PH::$JSON_TMP['sub']['object'][$object->name()]['connected'] = "true";
                    PH::$JSON_TMP['sub']['object'][$object->name()]['hostname'] = $managedDevice->hostname;
                    PH::$JSON_TMP['sub']['object'][$object->name()]['ip-address'] = $managedDevice->mgmtIP;
                    PH::$JSON_TMP['sub']['object'][$object->name()]['sw-version'] = $managedDevice->version;
                    PH::$JSON_TMP['sub']['object'][$object->name()]['model'] = $managedDevice->model;
                }
            }
            elseif( $device->isFawkes() || $device->isBuckbeak() )
            {
                if( $managedDevice->getDeviceContainer() != null )
                {
                    PH::print_stdout( $padding."DeviceContainer: ".$managedDevice->getDeviceContainer() );
                    PH::$JSON_TMP['sub']['object'][$object->name()]['on-prem'] = $managedDevice->getDeviceContainer();
                }

                if( $managedDevice->getDeviceVsysContainer() != null )
                {
                    PH::print_stdout( $padding."VsysContainer: ".$managedDevice->getDeviceVsysContainer() );
                    PH::$JSON_TMP['sub']['object'][$object->name()]['vsyscontainer'] = $managedDevice->getDeviceVsysContainer();
                }
            }
        }
        elseif( get_class($object) == "Template" )
        {
            /** @var Template $object */

            $padding = "       ";
            //Todo: PH::print_stdout( where this template is used // full templateStack hierarchy

            $vsyses = $object->deviceConfiguration->getVirtualSystems();
            foreach( $vsyses as $vsys )
                PH::print_stdout( $padding."  - ".get_class($vsys).": name: ".$vsys->name());

            PH::print_stdout( $padding."----------");
            $references = $object->getReferences();
            foreach( $references as $ref )
                PH::print_stdout( $padding."  - ".get_class($ref).": name: ".$ref->name());
        }
        elseif( get_class($object) == "Container" )
        {
            /** @var Container $object */
            $parentDGS = $object->parentContainers();
            $parentDGS['All'] = $object->owner;


            $tmp_padding = "";
            foreach( array_reverse( $parentDGS ) as $key => $DG)
            {
                PH::print_stdout( $context->padding.$tmp_padding."- ".$key );
                $tmp_padding .= "  ";
                PH::$JSON_TMP['sub']['object'][$object->name()]['hierarchy'][] = $key;
            }
        }
        elseif( get_class($object) == "DeviceCloud" )
        {
            /** @var DeviceCloud $object */
            $parentDGS = $object->parentContainer->parentContainers();
            $parentDGS['All'] = $object->owner;
            $parentDGS = array($object->name() => $object->name()) + $parentDGS;


            $tmp_padding = "";
            foreach( array_reverse( $parentDGS ) as $key => $DG)
            {
                PH::print_stdout( $context->padding.$tmp_padding."- ".$key );
                $tmp_padding .= "  ";
                PH::$JSON_TMP['sub']['object'][$object->name()]['hierarchy'][] = $key;
            }
        }
        elseif( get_class($object) == "DeviceOnPrem" )
        {
            /** @var DeviceOnPrem $object */
            $parentDGS = $object->parentContainer->parentContainers();
            $parentDGS['All'] = $object->owner;
            $parentDGS = array($object->name() => $object->name()) + $parentDGS;


            $tmp_padding = "";
            foreach( array_reverse( $parentDGS ) as $key => $DG)
            {
                PH::print_stdout( $context->padding.$tmp_padding."- ".$key );
                $tmp_padding .= "  ";
                PH::$JSON_TMP['sub']['object'][$object->name()]['hierarchy'][] = $key;
            }

            $padding = "       ";
            foreach( $object->devices as $serial => $device )
            {
                PH::print_stdout( $padding."- serial: ".$serial );
                PH::$JSON_TMP['sub']['object'][$object->name()]['serial'][$serial] = $serial;
            }
        }

        $xml = &DH::dom_to_xml( $object->xmlroot );
        $length = strlen( $xml );
        $length = round( $length/1000 );
        PH::print_stdout($context->padding."---");
        PH::print_stdout( $context->padding."- config-size: ".$length."kB");

        PH::print_stdout();
    },
);

DeviceCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;

        if( get_class($object) == "TemplateStack" )
        {
            $object->display_references(7);
        }
        elseif( get_class($object) == "Template" )
        {
            //Todo: Templates are not displaying templatestack until now
            $object->display_references(7);
        }
        elseif( get_class($object) == "VirtualSystem" )
        {
            /** @var VirtualSystem $object */
        }
        elseif( get_class($object) == "DeviceGroup" )
        {

        }
        elseif( get_class($object) == "ManagedDevice" )
        {
            //serial is references in DG / template-stack, but also in Securityrules as target
            //Todo: secrule target is missing until now
            $object->display_references(7);
        }

        return null;

    },
);

DeviceCallContext::$supportedActions['DeviceGroup-create'] = array(
    'name' => 'devicegroup-create',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
    },
    'GlobalFinishFunction' => function (DeviceCallContext $context) {
        if( $context->first )
        {


            $dgName = $context->arguments['name'];
            $parentDG = $context->arguments['parentdg'];

            $pan = $context->subSystem;

            if( !$pan->isPanorama() )
                derr("only supported on Panorama config");

            if( $parentDG != 'null' )
            {
                $tmp_parentdg = $pan->findDeviceGroup($parentDG);
                if( $tmp_parentdg === null )
                {
                    $string = "parentDG set with '" . $parentDG . "' but not found on this config";
                    PH::ACTIONstatus($context, "SKIPPED", $string);
                    $parentDG = null;
                }
            }

            $tmp_dg = $pan->findDeviceGroup($dgName);
            if( $tmp_dg === null )
            {
                $string = "create DeviceGroup: " . $dgName;
                #PH::ACTIONlog($context, $string);
                if( $parentDG == 'null' )
                    $parentDG = null;

                $dg = $pan->createDeviceGroup($dgName, $parentDG);

                if( $context->isAPI )
                {
                    $dg->API_sync();
                    if( $parentDG !== null )
                        $dg->owner->API_syncDGparentEntry($dg->name(), $parentDG);
                }

            }
            else
            {
                $string = "DeviceGroup with name: " . $dgName . " already available!";
                PH::ACTIONlog($context, $string);
            }

            $context->first = false;
        }
    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => 'false'),
        'parentdg' => array('type' => 'string', 'default' => 'null'),
    ),
);

DeviceCallContext::$supportedActions['DeviceGroup-addSerial'] = array(
    'name' => 'devicegroup-addserial',
    'MainFunction' => function (DeviceCallContext $context) {
    },
    'GlobalFinishFunction' => function (DeviceCallContext $context) {
        $dgName = $context->arguments['name'];
        $serial = $context->arguments['serial'];

        $pan = $context->subSystem;

        if( !$pan->isPanorama() )
            derr("only supported on Panorama config");

        $tmp_dg = $pan->findDeviceGroup($dgName);
        if( $tmp_dg === null )
        {
            $string = "DeviceGroup with name: " . $dgName . " not available!";
            PH::ACTIONlog( $context, $string );
        }
        else
        {
            $string = "DeviceGroup with name: " . $dgName . " got serial: ".$serial." added!";
            PH::ACTIONlog( $context, $string );
            if( $context->isAPI )
            {
                $con = findConnectorOrDie($tmp_dg);

                #$xpath = DH::elementToPanXPath($object->xmlroot);

                #$pan->removeDeviceGroup($object);
                #$con->sendDeleteRequest($xpath);
                $xpath = DH::elementToPanXPath($tmp_dg->xmlroot);
                $xpath .= '/devices';
                $con->sendSetRequest($xpath, "<entry name='{$serial}'/>");
            }
            else
                $tmp_dg->addDevice( $serial );

        }
    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => 'false'),
        'serial' => array('type' => 'string', 'default' => 'null'),
    ),
);

DeviceCallContext::$supportedActions['DeviceGroup-removeSerial'] = array(
    'name' => 'devicegroup-removeserial',
    'MainFunction' => function (DeviceCallContext $context) {
    },
    'GlobalFinishFunction' => function (DeviceCallContext $context) {
        $dgName = $context->arguments['name'];
        $serial = $context->arguments['serial'];

        $pan = $context->subSystem;

        if( !$pan->isPanorama() )
            derr("only supported on Panorama config");

        $tmp_dg = $pan->findDeviceGroup($dgName);
        if( $tmp_dg === null )
        {
            $string = "DeviceGroup with name: " . $dgName . " not available!";
            PH::ACTIONlog( $context, $string );
        }
        else
        {
            $string = "DeviceGroup with name: " . $dgName . " got serial: ".$serial." removed!";
            PH::ACTIONlog( $context, $string );
            if( $context->isAPI )
            {
                $con = findConnectorOrDie($tmp_dg);

                $xpath = DH::elementToPanXPath($tmp_dg->xmlroot);
                $xpath .= '/devices';
                $xpath .= "/entry[@name='{$serial}']";

                $con->sendDeleteRequest($xpath);
            }

            $tmp_dg->removeDevice( $serial );
        }
    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => 'false'),
        'serial' => array('type' => 'string', 'default' => 'null'),
    ),
);
DeviceCallContext::$supportedActions['DeviceGroup-removeSerial-Any'] = array(
    'name' => 'devicegroup-removeserial-any',
    'MainFunction' => function (DeviceCallContext $context)
    {

        $pan = $context->subSystem;

        if( !$pan->isPanorama() )
            derr("only supported on Panorama config");

        if( $context->isAPI )
        {
            $con = $context->connector;

            $xpath = DH::elementToPanXPath($context->object->xmlroot);
            $xpath .= '/devices';

            $con->sendDeleteRequest($xpath);
        }

        $context->object->removeDeviceAny( );
    }
);
DeviceCallContext::$supportedActions['DeviceGroup-delete'] = array(
    'name' => 'devicegroup-delete',
    'MainFunction' => function (DeviceCallContext $context) {

        $object = $context->object;
        $name = $object->name();

        $pan = $context->subSystem;
        if( !$pan->isPanorama() )
            derr( "only supported on Panorama config" );

        if( get_class($object) == "DeviceGroup" )
        {
            $childDG = $object->_childDeviceGroups;
            if( count($childDG) != 0 )
            {
                $string = "DG with name: '" . $name . "' has ChildDGs. DG can not removed";
                PH::ACTIONstatus($context, "SKIPPED", $string);
            }
            else
            {
                $string ="     * delete DeviceGroup: " . $name;
                PH::ACTIONlog( $context, $string );

                if( $context->isAPI )
                {
                    $con = findConnectorOrDie($object);
                    $xpath = DH::elementToPanXPath($object->xmlroot);

                    $con->sendDeleteRequest($xpath);
                }

                $pan->removeDeviceGroup($object);
            }
        }
    }
);

DeviceCallContext::$supportedActions['Template-create'] = array(
    'name' => 'template-create',
    'MainFunction' => function (DeviceCallContext $context) {
    },
    'GlobalFinishFunction' => function (DeviceCallContext $context) {
        $templateName = $context->arguments['name'];

        $pan = $context->subSystem;

        if( !$pan->isPanorama() )
            derr("only supported on Panorama config");


        $tmp_template = $pan->findTemplate($templateName);
        if( $tmp_template === null )
        {
            $string = "create Template: " . $templateName;
            #PH::ACTIONlog($context, $string);

            $dg = $pan->createTemplate($templateName);

            if( $context->isAPI )
                $dg->API_sync();
        }
        else
        {
            $string = "Template with name: " . $templateName . " already available!";
            PH::ACTIONlog( $context, $string );
        }
    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => 'false'),
    ),
);

DeviceCallContext::$supportedActions['Template-delete'] = array(
    'name' => 'template-delete',
    'MainFunction' => function (DeviceCallContext $context) {

        $object = $context->object;
        $name = $object->name();

        $pan = $context->subSystem;
        if( !$pan->isPanorama() )
            derr( "only supported on Panorama config" );

        if( get_class($object) == "Template" )
        {
            if( $object->countReferences() > 0 )
            {
                $string ="Template is used and can NOT be removed!";
                PH::ACTIONlog( $context, $string );
                return null;
            }
            /** @var Template $object */
            //if template is used in Template-Stack -> skip
            /*
            $childDG = $object->_childDeviceGroups;
            if( count($childDG) != 0 )
            {
                $string = "Template with name: '" . $name . "' is used in TemplateStack. Template can not removed";
                PH::ACTIONstatus($context, "SKIPPED", $string);
            }
            else
            {
            */
                $string ="     * delete Template: " . $name;
                PH::ACTIONlog( $context, $string );


                if( $context->isAPI )
                {
                    $con = findConnectorOrDie($object);
                    $xpath = DH::elementToPanXPath($object->xmlroot);

                    $pan->removeTemplate($object);
                    $con->sendDeleteRequest($xpath);
                }
                else
                    $pan->removeTemplate($object);

            //}
        }
    }
);

DeviceCallContext::$supportedActions['Template-clone '] = array(
    'name' => 'template-clone',
    'MainFunction' => function (DeviceCallContext $context) {

        $object = $context->object;
        $name = $object->name();

        $newName = $context->arguments['newname'];

        $pan = $context->subSystem;
        if( !$pan->isPanorama() )
            derr( "only supported on Panorama config" );

        if( get_class($object) == "Template" )
        {
            $string ="     * clone Template: " . $name." to: ".$newName;
            PH::ACTIONlog( $context, $string );

            $tmp = $pan->createTemplate($newName);
            $test = $object->xmlroot->cloneNode();
            //Todo: 20250115 swaschkut - not working in API mode - same for device-group
            //missing stuff import to document
            $node = $object->xmlroot->ownerDocument->importNode($test, true);
            //$object->owner->xmlroot->appendChild($node);
            //$node = DH::findFirstElementByNameAttr( "entry", $newName, $object->owner->xmlroot );

            $tmp->xmlroot = $node;
            //$tmp->owner missing
            $tmp->setName( $newName );

            if( $context->isAPI )
            {
                if( $context->isAPI )
                    $tmp->API_sync();
            }
        }
    },
    'args' => array(
        'newname' => array('type' => 'string', 'default' => 'false'),
    ),
);

DeviceCallContext::$supportedActions['Template-create-vsys'] = array(
    'name' => 'template-create-vsys',
    'MainFunction' => function (DeviceCallContext $context)
    {
    },
    'GlobalFinishFunction' => function (DeviceCallContext $context)
    {
        $templateName = $context->arguments['name'];
        $vsysName = $context->arguments['vsys-name'];

        $pan = $context->subSystem;
        if( !$pan->isPanorama() )
            derr("only supported on Panorama config");


        $tmp_template = $pan->findTemplate($templateName);
        if( $tmp_template === null )
        {
            $string = "create Template: " . $templateName;
            PH::ACTIONlog($context, $string);

            $tmp_template = $pan->createTemplate($templateName);

            if( $context->isAPI )
                $tmp_template->API_sync();
        }

        $tmp_template->createVsys($vsysName);

        if( $context->isAPI )
            $tmp_template->API_sync();

    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => 'false'),
        'vsys-name' => array('type' => 'string', 'default' => 'false'),
    ),
);

DeviceCallContext::$supportedActions['TemplateStack-create'] = array(
    'name' => 'templatestack-create',
    'MainFunction' => function (DeviceCallContext $context) {
    },
    'GlobalFinishFunction' => function (DeviceCallContext $context) {
        if( $context->object !== null && get_class($context->object) !== "TemplateStack" )
        {
            $string = "devicetype=templatestack missing";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $templateName = $context->arguments['name'];

        $pan = $context->subSystem;

        if( !$pan->isPanorama() )
            derr("only supported on Panorama config");


        $tmp_template = $pan->findTemplateStack($templateName);
        if( $tmp_template === null )
        {
            $string = "create TemplateStack: " . $templateName;
            #PH::ACTIONlog($context, $string);

            $dg = $pan->createTemplateStack($templateName);

            if( $context->isAPI )
                $dg->API_sync();
        }
        else
        {
            $string = "Template with name: " . $templateName . " already available!";
            PH::ACTIONlog( $context, $string );
        }
    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => 'false'),
    ),
);

DeviceCallContext::$supportedActions['TemplateStack-delete'] = array(
    'name' => 'templatestack-delete',
    'MainFunction' => function (DeviceCallContext $context) {
        if( $context->object !== null && get_class($context->object) !== "TemplateStack" )
        {
            $string = "devicetype=templatestack missing";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $object = $context->object;
        $name = $object->name();

        $pan = $context->subSystem;
        if( !$pan->isPanorama() )
            derr( "only supported on Panorama config" );

        if( get_class($object) == "TemplateStack" )
        {
            if( $object->countReferences() > 0 )
            {
                $string ="TemplateStack is used and can NOT be removed!";
                PH::ACTIONlog( $context, $string );
                return null;
            }
            /** @var Template $object */
            //if template is used in Template-Stack -> skip
            /*
            $childDG = $object->_childDeviceGroups;
            if( count($childDG) != 0 )
            {
                $string = "Template with name: '" . $name . "' is used in TemplateStack. Template can not removed";
                PH::ACTIONstatus($context, "SKIPPED", $string);
            }
            else
            {
            */
            $string ="     * delete TemplateStack: " . $name;
            PH::ACTIONlog( $context, $string );


            if( $context->isAPI )
            {
                $con = findConnectorOrDie($object);
                $xpath = DH::elementToPanXPath($object->xmlroot);

                $pan->removeTemplateStack($object);
                $con->sendDeleteRequest($xpath);
            }
            else
                $pan->removeTemplateStack($object);

            //}
        }
    }
);

DeviceCallContext::$supportedActions['TemplateStack-clone '] = array(
    'name' => 'templatestack-clone',
    'MainFunction' => function (DeviceCallContext $context) {
        if( $context->object !== null && get_class($context->object) !== "TemplateStack" )
        {
            $string = "devicetype=templatestack missing";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $object = $context->object;
        $name = $object->name();

        $newName = $context->arguments['newname'];

        $pan = $context->subSystem;
        if( !$pan->isPanorama() )
            derr( "only supported on Panorama config" );

        if( get_class($object) == "TemplateStack" )
        {
            $string ="     * clone TemplateStack: " . $name." to: ".$newName;
            PH::ACTIONlog( $context, $string );

            $tmp = $pan->createTemplateStack($newName);
            $test = $object->xmlroot->cloneNode();
            $tmp->xmlroot = $test;
            $tmp->setName( $newName );

            if( $context->isAPI )
            {
                if( $context->isAPI )
                    $tmp->API_sync();
            }
        }
    },
    'args' => array(
        'newname' => array('type' => 'string', 'default' => 'false'),
    ),
);

DeviceCallContext::$supportedActions['TemplateStack-addSerial'] = array(
    'name' => 'templatestack-addserial',
    'MainFunction' => function (DeviceCallContext $context) {
    },
    'GlobalFinishFunction' => function (DeviceCallContext $context) {
        if( $context->object !== null && get_class($context->object) !== "TemplateStack" )
        {
            $string = "devicetype=templatestack missing";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $dgName = $context->arguments['name'];
        $serial = $context->arguments['serial'];

        $pan = $context->subSystem;

        if( !$pan->isPanorama() )
            derr("only supported on Panorama config");

        $tmp_dg = $pan->findTemplateStack($dgName);
        if( $tmp_dg === null )
        {
            $string = "TemplateStack with name: " . $dgName . " not available!";
            PH::ACTIONlog( $context, $string );
        }
        else
        {
            $string = "TemplateStack with name: " . $dgName . " got serial: ".$serial." added!";
            PH::ACTIONlog( $context, $string );
            if( $context->isAPI )
            {
                $con = findConnectorOrDie($tmp_dg);

                #$xpath = DH::elementToPanXPath($object->xmlroot);

                #$pan->removeDeviceGroup($object);
                #$con->sendDeleteRequest($xpath);
                $xpath = DH::elementToPanXPath($tmp_dg->xmlroot);
                $xpath .= '/devices';
                $con->sendSetRequest($xpath, "<entry name='{$serial}'/>");
            }
            else
                $tmp_dg->addDevice( $serial );

        }
    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => 'false'),
        'serial' => array('type' => 'string', 'default' => 'null'),
    ),
);

DeviceCallContext::$supportedActions['TemplateStack-removeSerial'] = array(
    'name' => 'templatestack-removeserial',
    'MainFunction' => function (DeviceCallContext $context) {
    },
    'GlobalFinishFunction' => function (DeviceCallContext $context) {
        if( $context->object !== null && get_class($context->object) !== "TemplateStack" )
        {
            $string = "devicetype=templatestack missing";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $dgName = $context->arguments['name'];
        $serial = $context->arguments['serial'];

        $pan = $context->subSystem;

        if( !$pan->isPanorama() )
            derr("only supported on Panorama config");

        $tmp_dg = $pan->findTemplateStack($dgName);
        if( $tmp_dg === null )
        {
            $string = "TemplateStack with name: " . $dgName . " not available!";
            PH::ACTIONlog( $context, $string );
        }
        else
        {
            $string = "TemplateStack with name: " . $dgName . " got serial: ".$serial." removed!";
            PH::ACTIONlog( $context, $string );
            if( $context->isAPI )
            {
                $con = findConnectorOrDie($tmp_dg);

                $xpath = DH::elementToPanXPath($tmp_dg->xmlroot);
                $xpath .= '/devices';
                $xpath .= "/entry[@name='{$serial}']";

                $con->sendDeleteRequest($xpath);
            }

            $tmp_dg->removeDevice( $serial );
        }
    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => 'false'),
        'serial' => array('type' => 'string', 'default' => 'null'),
    ),
);
DeviceCallContext::$supportedActions['TemplateStack-removeSerial-any'] = array(
    'name' => 'templatestack-removeserial-any',
    'MainFunction' => function (DeviceCallContext $context) {
        if( $context->object !== null && get_class($context->object) !== "TemplateStack" )
        {
            $string = "devicetype=templatestack missing";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $pan = $context->subSystem;

        if( !$pan->isPanorama() )
            derr("only supported on Panorama config");


        if( $context->isAPI )
        {
            $con = $context->connector;

            $xpath = DH::elementToPanXPath($context->object->xmlroot);
            $xpath .= '/devices';

            $con->sendDeleteRequest($xpath);
        }

        $context->object->removeDeviceAny();
    }
);
DeviceCallContext::$supportedActions['VirtualSystem-delete'] = array(
    'name' => 'virtualsystem-delete',
    'MainFunction' => function (DeviceCallContext $context) {
        if( $context->object !== null && get_class($context->object) !== "VirtualSystem" )
        {
            $string = "devicetype=virtualsystem missing";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $object = $context->object;
        $name = $object->name();

        $pan = $context->subSystem;
        if( !$pan->isFirewall() )
            derr( "only supported on Firewall config" );

        if( get_class($object) == "VirtualSystem" )
        {
            $string ="     * delete VirtualSystem: " . $name;
            PH::ACTIONlog( $context, $string );

            if( $context->isAPI )
            {
                $con = findConnectorOrDie($object);
                $xpath = DH::elementToPanXPath($object->xmlroot);

                $con->sendDeleteRequest($xpath);
            }

            $pan->removeVirtualSystem($object);
        }
    }
);

DeviceCallContext::$supportedActions['SharedGateway-delete'] = array(
    'name' => 'sharedgateway-delete',
    'MainFunction' => function (DeviceCallContext $context) {
        if( $context->object !== null && get_class($context->object) !== "SharedGateway" )
        {
            $string = "devicetype=sharedgateway missing";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $object = $context->object;
        $name = $object->name();

        $pan = $context->subSystem;
        if( !$pan->isFirewall() )
            derr( "only supported on Firewall config" );

        if( get_class($object) == "VirtualSystem" )
        {
            $string ="     * delete SharedGateway: " . $name;
            PH::ACTIONlog( $context, $string );

            if( $context->isAPI )
            {
                $con = findConnectorOrDie($object);
                $xpath = DH::elementToPanXPath($object->xmlroot);

                $con->sendDeleteRequest($xpath);
            }

            $pan->removeSharedGateway($object);
        }
    }
);

DeviceCallContext::$supportedActions['SharedGateway-migrate-to-vsys'] = array(
    'name' => 'sharedgateway-migrate-to-vsys',
    'MainFunction' => function (DeviceCallContext $context) {
        if( $context->object !== null && get_class($context->object) !== "SharedGateway" )
        {
            $string = "devicetype=sharedgateway missing";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $object = $context->object;
        $name = $object->name();

        $pan = $context->subSystem;
        if( !$pan->isFirewall() )
            derr( "only supported on Firewall config", null, false );
        if( get_class($object->owner) !== "SharedGatewayStore" )
            derr( "this is not a SharedGateway", null, false );

        if( get_class($object) == "VirtualSystem" )
        {
            $newVSYSname = $context->arguments['name'];
            $vsys_number = str_replace( "vsys", "", $newVSYSname);

            $string ="     * migrate SharedGateway: " . $name." to vsys: ".$newVSYSname;
            PH::ACTIONlog( $context, $string );

            $vsys = $pan->createVirtualSystem($vsys_number);

            $clone = $object->xmlroot->cloneNode(true);

            $clone->setAttribute("name", "vsys".$vsys_number);

            $vsys->xmlroot->parentNode->appendChild($clone);
            $vsys->xmlroot->parentNode->removeChild($vsys->xmlroot);

            $object->owner->xmlroot->removeChild($object->xmlroot);
        }
    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => 'false'),
    ),
);


DeviceCallContext::$supportedActions['ManagedDevice-create'] = array(
    'name' => 'manageddevice-create',
    'MainFunction' => function (DeviceCallContext $context) {
    },
    'GlobalFinishFunction' => function (DeviceCallContext $context) {

        if( $context->object !== null && get_class($context->object) !== "ManagedDevice" )
        {
            $string = "devicetype=managedevice missing";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $serialName = $context->arguments['serial'];

        $pan = $context->subSystem->owner;

        if( !$pan->isPanorama() )
            derr("only supported on Panorama config");


        $tmp_manageddevice = $pan->managedFirewallsStore->find($serialName);
        if( $tmp_manageddevice === null )
        {
            $string = "create ManagedDevice: " . $serialName;
            PH::ACTIONlog($context, $string);

            $dg = $pan->managedFirewallsStore->findOrCreate($serialName);

            if( $context->isAPI )
            {
                $con = findConnectorOrDie($dg);

                $xpath = '/config/mgt-config/devices';
                $con->sendSetRequest($xpath, "<entry name='{$serialName}'/>");
            }
        }
        else
        {
            $string = "ManagedDevice with name: " . $serialName . " already available!";
            PH::ACTIONlog( $context, $string );
        }
    },
    'args' => array(
        'serial' => array('type' => 'string', 'default' => 'false'),
    ),
);

DeviceCallContext::$supportedActions['ManagedDevice-delete'] = array(
    'name' => 'manageddevice-delete',
    'MainFunction' => function (DeviceCallContext $context) {
    },
    'GlobalFinishFunction' => function (DeviceCallContext $context) {
        if( $context->object !== null && get_class($context->object) !== "ManagedDevice" )
        {
            $string = "devicetype=managedevice missing";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $serial_tosearch = $context->arguments['serial'];
        $force = $context->arguments['force'];

        /** @var ManagedDevice $object */
        $object = $context->object;

        #$pan = $context->subSystem
        $pan = $context->subSystem->owner;

        if( !$pan->isPanorama() )
            derr("only supported on Panorama config");

        $tmp_dg = $pan->findManagedDevice($serial_tosearch);
        if( $tmp_dg === null )
        {
            $string = "ManagedDevice with name: " . $serial_tosearch . " not available!";
            PH::ACTIONlog( $context, $string );
        }
        else
        {
            $tmp_manageddevice = $object;
            $serial = $object->name();

            /** @var ManagedDevice $tmp_manageddevice */
            if ($force)
            {

                $references = $tmp_manageddevice->getReferences();
                foreach ($references as $ref) {
                    $class = get_class($ref);
                    #print $class."\n";
                    if ($class === "DeviceGroup") {
                        /** @var DeviceGroup $ref */
                        //remove serial from DG
                        if ($context->isAPI) {
                            $con = findConnectorOrDie($ref);

                            $xpath = DH::elementToPanXPath($ref->xmlroot);
                            $xpath .= '/devices';
                            $xpath .= "/entry[@name='{$serial}']";

                            $con->sendDeleteRequest($xpath);
                        }

                        $ref->removeDevice($serial);
                        $tmp_manageddevice->removeReference($ref);
                    } elseif ($class === "TemplateStack") {
                        /** @var TemplateStack $ref */
                        if ($context->isAPI) {
                            $con = findConnectorOrDie($ref);

                            $xpath = DH::elementToPanXPath($ref->xmlroot);
                            $xpath .= '/devices';
                            $xpath .= "/entry[@name='{$serial}']";

                            $con->sendDeleteRequest($xpath);
                        }

                        $ref->removeDevice($serial);
                        $tmp_manageddevice->removeReference($ref);
                    } elseif ($class === "LogCollectorGroup") {
                        $string = "force delete ManagedDevice is not yet implemented for LogCollectorGroup!";
                        PH::ACTIONlog($context, $string);
                        return null;
                    }
                }
            }


            if ($tmp_manageddevice->countReferences() > 0) {
                $string = "ManagedDevice is used and can NOT be removed!";
                PH::ACTIONlog($context, $string);
                return null;
            }

            $string = "delete ManagedDevice: " . $tmp_manageddevice->name();
            PH::ACTIONlog($context, $string);


            if ($context->isAPI) {
                $con = findConnectorOrDie($tmp_manageddevice);
                $xpath = "/config/mgt-config/devices/entry[@name='{$tmp_manageddevice->name()}']";
                $con->sendDeleteRequest($xpath);
            } else
                $pan->managedFirewallsStore->removeManagedDevice($tmp_manageddevice->name());
        }
    },
    'args' => array(
        'serial' => array('type' => 'string', 'default' => 'false'),
        'force' => array('type' => 'bool', 'default' => 'false',
            'help' => "decommission Manageddevice, also if used on Device-Group or Template-stack"
        )
    ),
);

DeviceCallContext::$supportedActions['ManagedDevice-delete-any'] = array(
    'name' => 'manageddevice-delete-any',
    'MainFunction' => function (DeviceCallContext $context) {
        if( $context->object !== null && get_class($context->object) !== "ManagedDevice" )
        {
            $string = "devicetype=managedevice missing";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $debug = $context->arguments['debug'];
        $force = $context->arguments['force'];

        /** @var ManagedDevice $object */
        $object = $context->object;
        $pan = $context->subSystem->owner;

        if( !$pan->isPanorama() )
            derr("only supported on Panorama config");

        $tmp_manageddevice = $object;
        $serial = $object->name();

        /** @var ManagedDevice $tmp_manageddevice */
        if( $force )
        {
            $references = $tmp_manageddevice->getReferences();
            //Todo: for API this references are 0 why???

            foreach( $references as $ref )
            {
                $class = get_class( $ref );
                if( $class === "DeviceGroup"  )
                {
                    /** @var DeviceGroup $ref */
                    //remove serial from DG
                    if( $context->isAPI )
                    {
                        $con = findConnectorOrDie($ref);

                        $xpath = DH::elementToPanXPath($ref->xmlroot);
                        $xpath .= '/devices';
                        $xpath .= "/entry[@name='{$serial}']";
                        $con->sendDeleteRequest($xpath);

                        $user_group_source_node = DH::findFirstElement("user-group-source", $ref->xmlroot);
                        if( $user_group_source_node !== false )
                        {
                            $master_device_node = DH::findFirstElement("master-device", $user_group_source_node);
                            if($master_device_node !== false)
                            {
                                $device_node = DH::findFirstElement("device", $master_device_node);
                                if($device_node->textContent == $serial)
                                {
                                    $xpath = DH::elementToPanXPath($ref->xmlroot);
                                    $xpath .= '/user-group-source';
                                    $xpath .= "/master-device";
                                    $con->sendDeleteRequest($xpath);
                                }
                            }
                        }
                    }

                    $ref->removeDevice( $serial, $debug );
                    $tmp_manageddevice->removeReference( $ref );
                }
                elseif( $class === "TemplateStack" )
                {
                    /** @var TemplateStack $ref */
                    if( $context->isAPI )
                    {
                        $con = findConnectorOrDie($ref);

                        $xpath = DH::elementToPanXPath($ref->xmlroot);
                        $xpath .= '/devices';
                        $xpath .= "/entry[@name='{$serial}']";
                        $con->sendDeleteRequest($xpath);

                        $user_group_source_node = DH::findFirstElement("user-group-source", $this->xmlroot);
                        if( $user_group_source_node !== false )
                        {
                            $master_device_node = DH::findFirstElement("master-device", $user_group_source_node);
                            if($master_device_node !== false)
                            {
                                $device_node = DH::findFirstElement("device", $master_device_node);
                                if($device_node->textContent == $serial)
                                {
                                    $xpath = DH::elementToPanXPath($ref->xmlroot);
                                    $xpath .= '/user-group-source';
                                    $xpath .= "/master-device";
                                    $con->sendDeleteRequest($xpath);
                                }
                            }
                        }
                    }

                    $ref->removeDevice( $serial, $debug );
                    $tmp_manageddevice->removeReference( $ref );
                }
                elseif( $class === "LogCollectorGroup" )
                {
                    /** @var LogCollectorGroup $ref */
                    if( $context->isAPI )
                    {
                        $con = findConnectorOrDie($ref);

                        $xpath = DH::elementToPanXPath($ref->xmlroot);
                        $xpath .= '/devices';
                        $xpath .= "/entry[@name='{$serial}']";
                        $con->sendDeleteRequest($xpath);
                    }

                    $ref->removeDevice( $serial, $debug );
                    $tmp_manageddevice->removeReference( $ref );
                }
                elseif( strpos( $class, "Rule" ) !== FALSE )
                {
                    /** @var SecurityRule $ref */
                    if( $context->isAPI )
                    {
                        $ref->API_setDescription($ref->description()."|target-serial:'".$serial."' removed|");
                        $ref->API_target_removeDevice($serial, "ANY");
                    }
                    else
                    {
                        $ref->setDescription($ref->description()."|target-serial:'".$serial."' removed|");
                        $ref->target_removeDevice($serial, "ANY", $debug);
                    }
                    $tmp_manageddevice->removeReference( $ref );
                }
            }
        }


        if( $tmp_manageddevice->countReferences() > 0 )
        {
            $references = $tmp_manageddevice->getReferences();
            foreach( $references as $ref )
            {
                $class = get_class($ref);
                PH::print_stdout("used in: ".$class." | name: ".$ref->name());
            }
            $string ="ManagedDevice is used and can NOT be removed!";
            PH::ACTIONlog( $context, $string );
            return null;
        }

        $string = "delete ManagedDevice: " . $tmp_manageddevice->name();
        PH::ACTIONlog($context, $string);


        if( $context->isAPI )
        {
            $con = findConnectorOrDie($tmp_manageddevice);
            $xpath = "/config/mgt-config/devices/entry[@name='{$tmp_manageddevice->name()}']";
            $con->sendDeleteRequest($xpath);
        }
        else
            $pan->managedFirewallsStore->removeManagedDevice( $tmp_manageddevice->name() );

    },
    'args' => array(
        'force' => array('type' => 'bool', 'default' => 'false',
            'help' => "decommission Manageddevice, also if used on Device-Group or Template-stack"
        ),
        'debug' => array('type' => 'string', 'default' => 'false'),
    ),
);

DeviceCallContext::$supportedActions['exportToExcel'] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (DeviceCallContext $context) {
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


        #$headers = '<th>location</th><th>name</th><th>template</th>';
        $headers = '<th>ID</th><th>name</th><th>template</th>';

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

                #$lines .= $context->encloseFunction(PH::getLocationString($object));

                $lines .= $context->encloseFunction($object->name());

                if( get_class($object) == "TemplateStack" )
                {
                    $lines .= $context->encloseFunction( array_reverse($object->templates) );
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

DeviceCallContext::$supportedActions['template-add'] = array(
    'name' => 'template-add',
    'MainFunction' => function (DeviceCallContext $context) {

        /** @var TemplateStack $object */
        $object = $context->object;

        $pan = $context->subSystem;
        if( !$pan->isPanorama() )
            derr( "only supported on Panorama config" );

        if( get_class($object) == "TemplateStack" )
        {
            $templateName = $context->arguments['templateName'];
            $position = $context->arguments['position'];


            $template = $object->owner->findTemplate( $templateName );

            if( $template == null )
            {
                $string = "adding template '".$templateName."' because it is not found in this config";
                PH::ACTIONstatus( $context, "SKIPPED", $string );

                return null;
            }

            if( $context->isAPI )
                $object->API_addTemplate( $template, $position );
            else
                $object->addTemplate( $template, $position );
        }
        PH::print_stdout();
    },
    'args' => array(
        'templateName' => array('type' => 'string', 'default' => 'false'),
        'position' => array('type' => 'string', 'default' => 'bottom'),
    ),
);

DeviceCallContext::$supportedActions['AddressStore-rewrite'] = array(
    'name' => 'addressstore-rewrite',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {

        /** @var DeviceGroup $object */
        $object = $context->object;

        $pan = $context->subSystem;
        if( !$pan->isPanorama() )
            derr( "only supported on Panorama config" );

        if( get_class($object) == "DeviceGroup" )
        {
            if( $context->first )
            {
                $object->owner->addressStore->rewriteAddressStoreXML();
                $object->owner->addressStore->rewriteAddressGroupStoreXML();
                $context->first = false;
            }

            $object->addressStore->rewriteAddressStoreXML();
            $object->addressStore->rewriteAddressGroupStoreXML();
        }

    }
  //rewriteAddressStoreXML()
);

DeviceCallContext::$supportedActions['exportInventoryToExcel'] = array(
    'name' => 'exportInventoryToExcel',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
        $context->fields = array();
        $context->device_array = array();
    },
    'MainFunction' => function (DeviceCallContext $context)
    {

        if( $context->first && get_class($context->object) == "ManagedDevice" )
        {
            $connector = findConnectorOrDie($context->object);
            $context->device_array = $connector->panorama_getAllFirewallsSerials();


            foreach( $context->device_array as $index => &$array )
            {
                foreach( $array as $key => $value )
                    $context->fields[$key] = $key;
            }


            foreach( $context->device_array as $index => &$array )
            {
                foreach( $context->fields as $key => $value )
                {
                    if( !isset( $array[$key] ) )
                        $array[$key] = "not set";
                }
            }
        }

    },
    'GlobalFinishFunction' => function (DeviceCallContext $context)
    {
        $content = "";
        if( get_class($context->object) == "ManagedDevice" )
        {
            $lines = '';

            $count = 0;
            if( !empty($context->device_array) )
            {
                foreach ($context->device_array as $device)
                {
                    $count++;

                    /** @var SecurityRule|NatRule $rule */
                    if ($count % 2 == 1)
                        $lines .= "<tr>\n";
                    else
                        $lines .= "<tr bgcolor=\"#DDDDDD\">";

                    foreach($context->fields as $fieldName => $fieldID )
                    {
                        $lines .= "<td>".$device[$fieldID]."</td>";
                    }
                    $lines .= "</tr>\n";
                }
            }

            $tableHeaders = '';
            foreach($context->fields as $fName => $value )
                $tableHeaders .= "<th>{$fName}</th>\n";

            $content = file_get_contents(dirname(__FILE__).'/html/export-template.html');


            $content = str_replace('%TableHeaders%', $tableHeaders, $content);

            $content = str_replace('%lines%', $lines, $content);

            $jscontent =  file_get_contents(dirname(__FILE__).'/html/jquery.min.js');
            $jscontent .= "\n";
            $jscontent .= file_get_contents(dirname(__FILE__).'/html/jquery.stickytableheaders.min.js');
            $jscontent .= "\n\$('table').stickyTableHeaders();\n";

            $content = str_replace('%JSCONTENT%', $jscontent, $content);
        }
        file_put_contents($context->arguments['filename'], $content);
    },
    'args' => array(
        'filename' => array('type' => 'string', 'default' => '*nodefault*',
            'help' => "only usable with 'devicetype=manageddevice'"
        )
    )
);

DeviceCallContext::$supportedActions['exportLicenseToExcel'] = array(
    'name' => 'exportLicenseToExcel',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
        $context->fields = array();
        $context->device_array = array();
    },
    'MainFunction' => function (DeviceCallContext $context)
    {

        if( $context->first && get_class($context->object) == "ManagedDevice" )
        {
            $connector = findConnectorOrDie($context->object);
            $configRoot = $connector->sendOpRequest( '<request><batch><license><info></info></license></batch></request>' );



            $configRoot = DH::findFirstElement('result', $configRoot);
            if( $configRoot === FALSE )
                derr("<result> was not found", $configRoot);

            $configRoot = DH::findFirstElement('devices', $configRoot);
            if( $configRoot === FALSE )
                derr("<config> was not found", $configRoot);


#var_dump( $configRoot );

            foreach( $configRoot->childNodes as $entry )
            {
                if( $entry->nodeType != XML_ELEMENT_NODE )
                    continue;

                foreach( $entry->childNodes as $node )
                {
                    if( $node->nodeType != XML_ELEMENT_NODE )
                        continue;


                    if( $node->nodeName == "serial" ||  $node->nodeName == "serial-no" )
                    {
                        #print $node->nodeName." : ".$node->textContent."\n";
                        $serial_no = $node->textContent;
                        $context->device_array[ $serial_no ][ $node->nodeName ] = $serial_no;
                    }
                    else
                    {
                        #print $node->nodeName." : ".$node->textContent."\n";
                        $tmp_node = $node->textContent;
                        #$tmp_key = $tmp_node;
                        $tmp_key = $serial_no;
                        $context->device_array[ $tmp_key ][ $node->nodeName ] = $tmp_node;

                        if( $node->childNodes->length > 1 )
                        {
                            foreach( $node->childNodes as $child )
                            {
                                if( $node->nodeType != XML_ELEMENT_NODE )
                                    continue;


                                if( $child->nodeName == "entry" )
                                {
                                    $tmp_node = $child->textContent;
                                    $context->device_array[ $tmp_key ][ $child->getAttribute('name') ] = $tmp_node;
                                }
                            }
                        }
                    }
                }
            }

            foreach( $context->device_array as $index => &$array )
            {
                foreach( $array as $key => $value )
                    $context->fields[$key] = $key;
            }


            foreach( $context->device_array as $index => &$array )
            {
                foreach( $context->fields as $key => $value )
                {
                    if( !isset( $array[$key] ) )
                        $array[$key] = "- - - - -";
                }
            }
        }
    },
    'GlobalFinishFunction' => function (DeviceCallContext $context)
    {
        $content = "";
        if( get_class($context->object) == "ManagedDevice" )
        {
            $lines = '';

            $count = 0;
            if( !empty($context->device_array) )
            {
                foreach ($context->device_array as $device)
                {
                    $count++;

                    /** @var SecurityRule|NatRule $rule */
                    if ($count % 2 == 1)
                        $lines .= "<tr>\n";
                    else
                        $lines .= "<tr bgcolor=\"#DDDDDD\">";

                    foreach($context->fields as $fieldName => $fieldID )
                    {
                        $lines .= "<td>".$device[$fieldID]."</td>";
                    }

                    $lines .= "</tr>\n";
                }
            }


            $tableHeaders = '';
            foreach($context->fields as $fName => $value )
                $tableHeaders .= "<th>{$fName}</th>\n";

            $content = file_get_contents(dirname(__FILE__).'/html/export-template.html');


            $content = str_replace('%TableHeaders%', $tableHeaders, $content);

            $content = str_replace('%lines%', $lines, $content);

            $jscontent =  file_get_contents(dirname(__FILE__).'/html/jquery.min.js');
            $jscontent .= "\n";
            $jscontent .= file_get_contents(dirname(__FILE__).'/html/jquery.stickytableheaders.min.js');
            $jscontent .= "\n\$('table').stickyTableHeaders();\n";

            $content = str_replace('%JSCONTENT%', $jscontent, $content);


        }

        file_put_contents($context->arguments['filename'], $content);
    },
    'args' => array(
        'filename' => array('type' => 'string', 'default' => '*nodefault*',
        'help' => "only usable with 'devicetype=manageddevice'"
        )
    )
);

DeviceCallContext::$supportedActions['display-shadowrule'] = array(
    'name' => 'display-shadowrule',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;

        if( !$context->isAPI )
            derr( "API mode needed for actions=display-shadowrule" );

        $context->jsonArray = array();

        $context->fields = array(
            'location' => 'location',
            'rulebase' => 'rulebase',
            'type' => 'type',
            'name' => 'name',
            'tag' => 'tags',
            'from' => 'from',
            'to' => 'to',
            'src_negated' => 'source_negated',
            'src' => 'source',
            'dst_negated' => 'destination_negated',
            'dst' => 'destination',
            'service' => 'service',
            'application' => 'application',
            'action' => 'action',
            'security' => 'security-profile',
            'disabled' => 'disabled',
            'src user' => 'src-user',
            'log start' => 'log_start',
            'log end' => 'log_end',
            'log prof' => 'log_profile',
            'log prof name' => 'log_profile_name',
            'snat type' => 'snat_type',
            'snat_address' => 'snat_address',
            'dnat_host' => 'dnat_host',
            'description' => 'description',
            'schedule' => 'schedule',
            'target' => 'target'
        );

        $actionProperties = "exportToExcel";
        $arguments = "";
        $context->ruleContext = new RuleCallContext( $actionProperties, $arguments);
    },
    'MainFunction' => function (DeviceCallContext $context)
    {
        $object = $context->object;
        $classtype = get_class($object);

        $sub_name = $object->name();
        $shadowArray = array();
        if( $classtype == "VirtualSystem" )
        {
            if( $context->object->version < 91 )
                derr( "PAN-OS >= 9.1 is needed for display-shadowrule", null, false );

            $type = "vsys";
            $type_name = $object->name();
            $countInfo = "<" . $type . ">" . $type_name . "</" . $type . ">";

            $shadowArray = $context->connector->getShadowInfo($countInfo, false);
        }
        elseif( $classtype == "ManagedDevice" )
        {
            if( $object->isConnected )
            {
                #if( $context->object->version < 91 )
                #    derr( "PAN-OS >= 9.1 is needed for display-shadowrule", null, false );

                $type = "device-serial";
                $type_name = $object->name();
                $countInfo = "<" . $type . ">" . $type_name . "</" . $type . ">";

                $shadowArray = $context->connector->getShadowInfo($countInfo, true, "", true);
            }
        }
        elseif( $classtype == "DeviceGroup" )
        {
            if( $context->object->version < 91 )
                derr( "PAN-OS >= 9.1 is needed for display-shadowrule", null, false );

            /** @var DeviceGroup $object */
            $devices = $object->getDevicesInGroup();

            $shadowArray = array();
            foreach( $devices as $serial => $device )
            {
                $managedDevice = $object->owner->managedFirewallsStore->find( $serial );
                if( $managedDevice->isConnected )
                {
                    $type = "device-serial";
                    $type_name = $managedDevice->name();
                    $sub_name .= "-".$type_name;
                    $countInfo = "<" . $type . ">" . $type_name . "</" . $type . ">";

                    $shadowArray2 = $context->connector->getShadowInfo($countInfo, true, $object->name() );
                    $shadowArray = array_merge( $shadowArray, $shadowArray2 );
                }
            }
            //try to only use active device / skip passive FW
        }


        $jsonArray = array();
        $orig_sub_name = $sub_name;
        foreach( $shadowArray as $name => $array )
        {
            foreach( $array as $ruletype => $entries )
            {
                $sub_name = $orig_sub_name;

                if( $ruletype == 'security'  || $ruletype == "security-rule" )
                    $ruletype = "securityRules";
                elseif( $ruletype == 'nat'  || $ruletype == "nat-rule" )
                    $ruletype = "natRules";
                elseif( $ruletype == 'decryption' || $ruletype == "ssl-rule" )
                    $ruletype = "decryptionRules";
                else
                {
                    mwarning( "bugfix needed for type: ".$ruletype, null, false );
                    $ruletype = "securityRules";
                }


                if( $classtype == "ManagedDevice" )
                {
                    $subName = "DG";
                    PH::print_stdout( "     ** ".$subName.": " . $name );
                    $sub_name .= "-".$name;
                }

                foreach( $entries as $key => $item  )
                {
                    $rule = null;

                    $origName = $name;
                    //uid: $key -> search rule name for uid
                    if( $classtype == "ManagedDevice" )
                    {
                        /** @var PanoramaConf $pan */
                        $pan = $object->owner->owner;

                        /** @var DeviceGroup $sub */
                        $sub = $pan->findDeviceGroup($name);
                        $rule = $sub->$ruletype->findByUUID( $key );
                        $ownerDG = $name;

                        while( $rule === null )
                        {
                            $sub = $sub->parentDeviceGroup;
                            if( $sub !== null )
                            {
                                $rule = $sub->$ruletype->findByUUID( $key );
                                $ownerDG = $sub->name();
                            }
                            else
                            {
                                $rule = $pan->$ruletype->findByUUID( $key );
                                $ownerDG = "shared";
                                if( $rule === null )
                                    break;
                            }
                        }
                    }
                    elseif( $classtype == "VirtualSystem" )
                    {
                        /** @var PANConf $pan */
                        $pan = $object->owner;

                        /** @var VirtualSystem $sub */
                        $sub = $pan->findVirtualSystem( $name );
                        $rule = $sub->$ruletype->findByUUID( $key );
                        $ownerDG = $name;

                        if( $rule === null )
                        {
                            $ruleArray = $sub->$ruletype->resultingRuleSet();
                            foreach( $ruleArray as $ruleSingle )
                            {
                                /** @var SecurityRule $ruleSingle */
                                if( $ruleSingle->uuid() === $key )
                                {
                                    $rule = $ruleSingle;
                                    $ownerDG = "panoramaPushedConfig";
                                }
                            }
                        }
                    }
                    elseif( $classtype == "DeviceGroup" )
                    {
                        /** @var PanoramaConf $pan */
                        $pan = $object->owner;

                        $rule = $object->$ruletype->findByUUID( $key );
                        $sub = $object;
                        $ownerDG = $sub->name();

                        while( $rule === null )
                        {
                            $sub = $sub->parentDeviceGroup;
                            if( $sub !== null )
                            {
                                $rule = $sub->$ruletype->findByUUID( $key );
                                $ownerDG = $sub->name();
                            }
                            else
                            {
                                $rule = $pan->$ruletype->findByUUID( $key );
                                $ownerDG = "shared";
                                if( $rule === null )
                                    break;
                            }
                        }
                    }

                    PH::print_stdout();
                    if( $rule !== null )
                    {
                        PH::print_stdout( "        * RULE of type ".$ruletype.": '" . $rule->name(). "' owner: '".$ownerDG."' shadows rule: " );
                        $tmpName = $rule->name();
                        $jsonArray[$ruletype][$tmpName]['rule'] = $rule;
                    }

                    else
                    {
                        PH::print_stdout( "        * RULE of type ".$ruletype.": '" . $key."'" );
                        $tmpName = $key;
                        $jsonArray[$ruletype][$tmpName]['rule'] = $key;
                    }


                    foreach( $item as $shadow )
                    {
                        if( $classtype == "VirtualSystem" )
                            $shadow2 = PH::find_string_between( $shadow, " shadows rule '", "'.");
                        else
                            $shadow2 = PH::find_string_between( $shadow, " shadows '", "'.");


                        if( $classtype == "ManagedDevice" )
                        {
                            $sub = $pan->findDeviceGroup($ownerDG);
                            $shadowedRuleObj = $sub->$ruletype->find( $shadow2 );
                            while( $shadowedRuleObj === null )
                            {
                                $sub = $sub->parentDeviceGroup;
                                if( $sub !== null )
                                {
                                    $shadowedRuleObj = $sub->$ruletype->find( $shadow2 );
                                }
                                else
                                {
                                    $shadowedRuleObj = $pan->$ruletype->find( $shadow2 );
                                    if( $shadowedRuleObj === null )
                                        break;
                                }
                            }
                        }
                        elseif( $classtype == "VirtualSystem" )
                        {
                            if( $ownerDG === "panoramaPushedConfig" )
                            {
                                derr( "shadow Rule check on FW with panoramaPushedConfig is not implemented", null, FALSE );
                            }
                            else
                                $sub = $pan->findVirtualSystem( $ownerDG );

                            $shadowedRuleObj = $sub->$ruletype->find( $shadow2 );
                            if( $shadowedRuleObj === null )
                            {
                                $ruleArray = $sub->$ruletype->resultingRuleSet();
                                foreach( $ruleArray as $ruleSingle )
                                {
                                    /** @var SecurityRule $ruleSingle */
                                    if( $ruleSingle->name() === $shadow2 )
                                        $shadowedRuleObj = $ruleSingle;
                                }
                            }
                        }
                        elseif( $classtype == "DeviceGroup" )
                        {
                            /** @var PanoramaConf $pan */
                            $pan = $object->owner;
                            $sub = $object;

                            $shadowedRuleObj = $sub->$ruletype->find( $shadow2 );
                            while( $shadowedRuleObj === null )
                            {
                                $sub = $sub->parentDeviceGroup;
                                if( $sub !== null )
                                    $shadowedRuleObj = $sub->$ruletype->find( $shadow2 );
                                else
                                {
                                    $shadowedRuleObj = $pan->$ruletype->find( $shadow2 );
                                    if( $shadowedRuleObj === null )
                                        break;
                                }
                            }
                        }


                        if( $shadowedRuleObj !== null )
                        {
                            $jsonArray[$ruletype][$tmpName]['shadow'][] = $shadowedRuleObj;
                            PH::print_stdout( "          - '" . $shadowedRuleObj->name()."'" );
                        }
                        else
                        {
                            $jsonArray[$ruletype][$tmpName]['shadow'][] = $shadow2;
                            PH::print_stdout( "          - '" . $shadow2."'" );
                        }
                    }
                }

                if( $classtype == "ManagedDevice" )
                {
                    PH::$JSON_TMP['sub'] = $jsonArray;
                    $context->jsonArray[$sub_name] = $jsonArray;
                }
            }
        }

        if( $classtype !== "ManagedDevice" )
        {
            PH::$JSON_TMP['sub'] = $jsonArray;
            $context->jsonArray[$sub_name] = $jsonArray;
        }

    },
    'GlobalFinishFunction' => function (DeviceCallContext $context) {
            $filename = $context->arguments['exportToExcel'];
            if( $filename !== "*nodefault*" )
            {
                if( isset( $_SERVER['REQUEST_METHOD'] ) )
                    $filename = "project/html/".$filename;

                $lines = '';

                $headers = '<th>sub</th><th>ruletype</th>';
                foreach( $context->fields as $fieldName => $fieldID )
                    $headers .= '<th>'.$fieldID.'</th>';

                $count = 0;

                    foreach( $context->jsonArray as $subtype => $sub )
                    {
                        foreach( $sub as $keyruletype => $ruletype )
                        {
                            foreach( $ruletype as $keyrule => $rule )
                            {
                                $count++;

                                /** @var Tag $object */
                                if( $count % 2 == 1 )
                                    $lines .= "<tr>\n";
                                else
                                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                                #$lines .= $context->encloseFunction(PH::getLocationString($object));

                                $lines .= $context->encloseFunction( strval($subtype) );
                                $lines .= $context->encloseFunction( strval($keyruletype) ) ;


                                if( is_object( $rule['rule'] ) )
                                {
                                    $line = "";
                                    foreach( $context->fields as $fieldName => $fieldID )
                                        $line .= $context->ruleContext->ruleFieldHtmlExport($rule['rule'], $fieldID);
                                    #$lines .= $context->encloseFunction( $line );
                                    $lines .= $line;

                                    #$lines .= $context->encloseFunction( $rule['rule']->name() );
                                }
                                else
                                    $lines .= $context->encloseFunction( $rule['rule'] );

                                $lines .= "</tr>\n";

                                $shadowRuleString = array();
                                foreach( $rule['shadow'] as $keyl => $ruleItem )
                                {
                                    if( $count % 2 == 1 )
                                        $lines .= "<tr>\n";
                                    else
                                        $lines .= "<tr bgcolor=\"#DDDDDD\">";

                                    $lines .= $context->encloseFunction( "---" );
                                    $lines .= $context->encloseFunction( "shadowed" ) ;



                                    if( is_object( $ruleItem ) )
                                    {
                                        $line = "";
                                        foreach( $context->fields as $fieldName => $fieldID )
                                            $line .= $context->ruleContext->ruleFieldHtmlExport($ruleItem, $fieldID);
                                        #$lines .= $context->encloseFunction( $line );
                                        $lines .= $line;

                                        #$lines .= $context->encloseFunction( $ruleItem->name() );
                                    }

                                    else
                                        $lines .= $context->encloseFunction( strval($ruleItem) );

                                    $lines .= "</tr>\n";
                                }



                            }
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
            }
    },
    'args' => array(
        'exportToExcel' => array('type' => 'string', 'default' => '*nodefault*', 'help' => "define an argument with filename to also store shadow rule to an excel/html speardsheet file",
    )
)
);

DeviceCallContext::$supportedActions['geoIP-check'] = array(
    'name' => 'geoIP-check',
    'GlobalInitFunction' => function (DeviceCallContext $context) {


        if( $context->subSystem->isPanorama() )
        {
            derr( "this action can be only run against PAN-OS FW", null, false );
        }

        $geoip = str_pad("geoIP JSON: ", 15) ."----------";
        $panos_geoip = str_pad("PAN-OS: ", 15) ."----------";

        $prefix = $context->arguments['checkIP'];

        if( filter_var($prefix, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) )
        {
            $filename = "ipv6";
            $prefixArray = explode(':', $prefix);
            $pattern = '/^' . $prefixArray[0] . ':' . $prefixArray[1] . ':/';
        }
        elseif( filter_var($prefix, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) )
        {
            $filename = "ipv4";
            $prefixArray = explode('.', $prefix);
            $pattern = '/^' . $prefixArray[0] . './';
        }
        else
            derr("not a valid IP: " . $prefix);


        $filepath = dirname(__FILE__)."/../../lib/resources/geoip/data/";
        $file = $filepath."RegionCC" . $filename . ".json";
        if ( !file_exists($file) )
        {
            derr( "Maxmind geo2ip lite database not downloaded correctly for PAN-OS-PHP", null, false );
        }
        $fileLine = file_get_contents( $file );
        $array = json_decode($fileLine, TRUE);
        if( $array === null )
            derr( "invalid JSON file provided", null, FALSE );
        unset( $fileLine);

        foreach( $array as $countryKey => $country )
        {
            foreach( $country as $value )
            {
                if( preg_match($pattern, $value) )
                    $responseArray[$value] = $countryKey;
            }
        }
        unset( $array );


        foreach( $responseArray as $ipKey => $countryKey )
        {
            if( cidr::netMatch($ipKey, $prefix) > 0 )
                $geoip = str_pad("geoIP JSON: ", 15) . $countryKey . " - " . $ipKey;
        }


        //###################################################

        if( $context->isAPI && $filename !== "ipv6" )
        {
            $request = "<show><location><ip>" . $prefix . "</ip></location></show>";

            try
            {
                $candidateDoc = $context->connector->sendOpRequest($request);
            }
            catch(Exception $e)
            {
                PH::disableExceptionSupport();
                print " ***** an error occured : " . $e->getMessage() . "\n\n";
            }


            #print $geoip . "\n";
            #$candidateDoc->preserveWhiteSpace = FALSE;
            #$candidateDoc->formatOutput = TRUE;
            #print $candidateDoc->saveXML();


            $result = DH::findFirstElement('result', $candidateDoc);
            $entry = DH::findFirstElement('entry', $result);

            $country = $entry->getAttribute("cc");
            $ip = DH::findFirstElement('ip', $entry)->textContent;
            $countryName = DH::findFirstElement('country', $entry)->textContent;

            $panos_geoip = str_pad("PAN-OS: ", 15) . $country . " - " . $ip . " - " . $countryName;
        }
        elseif($filename === "ipv6")
        {
            PH::print_stdout("not working for PAN-OS - ipv6 syntax for 'show location ip' not yet clear");
        }

        PH::print_stdout();
        PH::print_stdout();
        PH::print_stdout($geoip);
        PH::print_stdout($panos_geoip);
        PH::print_stdout();

    },
    'MainFunction' => function (DeviceCallContext $context)
    {
    },
    'args' => array(
        'checkIP' => array('type' => 'string', 'default' => '8.8.8.8',
            'help' => "checkIP is IPv4 or IPv6 host address",
        )
    )
);

DeviceCallContext::$commonActionFunctions['sp_spg-create'] = array(
    'function_xmlfiles' => function (DeviceCallContext $context) {
        $f = DeviceCallContext::$commonActionFunctions['sp_spg-create']['function_panVersion'];
        $panVersion = $f($context);

        $pathString = dirname(__FILE__)."/../../iron-skillet";

        $context->vp_xmlString = file_get_contents( $pathString."/panos_v10.0/templates/panorama/snippets/profiles_vulnerability.xml");
        $context->fb_xmlString = file_get_contents( $pathString."/panos_v10.0/templates/panorama/snippets/profiles_file_blocking.xml");
        $context->wf_xmlString = file_get_contents( $pathString."/panos_v10.0/templates/panorama/snippets/profiles_wildfire_analysis.xml");

        if( $context->object->owner->version < 90 )
        {
            $context->av_xmlString = file_get_contents( $pathString."/panos_v8.1/templates/panorama/snippets/profiles_virus.xml");
            $context->as_xmlString = file_get_contents( $pathString."/panos_v8.1/templates/panorama/snippets/profiles_spyware.xml");
            $context->url_xmlString = file_get_contents( $pathString."/panos_v8.1/templates/panorama/snippets/profiles_url_filtering.xml");
        }
        elseif( $context->object->owner->version < 100 )
        {
            $context->av_xmlString = file_get_contents( $pathString."/panos_v9.1/templates/panorama/snippets/profiles_virus.xml");
            $context->as_xmlString = file_get_contents( $pathString."/panos_v9.1/templates/panorama/snippets/profiles_spyware.xml");
            $context->url_xmlString = file_get_contents( $pathString."/panos_v9.1/templates/panorama/snippets/profiles_url_filtering.xml");
        }
        elseif( $context->object->owner->version >= 100 and $context->object->owner->version < 112 )
        {
            $context->av_xmlString = file_get_contents( $pathString."/panos_v".$panVersion."/templates/panorama/snippets/profiles_virus.xml");
            $context->as_xmlString = file_get_contents( $pathString."/panos_v".$panVersion."/templates/panorama/snippets/profiles_spyware.xml");
            $context->vp_xmlString = file_get_contents( $pathString."/panos_v".$panVersion."/templates/panorama/snippets/profiles_vulnerability.xml");
            $context->url_xmlString = file_get_contents( $pathString."/panos_v".$panVersion."/templates/panorama/snippets/profiles_url_filtering.xml");
            $context->fb_xmlString = file_get_contents( $pathString."/panos_v".$panVersion."/templates/panorama/snippets/profiles_file_blocking.xml");
            $context->wf_xmlString = file_get_contents( $pathString."/panos_v".$panVersion."/templates/panorama/snippets/profiles_wildfire_analysis.xml");
        }
        elseif( $context->object->owner->version >= 112 )
        {
            $context->av_xmlString = file_get_contents( $pathString."/panos_v11.1/templates/panorama/snippets/profiles_virus.xml");
            $context->as_xmlString = file_get_contents( $pathString."/panos_v11.1/templates/panorama/snippets/profiles_spyware.xml");
            $context->vp_xmlString = file_get_contents( $pathString."/panos_v11.1/templates/panorama/snippets/profiles_vulnerability.xml");
            $context->url_xmlString = file_get_contents( $pathString."/panos_v11.1/templates/panorama/snippets/profiles_url_filtering.xml");
            $context->fb_xmlString = file_get_contents( $pathString."/panos_v11.1/templates/panorama/snippets/profiles_file_blocking.xml");
            $context->wf_xmlString = file_get_contents( $pathString."/panos_v11.1/templates/panorama/snippets/profiles_wildfire_analysis.xml");
        }
    },
    'function_panVersion' => function (DeviceCallContext $context) {
        $panVersion = substr_replace($context->object->owner->version, ".", -1, 0);
        return $panVersion;
    },
    'function_createProfile-alert' => function (DeviceCallContext $context, $type, $type_name, $sharedStore, $name, $xmlString, $ownerDocument)
    {
        $profile = $sharedStore->$type->find($name . "-" . $type_name);
        if( $profile === null )
        {
            $typeclass = str_replace( "Store", "", $type );
            $store = $sharedStore->$type;
            $profile = new $typeclass($name . "-" . $type_name, $store);
            $newdoc = new DOMDocument;
            $newdoc->loadXML($context->$xmlString, XML_PARSE_BIG_LINES);
            $node = $newdoc->importNode($newdoc->firstChild, TRUE);
            $node = DH::findFirstElementByNameAttr("entry", $name . "-" . $type_name, $node);

            if( $node !== FALSE && $node !== null )
            {
                $node = $ownerDocument->importNode($node, TRUE);
                $profile->load_from_domxml($node);
                $profile->owner = null;
                $store->addSecurityProfile($profile);
                PH::print_stdout(" * " . $typeclass . " create: '" . $name . "-" . $type_name . "'");

                if( $context->isAPI )
                    $profile->API_sync();
            }
            else
                PH::print_stdout(" * " . $typeclass . " not found in iron-skillet XML snippet: '" . $name . "-" . $type_name . "'");
        }
        return $profile;
    },
    'function_createProfile-bp' => function (DeviceCallContext $context, $type, $type_name, $sharedStore, $name, $xmlString, $ownerDocument) {
        $profile = $sharedStore->$type->find($name . "-" . $type_name);
        if( $profile === null )
        {
            $typeclass = str_replace("Store", "", $type);
            $store = $sharedStore->$type;
            $profile = new $typeclass($name . "-" . $type_name, $store);
            $newdoc = new DOMDocument;
            $newdoc->loadXML($context->$xmlString, XML_PARSE_BIG_LINES);
            $node = $newdoc->importNode($newdoc->firstChild, TRUE);
            $node = DH::findFirstElementByNameAttr("entry", $name . "-" . $type_name, $node);

            if( $node !== FALSE && $node !== null && $node->hasChildNodes() )
            {
                $node = $ownerDocument->importNode($node, TRUE);
                $profile->load_from_domxml($node);
                $profile->owner = null;
                if( isset($context->arguments['sp-name']) )
                    $profile->setName($name . "-" . $type_name);
                $store->addSecurityProfile($profile);
                PH::print_stdout(" * " . $typeclass . " create: '" . $name . "-" . $type_name . "'");

                if( $context->isAPI )
                    $profile->API_sync();
            }
            else
            {
                PH::print_stdout(" * " . $typeclass . " not found in iron-skillet XML snippet: '" . $name . "-" . $type_name . "'");
                $store->removeSecurityProfile($profile);
                $profile = null;
            }

        }
        return $profile;
    }
);

DeviceCallContext::$supportedActions['sp_spg-create-alert-only-BP'] = array(
    'name' => 'sp_spg-create-alert-only-bp',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;

        $context->av_xmlString = "";
        $context->as_xmlString = "";
        $context->vp_xmlString = "";
        $context->url_xmlString = "";
        $context->fb_xmlString = "";
        $context->wf_xmlString = "";

        if( $context->subSystem->isPanorama() )
        {
            $countDG = count( $context->subSystem->getDeviceGroups() );
            if( $countDG == 0  )
            {
                #$dg = $context->subSystem->createDeviceGroup( "alert-only" );
                derr( "NO DG available; please run 'pan-os-php type=device in=InputConfig.xml out=OutputConfig.xml actions=devicegroup-create:DG-NAME' first", null, false );
            }
        }
    },
    'MainFunction' => function (DeviceCallContext $context)
    {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            $f = DeviceCallContext::$commonActionFunctions['sp_spg-create']['function_xmlfiles'];
            $f($context);

            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $context->arguments['shared'] && !$context->subSystem->isFirewall() )
                    $sharedStore = $sub->owner;
                else
                    $sharedStore = $sub;


                $ownerDocument = $sub->xmlroot->ownerDocument;

                $nameArray = array("Alert-Only");
                #$name = "Alert-Only";

                foreach( $nameArray as $name)
                {
                    if( $context->object->owner->version < 90 )
                        $customURLarray = array("Black-List", "White-List", "Custom-No-Decrypt");
                    else
                        $customURLarray = array("Block", "Allow", "Custom-No-Decrypt");
                    foreach( $customURLarray as $entry )
                    {
                        $block = $sharedStore->customURLProfileStore->find($entry);
                        if( $block === null )
                        {
                            $block = $sharedStore->customURLProfileStore->newCustomSecurityProfileURL($entry);
                            PH::print_stdout(" * CustomURLProfile create: '" . $entry . "'");
                            if( $context->isAPI )
                                $block->API_sync();
                        }
                    }

                    $f = DeviceCallContext::$commonActionFunctions['sp_spg-create']['function_createProfile-alert'];

                    $av = $f($context, 'AntiVirusProfileStore', 'AV', $sharedStore, $name, 'av_xmlString', $ownerDocument);

                    $as = $f($context, 'AntiSpywareProfileStore', 'AS', $sharedStore, $name, 'as_xmlString', $ownerDocument);

                    $vp = $f($context, 'VulnerabilityProfileStore', 'VP', $sharedStore, $name, 'vp_xmlString', $ownerDocument);

                    $url = $f($context, 'URLProfileStore', 'URL', $sharedStore, $name, 'url_xmlString', $ownerDocument);

                    $fb = $f($context, 'FileBlockingProfileStore', 'FB', $sharedStore, $name, 'fb_xmlString', $ownerDocument);

                    $wf = $f($context, 'WildfireProfileStore', 'WF', $sharedStore, $name, 'wf_xmlString', $ownerDocument);


                    $secprofgrp = $sharedStore->securityProfileGroupStore->find($name);
                    if( $secprofgrp === null )
                    {
                        PH::print_stdout(" * SecurityProfileGroup create: '" . $name . "'");
                        $secprofgrp = new SecurityProfileGroup($name, $sharedStore->securityProfileGroupStore, TRUE);

                        if( $av !== null )
                        {
                            PH::print_stdout("   - add AV: '".$av->name()."'");
                            $secprofgrp->setSecProf_AV($av->name());
                        }
                        if( $as !== null )
                        {
                            PH::print_stdout("   - add AS: '".$as->name()."'");
                            $secprofgrp->setSecProf_Spyware($as->name());
                        }
                        if( $vp !== null )
                        {
                            PH::print_stdout("   - add VP: '".$vp->name()."'");
                            $secprofgrp->setSecProf_Vuln($vp->name());
                        }
                        if( $url !== null )
                        {
                            PH::print_stdout("   - add URL: '".$url->name()."'");
                            $secprofgrp->setSecProf_URL($url->name());
                        }
                        if( $fb !== null )
                        {
                            PH::print_stdout("   - add FB: '".$fb->name()."'");
                            $secprofgrp->setSecProf_FileBlock($fb->name());
                        }
                        if( $wf !== null )
                        {
                            PH::print_stdout("   - add WF: '".$wf->name()."'");
                            $secprofgrp->setSecProf_Wildfire($wf->name());
                        }


                        $sharedStore->securityProfileGroupStore->addSecurityProfileGroup($secprofgrp);

                        if( $context->isAPI )
                            $secprofgrp->API_sync();
                    }

                }
            }

            $context->first = FALSE;
        }
    },
    'args' => array(
        'shared' => array('type' => 'bool', 'default' => 'false',
            'help' => "if set to true; securityProfiles are create at SHARED level; at least one DG must be available"
        )
    )
);


DeviceCallContext::$supportedActions['sp_spg-create-BP'] = array(
    'name' => 'sp_spg-create-bp',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;

        $context->av_xmlString = "";
        $context->as_xmlString = "";
        $context->vp_xmlString = "";
        $context->url_xmlString = "";
        $context->fb_xmlString = "";
        $context->wf_xmlString = "";

        if( $context->subSystem->isPanorama() )
        {
            $countDG = count( $context->subSystem->getDeviceGroups() );
            if( $countDG == 0  )
            {
                #$dg = $context->subSystem->createDeviceGroup( "alert-only" );
                derr( "NO DG available; please run 'pan-os-php type=device in=InputConfig.xml out=OutputConfig.xml actions=devicegroup-create:DG-NAME' first", null, false );
            }
        }
    },
    'MainFunction' => function (DeviceCallContext $context)
    {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            $f = DeviceCallContext::$commonActionFunctions['sp_spg-create']['function_xmlfiles'];
            $f($context);

            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $context->arguments['shared'] && !$context->subSystem->isFirewall() )
                    $sharedStore = $sub->owner;
                else
                    $sharedStore = $sub;


                $ownerDocument = $sub->xmlroot->ownerDocument;

                $force = false; // check about actions argument introduction
                if( isset($context->arguments['sp-name']) && $context->arguments['sp-name'] !== "*nodefault*" )
                    $nameArray = array("Outbound");
                else
                    #$nameArray = array("Alert-Only", "Outbound", "Inbound", "Internal", "Exception");
                    $nameArray = array("Alert-Only", "Outbound", "Inbound", "Internal");


                foreach( $nameArray as $name)
                {
                    $ironskilletName = $name;
                    if( isset($context->arguments['sp-name']) )
                    {
                        if( $context->arguments['sp-name'] !== "*nodefault*" )
                            $name = $context->arguments['sp-name'];
                    }


                    if( $context->object->owner->version < 90 )
                        $customURLarray = array("Black-List", "White-List", "Custom-No-Decrypt");
                    else
                        $customURLarray = array("Block", "Allow", "Custom-No-Decrypt");
                    foreach( $customURLarray as $entry )
                    {
                        $block = $sharedStore->customURLProfileStore->find($entry);
                        if( $block === null )
                        {
                            $block = $sharedStore->customURLProfileStore->newCustomSecurityProfileURL($entry);
                            PH::print_stdout(" * CustomURLProfile create: '".$entry."'");
                            if( $context->isAPI )
                                $block->API_sync();
                        }
                    }

                    $f = DeviceCallContext::$commonActionFunctions['sp_spg-create']['function_createProfile-bp'];

                    $av = $f($context, 'AntiVirusProfileStore', 'AV', $sharedStore, $name, 'av_xmlString', $ownerDocument);

                    $as = $f($context, 'AntiSpywareProfileStore', 'AS', $sharedStore, $name, 'as_xmlString', $ownerDocument);

                    $vp = $f($context, 'VulnerabilityProfileStore', 'VP', $sharedStore, $name, 'vp_xmlString', $ownerDocument);

                    $url = $f($context, 'URLProfileStore', 'URL', $sharedStore, $name, 'url_xmlString', $ownerDocument);

                    $fb = $f($context, 'FileBlockingProfileStore', 'FB', $sharedStore, $name, 'fb_xmlString', $ownerDocument);

                    $wf = $f($context, 'WildfireProfileStore', 'WF', $sharedStore, $name, 'wf_xmlString', $ownerDocument);


                    $secprofgrp = $sharedStore->securityProfileGroupStore->find($name);
                    if( $secprofgrp === null )
                    {
                        PH::print_stdout(" * SecurityProfileGroup create: '".$name."'");
                        $secprofgrp = new SecurityProfileGroup($name, $sharedStore->securityProfileGroupStore, TRUE);

                        if( $av !== null )
                        {
                            PH::print_stdout("   - add AV: '".$av->name()."'");
                            $secprofgrp->setSecProf_AV($av->name());
                        }
                        if( $as !== null )
                        {
                            PH::print_stdout("   - add AS: '".$as->name()."'");
                            $secprofgrp->setSecProf_Spyware($as->name());
                        }
                        if( $vp !== null )
                        {
                            PH::print_stdout("   - add VP: '".$vp->name()."'");
                            $secprofgrp->setSecProf_Vuln($vp->name());
                        }
                        if( $url !== null )
                        {
                            PH::print_stdout("   - add URL: '".$url->name()."'");
                            $secprofgrp->setSecProf_URL($url->name());
                        }
                        if( $fb !== null )
                        {
                            PH::print_stdout("   - add FB: '".$fb->name()."'");
                            $secprofgrp->setSecProf_FileBlock($fb->name());
                        }
                        if( $wf !== null )
                        {
                            PH::print_stdout("   - add WF: '".$wf->name()."'");
                            $secprofgrp->setSecProf_Wildfire($wf->name());
                        }



                        $sharedStore->securityProfileGroupStore->addSecurityProfileGroup($secprofgrp);

                        if( $context->isAPI )
                            $secprofgrp->API_sync();
                    }
                }

                #$location = PH::getLocationString($object);
                #PH::print_stdout( "NAME: ".$location );
                //$context->first = false;
            }
        }
    },
    'args' => array(
        'shared' => array('type' => 'bool', 'default' => 'false',
            'help' => "if set to true; securityProfiles are create at SHARED level; at least one DG must be available"
        ),
        'sp-name' => array('type' => 'string', 'default' => '*nodefault*',
            'help' => "if set, only ironskillet SP called 'Outbound' are created with the name defined"
        )
    )
);

DeviceCallContext::$supportedActions['LogForwardingProfile-create-BP'] = array(
    'name' => 'logforwardingprofile-create-bp',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;

        if( $context->subSystem->isPanorama() )
        {
            $countDG = count( $context->subSystem->getDeviceGroups() );
            if( $countDG == 0 )
            {
                #$dg = $context->subSystem->createDeviceGroup( "alert-only" );
                derr( "NO DG available; please run 'pan-os-php type=device in=InputConfig.xml out=OutputConfig.xml actions=devicegroup-create:DG-NAME' first", null, false );
            }
        }
    },
    'MainFunction' => function (DeviceCallContext $context)
    {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            $pathString = dirname(__FILE__)."/../../iron-skillet";
            $lfp_bp_xmlstring = file_get_contents( $pathString."/panos_v10.0/templates/panorama/snippets/log_settings_profiles.xml");
            if( $context->util->pan->version >= 100 )
            {
                $f = DeviceCallContext::$commonActionFunctions['sp_spg-create']['function_panVersion'];
                $panVersion = $f($context);

                $lfp_bp_xmlstring = file_get_contents( $pathString."/panos_v".$panVersion."/templates/panorama/snippets/log_settings_profiles.xml");
            }

            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $context->arguments['shared'] || $context->subSystem->isFirewall() )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);
                }
                else
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;
                }

                $ownerDocument = $sub->xmlroot->ownerDocument;

                $newdoc = new DOMDocument;
                $newdoc->loadXML( $lfp_bp_xmlstring, XML_PARSE_BIG_LINES);
                $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                $node = DH::findFirstElementByNameAttr( "entry", "default", $node );
                $node = $ownerDocument->importNode($node, TRUE);


                $logSettings = DH::findFirstElementOrCreate('log-settings', $xmlRoot);
                $logSettingProfiles = DH::findFirstElementOrCreate('profiles', $logSettings);

                $entryDefault = DH::findFirstElementByNameAttr( 'entry', 'default', $logSettingProfiles );


                if( $entryDefault === null )
                {
                    $logSettingProfiles->appendChild( $node );

                    if( $context->isAPI )
                    {
                        $entryDefault_xmlroot = DH::findFirstElementByNameAttr( 'entry', 'default', $logSettingProfiles );

                        $xpath = DH::elementToPanXPath($logSettingProfiles);
                        $con = findConnectorOrDie($object);

                        $getXmlText_inline = DH::dom_to_xml($entryDefault_xmlroot, -1, FALSE);
                        $con->sendSetRequest($xpath, $getXmlText_inline);
                    }
                }
                else
                {
                    $string = "LogForwardingProfile 'default' already available. BestPractise LogForwardingProfile 'default' not created";
                    PH::ACTIONstatus( $context, "SKIPPED", $string );
                }



                $context->first = false;
            }
        }
    },
    'args' => array(
        'shared' => array('type' => 'bool', 'default' => 'false',
            'help' => "if set to true; LogForwardingProfile is create at SHARED level; at least one DG must be available"
        )
    )
);

DeviceCallContext::$commonActionFunctions['zpp-create'] = array(
    'function' => function (DeviceCallContext $context, $entryProfileName, $validateZPPavailable = false) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            $pathString = dirname(__FILE__) . "/../../iron-skillet";

            $f = DeviceCallContext::$commonActionFunctions['sp_spg-create']['function_panVersion'];
            $panVersion = $f($context);

            if( $context->object->owner->version < 100 )
                $zpp_bp_xmlstring = file_get_contents($pathString . "/panos_v10.0/templates/panorama/snippets/zone_protection_profile.xml");
            elseif( $context->util->pan->version >= 100 )
                $zpp_bp_xmlstring = file_get_contents($pathString . "/panos_v" . $panVersion . "/templates/panorama/snippets/zone_protection_profile.xml");

            if( $classtype == "VirtualSystem" || $classtype == "Template" )
            {
                $sub = $object;

                $sharedStore = $sub;

                $allZones = array();
                if( $classtype == "VirtualSystem" )
                    $allZones = $sharedStore->zoneStore->zones();
                else
                {
                    /** @var Template $sharedStore */

                    $allVsys = $sharedStore->deviceConfiguration->getVirtualSystems();
                    foreach($allVsys as $vsys)
                    {
                        $vsys_Zones = $vsys->zoneStore->zones();
                        $allZones = array_merge($vsys_Zones, $allZones);
                    }
                }
                if( $validateZPPavailable )
                {
                    $create = FALSE;
                    foreach( $allZones as $zoneOBJ)
                    {
                        if( $zoneOBJ->zoneProtectionProfile == null)
                            $create = TRUE;
                    }
                }
                else
                {
                    $create = TRUE;
                }

                if( $create) {
                    if ($classtype == "Template") {
                        $xmlRoot = $sharedStore->deviceConfiguration->network->xmlroot;
                        if ($xmlRoot === null) {
                            $xmlRoot = DH::findFirstElementOrCreate('devices', $sharedStore->deviceConfiguration->xmlroot);

                            #$xmlRoot = DH::findFirstElementByNameAttrOrCreate( 'entry', 'localhost.localdomain', $xmlRoot, $sharedStore->deviceConfiguration->xmlroot->ownerDocument);
                            $xmlRoot = DH::findFirstElementOrCreate('entry', $xmlRoot);
                            $xmlRoot->setAttribute("name", 'localhost.localdomain');
                            $xmlRoot = DH::findFirstElementOrCreate('network', $xmlRoot);
                        }
                    } elseif ($classtype == "VirtualSystem") {
                        $xmlRoot = $sharedStore->owner->network->xmlroot;
                        if ($xmlRoot === null) {
                            $xmlRoot = DH::findFirstElementOrCreate('devices', $sharedStore->owner->xmlroot);

                            #$xmlRoot = DH::findFirstElementByNameAttrOrCreate( 'entry', 'localhost.localdomain', $xmlRoot, $sharedStore->owner->xmlroot->ownerDocument);
                            $xmlRoot = DH::findFirstElementOrCreate('entry', $xmlRoot);
                            $xmlRoot->setAttribute("name", 'localhost.localdomain');
                            $xmlRoot = DH::findFirstElementOrCreate('network', $xmlRoot);
                        }
                    }


                    $ownerDocument = $sub->xmlroot->ownerDocument;

                    $newdoc = new DOMDocument;
                    $newdoc->loadXML($zpp_bp_xmlstring, XML_PARSE_BIG_LINES);
                    $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                    $node = DH::findFirstElementByNameAttr("entry", $entryProfileName, $node);
                    if ($node === false || $node === null)
                        derr("there is an error with the Iron-Skillet update - Profile: " . $entryProfileName . " does not exist", null, false);
                    $node = $ownerDocument->importNode($node, TRUE);


                    $networkProfiles = DH::findFirstElementOrCreate('profiles', $xmlRoot);
                    $zppXMLroot = DH::findFirstElementOrCreate('zone-protection-profile', $networkProfiles);

                    $entryDefault = DH::findFirstElementByNameAttr('entry', $entryProfileName, $zppXMLroot);


                    if ($entryDefault === null) {
                        $zppXMLroot->appendChild($node);

                        if ($context->isAPI) {
                            $entryDefault_xmlroot = DH::findFirstElementByNameAttr('entry', $entryProfileName, $zppXMLroot);

                            $xpath = DH::elementToPanXPath($zppXMLroot);
                            $con = findConnectorOrDie($object);

                            $getXmlText_inline = DH::dom_to_xml($entryDefault_xmlroot, -1, FALSE);
                            $con->sendSetRequest($xpath, $getXmlText_inline);
                        }
                    } else {
                        $string = "ZoneProtectionProfile '" . $entryProfileName . "' already available. BestPractise ZoneProtectionProfile '" . $entryProfileName . "' not created";
                        PH::ACTIONstatus($context, "SKIPPED", $string);
                    }
                }

                //create for all VSYS and all templates
                #$context->first = false;
            }
        }
    }
);

DeviceCallContext::$supportedActions['ZoneProtectionProfile-create-BP'] = array(
    'name' => 'zoneprotectionprofile-create-bp',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context)
    {
        $f = DeviceCallContext::$commonActionFunctions['zpp-create']['function'];
        $f($context, 'Recommended_Zone_Protection');
    }
);

DeviceCallContext::$supportedActions['ZPP-create-BP'] = array(
    'name' => 'zpp-create-bp',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context)
    {
        $f = DeviceCallContext::$commonActionFunctions['zpp-create']['function'];
        $f($context, 'Recommended_Zone_Protection');
    }
);

DeviceCallContext::$supportedActions['ZPP-create-alert-only-BP'] = array(
    'name' => 'zpp-create-alert-only-bp',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context)
    {
        $f = DeviceCallContext::$commonActionFunctions['zpp-create']['function'];
        $f($context, 'Alert_Only_Zone_Protection', $context->arguments['zpp-availability-validation']);
    },
    'args' => array(
        'zpp-availability-validation' => array('type' => 'bool', 'default' => 'false',
            'help' => "if set to true; the script validate if already another ZPP is available, if available no creation of ZPP"
        )
    )

);


DeviceCallContext::$supportedActions['CleanUpRule-create-BP'] = array(
    'name' => 'cleanuprule-create-bp',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            if( $context->arguments['logprof'] )
                $logprof = $context->arguments['logprof'];
            else
                $logprof = "default";

            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                $skip = false;
                if( $classtype == "VirtualSystem" )
                {
                    //create security Rule at end
                    $name = "CleanupRule-BP";
                    $cleanupRule = $sub->securityRules->find( $name );
                    if( $cleanupRule === null )
                        $cleanupRule = $sub->securityRules->newSecurityRule( $name );
                    else
                        $skip = true;
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;

                    //create security Rule at end
                    $name = "CleanupRule-BP";
                    $cleanupRule = $sharedStore->securityRules->find( $name );
                    if( $cleanupRule === null )
                        $cleanupRule = $sharedStore->securityRules->newSecurityRule("CleanupRule-BP", true);
                    else
                        $skip = true;
                }

                if( !$skip )
                {
                    $cleanupRule->source->setAny();
                    $cleanupRule->destination->setAny();
                    $cleanupRule->services->setAny();
                    $cleanupRule->setAction( 'deny');
                    $cleanupRule->setLogStart( false );
                    $cleanupRule->setLogEnd( true );
                    $cleanupRule->setLogSetting( $logprof );
                    if( $context->isAPI )
                        $cleanupRule->API_sync();
                }

                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    },
    'args' => array(
    'logprof' => array('type' => 'string', 'default' => 'default',
        'help' => "LogForwardingProfile name"
    )
)
);

DeviceCallContext::$supportedActions['DefaultSecurityRule-create-BP'] = array(
    'name' => 'defaultsecurityRule-create-bp',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            if( $context->arguments['logprof'] )
                $logprof = $context->arguments['logprof'];
            else
                $logprof = "default";

            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $classtype == "VirtualSystem" )
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;

                    $rulebase = DH::findFirstElementOrCreate( "rulebase", $xmlRoot );
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);

                    $rulebase = DH::findFirstElementOrCreate( "post-rulebase", $xmlRoot );
                }

                $defaultSecurityRules = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );
                $rulebase->removeChild( $defaultSecurityRules );

                $defaultSecurityRules_xml = "<default-security-rules>
                    <rules>
                      <entry name=\"intrazone-default\">
                        <action>deny</action>
                        <log-start>no</log-start>
                        <log-end>yes</log-end>
                        <log-setting>".$logprof."</log-setting>
                      </entry>
                      <entry name=\"interzone-default\">
                        <action>deny</action>
                        <log-start>no</log-start>
                        <log-end>yes</log-end>
                        <log-setting>".$logprof."</log-setting>
                      </entry>
                    </rules>
                  </default-security-rules>";

                $ownerDocument = $sub->xmlroot->ownerDocument;

                $newdoc = new DOMDocument;
                $newdoc->loadXML( $defaultSecurityRules_xml, XML_PARSE_BIG_LINES);
                $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                $node = $ownerDocument->importNode($node, TRUE);
                $rulebase->appendChild( $node );

                if( $context->isAPI )
                {
                    $defaultSecurityRules_xmlroot = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );

                    $xpath = DH::elementToPanXPath($defaultSecurityRules_xmlroot);
                    $con = findConnectorOrDie($object);

                    $getXmlText_inline = DH::dom_to_xml($defaultSecurityRules_xmlroot, -1, FALSE);
                    $con->sendEditRequest($xpath, $getXmlText_inline);
                }

                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    },
    'args' => array(
        'logprof' => array('type' => 'string', 'default' => 'default',
            'help' => "LogForwardingProfile name"
        )
    )
);

DeviceCallContext::$supportedActions['DefaultSecurityRule-logend-enable'] = array(
    'name' => 'defaultsecurityrule-logend-enable',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $classtype == "VirtualSystem" )
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;

                    $rulebase = DH::findFirstElementOrCreate( "rulebase", $xmlRoot );
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);

                    $rulebase = DH::findFirstElementOrCreate( "post-rulebase", $xmlRoot );
                }

                $defaultSecurityRules = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );
                $rules = DH::findFirstElementOrCreate( "rules", $defaultSecurityRules );

                $array = array( "intrazone-default", "interzone-default" );
                foreach( $array as $entry)
                {
                    $tmp_XYZzone_xml = DH::findFirstElementByNameAttrOrCreate( "entry", $entry, $rules, $sharedStore->xmlroot->ownerDocument );
                    $logend = DH::findFirstElementOrCreate( "log-end", $tmp_XYZzone_xml );

                    $logend->textContent = "yes";

                    $action = DH::findFirstElement( "action", $tmp_XYZzone_xml );
                    if( $action === FALSE )
                    {
                        if( $entry === "intrazone-default" )
                            $action_txt = "allow";
                        elseif( $entry === "interzone-default" )
                            $action_txt = "deny";

                        $action = DH::findFirstElementOrCreate( "action", $tmp_XYZzone_xml );
                        $action->textContent = $action_txt;
                    }
                }

                if( $context->isAPI )
                {
                    $defaultSecurityRules_xmlroot = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );

                    $xpath = DH::elementToPanXPath($defaultSecurityRules_xmlroot);
                    $con = findConnectorOrDie($object);

                    $getXmlText_inline = DH::dom_to_xml($defaultSecurityRules_xmlroot, -1, FALSE);
                    $con->sendEditRequest($xpath, $getXmlText_inline);
                }

                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    }
);

DeviceCallContext::$supportedActions['DefaultSecurityRule-logstart-disable'] = array(
    'name' => 'defaultsecurityrule-logstart-disable',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $classtype == "VirtualSystem" )
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;

                    $rulebase = DH::findFirstElementOrCreate( "rulebase", $xmlRoot );
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);

                    $rulebase = DH::findFirstElementOrCreate( "post-rulebase", $xmlRoot );
                }

                $defaultSecurityRules = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );
                $rules = DH::findFirstElementOrCreate( "rules", $defaultSecurityRules );

                $array = array( "intrazone-default", "interzone-default" );
                foreach( $array as $entry)
                {
                    $tmp_XYZzone_xml = DH::findFirstElementByNameAttrOrCreate( "entry", $entry, $rules, $sharedStore->xmlroot->ownerDocument );

                    $logstart = DH::findFirstElementOrCreate( "log-start", $tmp_XYZzone_xml );
                    $logstart->textContent = "no";

                    $action = DH::findFirstElement( "action", $tmp_XYZzone_xml );
                    if( $action === FALSE )
                    {
                        if( $entry === "intrazone-default" )
                            $action_txt = "allow";
                        elseif( $entry === "interzone-default" )
                            $action_txt = "deny";

                        $action = DH::findFirstElementOrCreate( "action", $tmp_XYZzone_xml );
                        $action->textContent = $action_txt;
                    }
                }

                if( $context->isAPI )
                {
                    $defaultSecurityRules_xmlroot = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );

                    $xpath = DH::elementToPanXPath($defaultSecurityRules_xmlroot);
                    $con = findConnectorOrDie($object);

                    $getXmlText_inline = DH::dom_to_xml($defaultSecurityRules_xmlroot, -1, FALSE);
                    $con->sendEditRequest($xpath, $getXmlText_inline);
                }

                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    }
);

DeviceCallContext::$supportedActions['DefaultSecurityRule-logsetting-set'] = array(
    'name' => 'defaultsecurityrule-logsetting-set',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            if( $context->arguments['logprof'] )
                $logprof = $context->arguments['logprof'];
            else
                $logprof = "default";

            $force = $context->arguments['force'];

            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $classtype == "VirtualSystem" )
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;

                    $rulebase = DH::findFirstElementOrCreate( "rulebase", $xmlRoot );
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);

                    $rulebase = DH::findFirstElementOrCreate( "post-rulebase", $xmlRoot );
                }

                $defaultSecurityRules = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );
                $rules = DH::findFirstElementOrCreate( "rules", $defaultSecurityRules );

                $array = array( "intrazone-default", "interzone-default" );
                foreach( $array as $entry)
                {
                    $tmp_XYZzone_xml = DH::findFirstElementByNameAttrOrCreate( "entry", $entry, $rules, $sharedStore->xmlroot->ownerDocument );

                    $logsetting = DH::findFirstElement( "log-setting", $tmp_XYZzone_xml );
                    if( $logsetting !== FALSE || $force )
                    {
                        if( $force )
                            $logsetting->textContent = $logprof;
                    }
                    else
                    {
                        $logsetting = DH::findFirstElementOrCreate( "log-setting", $tmp_XYZzone_xml );
                        $logsetting->textContent = $logprof;
                    }

                    $action = DH::findFirstElement( "action", $tmp_XYZzone_xml );
                    if( $action === FALSE )
                    {
                        if( $entry === "intrazone-default" )
                            $action_txt = "allow";
                        elseif( $entry === "interzone-default" )
                            $action_txt = "deny";

                        $action = DH::findFirstElementOrCreate( "action", $tmp_XYZzone_xml );
                        $action->textContent = $action_txt;
                    }
                }

                if( $context->isAPI )
                {
                    $defaultSecurityRules_xmlroot = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );

                    $xpath = DH::elementToPanXPath($defaultSecurityRules_xmlroot);
                    $con = findConnectorOrDie($object);

                    $getXmlText_inline = DH::dom_to_xml($defaultSecurityRules_xmlroot, -1, FALSE);
                    $con->sendEditRequest($xpath, $getXmlText_inline);
                }

                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    },
    'args' => array(
        'logprof' => array('type' => 'string', 'default' => 'default',
            'help' => "LogForwardingProfile name"
        ),
        'force' => array('type' => 'bool', 'default' => 'false',
            'help' => "LogForwardingProfile overwrite"
        )
    )
);

DeviceCallContext::$supportedActions['DefaultSecurityRule-remove-override'] = array(
    'name' => 'defaultsecurityrule-remove-override',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $classtype == "VirtualSystem" )
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;

                    $rulebase = DH::findFirstElementOrCreate( "rulebase", $xmlRoot );
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);

                    $rulebase = DH::findFirstElementOrCreate( "post-rulebase", $xmlRoot );
                }

                $defaultSecurityRules = DH::findFirstElement( "default-security-rules", $rulebase );
                if( $defaultSecurityRules !== FALSE )
                    $rulebase->removeChild( $defaultSecurityRules );
                else
                    return;

                if( $context->isAPI )
                {
                    $defaultSecurityRules_xmlroot = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );
                    if( $defaultSecurityRules_xmlroot !== FALSE )
                    {
                        $xpath = DH::elementToPanXPath($defaultSecurityRules_xmlroot);
                        $con = findConnectorOrDie($object);

                        $con->sendDeleteRequest( $xpath );
                    }
                }

                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    }
);

DeviceCallContext::$supportedActions['DefaultSecurityRule-securityProfile-Remove'] = array(
    'name' => 'defaultsecurityrule-securityprofile-remove',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            $force = $context->arguments['force'];

            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $classtype == "VirtualSystem" )
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;

                    $rulebase = DH::findFirstElementOrCreate( "rulebase", $xmlRoot );
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);

                    $rulebase = DH::findFirstElementOrCreate( "post-rulebase", $xmlRoot );
                }

                $defaultSecurityRules = DH::findFirstElement( "default-security-rules", $rulebase );
                if( $defaultSecurityRules === FALSE )
                    return;

                $rules = DH::findFirstElement( "rules", $defaultSecurityRules );
                if( $rules === FALSE )
                    return;

                $array = array( "intrazone-default", "interzone-default" );
                foreach( $array as $entry)
                {
                    $tmp_XYZzone_xml = DH::findFirstElementByNameAttr( "entry", $entry, $rules );
                    if( $tmp_XYZzone_xml !== null )
                    {
                        $action = DH::findFirstElement( "action", $tmp_XYZzone_xml );
                        if( $action === FALSE )
                        {
                            if( $entry === "intrazone-default" )
                                $action_txt = "allow";
                            elseif( $entry === "interzone-default" )
                                $action_txt = "deny";
                        }
                        else
                            $action_txt = $action->textContent;

                        if( $action_txt !== "allow" || $force )
                        {
                            $profilesetting = DH::findFirstElement( "profile-setting", $tmp_XYZzone_xml );
                            if( $profilesetting !== FALSE )
                                $tmp_XYZzone_xml->removeChild( $profilesetting );
                        }
                    }
                }

                if( $context->isAPI )
                {
                    $defaultSecurityRules_xmlroot = DH::findFirstElement( "default-security-rules", $rulebase );
                    if( $defaultSecurityRules === FALSE )
                        return;

                    $xpath = DH::elementToPanXPath($defaultSecurityRules_xmlroot);
                    $con = findConnectorOrDie($object);

                    $getXmlText_inline = DH::dom_to_xml($defaultSecurityRules_xmlroot, -1, FALSE);
                    $con->sendEditRequest($xpath, $getXmlText_inline);
                }

                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    },
    'args' => array(
        'force' => array('type' => 'bool', 'default' => 'false',
            'help' => "per default, remove SecurityProfiles only if Rule action is NOT allow. force=true => remove always"
        )
    )
);

DeviceCallContext::$supportedActions['DefaultSecurityRule-SecurityProfileGroup-Set'] = array(
    'name' => 'defaultsecurityrule-securityprofilegroup-set',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            $secProfGroup = $context->arguments['securityProfileGroup'];



            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                //validation, if this group name is available in the relevant store or above
                $tmp_secgroup = $sub->securityProfileGroupStore->find( $secProfGroup );
                if( $tmp_secgroup === null )
                {
                    PH::ACTIONstatus($context, "skipped", "SecurityProfileGroup name: ".$secProfGroup." not found!" );
                    return;
                }

                if( $classtype == "VirtualSystem" )
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;

                    $rulebase = DH::findFirstElementOrCreate( "rulebase", $xmlRoot );
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);

                    $rulebase = DH::findFirstElementOrCreate( "post-rulebase", $xmlRoot );
                }

                $defaultSecurityRules = DH::findFirstElement( "default-security-rules", $rulebase );
                if( $defaultSecurityRules === FALSE )
                    return;

                $rules = DH::findFirstElement( "rules", $defaultSecurityRules );
                if( $rules === FALSE )
                    return;

                $array = array( "intrazone-default", "interzone-default" );
                foreach( $array as $entry)
                {
                    $tmp_XYZzone_xml = DH::findFirstElementByNameAttr( "entry", $entry, $rules );
                    if( $tmp_XYZzone_xml !== null )
                    {
                        $action = DH::findFirstElement( "action", $tmp_XYZzone_xml );
                        if( $action === FALSE )
                        {
                            if( $entry === "intrazone-default" )
                                $action_txt = "allow";
                            elseif( $entry === "interzone-default" )
                                $action_txt = "deny";
                        }
                        else
                            $action_txt = $action->textContent;

                        if( $action_txt == "allow")
                        {
                            $profilesetting = DH::findFirstElement( "profile-setting", $tmp_XYZzone_xml );

                            if( $profilesetting === false )
                                $profilesetting = DH::findFirstElementOrCreate( "profile-setting", $tmp_XYZzone_xml );
                            else
                            {
                                $tmp_XYZzone_xml->removeChild( $profilesetting );
                                $profilesetting = DH::findFirstElementOrCreate( "profile-setting", $tmp_XYZzone_xml );
                            }

                            $group = DH::findFirstElementOrCreate( "group", $profilesetting );
                            $tmp = DH::findFirstElementOrCreate( "member", $group );

                            $tmp->textContent = $secProfGroup;
                        }
                    }
                }

                if( $context->isAPI )
                {
                    $defaultSecurityRules_xmlroot = DH::findFirstElement( "default-security-rules", $rulebase );
                    if( $defaultSecurityRules === FALSE )
                        return;

                    $xpath = DH::elementToPanXPath($defaultSecurityRules_xmlroot);
                    $con = findConnectorOrDie($object);

                    $getXmlText_inline = DH::dom_to_xml($defaultSecurityRules_xmlroot, -1, FALSE);
                    $con->sendEditRequest($xpath, $getXmlText_inline);
                }

                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    },
    'args' => array(
        'securityProfileGroup' => array('type' => 'string', 'default' => '*nodefault*',
            'help' => "set SecurityProfileGroup to default SecurityRules, if the Rule is an allow rule"
        )
    )
);

DeviceCallContext::$supportedActions['DefaultSecurityRule-SecurityProfile-SetAlert'] = array(
    'name' => 'defaultsecurityrule-securityprofile-setAlert',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        $force = $context->arguments['force'];

        if( $context->first )
        {
            $secProfGroup = "Alert-Only";

            $secProf = array();
            $secProf['VP'] = "Alert-Only-VP";
            $secProf['AS'] = "Alert-Only-AS";
            $secProf['AV'] = "Alert-Only-AV";
            $secProf['URL'] = "Alert-Only-URL";
            $secProf['FB'] = "Alert-Only-FB";
            $secProf['WF'] = "Alert-Only-WF";

            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                /** @var VirtualSystem|DeviceGroup $sub */
                $sub = $object;

                //validation, if this group name is available in the relevant store or above
                $tmp_secgroup = $sub->securityProfileGroupStore->find( $secProfGroup );
                if( $tmp_secgroup === null )
                {
                    PH::ACTIONstatus($context, "skipped", "SecurityProfileGroup name: ".$secProfGroup." not found!" );
                    return;
                }
                $tmp_secprof = $sub->VulnerabilityProfileStore->find( $secProf['VP'] );
                if( $tmp_secprof === null )
                {
                    PH::ACTIONstatus($context, "skipped", "SecurityProfile VP name: ".$secProf['VP']." not found!" );
                    return;
                }
                $tmp_secprof = $sub->AntiSpywareProfileStore->find( $secProf['AS'] );
                if( $tmp_secprof === null )
                {
                    PH::ACTIONstatus($context, "skipped", "SecurityProfile AS name: ".$secProf['AS']." not found!" );
                    return;
                }
                $tmp_secprof = $sub->AntiVirusProfileStore->find( $secProf['AV'] );
                if( $tmp_secprof === null )
                {
                    PH::ACTIONstatus($context, "skipped", "SecurityProfile AV name: ".$secProf['AV']." not found!" );
                    return;
                }
                $tmp_secprof = $sub->URLProfileStore->find( $secProf['URL'] );
                if( $tmp_secprof === null )
                {
                    PH::ACTIONstatus($context, "skipped", "SecurityProfile URL name: ".$secProf['URL']." not found!" );
                    return;
                }
                $tmp_secprof = $sub->FileBlockingProfileStore->find( $secProf['FB'] );
                if( $tmp_secprof === null )
                {
                    PH::ACTIONstatus($context, "skipped", "SecurityProfile FB name: ".$secProf['FB']." not found!" );
                    return;
                }
                $tmp_secprof = $sub->WildfireProfileStore->find( $secProf['WF'] );
                if( $tmp_secprof === null )
                {
                    PH::ACTIONstatus($context, "skipped", "SecurityProfile WF name: ".$secProf['WF']." not found!" );
                    return;
                }


                if( $classtype == "VirtualSystem" )
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;

                    $rulebase = DH::findFirstElementOrCreate( "rulebase", $xmlRoot );
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);

                    $rulebase = DH::findFirstElementOrCreate( "post-rulebase", $xmlRoot );
                }

                $defaultSecurityRules = DH::findFirstElement( "default-security-rules", $rulebase );
                if( $defaultSecurityRules === FALSE )
                    return;

                $rules = DH::findFirstElement( "rules", $defaultSecurityRules );
                if( $rules === FALSE )
                    return;

                $array = array( "intrazone-default", "interzone-default" );
                foreach( $array as $entry)
                {
                    $tmp_XYZzone_xml = DH::findFirstElementByNameAttr( "entry", $entry, $rules );
                    if( $tmp_XYZzone_xml !== null )
                    {
                        $action = DH::findFirstElement( "action", $tmp_XYZzone_xml );
                        if( $action === FALSE )
                        {
                            if( $entry === "intrazone-default" )
                                $action_txt = "allow";
                            elseif( $entry === "interzone-default" )
                                $action_txt = "deny";
                        }
                        else
                            $action_txt = $action->textContent;

                        if( $action_txt == "allow")
                        {
                            $profilesetting = DH::findFirstElement( "profile-setting", $tmp_XYZzone_xml );

                            if( $profilesetting === false )
                            {
                                $profilesetting = DH::findFirstElementOrCreate( "profile-setting", $tmp_XYZzone_xml );
                                $group = DH::findFirstElementOrCreate( "group", $profilesetting );
                                $tmp = DH::findFirstElementOrCreate( "member", $group );

                                $tmp->textContent = $secProfGroup;
                            }

                            else
                            {
                                $profiles = DH::findFirstElement( "profiles", $profilesetting );
                                if( $profiles !== false )
                                {
                                    $seprof = DH::findFirstElement( "url-filtering", $profiles );
                                    if( $seprof === false )
                                    {
                                        $seprof = DH::findFirstElementOrCreate( "url-filtering", $profiles );
                                        $tmp = DH::findFirstElementOrCreate( "member", $seprof );
                                        if( $tmp->textContent === "" || $tmp->textContent === "None" || $tmp->textContent === "none" )
                                            $tmp->textContent = $secProf['URL'];
                                    }
                                    $seprof = DH::findFirstElement( "file-blocking", $profiles );
                                    if( $seprof === false )
                                    {
                                        $seprof = DH::findFirstElementOrCreate( "file-blocking", $profiles );
                                        $tmp = DH::findFirstElementOrCreate( "member", $seprof );
                                        if( $tmp->textContent === "" || $tmp->textContent === "None" || $tmp->textContent === "none" )
                                            $tmp->textContent = $secProf['FB'];
                                    }
                                    $seprof = DH::findFirstElement( "virus", $profiles );
                                    if( $seprof === false )
                                    {
                                        $seprof = DH::findFirstElementOrCreate( "virus", $profiles );
                                        $tmp = DH::findFirstElementOrCreate( "member", $seprof );
                                        if( $tmp->textContent === "" || $tmp->textContent === "None" || $tmp->textContent === "none" )
                                            $tmp->textContent = $secProf['AV'];
                                    }
                                    $seprof = DH::findFirstElement( "spyware", $profiles );
                                    if( $seprof === false )
                                    {
                                        $seprof = DH::findFirstElementOrCreate( "spyware", $profiles );
                                        $tmp = DH::findFirstElementOrCreate( "member", $seprof );
                                        if( $tmp->textContent === "" || $tmp->textContent === "None" || $tmp->textContent === "none" )
                                            $tmp->textContent = $secProf['AS'];
                                    }
                                    $seprof = DH::findFirstElement( "vulnerability", $profiles );
                                    if( $seprof === false )
                                    {
                                        $seprof = DH::findFirstElementOrCreate( "vulnerability", $profiles );
                                        $tmp = DH::findFirstElementOrCreate( "member", $seprof );
                                        if( $tmp->textContent === "" || $tmp->textContent === "None" || $tmp->textContent === "none" )
                                            $tmp->textContent = $secProf['VP'];
                                    }
                                    $seprof = DH::findFirstElement( "wildfire-analysis", $profiles );
                                    if( $seprof === false )
                                    {
                                        $seprof = DH::findFirstElementOrCreate( "wildfire-analysis", $profiles );
                                        $tmp = DH::findFirstElementOrCreate( "member", $seprof );
                                        if( $tmp->textContent === "" || $tmp->textContent === "None" || $tmp->textContent === "none" )
                                            $tmp->textContent = $secProf['WF'];
                                    }
                                }
                            }
                        }
                    }
                }

                if( $context->isAPI )
                {
                    $defaultSecurityRules_xmlroot = DH::findFirstElement( "default-security-rules", $rulebase );
                    if( $defaultSecurityRules === FALSE )
                        return;

                    $xpath = DH::elementToPanXPath($defaultSecurityRules_xmlroot);
                    $con = findConnectorOrDie($object);

                    $getXmlText_inline = DH::dom_to_xml($defaultSecurityRules_xmlroot, -1, FALSE);
                    $con->sendEditRequest($xpath, $getXmlText_inline);
                }

                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    }
);


DeviceCallContext::$supportedActions['DefaultSecurityRule-action-set'] = array(
    'name' => 'defaultsecurityrule-action-set',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->arguments['ruletype'] )
            $ruletype = $context->arguments['ruletype'];

        if( $context->arguments['action'] )
            $action = $context->arguments['action'];

        if( $ruletype !== 'intrazone' && $ruletype !== 'interzone' && $ruletype !== 'all' )
        {
            $string ="only ruletype 'intrazone'|'interzone'|'all' is allowed";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        else
            $ruletype .= "-default";

        if( $action !== 'allow' && $action !== 'deny' )
        {
            $string = "only action 'allow' or 'deny' is allowed";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $context->first )
        {
            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $classtype == "VirtualSystem" )
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;

                    $rulebase = DH::findFirstElementOrCreate( "rulebase", $xmlRoot );
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);

                    $rulebase = DH::findFirstElementOrCreate( "post-rulebase", $xmlRoot );
                }

                $defaultSecurityRules = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );
                $rules = DH::findFirstElementOrCreate( "rules", $defaultSecurityRules );

                if( $ruletype === 'all-default' )
                    $array = array( "intrazone-default", "interzone-default" );
                else
                    $array = array( $ruletype );

                foreach( $array as $entry)
                {
                    $tmp_XYZzone_xml = DH::findFirstElementByNameAttrOrCreate( "entry", $entry, $rules, $sharedStore->xmlroot->ownerDocument );

                    if( $entry === "intrazone-default" )
                        $action_txt = $action;
                    elseif( $entry === "interzone-default" )
                        $action_txt = $action;

                    /*
                    if( $entry === "intrazone-default" && $action === "allow" )
                    {
                        $string = "ruletype: intrazone-default and action:allow - is default value";
                        PH::ACTIONstatus( $context, "SKIPPED", $string );
                        return;
                    }
                    */


                    $xmlAction = DH::findFirstElement( "action", $tmp_XYZzone_xml );
                    if( $xmlAction !== FALSE )
                    {
                        if( $xmlAction->textContent !== $action_txt )
                        {
                            $action = DH::findFirstElementOrCreate( "action", $tmp_XYZzone_xml );
                            $xmlAction->nodeValue = $action_txt;
                        }
                    }
                    else
                    {
                        $xmlAction = DH::findFirstElementOrCreate( "action", $tmp_XYZzone_xml );
                        $xmlAction->nodeValue = $action_txt;
                    }



                    if( $context->isAPI )
                    {
                        $defaultSecurityRules_xmlroot = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );
                        $rules_zml = DH::findFirstElementOrCreate( "rules", $defaultSecurityRules_xmlroot );
                        $tmp_XYZzone_xml = DH::findFirstElementByNameAttr( "entry", $entry, $rules_zml, $sharedStore->xmlroot->ownerDocument );

                        $xpath = DH::elementToPanXPath($defaultSecurityRules_xmlroot);
                        $con = findConnectorOrDie($object);

                        $getXmlText_inline = DH::dom_to_xml($defaultSecurityRules_xmlroot, -1, FALSE);
                        $con->sendEditRequest($xpath, $getXmlText_inline);
                    }

                }



                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    },
    'args' => array(
        'ruletype' => array('type' => 'string', 'default' => '*nodefault*',
            'help' => "define which ruletype; 'intrazone'|'interzone'|'all' "
        ),
        'action' => array('type' => 'string', 'default' => '*nodefault*',
            'help' => "define the action you like to set 'allow'|'deny'"
        )
    )
);


DeviceCallContext::$supportedActions['find-zone-from-ip'] = array(
    'name' => 'find-zone-from-ip',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        //
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $device = $context->object;

        if( get_class( $device ) !== "VirtualSystem" && get_class( $device ) !== "ManagedDevice" )
        {
            print get_class( $device )."\n";
            derr( "not of type 'VirtualSystem' / 'ManagedDevice', not supporedted" );
        }

        $zoneContainer = new ZoneRuleContainer( null );
        $system = $device;
        $configIsOnLocalFirewall = FALSE;
        if( get_class( $device ) == "VirtualSystem" )
        {
            $zones = $device->zoneStore->getAll();
            foreach( $zones as $zone )
            {
                #print "add Zone: ".$zone->name()."\n";
                $zoneContainer->addZone( $zone, false );
            }
        }

        elseif( get_class( $device ) == "ManagedDevice" )
        {
            $configIsOnLocalFirewall = TRUE;
            $context->arguments['template'] = "api@".$device->name();
        }

        $ip_address = $context->arguments['ip'];
        if( strpos( $ip_address, ":" ) !== FALSE )
            derr( "IPv6 is NOT yet supported", null, FALSE );


        $ip = new Address( $ip_address, null );
        $ip->setType( "ip-netmask", false);
        $ip->setValue( $ip_address, false );

        $addressContainer = new AddressRuleContainer( null );
        $addressContainer->addObject( $ip );

        $RouterStore = "virtualRouterStore";
        if( get_class($system) == "VirtualSystem" && isset($system->owner) && get_class($system->owner) == "PANConf" )
        {
            if( $system->owner->_advance_routing_enabled )
                $RouterStore = "logicalRouterStore";
        }

        /** @var VirtualRouter|LogicalRouter $virtualRouterToProcess */
        $virtualRouterToProcess = null;

        if( !isset($context->cachedIPmapping) )
            $context->cachedIPmapping = array();

        $serial = spl_object_hash($device->owner);


        if( !isset($context->cachedIPmapping[$serial]) )
        {
            if( $system->isDeviceGroup() || $system->isPanorama() || $system->isManagedDevice() )
            {
                $firewall = null;
                $panorama = $system;
                if( $system->isDeviceGroup() )
                    $panorama = $system->owner;

                if( $context->arguments['template'] == $context->actionRef['args']['template']['default'] )
                    derr('with Panorama configs, you need to specify a template name');

                if( !$system->isManagedDevice() )
                    if( $context->arguments['virtualRouter'] == $context->actionRef['args']['virtualRouter']['default'] )
                        derr('with Panorama configs, you need to specify virtualRouter argument. Available virtual routes are: ');

                $_tmp_explTemplateName = explode('@', $context->arguments['template']);
                if( count($_tmp_explTemplateName) > 1 )
                {
                    $firewall = new PANConf();
                    $configIsOnLocalFirewall = TRUE;
                    $doc = null;

                    if( strtolower($_tmp_explTemplateName[0]) == 'api' )
                    {
                        $panoramaConnector = findConnector($system);
                        $connector = new PanAPIConnector($panoramaConnector->apihost, $panoramaConnector->apikey, 'panos-via-panorama', $_tmp_explTemplateName[1]);
                        $firewall->connector = $connector;
                        $doc = $connector->getMergedConfig();
                        $firewall->load_from_domxml($doc);
                        unset($connector);
                    }
                    elseif( strtolower($_tmp_explTemplateName[0]) == 'file' )
                    {
                        $filename = $_tmp_explTemplateName[1];
                        if( !file_exists($filename) )
                            derr("cannot read firewall configuration file '{$filename}''");
                        $doc = new DOMDocument();
                        if( !$doc->load($filename, XML_PARSE_BIG_LINES) )
                            derr("invalive xml file" . libxml_get_last_error()->message);
                        unset($filename);
                    }
                    else
                        derr("unsupported method: {$_tmp_explTemplateName[0]}@");


                    // delete rules to avoid loading all the config
                    $deletedNodesCount = DH::removeChildrenElementsMatchingXPath("/config/devices/entry/vsys/entry/rulebase/*", $doc);
                    if( $deletedNodesCount === FALSE )
                        derr("xpath issue");
                    $deletedNodesCount = DH::removeChildrenElementsMatchingXPath("/config/shared/rulebase/*", $doc);
                    if( $deletedNodesCount === FALSE )
                        derr("xpath issue");

                    //PH::print_stdout( "\n\n deleted $deletedNodesCount nodes" );

                    $firewall->load_from_domxml($doc);

                    unset($deletedNodesCount);
                    unset($doc);
                }


                /** @var Template $template */
                if( !$configIsOnLocalFirewall )
                {
                    $template = $panorama->findTemplate($context->arguments['template']);
                    if( $template === null )
                        derr("cannot find Template named '{$context->arguments['template']}'. Available template list:" . PH::list_to_string($panorama->templates));
                }

                if( $configIsOnLocalFirewall )
                    $virtualRouterToProcess = $firewall->network->$RouterStore->findVirtualRouter($context->arguments['virtualRouter']);
                else
                    $virtualRouterToProcess = $template->deviceConfiguration->network->$RouterStore->findVirtualRouter($context->arguments['virtualRouter']);

                if( $virtualRouterToProcess === null )
                {
                    if( $configIsOnLocalFirewall )
                        $tmpVar = $firewall->network->$RouterStore->virtualRouters();
                    else
                        $tmpVar = $template->deviceConfiguration->network->$RouterStore->virtualRouters();

                    derr("cannot find VirtualRouter named '{$context->arguments['virtualRouter']}' in Template '{$context->arguments['template']}'. Available VR list: " . PH::list_to_string($tmpVar), null, false);
                }

                if( (!$configIsOnLocalFirewall && count($template->deviceConfiguration->virtualSystems) == 1) || ($configIsOnLocalFirewall && count($firewall->virtualSystems) == 1) )
                {
                    if( $configIsOnLocalFirewall )
                        $system = $firewall->virtualSystems[0];
                    else
                        $system = $template->deviceConfiguration->virtualSystems[0];
                }
                else
                {
                    $vsysConcernedByVR = $virtualRouterToProcess->findConcernedVsys();
                    if( count($vsysConcernedByVR) == 1 )
                    {
                        $system = array_pop($vsysConcernedByVR);
                    }
                    elseif( $context->arguments['vsys'] == '*autodetermine*' )
                    {
                        derr("cannot autodetermine resolution context from Template '{$context->arguments['template']}' VR '{$context->arguments['virtualRouter']}'' , multiple VSYS are available: " . PH::list_to_string($vsysConcernedByVR) . ". Please provide choose a VSYS.");
                    }
                    else
                    {
                        if( $configIsOnLocalFirewall )
                            $vsys = $firewall->findVirtualSystem($context->arguments['vsys']);
                        else
                            $vsys = $template->deviceConfiguration->findVirtualSystem($context->arguments['vsys']);
                        if( $vsys === null )
                            derr("cannot find VSYS '{$context->arguments['vsys']}' in Template '{$context->arguments['template']}'");
                        $system = $vsys;
                    }
                }

                //derr(DH::dom_to_xml($template->deviceConfiguration->xmlroot));
                //$tmpVar = $system->importedInterfaces->interfaces();
                //derr(count($tmpVar)." ".PH::list_to_string($tmpVar));
            }
            else if( $context->arguments['virtualRouter'] != '*autodetermine*' )
            {
                $virtualRouterToProcess = $system->owner->network->$RouterStore->findVirtualRouter($context->arguments['virtualRouter']);
                if( $virtualRouterToProcess === null )
                    derr("VirtualRouter named '{$context->arguments['virtualRouter']}' not found");

                #print "router: ".$virtualRouterToProcess->name()."\n";
            }
            else
            {
                $vRouters = $system->owner->network->$RouterStore->virtualRouters();
                $foundRouters = array();

                foreach( $vRouters as $router )
                {
                    #print "router: ".$router->name()."\n";
                    foreach( $router->attachedInterfaces->interfaces() as $if )
                    {
                        if( $system->importedInterfaces->hasInterfaceNamed($if->name()) )
                        {
                            $foundRouters[] = $router;
                            break;
                        }
                    }
                }

                $string = "VSYS/DG '{$system->name()}' has interfaces attached to " . count($foundRouters) . " virtual routers";
                PH::ACTIONlog($context, $string);
                if( count($foundRouters) > 1 )
                    derr("more than 1 suitable virtual routers found, please specify one of the following: " . PH::list_to_string($foundRouters), null, false);
                if( count($foundRouters) == 0 )
                    derr("no suitable VirtualRouter found, please force one or check your configuration", null, false);

                $virtualRouterToProcess = $foundRouters[0];
            }
            $context->cachedIPmapping[$serial] = $virtualRouterToProcess->getIPtoZoneRouteMapping($system);
        }


        $ipMapping = &$context->cachedIPmapping[$serial];
        #print_r( $ipMapping );

        if( $addressContainer->isAny() )
        {
            $string = "address container is ANY()";
            PH::ACTIONstatus($context, "SKIPPED", $string);
            return;
        }


        $resolvedZones = &$addressContainer->calculateZonesFromIP4Mapping($ipMapping['ipv4']);
        //Todo: IPv6 not implemented yet
        $resolvedZonesv6 = &$addressContainer->calculateZonesFromIP6Mapping($ipMapping['ipv6']);

        if( count($resolvedZones) == 0 )
        {
            $string = "no zone resolved (FQDN? IPv6?)";
            PH::ACTIONstatus($context, "WARNING", $string);
            return;
        }

        $padding = "     ";
        foreach( $resolvedZones as $zoneName => $zone )
        {
            if( $device->isManagedDevice() )
                PH::print_stdout( $padding."* Hostname: ".$device->hostname );

            PH::print_stdout( $padding."* Zone: ".$zoneName );


            if( $device->isVirtualSystem() )
            {
                $zone_obj = $device->zoneStore->find( $zoneName );
                $interfaces = $zone_obj->attachedInterfaces->getAll();
                foreach( $interfaces as $interface )
                    $interface->display();
            }
        }


    },
    'args' => array(
        'ip' => array('type' => 'string',
            'default' => '*noDefault*',
            'help' => "Please bring in an IP-Address, to find the corresponding Zone."
        ),
        'virtualRouter' => array('type' => 'string',
            'default' => '*autodetermine*',
            'help' => "Can optionally be provided if script cannot find which virtualRouter it should be using" .
                " (ie: there are several VR in same VSYS)"
        ),
        'template' => array('type' => 'string',
            'default' => '*notPanorama*',
            'help' => "When you are using Panorama then 1 or more templates could apply to a DeviceGroup, in" .
                " such a case you may want to specify which Template name to use.\nBeware that if the Template is overriden" .
                " or if you are not using Templates then you will want load firewall config in lieu of specifying a template." .
                " \nFor this, give value 'api@XXXXX' where XXXXX is serial number of the Firewall device number you want to use to" .
                " calculate zones.\nIf you don't want to use API but have firewall config file on your computer you can then" .
                " specify file@/folderXYZ/config.xml."
        ),
        'vsys' => array('type' => 'string',
            'default' => '*autodetermine*',
            'help' => "specify vsys when script cannot autodetermine it or when you when to manually override"
        ),
    ),
    'help' => "This Action will use routing tables to resolve zones. When the program cannot find all parameters by" .
        " itself (like vsys or template name you will have to manually provide them.\n\n" .
        "Usage examples:\n\n" .
        "    - find-zone-from-ip:8.8.8.8\n" .
        "    - find-zone-from-ip:8.8.8.8,vr1\n" .
        "    - find-zone-from-ip:8.8.8.8,vr3,api@0011C890C,vsys1\n" .
        "    - find-zone-from-ip:8.8.8.8,vr5,Datacenter_template\n" .
        "    - find-zone-from-ip:8.8.8.8,vr3,file@firewall.xml,vsys1\n"
);


DeviceCallContext::$supportedActions['system-mgt-config_users'] = array(
    'name' => 'system-mgt-config_users',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);
        

        if( $context->first )
        {
            $cursor = DH::findXPathSingleEntryOrDie( "/config/mgt-config", $context->object->owner->xmldoc);

            $cursor = DH::findFirstElement('users', $cursor);

            foreach( $cursor->childNodes as $user )
            {
                if( $user->nodeType != XML_ELEMENT_NODE ) continue;

                PH::print_stdout();
                PH::print_stdout("NAME: '" . PH::boldText($user->getAttribute('name')) . "'");

                foreach( $user->childNodes as $node )
                {
                    if( $node->nodeType != XML_ELEMENT_NODE )
                        continue;

                    if( $node->nodeName === "authentication-profile" )
                    {
                        PH::print_stdout("  - AUTHENTICATION-PROFILE: '" . PH::boldText($node->textContent) . "'");
                    }
                    elseif( $node->nodeName === "permissions" )
                    {
                        //role-based
                        $cursor = DH::findFirstElement('role-based', $node);

                        foreach( $cursor->childNodes as $node2 )
                        {
                            if( $node2->nodeType != XML_ELEMENT_NODE )
                                continue;

                            PH::print_stdout("  - ROLE: '" . PH::boldText($node2->nodeName) . "'");

                            if( $node2->nodeName == "custom" )
                            {
                                $customProfile = DH::findFirstElement('profile', $node2);
                                $customDGProfile = DH::findFirstElement( 'dg-template-profiles', $node2);
                                if( $customProfile !== FALSE )
                                {
                                    $profileName = $customProfile->textContent;
                                    PH::print_stdout("  - Profile:: '" . PH::boldText( $profileName ) . "'");
                                }
                                elseif( $customDGProfile !== FALSE )
                                {
                                    $customEntry = DH::findFirstElement('entry', $customDGProfile);
                                    $entryName = DH::findAttribute( 'name', $customEntry );

                                    $customEntry = DH::findFirstElement('profile', $customEntry);

                                    $profileName = $customEntry->textContent;
                                    PH::print_stdout("  - AccessDomain: '".PH::boldText($entryName)."'" );
                                    PH::print_stdout("  - DG-Template Profile: '" . PH::boldText( $profileName ) . "'");
                                }
                            }
                        }
                    }
                }
                PH::print_stdout();
                PH::print_stdout("-----------------");
            }

            $context->first = FALSE;
        }
    },
    'help' => "This Action will display the configured Admin users on the Device"
);



DeviceCallContext::$supportedActions['system-restart'] = array(
    'name' => 'system-restart',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);


        if( $context->first )
        {

            $apiArgs = array();
            $apiArgs['type'] = 'op';
            $apiArgs['cmd'] = '<request><restart><system></system></restart></request>';

            if( $context->isAPI )
            {
                $response = $context->connector->sendRequest($apiArgs);
                $cursor = DH::findXPathSingleEntryOrDie('/response', $response);
                $cursor = DH::findFirstElement('result', $cursor);
            }
            else
                derr( "only working in API mode" );


            PH::print_stdout( $cursor->textContent );
            PH::print_stdout( "Device reboot in progress" );

            if( $classtype == "DeviceGroup" )
                $context->first = FALSE;
        }
    },
    'help' => "This Action is rebooting the Device"
);

DeviceCallContext::$supportedActions['system-admin-session'] = array(
    'name' => 'system-admin-session',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        $action = $context->arguments['action'];

        if( $context->first )
        {
            $apiArgs = array();
            $apiArgs['type'] = 'op';
            $apiArgs['cmd'] = '<show><admins></admins></show>';

            if( $context->isAPI )
            {
                $response = $context->connector->sendRequest($apiArgs);
                $cursor = DH::findXPathSingleEntryOrDie('/response', $response);
                $cursor = DH::findFirstElement('result', $cursor);
                $cursor = DH::findFirstElement('admins', $cursor);
            }
            else
                derr( "only working in API mode" );


            foreach( $cursor->childNodes as $admin)
            {
                if( $admin->nodeType != XML_ELEMENT_NODE )
                    continue;

                PH::print_stdout();

                $tmpString = DH::findFirstElement('admin', $admin);
                if( $tmpString !== FALSE )
                {
                    $adminUser = $tmpString->textContent;
                    $string = "   - USER: ";
                    PH::print_stdout(str_pad($string, 22) . $tmpString->textContent);
                }

                $tmpString = DH::findFirstElement('from', $admin);
                if( $tmpString !== FALSE )
                {
                    $string = "   - IP: ";
                    PH::print_stdout(str_pad($string, 22) . $tmpString->textContent);
                }

                $tmpString = DH::findFirstElement('type', $admin);
                if( $tmpString !== FALSE )
                {
                    $string = "   - TYPE: ";
                    PH::print_stdout(str_pad($string, 22) . $tmpString->textContent);
                }

                $tmpString = DH::findFirstElement('session-start', $admin);
                if( $tmpString !== FALSE )
                {
                    $sessionStart = $tmpString->textContent;
                    $string = "   - SESSION START: ";
                    PH::print_stdout(str_pad($string, 22) . $tmpString->textContent);
                }

                $tmpString = DH::findFirstElement('idle-for', $admin);
                if( $tmpString !== FALSE )
                {
                    $idleTime = $tmpString->textContent;
                    $idleTime = str_replace( "s", "", $idleTime);
                    $string = "   - SESSION IDLE for: ";
                    PH::print_stdout( str_pad( $string, 22 ).$tmpString->textContent);
                }

                $tmpString = DH::findFirstElement('session-expiry', $admin);
                if( $tmpString !== FALSE )
                {
                    $string = "   - SESSION EXPIRY: ";
                    PH::print_stdout( str_pad( $string, 22 ).$tmpString->textContent);
                }
//


                if( $action == "delete" )
                {
                    $hours = $context->arguments['idle-since-hours'];
                    if( is_integer($hours) )
                        derr( "argument need to be an integer" );


                    $time = time() - ($hours * 3600);
                    $calculatedtime = date('Y/m/d H:i:s', $time);

                    $dateTime = new DateTime($sessionStart);
                    $sessiontime = $dateTime->format('Y/m/d H:i:s'); // 15th Apr 2010



                    $seconds = strtotime("1970-01-01 $idleTime UTC");
                    #PH::print_stdout( "      * idle seconds: ".$seconds );
                    $actual = date('Y/m/d H:i:s');
                    $idlesince = strtotime( $actual ) - $seconds;
                    $idleTime = date("Y-m-d H:i:s", $idlesince);



                    if( strpos( $adminUser,"panorama" ) !== false )
                    {
                        PH::ACTIONstatus( $context, "SKIPPED", "needed for Panorama connection");
                        continue;
                    }


                    PH::print_stdout();
                    PH::print_stdout(  "      * Idle since : ".$idleTime);//." - ".strtotime( $idleTime ) );
                    PH::print_stdout( "      * deletion, if Idle before: ".$calculatedtime );//. " - ".strtotime( $calculatedtime ) );
                    #if( $time < $dateTime )
                    if( strtotime($calculatedtime) < strtotime($idleTime) )
                    {
                        PH::print_stdout();
                        PH::print_stdout( "      * this session is not old enough - skipped for deletion");
                        PH::print_stdout();
                        PH::print_stdout( "-------------------");
                        continue;
                    }


                    PH::print_stdout();
                    PH::print_stdout( "      * action delete is defined - deleting this admin session:");

                    $apiArgs = array();
                    $apiArgs['type'] = 'op';
                    $apiArgs['cmd'] = '<delete><admin-sessions><username>'.$adminUser.'</username></admin-sessions></delete>';

                    $response = $context->connector->sendRequest($apiArgs);
                    $cursor = DH::findXPathSingleEntryOrDie('/response', $response);
                    $cursor = DH::findFirstElement('result', $cursor);

                    PH::print_stdout( "   * ".$cursor->textContent );
                }

                PH::print_stdout();
                PH::print_stdout( "-------------------");
            }

            if( $classtype == "DeviceGroup" )
                $context->first = FALSE;
        }
    },
    'args' => array(
        'action' => array('type' => 'string', 'default' => 'display'),
        'idle-since-hours' => array('type' => 'string', 'default' => '8')
    ),
    'help' => "This Action is displaying the actual logged in admin sessions | possible action 'display' 'delete'"
);

DeviceCallContext::$supportedActions[] = array(
    'name' => 'xml-extract',
    'GlobalInitFunction' => function( DeviceCallContext $context)
    {
        $context->newdoc = new DOMDocument;
        $context->newdoc->preserveWhiteSpace = false;
        $context->newdoc->formatOutput = true;
        $context->rule = $context->newdoc->createElement('devices');
        $context->newdoc->appendChild($context->rule);

        $context->store = null;
    },
    'MainFunction' => function( DeviceCallContext $context)
    {
        $rule = $context->object;

        if( $context->store === null )
            $context->store = $rule->owner;


        $node = $context->newdoc->importNode($rule->xmlroot, true);
        $context->rule->appendChild($node);



    },
    'GlobalFinishFunction' => function(DeviceCallContext $context)
    {
        PH::$JSON_TMP['xmlroot-actions'] = $context->newdoc->saveXML();

        $store = $context->store;

        if( isset($store->owner->owner) && is_object($store->owner->owner) )
            $tmp_platform = get_class( $store->owner->owner );
        elseif( isset($store->owner) && is_object($store->owner) )
            $tmp_platform = get_class( $store->owner );
        else
            $tmp_platform = get_class( $store );

        PH::print_stdout( PH::$JSON_TMP, true, "xmlroot-actions" );
        PH::$JSON_TMP = array();

    },
);

DeviceCallContext::$supportedActions['authkey-set'] = array(
    'name' => 'authkey-set',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( !$object->owner->isFirewall() )
            derr("this device action is only working against Firewall device", null, false);

        $authkey = $context->arguments['authkey'];
        if( $authkey == '*nodefault*')
            derr("authkey not set", null, false);

        if( strpos($authkey, '$$colon$$') !== FALSE )
            $authkey = str_replace('$$colon$$', ":", $authkey);

        if( $context->first )
        {
            $apiArgs = array();
            $apiArgs['type'] = 'op';
            $apiArgs['cmd'] = '<request><authkey><set>'.$authkey.'</set></authkey></request>';

            if( $context->isAPI )
            {
                $response = $context->connector->sendRequest($apiArgs);
                $cursor = DH::findXPathSingleEntryOrDie('/response/msg', $response);

                PH::print_stdout( $cursor->textContent);
            }
            else
                derr( "only working in API mode" );


            $context->first = FALSE;
        }
    },
    'args' => array(
        'authkey' => array('type' => 'string', 'default' => '*nodefault*')
    ),
    'help' => "This Action is displaying the actual logged in admin sessions"
);

DeviceCallContext::$supportedActions['authkey-display-default'] = array(
    'name' => 'authkey-display-default',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;

        $classtype = get_class($object);

        if( !$object->owner->isPanorama() )
            derr("this device action is only working against Panorama device", null, false);

        if( $context->first )
        {
            $apiArgs = array();
            $apiArgs['type'] = 'op';
            $apiArgs['cmd'] = '<request><authkey><list>default</list></authkey></request>';

            if( $context->isAPI )
            {
                $response = $context->connector->sendRequest($apiArgs);
                $cursor = DH::findXPathSingleEntryOrDie('/response/result/authkey', $response);

                #DH::DEBUGprintDOMDocument($cursor);
                #PH::print_stdout( $cursor->textContent);

                $key = DH::findXPathSingleEntryOrDie('/entry[@name="default"]/key', $cursor);
                $count = DH::findXPathSingleEntryOrDie('/entry[@name="default"]/count', $cursor);
                #DH::DEBUGprintDOMDocument($key);
                PH::print_stdout();
                PH::print_stdout( "#########################################################");
                PH::print_stdout( "AUTHKEY: '". $key->textContent."'");
                PH::print_stdout("count: '".$count->textContent."'");
            }
            else
                derr( "only working in API mode" );


            $context->first = FALSE;
        }
    },
    'help' => "This Action is displaying the default authkey available in the Panorama"
);

DeviceCallContext::$supportedActions['authkey-display-all'] = array(
    'name' => 'authkey-display-all',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;

        $classtype = get_class($object);

        if( !$object->owner->isPanorama() )
            derr("this device action is only working against Panorama device", null, false);

        if( $context->first )
        {
            $apiArgs = array();
            $apiArgs['type'] = 'op';
            $apiArgs['cmd'] = '<request><authkey><list>*</list></authkey></request>';

            if( $context->isAPI )
            {
                $response = $context->connector->sendRequest($apiArgs);
                $cursor = DH::findXPathSingleEntryOrDie('/response/result/authkey', $response);

                foreach( $cursor->childNodes as $node )
                {

                    $name = DH::findAttribute("name", $node);
                    $name2 = DH::findFirstElement("name", $node);
                    $key = DH::findFirstElement("key", $node);
                    $count = DH::findFirstElement("count", $node);
                    $lifetime = DH::findFirstElement("lifetime", $node);

                    PH::print_stdout( "#########################################################");
                    #PH::print_stdout( "AUTHKEY: '". $key->textContent."'");
                    PH::print_stdout( "NAME: '". $name2->textContent."'");
                    PH::print_stdout( "LIFETIME: '". $lifetime->textContent."' [".strval(round(intval($lifetime->textContent)/60/60, 0))."h]");
                    PH::print_stdout("COUNT: '".$count->textContent."'");

                    $apiArgs = array();
                    $apiArgs['type'] = 'op';
                    $apiArgs['cmd'] = '<request><authkey><list>'.$name2->textContent.'</list></authkey></request>';

                    $response = $context->connector->sendRequest($apiArgs);
                    $cursor = DH::findXPathSingleEntryOrDie('/response/result/authkey', $response);

                    $key = DH::findXPathSingleEntryOrDie('/entry[@name="'.$name2->textContent.'"]/key', $cursor);

                    PH::print_stdout( "AUTHKEY: '". $key->textContent."'");
                }

            }
            else
                derr( "only working in API mode" );


            $context->first = FALSE;
        }
    },
    'help' => "This Action is displaying the default authkey available in the Panorama"
);

DeviceCallContext::$supportedActions['authkey-add'] = array(
    'name' => 'authkey-add',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;

        $classtype = get_class($object);
        $authkeyName = $context->arguments['authkey-name'];
        $authkeyLifetime = $context->arguments['lifetime'];

        if( !$object->owner->isPanorama() )
            derr("this device action is only working against Panorama device", null, false);

        if( $context->first )
        {
            $apiArgs = array();
            $apiArgs['type'] = 'op';
            #lifetime in minutes 1440 -> 1day
            $apiArgs['cmd'] = '<request><authkey><add><name>'.$authkeyName.'</name><lifetime>'.$authkeyLifetime.'</lifetime><count>100</count></add></authkey></request>';

            if( $context->isAPI )
            {
                $response = $context->connector->sendRequest($apiArgs);
                $cursor = DH::findXPathSingleEntryOrDie('/response', $response);

                PH::print_stdout();
                PH::print_stdout( "#########################################################");
                DH::DEBUGprintDOMDocument($cursor);

            }
            else
                derr( "only working in API mode" );


            $context->first = FALSE;
        }
    },
    'args' => array(
        'authkey-name' => array('type' => 'string', 'default' => 'pan-os-php-authkey'),
        'lifetime' => array('type' => 'string', 'default' => '86400')
    ),
    'help' => "This Action is displaying the default authkey available in the Panorama"
);

DeviceCallContext::$supportedActions['telemetry-enable'] = array(
    'name' => 'telemetry-enable',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;

        $telemetryEnable = $context->arguments['enable'];

        if( $telemetryEnable != "yes" && $telemetryEnable != "no" )
            derr( "enable value can only be 'yes' or 'no'", null, FALSE );

        if ($object->owner->isPanorama())
            derr("this device action is only working against Firewall device", null, false);

        if ($context->first)
        {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/device-telemetry";


            $elementArray = array();
            $elementArray[] = "<device-health-performance>".$telemetryEnable."</device-health-performance>";
            $elementArray[] = "<product-usage>".$telemetryEnable."</product-usage>";
            $elementArray[] = "<threat-prevention>".$telemetryEnable."</threat-prevention>";


            if( $context->isAPI )
            {
                foreach( $elementArray as $element )
                {
                    $response = $context->connector->sendSetRequest($xpath, $element);
                    $cursor = DH::findXPathSingleEntryOrDie('/response', $response);

                    PH::print_stdout();
                    PH::print_stdout( "#########################################################");
                    DH::DEBUGprintDOMDocument($cursor);
                }


            }
            else
                derr( "only working in API mode" );


            $context->first = FALSE;
        }
    },
    'args' => array(
        'enable' => array('type' => 'string', 'default' => 'no')
    ),
    'help' => "enable function: possible values: 'yes' or 'no'"
);