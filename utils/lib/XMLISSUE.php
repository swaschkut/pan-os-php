<?php
/**
 * ISC License
 *
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

class XMLISSUE extends UTIL
{
    public $region_array = array();

    public $pregMatch_pattern_wrong_characters = '/[^\w $\-.]/';

    public function utilStart()
    {
        $this->usageMsg = PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=api://[MGMT-IP-Address] ";


        #$this->prepareSupportedArgumentsArray();


        PH::processCliArgs();
        $this->help(PH::$args);
        $this->init_arguments();

        //special treatment as also API need to send output
        if( isset(PH::$args['out']) )
        {
            $this->configOutput = PH::$args['out'];
            if( !is_string($this->configOutput) || strlen($this->configOutput) < 1 )
                $this->display_error_usage_exit('"out" argument is not a valid string');
        }

        $this->load_config();


        $this->main();


        $this->save_our_work( true );
    }

    public function main()
    {


///////////////////////////////////////////////////////////
//clean stage config / delete all <deleted> entries
        $xpath = new DOMXpath($this->xmlDoc);

// example 1: for everything with an id
        $elements = $xpath->query("//deleted");


        foreach( $elements as $element )
        {
            $element->parentNode->removeChild($element);
        }
///////////////////////////////////////////////////////////

//REGION objects

        $filename = dirname(__FILE__) . '/../../lib/object-classes/predefined.xml';

        $xmlDoc_region = new DOMDocument();
        $xmlDoc_region->load($filename, XML_PARSE_BIG_LINES);

        $cursor = DH::findXPathSingleEntryOrDie('/predefined/region', $xmlDoc_region);
        foreach( $cursor->childNodes as $region_entry )
        {
            if( $region_entry->nodeType != XML_ELEMENT_NODE )
                continue;

            $region_name = DH::findAttribute('name', $region_entry);
            #PH::print_stdout( $region_name );
            $this->region_array[$region_name] = $region_entry;
        }


///////////////////////////////////////////////////////////




//
// REAL JOB STARTS HERE
//
//


        $totalAddressGroupsFixed = 0;
        $totalServiceGroupsFixed = 0;


        $totalAddressGroupsSubGroupFixed = 0;
        $totalDynamicAddressGroupsTagFixed = 0;
        $totalServiceGroupsSubGroupFixed = 0;

        $countDuplicateAddressObjects = 0;
        $fixedDuplicateAddressObjects = 0;
        $countDuplicateServiceObjects = 0;
        $fixedDuplicateServiceObjects = 0;

        $countDuplicateTagObjects = 0;
        $fixedDuplicateTagObjects = 0;

        $countDuplicateSecRuleObjects = 0;
        $countDuplicateNATRuleObjects = 0;

        $countSecRuleObjectsWithDoubleSpaces = 0;
        $countSecRuleObjectsWithWrongCharacters = 0;
        $countNATRuleObjectsWithDoubleSpaces = 0;
        $countNATRuleObjectsWithWrongCharacters = 0;

        $countMissconfiguredSecRuleServiceObjects=0;
        $fixedSecRuleServiceObjects=0;
        $countMissconfiguredSecRuleApplicationObjects=0;
        $fixedSecRuleApplicationObjects=0;

        $countMissconfiguredSecRuleTagObjects=0;
        $fixedSecRuleTagObjects=0;

        $countMissconfiguredSecRuleSourceObjects=0;
        $fixedSecRuleSourceObjects=0;
        $countMissconfiguredSecRuleDestinationObjects=0;
        $fixedSecRuleDestinationObjects=0;

        $countMissconfiguredSecRuleFromObjects=0;
        $fixedSecRuleFromObjects=0;
        $countMissconfiguredSecRuleToObjects=0;
        $fixedSecRuleToObjects=0;

        $countMissconfiguredSecRuleCategoryObjects=0;
        $fixedSecRuleCategoryObjects=0;

        $countMissconfiguredNatRuleSourceObjects=0;
        $fixedNatRuleSourceObjects=0;
        $countMissconfiguredNatRuleDestinationObjects=0;
        $fixedNatRuleDestinationObjects=0;

        $countMissconfiguredAddressObjects = 0;
        $countMissconfiguredAddressRegionObjects = 0;
        $countAddressObjectsWithDoubleSpaces = 0;
        $countAddressObjectsWithWrongCharacters = 0;

        $countMissconfiguredServiceObjects = 0;
        $countServiceObjectsWithDoubleSpaces = 0;
        $countServiceObjectsWithWrongCharacters = 0;
        $countServiceObjectsWithNameappdefault = 0;
        $fixedServiceObjectsWithSameTag = 0;

        $countMissconfiguredSecruleSourceUserObjects = 0;
        $fixedSecruleSourceUserObjects = 0;

        $countEmptyAddressGroup = 0;
        $countEmptyServiceGroup = 0;

        $service_app_default_available = false;
        $countMissconfiguredSecRuleServiceAppDefaultObjects = 0;

        $fixedReadOnlyDeviceGroupobjects=0;
        $fixedReadOnlyAddressGroupobjects=0;
        $fixedReadOnlyTemplateobjects=0;
        $fixedReadOnlyTemplateStackobjects=0;

        $fixedImportNetworkInterfaceWithSameInterface = 0;

        $totalApplicationGroupsFixed = 0;
        $totalCustomUrlCategoryFixed = 0;

        $countRulesWithAppDefault = 0;

        $address_region = array();
        $address_name = array();



        /** @var DOMElement[] $locationNodes */
        $locationNodes = array();
        $tmp_shared_node = DH::findXPathSingleEntry('/config/shared', $this->xmlDoc);
        if( $tmp_shared_node !== false )
            $locationNodes['shared'] = $tmp_shared_node;

        if( $this->configType == 'panos' )
            $tmpNodes = DH::findXPath('/config/devices/entry/vsys/entry', $this->xmlDoc);
        elseif( $this->configType == 'panorama' )
            $tmpNodes = DH::findXPath('/config/devices/entry/device-group/entry', $this->xmlDoc);
        elseif( $this->configType == 'fawkes' )
        {
            $search_array = array( '/config/devices/entry/container/entry','/config/devices/entry/device/cloud/entry' );
            $tmpNodes = DH::findXPath($search_array, $this->xmlDoc);

        }

        foreach( $tmpNodes as $node )
            $locationNodes[$node->getAttribute('name')] = $node;

        PH::print_stdout( " - Found " . count($locationNodes) . " locations (VSYS/DG/Container/DeviceCloud)");
        foreach( $locationNodes as $key => $tmpNode )
            PH::print_stdout( "   - ".$key);

        PH::print_stdout( "*******   ********   ********");

        foreach( $locationNodes as $locationName => $locationNode )
        {
            PH::print_stdout( "** PARSING VSYS/DG/Container/DeviceCloud '{$locationName}' **");

            $addressObjects = array();
            $addressGroups = array();
            $addressIndex = array();
            $addressRegion = array();

            $serviceObjects = array();
            $serviceGroups = array();
            $serviceIndex = array();



            $secRules = array();
            $secRuleIndex = array();
            $natRules = array();
            $natRuleIndex = array();
            $secRuleServiceIndex = array();
            $secRuleApplicationIndex = array();

            $zoneObjects = array();
            $zoneIndex = array();

            $address_region = array();
            $address_name = array();
            $address_wrong_name = array();
            $service_name = array();
            $service_wrong_name = array();
            $service_name_appdefault = array();
            $secrule_name = array();
            $secrule_wrong_name = array();
            $natrule_name = array();
            $natrule_wrong_name = array();

            $objectTypeNode = DH::findFirstElement('address', $locationNode);
            if( $objectTypeNode !== FALSE )
            {
                foreach( $objectTypeNode->childNodes as $objectNode )
                {
                    /** @var DOMElement $objectNode */
                    if( $objectNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $objectName = $objectNode->getAttribute('name');

                    $this->check_region( $objectName, $objectNode, $address_region );
                    $this->check_name( $objectName, $objectNode, $address_name );
                    $this->check_wrong_name( $objectName, $objectNode, $address_wrong_name );

                    $addressObjects[$objectName][] = $objectNode;

                    if( !isset($addressIndex[$objectName]) )
                        $addressIndex[$objectName] = array('regular' => array(), 'group' => array());

                    $addressIndex[$objectName]['regular'][] = $objectNode;
                }

            }

            $objectTypeNode = DH::findFirstElement('address-group', $locationNode);
            if( $objectTypeNode !== FALSE )
            {
                foreach( $objectTypeNode->childNodes as $objectNode )
                {
                    /** @var DOMElement $objectNode */
                    if( $objectNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $objectName = $objectNode->getAttribute('name');

                    $this->check_region( $objectName, $objectNode, $address_region );
                    $this->check_name( $objectName, $objectNode, $address_name );
                    $this->check_wrong_name( $objectName, $objectNode, $address_wrong_name );

                    $addressGroups[$objectName][] = $objectNode;

                    if( !isset($addressIndex[$objectName]) )
                        $addressIndex[$objectName] = array('regular' => array(), 'group' => array());

                    $addressIndex[$objectName]['group'][] = $objectNode;
                }
            }


            PH::print_stdout( "");
            PH::print_stdout( "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####");
            PH::print_stdout( " - parsed " . count($addressObjects) . " address objects and " . count($addressGroups) . " groups");
            PH::print_stdout( "");

            //
            //
            //
            PH::print_stdout( " - Scanning for address / addressgroup with same name as REGION objects...");
            foreach( $address_region as $objectName => $node )
            {
                PH::print_stdout( "    - address object '{$objectName}' from DG/VSYS {$locationName} has lower precedence as REGION object ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}");
                $countMissconfiguredAddressRegionObjects++;
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for address / addressgroup with double spaces in name...");
            foreach( $address_name as $objectName => $node )
            {
                PH::print_stdout( "    - address object '{$objectName}' from DG/VSYS {$locationName} has '  ' double Spaces in name, this causes problems by copy&past 'set commands' ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}");
                $countAddressObjectsWithDoubleSpaces++;
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for address / addressgroup with wrong characters in name...");
            foreach( $address_wrong_name as $objectName => $node )
            {
                preg_match_all($this->pregMatch_pattern_wrong_characters, $objectName, $matches , PREG_SET_ORDER, 0);

                $findings = array();
                foreach( $matches as $match )
                    $findings[$match[0]] = $match[0];
                #print_r($findings);
                PH::print_stdout( "    - address object '{$objectName}' from DG/VSYS {$locationName} has wrong characters in name, '".implode('', $findings)."' this causes commit issues  (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}");

                $newName = $objectName;
                foreach( $findings as $replace )
                    $newName = str_replace($replace, "_", $newName);

                PH::print_stdout( "       oldname: '".$objectName."' | suggested newname: '".$newName."'\n" );
                //xml-issue can not work on objects here :-)
                #$node->setName($newName);


                $countAddressObjectsWithWrongCharacters++;
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for address with missing IP-netmask/IP-range/FQDN information...");
            foreach( $addressObjects as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $ip_netmaskNode = DH::findFirstElement('ip-netmask', $node);
                    $ip_rangeNode = DH::findFirstElement('ip-range', $node);
                    $fqdnNode = DH::findFirstElement('fqdn', $node);
                    $ip_wildcardNode = DH::findFirstElement('ip-wildcard', $node);
                    if( $ip_netmaskNode === FALSE && $ip_rangeNode === FALSE && $fqdnNode === FALSE && $ip_wildcardNode === FALSE )
                    {
                        PH::print_stdout( "    - address object '{$objectName}' from DG/VSYS {$locationName} has missing IP configuration ... (*FIX_MANUALLY*)");
                        PH::print_stdout( "       - type 'Address' at XML line #{$node->getLineNo()}");
                        $countMissconfiguredAddressObjects++;
                    }
                }
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for address groups with empty members...");
            foreach( $addressGroups as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $staticNode = DH::findFirstElement('static', $node);
                    $dynamicNode = DH::findFirstElement('dynamic', $node);
                    if( $staticNode === FALSE && $dynamicNode === FALSE )
                    {
                        PH::print_stdout( "    - addressgroup object '{$objectName}' from DG/VSYS {$locationName} has no member ... (*FIX_MANUALLY*)");
                        PH::print_stdout( "       - type 'AddressGroup' at XML line #{$node->getLineNo()}");
                        $countEmptyAddressGroup++;
                    }
                }
            }


            //
            //
            //
            PH::print_stdout( " - Scanning for address groups with duplicate members...");
            foreach( $addressGroups as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $staticNode = DH::findFirstElement('static', $node);
                    if( $staticNode === FALSE )
                        continue;

                    $membersIndex = array();
                    /** @var DOMElement[] $nodesToRemove */
                    $nodesToRemove = array();

                    foreach( $staticNode->childNodes as $staticNodeMember )
                    {
                        /** @var DOMElement $staticNodeMember */
                        if( $staticNodeMember->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $memberName = $staticNodeMember->textContent;

                        if( isset($membersIndex[$memberName]) )
                        {
                            PH::print_stdout( "    - group '{$objectName}' from DG/VSYS {$locationName} has a duplicate member named '{$memberName}' ... *FIXED*");
                            $nodesToRemove[] = $staticNodeMember;
                            $totalAddressGroupsFixed++;
                            continue;
                        }

                        $membersIndex[$memberName] = TRUE;
                    }

                    foreach( $nodesToRemove as $nodeToRemove )
                        $nodeToRemove->parentNode->removeChild($nodeToRemove);
                }
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for address groups with own membership as subgroup...");
            foreach( $addressGroups as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $staticNode = DH::findFirstElement('static', $node);
                    if( $staticNode === FALSE )
                        continue;

                    $membersIndex = array();
                    /** @var DOMElement[] $nodesToRemove */
                    $nodesToRemove = array();

                    foreach( $staticNode->childNodes as $staticNodeMember )
                    {
                        /** @var DOMElement $staticNodeMember */
                        if( $staticNodeMember->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $memberName = $staticNodeMember->textContent;

                        if( strcmp( $objectName, $memberName) === 0 )
                        {
                            PH::print_stdout( "    - group '{$objectName}' from DG/VSYS {$locationName} has itself as member '{$memberName}' ... *FIXED*");
                            $staticNodeMember->parentNode->removeChild($staticNodeMember);
                            $totalAddressGroupsSubGroupFixed++;
                            continue;
                        }
                    }
                }
            }


            //
            //
            //
            PH::print_stdout( " - Scanning for dynamic address groups where tag and filter is same...");
            foreach( $addressGroups as $objectName => $nodes )
            {
                $filterArray = array();
                $tagArray = array();

                foreach( $nodes as $node )
                {
                    $dynamicNode = DH::findFirstElement('dynamic', $node);
                    if( $dynamicNode === FALSE )
                        continue;

                    $membersIndex = array();
                    /** @var DOMElement[] $nodesToRemove */
                    $nodesToRemove = array();

                    $tagNode = DH::findFirstElement('tag', $node);
                    if( $tagNode === FALSE )
                        continue;


                    foreach( $dynamicNode->childNodes as $filterNodeMember )
                    {
                        /** @var DOMElement $filterNodeMember */
                        if( $filterNodeMember->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $memberName = $filterNodeMember->textContent;


                        //something more todo; explode and / or maybe something more
                        $memberName = trim( $memberName );
                        $filterAndArray = explode( " and ", $memberName );
                        $filterOrArray = explode( " or ", $memberName );



                        if( count( $filterAndArray ) > 1 && count( $filterOrArray ) > 1  )
                        {
                            $filterArray = array();
                            $filterType = 'andor';
                        }
                        elseif( count( $filterAndArray ) > 1 )
                        {
                            foreach( $filterAndArray as $member )
                            {
                                $member = str_replace("'", "", $member);
                                $filterArray[ $member ] = $member;
                            }
                            $filterType = 'and';
                        }
                        elseif( count( $filterOrArray ) > 1 )
                        {
                            foreach( $filterOrArray as $member )
                            {
                                $member = str_replace("'", "", $member);
                                $filterArray[ $member ] = $member;
                            }
                            $filterType = 'or';
                        }
                        else
                        {
                            $memberName = str_replace("'", "", $memberName);
                            $filterArray[ $memberName ] = $memberName;
                            $filterType = 'single';
                        }
                    }


                    foreach( $tagNode->childNodes as $tagNodeMember )
                    {
                        /** @var DOMElement $tagNodeMember */
                        if( $tagNodeMember->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $memberName = $tagNodeMember->textContent;
                        $tagArray[ $memberName ] = $tagNodeMember;
                    }

                    if( count( $tagArray ) == 0 )
                        continue;

                    if( $filterType == "single" && in_array( array_key_first($tagArray), $filterArray ) )
                    {
                        PH::print_stdout( "    - group '{$objectName}' from DG/VSYS {$locationName} has its own filter as tag: '{$memberName}' ... *FIXED*");

                        $node = reset( $tagArray );
                        $node->parentNode->removeChild($node);
                        $totalDynamicAddressGroupsTagFixed++;
                        continue;
                    }
                    elseif( $filterType == "and" )
                    {
                        foreach( $tagArray as $tag => $value )
                            unset( $filterArray[$tag] );

                        if( count( $filterArray ) == 0 )
                        {
                            PH::print_stdout( "    - group '{$objectName}' from DG/VSYS {$locationName} has its own filter as tag: '{$memberName}' ... *FIXED*");
                            $value->parentNode->removeChild($value);
                            $totalDynamicAddressGroupsTagFixed++;
                            continue;
                        }
                    }
                    elseif( $filterType == "or" )
                    {
                        foreach( $tagArray as $tag )
                        {
                            if( in_array( $tag, $filterArray ) )
                            {
                                PH::print_stdout( "    - group '{$objectName}' from DG/VSYS {$locationName} has its own filter as tag: '{$memberName}' ... *FIXED*");
                                $tagNodeMember->parentNode->removeChild($tagNodeMember);
                                $totalDynamicAddressGroupsTagFixed++;
                                continue;
                            }
                        }
                    }
                }
            }


            //
            //
            //
            PH::print_stdout( " - Scanning for duplicate address objects...");
            foreach( $addressIndex as $objectName => $objectNodes )
            {
                $dupCount = count($objectNodes['regular']) + count($objectNodes['group']);

                if( $dupCount < 2 )
                    continue;

                PH::print_stdout( "   - found address object named '{$objectName}' that exists " . $dupCount . " time (*FIX_MANUALLY*):");

                $tmp_addr_array = array();
                foreach( $objectNodes['regular'] as $objectNode )
                {
                    $ip_netmaskNode = DH::findFirstElement('ip-netmask', $objectNode);
                    if( $ip_netmaskNode === FALSE )
                        $ip_netmaskNode = DH::findFirstElement('ip-range', $objectNode);
                    $ip_fqdnNode = DH::findFirstElement('fqdn', $objectNode);
                    if( $ip_netmaskNode !== FALSE )
                    {
                        /** @var DOMElement $objectNode */
                        $text = "       - type 'Address' value: '" . $ip_netmaskNode->nodeValue . "' at XML line #{$objectNode->getLineNo()}";

                        //Todo: check if address object value is same, then delete it
                        //TODO: VALIDATION needed if working as expected

                        if( strpos( $ip_netmaskNode->nodeValue, "/32" ) !== FALSE )
                            $tmp_ipvalue = str_replace( "/32", "", $ip_netmaskNode->nodeValue);
                        else
                            $tmp_ipvalue = $ip_netmaskNode->nodeValue;

                        if( !isset($tmp_addr_array[$tmp_ipvalue]) )
                        {
                            $tmp_addr_array[$tmp_ipvalue] = $tmp_ipvalue;
                            $countDuplicateAddressObjects++;
                        }
                        else
                        {
                            $objectNode->parentNode->removeChild($objectNode);
                            $text .= PH::boldText(" (removed - no manual fix needed)");
                            $countDuplicateAddressObjects--;
                            $fixedDuplicateAddressObjects++;
                        }

                        PH::print_stdout( $text );
                    }
                    elseif( $ip_fqdnNode !== FALSE )
                    {
                        /** @var DOMElement $objectNode */
                        PH::print_stdout( "       - type 'Address' value: '" . $ip_fqdnNode->nodeValue . "' at XML line #{$objectNode->getLineNo()}");

                        $countDuplicateAddressObjects++;
                    }
                    else
                        continue;

                }

                $tmp_srv_array = array();
                foreach( $objectNodes['group'] as $objectNode )
                {
                    #print_r($objectNodes['group']);
                    $protocolNode = DH::findFirstElement('static', $objectNode);
                    if( $protocolNode === FALSE )
                        continue;

                    $txt = "";
                    foreach( $protocolNode->childNodes as $member )
                    {
                        /** @var DOMElement $objectNode */
                        if( $member->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $txt .= $member->nodeValue;
                    }

                    /** @var DOMElement $objectNode */
                    $text = "       - type 'AddressGroup' at XML line #{$objectNode->getLineNo()}";

                    //Todo: check if servicegroup object value is same, then delete it
                    //TODO: VALIDATION needed if working as expected

                    if( !isset($tmp_srv_array[$txt]) )
                    {
                        $tmp_srv_array[$txt] = $txt;
                        $countDuplicateAddressObjects++;
                    }
                    else
                    {
                        $objectNode->parentNode->removeChild($objectNode);
                        $text .= PH::boldText(" (removed - no manual fix needed)");
                        $countDuplicateAddressObjects--;
                        $fixedDuplicateAddressObjects++;
                    }
                    PH::print_stdout( $text);
                }
                #$countDuplicateAddressObjects--;
            }


            //
            //
            //
            //
            //
            //

            $objectTypeNode = DH::findFirstElement('service', $locationNode);
            if( $objectTypeNode !== FALSE )
            {
                foreach( $objectTypeNode->childNodes as $objectNode )
                {
                    /** @var DOMElement $objectNode */
                    if( $objectNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $objectName = $objectNode->getAttribute('name');

                    $this->check_name( $objectName, $objectNode, $service_name );
                    $this->check_wrong_name( $objectName, $objectNode, $service_wrong_name );
                    $this->check_service_name_appdefault( $objectName, $objectNode, $service_name_appdefault );

                    if( strcmp( $objectName, "application-default") === 0 )
                        $service_app_default_available = true;

                    $serviceObjects[$objectName][] = $objectNode;

                    if( !isset($serviceIndex[$objectName]) )
                        $serviceIndex[$objectName] = array('regular' => array(), 'group' => array());

                    $serviceIndex[$objectName]['regular'][] = $objectNode;
                }

            }

            $objectTypeNode = DH::findFirstElement('service-group', $locationNode);
            if( $objectTypeNode !== FALSE )
            {
                foreach( $objectTypeNode->childNodes as $objectNode )
                {
                    /** @var DOMElement $objectNode */
                    if( $objectNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $objectName = $objectNode->getAttribute('name');

                    $this->check_name( $objectName, $objectNode, $service_name );
                    $this->check_wrong_name( $objectName, $objectNode, $service_wrong_name );
                    $this->check_service_name_appdefault( $objectName, $objectNode, $service_name_appdefault );

                    $serviceGroups[$objectName][] = $objectNode;

                    if( !isset($serviceIndex[$objectName]) )
                        $serviceIndex[$objectName] = array('regular' => array(), 'group' => array());

                    $serviceIndex[$objectName]['group'][] = $objectNode;
                }
            }

            PH::print_stdout( "");
            PH::print_stdout( "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####");
            PH::print_stdout( " - parsed " . count($serviceObjects) . " service objects and " . count($serviceGroups) . " groups");
            PH::print_stdout( "");

            //
            //
            //
            PH::print_stdout( " - Scanning for service / servicegroup with double spaces in name...");
            foreach( $service_name as $objectName => $node )
            {
                PH::print_stdout( "    - service object '{$objectName}' from DG/VSYS {$locationName} has '  ' double Spaces in name, this causes problems by copy&past 'set commands' ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}");
                $countServiceObjectsWithDoubleSpaces++;
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for service / servicegroup  with wrong characters in name...");
            foreach( $service_wrong_name as $objectName => $node )
            {
                preg_match_all($this->pregMatch_pattern_wrong_characters, $objectName, $matches , PREG_SET_ORDER, 0);

                $findings = array();
                foreach( $matches as $match )
                    $findings[$match[0]] = $match[0];
                #print_r($findings);

                PH::print_stdout( "    - service object '{$objectName}' from DG/VSYS {$locationName} has wrong characters in name, '".implode('', $findings)."' this causes commit issues  (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}");

                $newName = $objectName;
                foreach( $findings as $replace )
                    $newName = str_replace($replace, "_", $newName);

                PH::print_stdout( "       oldname: '".$objectName."' | suggested newname: '".$newName."'\n" );

                $countServiceObjectsWithWrongCharacters++;
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for service / servicegroup with application-default as name...");
            foreach( $service_name_appdefault as $objectName => $node )
            {
                //PH::print_stdout( "    - service object '{$objectName}' from DG/VSYS {$locationName} has name 'application-default' this causes problems with the default behaviour of the firewall ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}");
                PH::print_stdout( "    - service object 'application-default' from DG/VSYS {$locationName} has name 'application-default' this causes problems with the default behaviour of the firewall ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}");
                $countServiceObjectsWithNameappdefault++;
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for service with missing protocol information...");
            foreach( $serviceObjects as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $protocolNode = DH::findFirstElement('protocol', $node);
                    if( $protocolNode === FALSE )
                    {
                        PH::print_stdout( "    - service object '{$objectName}' from DG/VSYS {$locationName} has missing protocol configuration ... (*FIX_MANUALLY*)");
                        PH::print_stdout( "       - type 'Service' at XML line #{$node->getLineNo()}");
                        $countMissconfiguredServiceObjects++;
                    }
                }
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for service with multiple times same tag...");
            foreach( $serviceObjects as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $tagNode = DH::findFirstElement('tag', $node);
                    if( $tagNode !== FALSE )
                    {
                        $tagArray = array();
                        #PH::print_stdout( "    - service object '{$objectName}' from DG/VSYS {$locationName} has missing protocol configuration ... (*FIX_MANUALLY*)");
                        #PH::print_stdout( "       - type 'Service' at XML line #{$node->getLineNo()}");
                        #$countMissconfiguredServiceObjects++;

                        foreach( $tagNode->childNodes as $tagNodeMember )
                        {
                            /** @var DOMElement $tagNodeMember */
                            if ($tagNodeMember->nodeType != XML_ELEMENT_NODE)
                                continue;


                            $tagName = $tagNodeMember->textContent;
                            if( isset( $tagArray[$tagName] ) )
                            {
                                PH::print_stdout( "    - service object '{$objectName}' from DG/VSYS {$locationName} has duplicate TAG: ".$tagName." configured ... *FIXED*");
                                $tagNodeMember->parentNode->removeChild($tagNodeMember);
                                $fixedServiceObjectsWithSameTag++;
                            }
                            else
                            {
                                $tagArray[$tagName] = $tagName;
                            }
                        }
                    }
                }
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for service groups with empty members...");
            foreach( $serviceGroups as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $staticNode = DH::findFirstElement('members', $node);
                    if( $staticNode === FALSE )
                    {
                        PH::print_stdout( "    - servicegroup object '{$objectName}' from DG/VSYS {$locationName} has no member ... (*FIX_MANUALLY*)");
                        PH::print_stdout( "       - type 'ServiceGroup' at XML line #{$node->getLineNo()}");
                        $countEmptyServiceGroup++;
                    }
                }
            }

            PH::print_stdout( " - Scanning for service groups with duplicate members...");
            foreach( $serviceGroups as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $staticNode = DH::findFirstElement('members', $node);
                    if( $staticNode === FALSE )
                        continue;

                    $membersIndex = array();
                    /** @var DOMElement[] $nodesToRemove */
                    $nodesToRemove = array();

                    foreach( $staticNode->childNodes as $staticNodeMember )
                    {
                        /** @var DOMElement $staticNodeMember */
                        if( $staticNodeMember->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $memberName = $staticNodeMember->textContent;

                        if( isset($membersIndex[$memberName]) )
                        {
                            PH::print_stdout( "    - group '{$objectName}' from DG/VSYS {$locationName} has a duplicate member named '{$memberName}' ... *FIXED*");
                            $nodesToRemove[] = $staticNodeMember;
                            $totalServiceGroupsFixed++;
                            continue;
                        }

                        $membersIndex[$memberName] = TRUE;
                    }

                    foreach( $nodesToRemove as $nodeToRemove )
                        $nodeToRemove->parentNode->removeChild($nodeToRemove);
                }
            }


            //
            //
            //
            PH::print_stdout( " - Scanning for service groups with own membership as subgroup...");
            foreach( $serviceGroups as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $staticNode = DH::findFirstElement('members', $node);
                    if( $staticNode === FALSE )
                        continue;

                    $membersIndex = array();
                    /** @var DOMElement[] $nodesToRemove */
                    $nodesToRemove = array();

                    foreach( $staticNode->childNodes as $staticNodeMember )
                    {
                        /** @var DOMElement $staticNodeMember */
                        if( $staticNodeMember->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $memberName = $staticNodeMember->textContent;

                        if( strcmp( $objectName, $memberName) === 0 )
                        {
                            PH::print_stdout( "    - group '{$objectName}' from DG/VSYS {$locationName} has itself as member '{$memberName}' ... *FIXED*");
                            $staticNodeMember->parentNode->removeChild($staticNodeMember);
                            $totalServiceGroupsSubGroupFixed++;
                            continue;
                        }
                    }
                }
            }


            PH::print_stdout( " - Scanning for duplicate service objects...");
            foreach( $serviceIndex as $objectName => $objectNodes )
            {
                $dupCount = count($objectNodes['regular']) + count($objectNodes['group']);

                if( $dupCount < 2 )
                    continue;

                PH::print_stdout( "   - found service object named '{$objectName}' that exists " . $dupCount . " time (*FIX_MANUALLY*):");
                $tmp_srv_array = array();
                foreach( $objectNodes['regular'] as $objectNode )
                {
                    $protocolNode = DH::findFirstElement('protocol', $objectNode);
                    if( $protocolNode === FALSE )
                        continue;

                    /** @var DOMElement $objectNode */
                    $text = "       - type 'Service' value: '" . $protocolNode->nodeValue . "' at XML line #{$objectNode->getLineNo()}";

                    //Todo: check if service object value is same, then delete it
                    //TODO: VALIDATION needed if working as expected

                    if( !isset($tmp_srv_array[$protocolNode->nodeValue]) )
                    {
                        $tmp_srv_array[$protocolNode->nodeValue] = $protocolNode->nodeValue;
                        $countDuplicateServiceObjects++;
                    }
                    else
                    {
                        $objectNode->parentNode->removeChild($objectNode);
                        $text .= PH::boldText(" (removed - no manual fix needed)");
                        $countDuplicateServiceObjects--;
                        $fixedDuplicateServiceObjects++;
                    }
                    PH::print_stdout( $text);
                }

                $tmp_srv_array = array();
                foreach( $objectNodes['group'] as $objectNode )
                {
                    $protocolNode = DH::findFirstElement('members', $objectNode);
                    if( $protocolNode === FALSE )
                        continue;

                    $txt = "";
                    foreach( $protocolNode->childNodes as $member )
                    {
                        /** @var DOMElement $objectNode */
                        if( $member->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $txt .= $member->nodeValue;
                    }

                    /** @var DOMElement $objectNode */
                    $text = "       - type 'ServiceGroup' at XML line #{$objectNode->getLineNo()}";

                    //Todo: check if servicegroup object value is same, then delete it
                    //TODO: VALIDATION needed if working as expected

                    /*
                    if( !isset($tmp_srv_array[$protocolNode->nodeValue]) )
                    {
                        $tmp_srv_array[$protocolNode->nodeValue] = $protocolNode->nodeValue;
                        $countDuplicateServiceObjects++;
                    }
                    */
                    if( !isset($tmp_srv_array[$txt]) )
                    {
                        $tmp_srv_array[$txt] = $txt;
                        $countDuplicateAddressObjects++;
                    }
                    else
                    {
                        $objectNode->parentNode->removeChild($objectNode);
                        $text .= PH::boldText("(removed - no manual fix needed)" );
                        $countDuplicateServiceObjects--;
                        $fixedDuplicateServiceObjects++;
                    }
                    PH::print_stdout( $text);
                }
                #$countDuplicateServiceObjects--;
            }

            //
            //
            //
            //
            //
            //
            $applicationGroups = array();
            $applicationIndex = array();
            $this->checkRemoveDuplicateMembers( $locationNode, $locationName, 'application-group', $applicationGroups, $applicationIndex, $totalApplicationGroupsFixed );

            //
            //
            $customURLcategory = array();
            $customURLcategoryIndex = array();
            $locationNode_profiles = DH::findFirstElement('profiles', $locationNode);
            if( $locationNode_profiles !== FALSE )
                $this->checkRemoveDuplicateMembers( $locationNode_profiles, $locationName, 'custom-url-category', $customURLcategory, $customURLcategoryIndex, $totalCustomUrlCategoryFixed );

            //
            //
            //
            //
            //
            //


            $objectTypeNode_array_rulebase['rulebase'] = DH::findFirstElement('rulebase', $locationNode);
            $objectTypeNode_array_rulebase['pre-rulebase'] = DH::findFirstElement('pre-rulebase', $locationNode);
            $objectTypeNode_array_rulebase['post-rulebase'] = DH::findFirstElement('post-rulebase', $locationNode);

            //Todo: missing part: pre-rulebase / post-rulebase
            foreach( $objectTypeNode_array_rulebase as $key => $objectTypeNode_rulebase )
            {
                $secRules = array();
                $secRuleIndex = array();
                $natRules = array();
                $natRuleIndex = array();
                $secRuleSourceIndex = array();
                $secRuleDestinationIndex = array();
                $secRuleServiceIndex = array();
                $secRuleApplicationIndex = array();
                $secRuleCategoryIndex = array();
                $secRuleServiceAppDefaultIndex = array();
                $secRuleFromIndex = array();
                $secRuleToIndex = array();

                $secRuleSourceUserIndex = array();

                $natRuleSourceIndex = array();
                $natRuleDestinationIndex = array();

                if( $objectTypeNode_rulebase !== FALSE )
                {
                    PH::print_stdout( "");
                    PH::print_stdout( "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####");

                    PH::print_stdout( "[".$key."]");

                    foreach( $objectTypeNode_rulebase->childNodes as $objectNode_ruletype )
                    {
                        if( $objectNode_ruletype->nodeName == "security" )
                        {
                            $objectTypeNode = DH::findFirstElement('rules', $objectNode_ruletype);
                            if( $objectTypeNode !== FALSE )
                            {
                                foreach( $objectTypeNode->childNodes as $objectNode )
                                {
                                    $secRuleServices = array();
                                    $secRuleApplication = array();
                                    $secRuleSource = array();
                                    $secRuleDestination = array();
                                    $secRuleFrom = array();
                                    $secRuleTo = array();
                                    $secRuleCategory = array();
                                    $secRuleTags = array();
                                    $secRuleSourceUser = array();

                                    /** @var DOMElement $objectNode */
                                    if( $objectNode->nodeType != XML_ELEMENT_NODE )
                                        continue;

                                    $objectName = $objectNode->getAttribute('name');

                                    $this->check_name( $objectName, $objectNode, $secrule_name );
                                    $this->check_wrong_name( $objectName, $objectNode, $secrule_wrong_name );

                                    $secRules[$objectName][] = $objectNode;

                                    if( !isset($secRuleIndex[$objectName]) )
                                        $secRuleIndex[$objectName] = array('regular' => array(), 'group' => array());

                                    $secRuleIndex[$objectName]['regular'][] = $objectNode;

                                    //Todo:
                                    //check if service has 'application-default' and additional
                                    $objectNode_services = DH::findFirstElement('service', $objectNode);
                                    $demo = iterator_to_array($objectNode_services->childNodes);
                                    foreach( $demo as $objectService )
                                    {
                                        /** @var DOMElement $objectService */
                                        if( $objectService->nodeType != XML_ELEMENT_NODE )
                                            continue;

                                        $objectServiceName = $objectService->textContent;
                                        if( isset($secRuleServices[$objectServiceName]) )
                                        {
                                            //Secrule service has twice same service added
                                            $text = "     - Secrule: ".$objectName." has same service defined twice: ".$objectServiceName;
                                            $objectNode_services->removeChild($objectService);
                                            $text .= PH::boldText(" (removed - no manual fix needed)");
                                            PH::print_stdout( $text );
                                            $fixedSecRuleServiceObjects++;
                                        }
                                        else
                                            $secRuleServices[$objectServiceName] = $objectService;
                                    }
                                    if( isset($secRuleServices['application-default'])  )
                                    {
                                        if( count($secRuleServices) > 1 )
                                        {
                                            $secRuleServiceIndex[$objectName] = $secRuleServices['application-default'];
                                            #PH::print_stdout( "     - Rule: '" . $objectName . "' has service application-default + something else defined.");
                                            #print_r($secRuleServices);
                                        }
                                        else
                                        {
                                            $secRuleServiceAppDefaultIndex[$objectName] = $secRuleServices['application-default'];
                                        }

                                    }


                                    $objectNode_tags = DH::findFirstElement('tag', $objectNode);
                                    if( $objectNode_tags !== false )
                                    {
                                        $demo = iterator_to_array($objectNode_tags->childNodes);
                                        foreach( $demo as $objectTag )
                                        {
                                            /** @var DOMElement $objectTag */
                                            if( $objectTag->nodeType != XML_ELEMENT_NODE )
                                                continue;

                                            $objectTagName = $objectTag->textContent;
                                            if( isset($secRuleTags[$objectTagName]) )
                                            {
                                                //Secrule service has twice same service added
                                                $text = "     - Secrule: ".$objectName." has same tag defined twice: ".$objectTagName;
                                                $objectNode_tags->removeChild($objectTag);
                                                $text .= PH::boldText(" (removed - no manual fix needed)");
                                                PH::print_stdout( $text );
                                                $fixedSecRuleTagObjects++;
                                            }
                                            else
                                                $secRuleTags[$objectTagName] = $objectTag;
                                        }
                                    }

                                    //check if application has 'any' adn additional
                                    $objectNode_applications = DH::findFirstElement('application', $objectNode);
                                    $demo = iterator_to_array($objectNode_applications->childNodes);
                                    foreach( $demo as $objectApplication )
                                    {
                                        /** @var DOMElement $objectApplication */
                                        if( $objectApplication->nodeType != XML_ELEMENT_NODE )
                                            continue;

                                        $objectApplicationName = $objectApplication->textContent;
                                        if( isset($secRuleApplication[$objectApplicationName]) )
                                        {
                                            $text = "     - Secrule: ".$objectName." has same application defined twice: ".$objectApplicationName;
                                            $objectNode_applications->removeChild($objectApplication);
                                            $text .=PH::boldText(" (removed)")."\n";
                                            PH::print_stdout( $text );
                                            $fixedSecRuleApplicationObjects++;
                                        }
                                        else
                                            $secRuleApplication[$objectApplicationName] = $objectApplication;
                                    }
                                    if( isset($secRuleApplication['any']) and count($secRuleApplication) > 1 )
                                    {
                                        $secRuleApplicationIndex[$objectName] = $secRuleApplication['any'];
                                        #PH::print_stdout( "     - Rule: '".$objectName."' has application 'any' + something else defined.\n" ;
                                    }

                                    $objectNode_category = DH::findFirstElement('category', $objectNode);
                                    if( $objectNode_category && !$objectNode_category->hasChildNodes() )
                                    {
                                        #$secRuleCategoryIndex[$objectName] = $objectNode_category;
                                    }
                                    elseif( $objectNode_category !== FALSE )
                                    {
                                        //Todo: swaschkut 20230627
                                        //check if Category has 'any' and additional
                                        $demo = iterator_to_array($objectNode_category->childNodes);
                                        foreach( $demo as $objectCategory )
                                        {
                                            /** @var DOMElement $objectCategory */
                                            if( $objectCategory->nodeType != XML_ELEMENT_NODE )
                                                continue;

                                            $objectCategoryName = $objectCategory->textContent;
                                            if( isset($secRuleCategory[$objectCategoryName]) )
                                            {
                                                $text = "     - Secrule: ".$objectName." has same category defined twice: ".$objectCategoryName;
                                                $objectNode_category->removeChild($objectCategory);
                                                $text .=PH::boldText(" (removed)");
                                                PH::print_stdout( $text );
                                                $fixedSecRuleCategoryObjects++;
                                            }
                                            else
                                            {
                                                $secRuleCategory[$objectCategoryName] = $objectCategory;
                                                #PH::print_stdout( $objectName.'add to array: '.$objectSourceName );
                                            }

                                        }
                                        if( isset($secRuleCategory['any']) and count($secRuleCategory) > 1 )
                                        {
                                            $secRuleCategoryIndex[$objectName] = $secRuleCategory['any'];
                                            #PH::print_stdout( "     - Rule: '".$objectName."' has category 'any' + something else defined." );
                                        }
                                    }

                                    //check if source has 'any' and additional
                                    $objectNode_sources = DH::findFirstElement('source', $objectNode);
                                    $demo = iterator_to_array($objectNode_sources->childNodes);
                                    foreach( $demo as $objectSource )
                                    {
                                        /** @var DOMElement $objectSource */
                                        if( $objectSource->nodeType != XML_ELEMENT_NODE )
                                            continue;

                                        $objectSourceName = $objectSource->textContent;
                                        if( isset($secRuleSource[$objectSourceName]) )
                                        {
                                            $text = "     - Secrule: ".$objectName." has same source defined twice: ".$objectSourceName;
                                            $objectNode_sources->removeChild($objectSource);
                                            $text .=PH::boldText(" (removed)");
                                            PH::print_stdout( $text );
                                            $fixedSecRuleSourceObjects++;
                                        }
                                        else
                                        {
                                            $secRuleSource[$objectSourceName] = $objectSource;
                                            #PH::print_stdout( $objectName.'add to array: '.$objectSourceName );
                                        }

                                    }
                                    if( isset($secRuleSource['any']) and count($secRuleSource) > 1 )
                                    {
                                        $secRuleSourceIndex[$objectName] = $secRuleSource['any'];
                                        PH::print_stdout( "     - Rule: '".$objectName."' has source 'any' + something else defined." );
                                    }

                                    //check if destination has 'any' and additional
                                    $objectNode_destinations = DH::findFirstElement('destination', $objectNode);
                                    $demo = iterator_to_array($objectNode_destinations->childNodes);
                                    foreach( $demo as $objectDestination )
                                    {
                                        /** @var DOMElement $objectDestination */
                                        if( $objectDestination->nodeType != XML_ELEMENT_NODE )
                                            continue;

                                        $objectDestinationName = $objectDestination->textContent;
                                        #PH::print_stdout( "rule: ".$objectName." name: ".$objectDestinationName);
                                        if( isset($secRuleDestination[$objectDestinationName]) )
                                        {
                                            $text = "     - Secrule: ".$objectName." has same destination defined twice: ".$objectDestinationName;
                                            $objectNode_destinations->removeChild($objectDestination);
                                            $text .= PH::boldText(" (removed)")."\n";
                                            PH::print_stdout( $text );
                                            $fixedSecRuleDestinationObjects++;
                                        }
                                        else
                                            $secRuleDestination[$objectDestinationName] = $objectDestination;
                                    }

                                    if( isset($secRuleDestination['any']) and count($secRuleDestination) > 1 )
                                    {
                                        $secRuleDestinationIndex[$objectName] = $secRuleDestination['any'];
                                        #PH::print_stdout( "     - Rule: '".$objectName."' has application 'any' + something else defined.") ;
                                    }

                                    //check if from has 'any' and additional
                                    $objectNode_froms = DH::findFirstElement('from', $objectNode);
                                    $demo = iterator_to_array($objectNode_froms->childNodes);
                                    foreach( $demo as $objectFrom )
                                    {
                                        /** @var DOMElement $objectFrom */
                                        if( $objectFrom->nodeType != XML_ELEMENT_NODE )
                                            continue;

                                        $objectFromName = $objectFrom->textContent;
                                        #PH::print_stdout( "rule: ".$objectName." name: ".$objectDestinationName);
                                        if( isset($secRuleFrom[$objectFromName]) )
                                        {
                                            $text = "     - Secrule: ".$objectName." has same from defined twice: ".$objectFromName;
                                            $objectNode_froms->removeChild($objectFrom);
                                            $text .= PH::boldText(" (removed)")."\n";
                                            PH::print_stdout( $text );
                                            $fixedSecRuleFromObjects++;
                                        }
                                        else
                                            $secRuleFrom[$objectFromName] = $objectFrom;
                                    }

                                    if( isset($secRuleFrom['any']) and count($secRuleFrom) > 1 )
                                    {
                                        $secRuleFromIndex[$objectName] = $secRuleFrom['any'];
                                        #PH::print_stdout( "     - Rule: '".$objectName."' has application 'any' + something else defined.") ;
                                    }

                                    //check if from has 'any' and additional
                                    $objectNode_tos = DH::findFirstElement('to', $objectNode);
                                    $demo = iterator_to_array($objectNode_tos->childNodes);
                                    foreach( $demo as $objectTo )
                                    {
                                        /** @var DOMElement $objectTo */
                                        if( $objectTo->nodeType != XML_ELEMENT_NODE )
                                            continue;

                                        $objectToName = $objectTo->textContent;
                                        #PH::print_stdout( "rule: ".$objectName." name: ".$objectDestinationName);
                                        if( isset($secRuleTo[$objectToName]) )
                                        {
                                            $text = "     - Secrule: ".$objectName." has same to defined twice: ".$objectToName;
                                            $objectNode_tos->removeChild($objectTo);
                                            $text .= PH::boldText(" (removed)")."\n";
                                            PH::print_stdout( $text );
                                            $fixedSecRuleToObjects++;
                                        }
                                        else
                                            $secRuleTo[$objectToName] = $objectTo;
                                    }

                                    if( isset($secRuleTo['any']) and count($secRuleTo) > 1 )
                                    {
                                        $secRuleToIndex[$objectName] = $secRuleTo['any'];
                                        #PH::print_stdout( "     - Rule: '".$objectName."' has application 'any' + something else defined.") ;
                                    }

                                    //check if source-user has 'any' and additional
                                    $objectNode_source_users = DH::findFirstElement('source-user', $objectNode);
                                    if( $objectNode_source_users !== False )
                                    {
                                        $demo = iterator_to_array($objectNode_source_users->childNodes);
                                        foreach( $demo as $objectSourceUser )
                                        {
                                            /** @var DOMElement $objectSourceUser */
                                            if( $objectSourceUser->nodeType != XML_ELEMENT_NODE )
                                                continue;

                                            $objectSourceUserName = $objectSourceUser->textContent;
                                            #PH::print_stdout( "rule: ".$objectName." name: ".$objectDestinationName);
                                            if( isset($secRuleSourceUser[$objectSourceUserName]) )
                                            {
                                                $text = "     - Secrule: ".$objectName." has same source-user defined twice: ".$objectSourceUserName;
                                                $objectNode_source_users->removeChild($objectSourceUser);
                                                $text .= PH::boldText(" (removed)")."\n";
                                                PH::print_stdout( $text );
                                                $fixedSecruleSourceUserObjects++;
                                            }
                                            else
                                                $secRuleSourceUser[$objectSourceUserName] = $objectSourceUser;
                                        }

                                        if( isset($secRuleSourceUser['any']) and count($secRuleSourceUser) > 1 )
                                        {
                                            $secRuleSourceUserIndex[$objectName] = $secRuleSourceUser['any'];
                                        }
                                    }

                                }

                            }

                            PH::print_stdout( " - parsed " . count($secRules) . " Security Rules");
                            PH::print_stdout( "");
                        }

                        elseif( $objectNode_ruletype->nodeName == "nat" )
                        {

                            $objectTypeNode = DH::findFirstElement('rules', $objectNode_ruletype);
                            if( $objectTypeNode !== FALSE )
                            {
                                foreach( $objectTypeNode->childNodes as $objectNode )
                                {
                                    $natRuleSource = array();
                                    $natRuleDestination = array();

                                    /** @var DOMElement $objectNode */
                                    if( $objectNode->nodeType != XML_ELEMENT_NODE )
                                        continue;

                                    $objectName = $objectNode->getAttribute('name');

                                    $this->check_name( $objectName, $objectNode, $natrule_name );
                                    $this->check_name( $objectName, $objectNode, $natrule_wrong_name );

                                    $natRules[$objectName][] = $objectNode;

                                    if( !isset($natRuleIndex[$objectName]) )
                                        $natRuleIndex[$objectName] = array('regular' => array(), 'group' => array());

                                    $natRuleIndex[$objectName]['regular'][] = $objectNode;


                                    //check if source has 'any' and additional
                                    $objectNode_sources = DH::findFirstElement('source', $objectNode);
                                    $demo = iterator_to_array($objectNode_sources->childNodes);
                                    foreach( $demo as $objectSource )
                                    {
                                        /** @var DOMElement $objectSource */
                                        if( $objectSource->nodeType != XML_ELEMENT_NODE )
                                            continue;

                                        $objectSourceName = $objectSource->textContent;
                                        if( isset($natRuleSource[$objectSourceName]) )
                                        {
                                            $text = "     - Secrule: ".$objectName." has same source defined twice: ".$objectSourceName;
                                            $objectNode_sources->removeChild($objectSource);
                                            $text .=PH::boldText(" (removed)");
                                            PH::print_stdout( $text );
                                            $fixedNatRuleSourceObjects++;
                                        }
                                        else
                                        {
                                            $natRuleSource[$objectSourceName] = $objectSource;
                                            #PH::print_stdout( $objectName.'add to array: '.$objectSourceName );
                                        }

                                    }
                                    if( isset($natRuleSource['any']) and count($natRuleSource) > 1 )
                                    {
                                        $natRuleSourceIndex[$objectName] = $natRuleSource['any'];
                                        PH::print_stdout( "     - Rule: '".$objectName."' has source 'any' + something else defined." );
                                    }

                                    //check if destination has 'any' and additional
                                    $objectNode_destinations = DH::findFirstElement('destination', $objectNode);
                                    $demo = iterator_to_array($objectNode_destinations->childNodes);
                                    foreach( $demo as $objectDestination )
                                    {
                                        /** @var DOMElement $objectDestination */
                                        if( $objectDestination->nodeType != XML_ELEMENT_NODE )
                                            continue;

                                        $objectDestinationName = $objectDestination->textContent;
                                        #PH::print_stdout( "rule: ".$objectName." name: ".$objectDestinationName);
                                        if( isset($natRuleDestination[$objectDestinationName]) )
                                        {
                                            $text = "     - Secrule: ".$objectName." has same destination defined twice: ".$objectDestinationName;
                                            $objectNode_destinations->removeChild($objectDestination);
                                            $text .= PH::boldText(" (removed)")."\n";
                                            PH::print_stdout( $text );
                                            $fixedNatRuleDestinationObjects++;
                                        }
                                        else
                                            $natRuleDestination[$objectDestinationName] = $objectDestination;
                                    }

                                    if( isset($natRuleDestination['any']) and count($natRuleDestination) > 1 )
                                    {
                                        $natRuleDestinationIndex[$objectName] = $natRuleDestination['any'];
                                        #PH::print_stdout( "     - Rule: '".$objectName."' has application 'any' + something else defined.") ;
                                    }

                                }

                            }


                            PH::print_stdout( " - parsed " . count($natRules) . " NAT Rules");
                            PH::print_stdout( "");
                        }

                    }

                    //
                    //
                    //
                    PH::print_stdout( " - Scanning for Security Rules with double spaces in name...");
                    foreach( $secrule_name as $objectName => $node )
                    {
                        PH::print_stdout( "    - Security Rules object '{$objectName}' from DG/VSYS {$locationName} has '  ' double Spaces in name, this causes problems by copy&past 'set commands' ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}");
                        $countSecRuleObjectsWithDoubleSpaces++;
                    }

                    PH::print_stdout( " - Scanning for Security Rules with wrong characters in name...");
                    foreach( $secrule_wrong_name as $objectName => $node )
                    {
                        PH::print_stdout( "    - Security Rules object '{$objectName}' from DG/VSYS {$locationName} has wrong characters in name ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}");
                        $countSecRuleObjectsWithWrongCharacters++;
                    }

                    PH::print_stdout( " - Scanning for duplicate Security Rules...");
                    foreach( $secRuleIndex as $objectName => $objectNodes )
                    {
                        $dupCount = count($objectNodes['regular']) + count($objectNodes['group']);

                        if( $dupCount < 2 )
                            continue;

                        PH::print_stdout( "   - found Security Rule named '{$objectName}' that exists " . $dupCount . " time:");

                        $tmp_secrule_array = array();
                        foreach( $objectNodes['regular'] as $objectNode )
                        {

                            /** @var DOMElement $objectNode */
                            $text = "       - type 'Security Rules' at XML line #{$objectNode->getLineNo()}";

                            $newName = $key . $objectNode->getAttribute('name');
                            if( !isset($secRuleIndex[$newName]) )
                            {
                                $objectNode->setAttribute('name', $newName);
                                $text .= PH::boldText(" - new name: " . $newName . " (fixed)");
                                PH::print_stdout( $text );
                            }
                            else
                            {
                                $text .= " - Rulename can not be fixed: '" . $newName . "' is also available";
                                PH::print_stdout( $text );
                            }


                            $countDuplicateSecRuleObjects++;
                        }
                    }

                    //
                    //
                    //
                    PH::print_stdout( " - Scanning for NAT Rules with double spaces in name...");
                    foreach( $natrule_name as $objectName => $node )
                    {
                        PH::print_stdout( "    - NAT Rules object '{$objectName}' from DG/VSYS {$locationName} has '  ' double Spaces in name, this causes problems by copy&past 'set commands' ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}");
                        $countNATRuleObjectsWithDoubleSpaces++;
                    }
                    PH::print_stdout( " - Scanning for NAT Rules with wrong characters in name...");
                    foreach( $natrule_wrong_name as $objectName => $node )
                    {
                        PH::print_stdout( "    - NAT Rules object '{$objectName}' from DG/VSYS {$locationName} has wrong characters in name ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}");
                        $countNATRuleObjectsWithWrongCharacters++;
                    }

                    PH::print_stdout( "\n - Scanning for duplicate NAT Rules...");
                    foreach( $natRuleIndex as $objectName => $objectNodes )
                    {
                        $dupCount = count($objectNodes['regular']) + count($objectNodes['group']);

                        if( $dupCount < 2 )
                            continue;

                        PH::print_stdout( "   - found NAT Rule named '{$objectName}' that exists " . $dupCount . " time:");
                        $tmp_natrule_array = array();
                        foreach( $objectNodes['regular'] as $key => $objectNode )
                        {

                            /** @var DOMElement $objectNode */
                            $text = "       - type 'NAT Rules' at XML line #{$objectNode->getLineNo()}";


                            $newName = $key . $objectNode->getAttribute('name');
                            if( !isset($natRuleIndex[$newName]) )
                            {
                                $objectNode->setAttribute('name', $newName);
                                $text .= PH::boldText(" - new name: " . $newName . " (fixed)\n");
                                PH::print_stdout( $text );
                            }
                            else
                            {
                                $text .= " - Rulename can not be fixed: '" . $newName . "' is also available";
                                PH::print_stdout( $text );
                            }


                            $countDuplicateNATRuleObjects++;
                        }
                    }

                    PH::print_stdout( "\n - Scanning for missconfigured From Field in Security Rules...");
                    foreach( $secRuleFromIndex as $objectName => $objectNode )
                    {
                        PH::print_stdout( "   - found Security Rule named '{$objectName}' that has from 'any' and additional from configured at XML line #{$objectNode->getLineNo()}");
                        $countMissconfiguredSecRuleFromObjects++;
                    }

                    PH::print_stdout( " - Scanning for missconfigured To Field in Security Rules...");
                    foreach( $secRuleToIndex as $objectName => $objectNode )
                    {
                        PH::print_stdout( "   - found Security Rule named '{$objectName}' that has to 'any' and additional to configured at XML line #{$objectNode->getLineNo()}");
                        $countMissconfiguredSecRuleToObjects++;
                    }

                    PH::print_stdout( "\n - Scanning for missconfigured Source Field in Security Rules...");
                    foreach( $secRuleSourceIndex as $objectName => $objectNode )
                    {
                        PH::print_stdout( "   - found Security Rule named '{$objectName}' that has source 'any' and additional source configured at XML line #{$objectNode->getLineNo()}");
                        $countMissconfiguredSecRuleSourceObjects++;
                    }

                    PH::print_stdout( " - Scanning for missconfigured Destination Field in Security Rules...");
                    foreach( $secRuleDestinationIndex as $objectName => $objectNode )
                    {
                        PH::print_stdout( "   - found Security Rule named '{$objectName}' that has destination 'any' and additional destination configured at XML line #{$objectNode->getLineNo()}");
                        $countMissconfiguredSecRuleDestinationObjects++;
                    }

                    PH::print_stdout( " - Scanning for missconfigured Service Field in Security Rules...");
                    foreach( $secRuleServiceIndex as $objectName => $objectNode )
                    {
                        PH::print_stdout( "   - found Security Rule named '{$objectName}' that has service 'application-default' and an additional service configured at XML line #{$objectNode->getLineNo()}");
                        $countMissconfiguredSecRuleServiceObjects++;
                    }


                    PH::print_stdout( " - Scanning for missconfigured Application Field in Security Rules...");
                    foreach( $secRuleApplicationIndex as $objectName => $objectNode )
                    {
                        PH::print_stdout( "   - found Security Rule named '{$objectName}' that has application 'any' and additional application configured at XML line #{$objectNode->getLineNo()}");
                        $countMissconfiguredSecRuleApplicationObjects++;
                    }

                    PH::print_stdout( " - Scanning for missconfigured Category Field in Security Rules...");
                    foreach( $secRuleCategoryIndex as $objectName => $objectNode )
                    {
                        #PH::print_stdout( "   - found Security Rule named '{$objectName}' that has XML element 'category' but not child element 'member' configured at XML line #{$objectNode->getLineNo()}");
                        PH::print_stdout( "   - found Security Rule named '{$objectName}' that has category 'any' and additional category configured at XML line #{$objectNode->getLineNo()}");
                        $countMissconfiguredSecRuleCategoryObjects++;
                    }

                    PH::print_stdout( " - Scanning for missconfigured SourceUser Field in Security Rules...");
                    foreach( $secRuleSourceUserIndex as $objectName => $objectNode )
                    {
                        PH::print_stdout( "   - found Security Rule named '{$objectName}' that has source-user 'any' and additional source-user configured at XML line #{$objectNode->getLineNo()}");
                        $countMissconfiguredSecruleSourceUserObjects++;
                    }

                    PH::print_stdout( "\n - Scanning for missconfigured Source Field in NAT Rules...");
                    foreach( $natRuleSourceIndex as $objectName => $objectNode )
                    {
                        PH::print_stdout( "   - found NAT Rule named '{$objectName}' that has source 'any' and additional source configured at XML line #{$objectNode->getLineNo()}");
                        $countMissconfiguredNatRuleSourceObjects++;
                    }

                    PH::print_stdout( " - Scanning for missconfigured Destination Field in NAT Rules...");
                    foreach( $natRuleDestinationIndex as $objectName => $objectNode )
                    {
                        PH::print_stdout( "   - found NAT Rule named '{$objectName}' that has destination 'any' and additional destination configured at XML line #{$objectNode->getLineNo()}");
                        $countMissconfiguredNatRuleDestinationObjects++;
                    }

                    if( $service_app_default_available )
                    {
                        PH::print_stdout( " - Scanning for Security Rules with 'application-default' set | service object 'application-default' is available ...");
                        foreach( $secRuleServiceAppDefaultIndex as $objectName => $objectNode )
                        {
                            PH::print_stdout( "   - found Security Rule named '{$objectName}' that is using SERVICE OBJECT at XML line #{$objectNode->getLineNo()}");
                            $countMissconfiguredSecRuleServiceAppDefaultObjects++;
                        }
                    }
                }
            }


            ///config/readonly/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='mn053-mnr-int']/address-group
            ///
            ///
            PH::print_stdout( " - Scanning for /config/readonly/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='".$locationName."'] for duplicate address-group ...");
            $tmpReadOnly = DH::findXPath("/config/readonly/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='".$locationName."']", $this->xmlDoc);
            $readOnly = array();

            foreach( $tmpReadOnly as $node )
                $readOnly[] = $node;

            $readonlyDGAddressgroups = array();

            if( isset( $readOnly[0] ) )
            {
                $readonlyAddressgroups = DH::findFirstElement('address-group', $readOnly[0]);
                if( $readonlyAddressgroups !== false )
                    $demo = iterator_to_array($readonlyAddressgroups->childNodes);
                else
                    $demo = array();
            }
            else
                $demo = array();

            foreach( $demo as $objectAddressGroup )
            {
                /** @var DOMElement $objectApplication */
                if( $objectAddressGroup->nodeType != XML_ELEMENT_NODE )
                    continue;

                $objectAddressGroupName = $objectAddressGroup->getAttribute('name');
                if( isset($readonlyDGAddressgroups[$objectAddressGroupName]) )
                {
                    $text = "     - readOnly DG: ".$locationName." has same addressgroup defined twice: ".$objectAddressGroupName;
                    $readonlyAddressgroups->removeChild($objectAddressGroup);
                    $text .= PH::boldText(" (removed)");
                    PH::print_stdout($text);
                    $fixedReadOnlyAddressGroupobjects++;
                }
                else
                    $readonlyDGAddressgroups[$objectAddressGroupName] = $objectAddressGroup;
            }


            //
            //
            //
            //
            //
            //


            $objectTypeNode = DH::findFirstElement('zone', $locationNode);
            if( $objectTypeNode !== FALSE )
            {
                foreach( $objectTypeNode->childNodes as $objectNode )
                {
                    /** @var DOMElement $objectNode */
                    if( $objectNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $objectName = $objectNode->getAttribute('name');

                    $zoneObjects[$objectName][] = $objectNode;

                    if( !isset($zoneIndex[$objectName]) )
                        $zoneIndex[$objectName] = array('regular' => array(), 'group' => array());

                    $zoneIndex[$objectName]['regular'][] = $objectNode;
                }

            }

            PH::print_stdout( "");
            PH::print_stdout( "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####");
            PH::print_stdout( " - parsed " . count($zoneObjects) . " zone objects");
            PH::print_stdout( "");

            //
            //
            //
            PH::print_stdout( " - Scanning for zones with wrong zone type (e.g. Layer3 instead of layer3 - case sensitive - Expedition issue?)...");
            foreach( $zoneObjects as $objectName => $nodes )
            {
                foreach( $nodes as $node )
                {
                    $zone_network = DH::findFirstElement('network', $node);
                    if( $zone_network !== FALSE )
                    {
                        foreach( $zone_network->childNodes as $key => $zone_type )
                        {
                            /** @var DOMElement $objectNode */
                            if( $zone_type->nodeType != XML_ELEMENT_NODE )
                                continue;

                            $str = $zone_type->nodeName;

                            if( preg_match_all('/[A-Z][^A-Z]*/', $str, $results) )
                            {
                                if( isset($results[0][0]) )
                                {
                                    PH::print_stdout("       - type 'Zone' name: '" . $node->getAttribute('name') . "' - '" . $results[0][0] . "' at XML line #{$zone_type->getLineNo()} (*FIX_MANUALLY*)");
                                }
                            }
                        }
                    }
                }
            }

            PH::print_stdout( "** ** ** ** ** ** **");
        }


        PH::print_stdout( "");
        PH::print_stdout( "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####");
///
///
///
        PH::print_stdout( " - Scanning for /config/readonly/shared for duplicate address-group ...");
        $tmpReadOnly = DH::findXPath("/config/readonly/shared", $this->xmlDoc);
        $readOnly = array();

        foreach( $tmpReadOnly as $node )
            $readOnly[] = $node;

        $readonlyDGAddressgroups = array();

        if( isset( $readOnly[0] ) )
        {
            $readonlyAddressgroups = DH::findFirstElement('address-group', $readOnly[0]);
            if( $readonlyAddressgroups !== false )
                $demo = iterator_to_array($readonlyAddressgroups->childNodes);
            else
                $demo = array();
        }
        else
            $demo = array();

        foreach( $demo as $objectAddressGroup )
        {
            /** @var DOMElement $objectApplication */
            if( $objectAddressGroup->nodeType != XML_ELEMENT_NODE )
                continue;

            $objectAddressGroupName = $objectAddressGroup->getAttribute('name');
            if( isset($readonlyDGAddressgroups[$objectAddressGroupName]) )
            {
                $text = "     - readOnly shared has same addressgroup defined twice: ".$objectAddressGroupName;
                $readonlyAddressgroups->removeChild($objectAddressGroup);
                $text .=PH::boldText(" (removed)");
                PH::print_stdout($text);
                $fixedReadOnlyAddressGroupobjects++;
            }
            else
                $readonlyDGAddressgroups[$objectAddressGroupName] = $objectAddressGroup;
        }

        ////////////////////////////////////////////////////////////
        ///config/readonly/devices/entry[@name='localhost.localdomain']/device-group

        PH::print_stdout( " - Scanning for config/readonly/devices/entry[@name='localhost.localdomain'] for duplicate devicegroup ...");
        $tmpReadOnly = DH::findXPath("/config/readonly/devices/entry[@name='localhost.localdomain']", $this->xmlDoc);
        $readOnly = array();

        foreach( $tmpReadOnly as $node )
            $readOnly[] = $node;

        $readonlyDeviceGroupsArray = array();

        if( isset( $readOnly[0] ) )
        {
            $readonlyDeviceGroups = DH::findFirstElement('device-group', $readOnly[0]);
            if( $readonlyDeviceGroups !== false )
                $demo = iterator_to_array($readonlyDeviceGroups->childNodes);
            else
                $demo = array();
        }
        else
            $demo = array();

        foreach( $demo as $objectDeviceGroup )
        {
            /** @var DOMElement $objectDeviceGroup */
            if( $objectDeviceGroup->nodeType != XML_ELEMENT_NODE )
                continue;

            $objectDeviceGroupName = $objectDeviceGroup->getAttribute('name');
            if( isset($readonlyDeviceGroupsArray[$objectDeviceGroupName]) )
            {
                $text = "     - readOnly /config/readonly/devices/entry[@name='localhost.localdomain']/device-group has same DeviceGroup defined twice: ".$objectDeviceGroupName;
                $readonlyDeviceGroups->removeChild($objectDeviceGroup);
                $text .=PH::boldText(" (removed)");
                PH::print_stdout($text);
                $fixedReadOnlyDeviceGroupobjects++;
            }
            else
                $readonlyDeviceGroupsArray[$objectDeviceGroupName] = $objectDeviceGroup;
        }


        ////////////////////////////////////////////////////////////
        ///config/readonly/devices/entry[@name='localhost.localdomain']/template

        PH::print_stdout( " - Scanning for config/readonly/devices/entry[@name='localhost.localdomain'] for duplicate template ...");
        $tmpReadOnly = DH::findXPath("/config/readonly/devices/entry[@name='localhost.localdomain']", $this->xmlDoc);
        $readOnly = array();

        foreach( $tmpReadOnly as $node )
            $readOnly[] = $node;

        $readonlyTemplatesArray = array();

        if( isset( $readOnly[0] ) )
        {
            $readonlyTemplates = DH::findFirstElement('template', $readOnly[0]);
            if( $readonlyTemplates !== false )
                $demo = iterator_to_array($readonlyTemplates->childNodes);
            else
                $demo = array();
        }
        else
            $demo = array();

        foreach( $demo as $objectTemplate )
        {
            /** @var DOMElement $objectTemplate */
            if( $objectTemplate->nodeType != XML_ELEMENT_NODE )
                continue;

            $objectTemplateName = $objectTemplate->getAttribute('name');
            if( isset($readonlyTemplatesArray[$objectTemplateName]) )
            {
                $text = "     - readOnly /config/readonly/devices/entry[@name='localhost.localdomain']/template has same Template defined twice: ".$objectTemplateName;
                $readonlyTemplates->removeChild($objectTemplate);
                $text .=PH::boldText(" (removed)");
                PH::print_stdout($text);
                $fixedReadOnlyTemplateobjects++;
            }
            else
                $readonlyTemplatesArray[$objectTemplateName] = $objectTemplate;
        }


        ////////////////////////////////////////////////////////////
        ///config/readonly/devices/entry[@name='localhost.localdomain']/template-stack

        PH::print_stdout( " - Scanning for config/readonly/devices/entry[@name='localhost.localdomain'] for duplicate template-stack ...");
        $tmpReadOnly = DH::findXPath("/config/readonly/devices/entry[@name='localhost.localdomain']", $this->xmlDoc);
        $readOnly = array();

        foreach( $tmpReadOnly as $node )
            $readOnly[] = $node;

        $readonlyTemplateStacksArray = array();

        if( isset( $readOnly[0] ) )
        {
            $readonlyTemplateStacks = DH::findFirstElement('template-stack', $readOnly[0]);
            if( $readonlyTemplateStacks !== false )
                $demo = iterator_to_array($readonlyTemplateStacks->childNodes);
            else
                $demo = array();
        }
        else
            $demo = array();

        foreach( $demo as $objectTemplateStack )
        {
            /** @var DOMElement $objectTemplateStack */
            if( $objectTemplateStack->nodeType != XML_ELEMENT_NODE )
                continue;

            $objectTemplateStackName = $objectTemplateStack->getAttribute('name');
            if( isset($readonlyTemplateStacksArray[$objectTemplateStackName]) )
            {
                $text = "     - readOnly /config/readonly/devices/entry[@name='localhost.localdomain']/template-stack has same Template-Stack defined twice: ".$objectTemplateName;
                $readonlyTemplateStacks->removeChild($objectTemplateStack);
                $text .=PH::boldText(" (removed)");
                PH::print_stdout($text);
                $fixedReadOnlyTemplateStackobjects++;
            }
            else
                $readonlyTemplateStacksArray[$objectTemplateStackName] = $objectTemplateStack;
        }


        PH::print_stdout( "");
        PH::print_stdout( "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####");

        ////////////////////////////////////////////////////////////
        ///scanning for all import/network/interfaces

        PH::print_stdout( " - Scanning for import/network/interface for duplicate entries ...");

        $nodeList = $this->xmlDoc->getElementsByTagName("import");
        $nodeArray = iterator_to_array($nodeList);

        foreach( $nodeArray as $item )
        {
            $network = DH::findFirstElement("network", $item);
            if( $network !== FALSE )
            {
                $interfaces = DH::findFirstElement("interface", $network);

                if( $interfaces !== FALSE )
                {
                    $interfaceArray = array();
                    foreach( $interfaces->childNodes as $interface )
                    {
                        /** @var DOMElement $interface */
                        if( $interface->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $interfaceName = $interface->textContent;
                        if( isset($interfaceArray[$interfaceName]) )
                        {
                            $xpath = $interface->getNodePath();
                            //remove node
                            PH::print_stdout( "    - remove interface: '<member>".$interfaceName."</member>' from xPath: '".$xpath."' as it is a duplicate entry ... *FIXED*");
                            $interface->parentNode->removeChild($interface);
                            $fixedImportNetworkInterfaceWithSameInterface++;
                        }
                        else
                            $interfaceArray[$interfaceName] = $interfaceName;
                    }
                }
            }
        }
        ////////////////////////////////////////////////////////////
        PH::print_stdout( "");
        PH::print_stdout( "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####");
        PH::print_stdout();

        PH::print_stdout( "Summary:" );
        if( $fixedDuplicateAddressObjects > 0 )
            PH::print_stdout( " - FIXED: duplicate address objects: {$fixedDuplicateAddressObjects}");
        if( $fixedDuplicateServiceObjects > 0 )
            PH::print_stdout( " - FIXED: duplicate service objects: {$fixedDuplicateServiceObjects}");

        if( $totalAddressGroupsFixed > 0 )
            PH::print_stdout( "\n - FIXED: duplicate address-group members: {$totalAddressGroupsFixed}");
        if( $totalServiceGroupsFixed > 0 )
            PH::print_stdout( " - FIXED: duplicate service-group members: {$totalServiceGroupsFixed}");
        if( $totalAddressGroupsSubGroupFixed > 0 )
            PH::print_stdout( " - FIXED: own address-group as subgroup member: {$totalAddressGroupsSubGroupFixed}");
        if( $totalDynamicAddressGroupsTagFixed > 0 )
            PH::print_stdout( " - FIXED: own dynamic address-group as tag member: {$totalDynamicAddressGroupsTagFixed}");

        if( $fixedServiceObjectsWithSameTag > 0 )
            PH::print_stdout( "\n - FIXED: service objects with multiple times same tag: {$fixedServiceObjectsWithSameTag}");

        if( $totalServiceGroupsSubGroupFixed > 0 )
            PH::print_stdout( "\n - FIXED: own service-group as subgroup members: {$totalServiceGroupsSubGroupFixed}");

        if( $totalApplicationGroupsFixed > 0 )
            PH::print_stdout( "\n - FIXED: duplicate application-group members: {$totalApplicationGroupsFixed}");
        if( $totalCustomUrlCategoryFixed > 0 )
            PH::print_stdout( " - FIXED: duplicate custom-url-category members: {$totalCustomUrlCategoryFixed}");

        PH::print_stdout();

        if( $fixedSecRuleFromObjects > 0 )
            PH::print_stdout( "\n - FIXED: SecRule with duplicate from members: {$fixedSecRuleFromObjects}");
        if( $fixedSecRuleToObjects > 0 )
            PH::print_stdout( " - FIXED: SecRule with duplicate to members: {$fixedSecRuleToObjects}");
        if( $fixedSecRuleSourceObjects > 0 )
            PH::print_stdout( " - FIXED: SecRule with duplicate source members: {$fixedSecRuleSourceObjects}");
        if( $fixedSecRuleDestinationObjects > 0 )
            PH::print_stdout( " - FIXED: SecRule with duplicate destination members: {$fixedSecRuleDestinationObjects}");
        if( $fixedSecRuleServiceObjects > 0 )
            PH::print_stdout( " - FIXED: SecRule with duplicate service members: {$fixedSecRuleServiceObjects}");
        if( $fixedSecRuleApplicationObjects > 0 )
            PH::print_stdout( " - FIXED: SecRule with duplicate application members: {$fixedSecRuleApplicationObjects}");
        if( $fixedSecRuleCategoryObjects > 0 )
            PH::print_stdout( " - FIXED: SecRule with duplicate category members: {$fixedSecRuleCategoryObjects}");
        if( $fixedSecRuleTagObjects > 0 )
            PH::print_stdout( " - FIXED: SecRule with duplicate tag members: {$fixedSecRuleTagObjects}");
        if( $fixedSecruleSourceUserObjects > 0 )
            PH::print_stdout( " - FIXED: SecRule with duplicate source-user members: {$fixedSecruleSourceUserObjects}");

        PH::print_stdout();

        if( $fixedNatRuleSourceObjects > 0 )
            PH::print_stdout( " - FIXED: NatRule with duplicate source members: {$fixedNatRuleSourceObjects}");
        if( $fixedNatRuleDestinationObjects > 0 )
            PH::print_stdout( " - FIXED: NatRule with duplicate destination members: {$fixedNatRuleDestinationObjects}");

        PH::print_stdout();

        if( $fixedReadOnlyAddressGroupobjects > 0 )
            PH::print_stdout( "\n - FIXED: ReadOnly duplicate AddressGroup : {$fixedReadOnlyAddressGroupobjects}");
        if( $fixedReadOnlyDeviceGroupobjects > 0 )
            PH::print_stdout( " - FIXED: ReadOnly duplicate DeviceGroup : {$fixedReadOnlyDeviceGroupobjects}");
        if( $fixedReadOnlyTemplateobjects > 0 )
            PH::print_stdout( " - FIXED: ReadOnly duplicate Template : {$fixedReadOnlyTemplateobjects}");
        if( $fixedReadOnlyTemplateStackobjects > 0 )
            PH::print_stdout( " - FIXED: ReadOnly duplicate TemplateStack : {$fixedReadOnlyTemplateStackobjects}");

        if( $fixedImportNetworkInterfaceWithSameInterface > 0 )
            PH::print_stdout( "\n - FIXED: import/network/interface : {$fixedImportNetworkInterfaceWithSameInterface}");


        PH::print_stdout( "\n\nIssues that could not be fixed (look in logs for FIX_MANUALLY keyword):");


        if( $countDuplicateAddressObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: duplicate address objects: {$countDuplicateAddressObjects} (look in the logs )");
        if( $countDuplicateServiceObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: duplicate service objects: {$countDuplicateServiceObjects} (look in the logs)");
        PH::print_stdout();

        if( $countMissconfiguredAddressObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured address objects: {$countMissconfiguredAddressObjects} (look in the logs)");
        if( $countAddressObjectsWithDoubleSpaces > 0 )
            PH::print_stdout( " - FIX_MANUALLY: address objects with double spaces in name: {$countAddressObjectsWithDoubleSpaces} (look in the logs)");
        if( $countAddressObjectsWithWrongCharacters > 0 )
            PH::print_stdout( " - FIX_MANUALLY: address objects with wrong Characters in name: {$countAddressObjectsWithWrongCharacters} (look in the logs)");
        if( $countMissconfiguredAddressRegionObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: address objects with same name as REGION: {$countMissconfiguredAddressRegionObjects} (look in the logs)");
        if( $countEmptyAddressGroup > 0 )
            PH::print_stdout( " - FIX_MANUALLY: empty address-group: {$countEmptyAddressGroup} (look in the logs)");
        PH::print_stdout();

        if( $countMissconfiguredServiceObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured service objects: {$countMissconfiguredServiceObjects} (look in the logs)");
        if( $countServiceObjectsWithDoubleSpaces > 0 )
            PH::print_stdout( " - FIX_MANUALLY: service objects with double spaces in name: {$countServiceObjectsWithDoubleSpaces} (look in the logs)");
        if( $countServiceObjectsWithWrongCharacters > 0 )
            PH::print_stdout( " - FIX_MANUALLY: service objects with wrong Characters in name: {$countServiceObjectsWithWrongCharacters} (look in the logs)");
        if( $countServiceObjectsWithNameappdefault > 0 )
            PH::print_stdout( " - FIX_MANUALLY: service objects with name 'application-default': {$countServiceObjectsWithNameappdefault} (look in the logs)");
        if( $countEmptyServiceGroup > 0 )
            PH::print_stdout( " - FIX_MANUALLY: empty service-group: {$countEmptyServiceGroup} (look in the logs)");
        PH::print_stdout();

        if( $countSecRuleObjectsWithDoubleSpaces > 0 )
            PH::print_stdout( " - FIX_MANUALLY: Security Rules with double spaces in name: {$countSecRuleObjectsWithDoubleSpaces} (look in the logs )");
        if( $countSecRuleObjectsWithWrongCharacters > 0 )
            PH::print_stdout( " - FIX_MANUALLY: Security Rules with wrong characters in name: {$countSecRuleObjectsWithWrongCharacters} (look in the logs )");
        if( $countDuplicateSecRuleObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: duplicate Security Rules: {$countDuplicateSecRuleObjects} (look in the logs )");
        if( $countNATRuleObjectsWithDoubleSpaces > 0 )
            PH::print_stdout( " - FIX_MANUALLY: NAT Rules with double spaces in name: {$countNATRuleObjectsWithDoubleSpaces} (look in the logs )");
        if( $countNATRuleObjectsWithWrongCharacters > 0 )
            PH::print_stdout( " - FIX_MANUALLY: NAT Rules with wrong characters in name: {$countNATRuleObjectsWithWrongCharacters} (look in the logs )");
        if( $countDuplicateNATRuleObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: duplicate NAT Rules: {$countDuplicateNATRuleObjects} (look in the logs )");
        PH::print_stdout();

        if( $countMissconfiguredSecRuleFromObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured From Field in Security Rules: {$countMissconfiguredSecRuleFromObjects} (look in the logs )");
        if( $countMissconfiguredSecRuleToObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured To Field in Security Rules: {$countMissconfiguredSecRuleToObjects} (look in the logs )");
        if( $countMissconfiguredSecRuleSourceObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured Source Field in Security Rules: {$countMissconfiguredSecRuleSourceObjects} (look in the logs )");
        if( $countMissconfiguredSecRuleDestinationObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured Destination Field in Security Rules: {$countMissconfiguredSecRuleDestinationObjects} (look in the logs )");
        if( $countMissconfiguredSecRuleServiceObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured Service Field in Security Rules: {$countMissconfiguredSecRuleServiceObjects} (look in the logs )");
        if( $countMissconfiguredSecRuleApplicationObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured Application Field in Security Rules: {$countMissconfiguredSecRuleApplicationObjects} (look in the logs )");
        if( $countMissconfiguredSecRuleCategoryObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured Category Field in Security Rules: {$countMissconfiguredSecRuleCategoryObjects} (look in the logs )");
        if( $countMissconfiguredSecruleSourceUserObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured SourceUser Field in Security Rules: {$countMissconfiguredSecruleSourceUserObjects} (look in the logs )");
        PH::print_stdout();
        if( $countMissconfiguredNatRuleSourceObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured Source Field in NAT Rules: {$countMissconfiguredNatRuleSourceObjects} (look in the logs )");
        if( $countMissconfiguredNatRuleDestinationObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured Destination Field in NAT Rules: {$countMissconfiguredNatRuleDestinationObjects} (look in the logs )");
        PH::print_stdout();

        if( $service_app_default_available )
        {
            if( $countMissconfiguredSecRuleServiceAppDefaultObjects > 0 )
                PH::print_stdout( " - FIX_MANUALLY: SERVICE OBJECT 'application-default' available and used in Security Rules: {$countMissconfiguredSecRuleServiceAppDefaultObjects} (look in the logs )");
            PH::print_stdout();
        }

        if( $this->configInput['type'] == 'api' )
            PH::print_stdout( "\n\nINPUT mode API detected: FIX is ONLY saved in offline file.");

    }

    public function supportedArguments()
    {

        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['apitimeout'] = array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to answer, increase this value (default=60)');

    }

    function check_region( $name, $object, &$address_region )
    {
        if( strlen( $name ) == 2 && ctype_upper( $name ) )
        {
            if( array_key_exists( $name, $this->region_array ) )
            {
                $address_region[ $name ] = $object;
            }
        }
    }

    /**
     * @param $name string
     * @param $object DOMNode
     * @param $object_name array
     **/
    function check_name( $name, $object, &$object_name )
    {
        $needle = "  ";
        if( strpos( $name, $needle ) !== FALSE )
        {
            $object_name[ $name ] = $object;
        }
    }

    /**
     * @param $name string
     * @param $object DOMNode
     * @param $wrong_name array
     **/
    function check_wrong_name( $name, $object, &$wrong_name )
    {
        preg_match_all($this->pregMatch_pattern_wrong_characters, $name, $matches , PREG_SET_ORDER, 0);
        if( count($matches) > 0 )
            $wrong_name[ $name ] = $object;
    }

    /**
     * @param $name string
     * @param $object DOMNode
     * @param $address_name array
     **/
    function check_service_name_appdefault( $name, $object, &$service_name_appdefault )
    {
        if( $name == "application-default" )
            $service_name_appdefault[] = $object;
    }

    function checkRemoveDuplicateMembers( $locationNode, $locationName, $tagName, &$tagNameArray, &$tagNameIndex, &$totalTagNameFixed )
    {
        $objectTypeNode = DH::findFirstElement($tagName, $locationNode);
        if( $objectTypeNode !== FALSE )
        {
            foreach( $objectTypeNode->childNodes as $objectNode )
            {
                /** @var DOMElement $objectNode */
                if( $objectNode->nodeType != XML_ELEMENT_NODE )
                    continue;

                $objectName = $objectNode->getAttribute('name');

                $this->check_region( $objectName, $objectNode, $address_region );

                $tagNameArray[$objectName][] = $objectNode;

                if( !isset($tagNameIndex[$objectName]) )
                    $tagNameIndex[$objectName] = array('regular' => array(), 'group' => array());

                $tagNameIndex[$objectName]['group'][] = $objectNode;
            }
        }

        //
        //
        //

        PH::print_stdout( "");
        PH::print_stdout( "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####");
        PH::print_stdout( " - parsed ". count($tagNameArray) . " ".$tagName );
        PH::print_stdout( "");
        PH::print_stdout( " - Scanning for ".$tagName." with duplicate members..." );

        foreach( $tagNameArray as $objectName => $nodes )
        {
            foreach( $nodes as $node )
            {

                //custom-url-category
                $staticNode = DH::findFirstElement('list', $node);
                if( $staticNode === FALSE )
                {
                    //application-group and all other address-group/service-group
                    $staticNode = DH::findFirstElement('members', $node);
                    if( $staticNode === FALSE )
                        continue;
                }

                $membersIndex = array();
                /** @var DOMElement[] $nodesToRemove */
                $nodesToRemove = array();

                $demo = iterator_to_array($staticNode->childNodes);
                foreach( $demo as $NodeMember )
                {
                    /** @var DOMElement $NodeMember */
                    if( $NodeMember->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $memberName = $NodeMember->textContent;

                    if( isset($membersIndex[$memberName]) )
                    {
                        PH::print_stdout( "    - group '{$objectName}' from DG/VSYS {$locationName} has a duplicate member named '{$memberName}' ... *FIXED*" );
                        $staticNode->removeChild($NodeMember);
                        $totalTagNameFixed++;
                        continue;
                    }

                    $membersIndex[$memberName] = TRUE;
                }
            }
        }
    }

}