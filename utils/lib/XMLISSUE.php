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

    public $htmlOutput = [];
    public $summaryOutput = [
        'total_findings' => 0,
        'fixed' => 0,
        'not_fixed' => 0
    ];

    public $counters = array();

    public $totalAddressGroupsFixed = 0;
    public $totalServiceGroupsFixed = 0;


    public $totalAddressGroupsSubGroupFixed = 0;
    public $totalDynamicAddressGroupsTagFixed = 0;
    public $totalServiceGroupsSubGroupFixed = 0;

    public $countDuplicateAddressObjects = 0;
    public $fixedDuplicateAddressObjects = 0;
    public $countDuplicateServiceObjects = 0;
    public $fixedDuplicateServiceObjects = 0;

    public $countDuplicateTagObjects = 0;
    public $fixedDuplicateTagObjects = 0;

    public $countDuplicateSecRuleObjects = 0;
    public $countDuplicateNATRuleObjects = 0;

    public $countSecRuleObjectsWithDoubleSpaces = 0;
    public $countSecRuleObjectsWithWrongCharacters = 0;
    public $countNATRuleObjectsWithDoubleSpaces = 0;
    public $countNATRuleObjectsWithWrongCharacters = 0;

    public $countMissconfiguredSecRuleServiceObjects=0;
    public $fixedSecRuleServiceObjects=0;
    public $countMissconfiguredSecRuleApplicationObjects=0;
    public $fixedSecRuleApplicationObjects=0;

    public $countMissconfiguredSecRuleTagObjects=0;
    public $fixedSecRuleTagObjects=0;

    public $countMissconfiguredSecRuleSourceObjects=0;
    public $fixedSecRuleSourceObjects=0;
    public $countMissconfiguredSecRuleDestinationObjects=0;
    public $fixedSecRuleDestinationObjects=0;

    public $countMissconfiguredSecRuleFromObjects=0;
    public $fixedSecRuleFromObjects=0;
    public $countMissconfiguredSecRuleToObjects=0;
    public $fixedSecRuleToObjects=0;

    public $countMissconfiguredSecRuleCategoryObjects=0;
    public $fixedSecRuleCategoryObjects=0;

    public $countMissconfiguredNatRuleSourceObjects=0;
    public $fixedNatRuleSourceObjects=0;
    public $countMissconfiguredNatRuleDestinationObjects=0;
    public $fixedNatRuleDestinationObjects=0;

    public $countMissconfiguredAddressObjects = 0;
    public $countMissconfiguredAddressRegionObjects = 0;
    public $countAddressObjectsWithDoubleSpaces = 0;
    public $countAddressObjectsWithWrongCharacters = 0;

    public $countMissconfiguredServiceObjects = 0;
    public $countServiceObjectsWithDoubleSpaces = 0;
    public $countServiceObjectsWithWrongCharacters = 0;
    public $countServiceObjectsWithNameappdefault = 0;
    public $fixedServiceObjectsWithSameTag = 0;

    public $countMissconfiguredSecruleSourceUserObjects = 0;
    public $fixedSecruleSourceUserObjects = 0;

    public $countEmptyAddressGroup = 0;
    public $countEmptyServiceGroup = 0;

    public $service_app_default_available = false;
    public $countMissconfiguredSecRuleServiceAppDefaultObjects = 0;

    public $fixedReadOnlyDeviceGroupobjects=0;
    public $fixedReadOnlyAddressGroupobjects=0;
    public $fixedReadOnlyTemplateobjects=0;
    public $fixedReadOnlyTemplateStackobjects=0;

    public $fixedImportNetworkInterfaceWithSameInterface = 0;
    public $fixedGroupIncludeListWithSameNode = 0;
    public $fixedScheduleCount = 0;

    public $totalApplicationGroupsFixed = 0;
    public $totalApplicationFiltersFixed = 0;
    public $totalCustomUrlCategoryFixed = 0;

    public $countRulesWithAppDefault = 0;

    public $address_region = array();
    public $address_name = array();

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

        // Generate the HTML file at the end
        $this->generateHTML();

        $this->save_our_work( true );
    }

    public function main()
    {
        $this->counters['fixed'] = array();
        $this->counters['manual'] = array();

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

        unset($filename);
        unset($xmlDoc_region);
        unset($xpath);


///////////////////////////////////////////////////////////




//
// REAL JOB STARTS HERE
//
//





        /** @var DOMElement[] $locationNodes */
        $locationNodes = array();
        $tmp_shared_node = DH::findXPathSingleEntry('/config/shared', $this->xmlDoc);
        if( $tmp_shared_node !== false )
            $locationNodes['shared'] = $tmp_shared_node;

        if( $this->configType == 'panos' )
            $tmpNodes = DH::findXPath('/config/devices/entry/vsys/entry', $this->xmlDoc);
        elseif( $this->configType == 'panorama' )
            $tmpNodes = DH::findXPath('/config/devices/entry/device-group/entry', $this->xmlDoc);
        elseif( $this->configType == 'fawkes' || $this->configType == 'buckbeak' )
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
                $text = "address object '{$objectName}' from DG/VSYS {$locationName} ";
                $text1 = "has lower precedence as REGION object";
                $text1 .= " at XML line #{$node->getLineNo()}";
                $text2 = " ... (*FIX_MANUALLY*)";
                PH::print_stdout( "    - ".$text.$text1.$text2);
                $this->logFinding($locationName, $objectName, $text1, false);

                $this->counters['manual']['Address Region misconfiguration'] = ($this->counters['manual']['Address Region misconfiguration'] ?? 0) + 1;
                $this->countMissconfiguredAddressRegionObjects++;
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for address / addressgroup with double spaces in name...");
            foreach( $address_name as $objectName => $node )
            {
                $text = "address object '{$objectName}' from DG/VSYS {$locationName} ";
                $text1 = "has '  ' double Spaces in name, this causes problems by copy&past 'set commands'";
                $text1 .= " at XML line #{$node->getLineNo()}";
                $text2 = " ... (*FIX_MANUALLY*)";
                PH::print_stdout( "    - ".$text.$text1.$text2);
                $this->logFinding($locationName, $objectName, $text1, false);

                $this->counters['manual']['Address Objects doubleSpace'] = ($this->counters['manual']['Address Objects doubleSpace'] ?? 0) + 1;
                $this->countAddressObjectsWithDoubleSpaces++;
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

                $text = "address object '{$objectName}' from DG/VSYS {$locationName} ";
                $text1 = "has wrong characters in name, '".implode('', $findings)."' this causes commit issues";
                $text1 .= " at XML line #{$node->getLineNo()}";
                $text2 = " ... (*FIX_MANUALLY*)";
                PH::print_stdout( "    - ".$text.$text1.$text2);
                $this->logFinding($locationName, $objectName, $text1, false);

                $newName = $objectName;
                foreach( $findings as $replace )
                    $newName = str_replace($replace, "_", $newName);

                PH::print_stdout( "       oldname: '".$objectName."' | suggested newname: '".$newName."'\n" );
                //xml-issue can not work on objects here :-)
                #$node->setName($newName);

                $this->counters['manual']['Address Objects wrongCharacters'] = ($this->counters['manual']['Address Objects wrongCharacters'] ?? 0) + 1;
                $this->countAddressObjectsWithWrongCharacters++;
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
                        $text = "address object '{$objectName}' from DG/VSYS {$locationName} ";
                        $text1 = "has missing IP configuration";
                        $text1 .= " at XML line #{$node->getLineNo()}";
                        $text2 = " ... (*FIX_MANUALLY*)";
                        PH::print_stdout( "    - ".$text.$text1.$text2);
                        $this->logFinding($locationName, $objectName, $text1, false);

                        $this->counters['fixed']['Address Objects misconfigured'] = ($this->counters['fixed']['Address Objects misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredAddressObjects++;
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
                        $text = "addressgroup object '{$objectName}' from DG/VSYS {$locationName} ";
                        $text1 = "has no member";
                        $text1 .= " at XML line #{$node->getLineNo()}";
                        $text2 = " ... (*FIX_MANUALLY*)";
                        PH::print_stdout( "    - ".$text.$text1.$text2);
                        $this->logFinding($locationName, $objectName, $text1, false);

                        $this->counters['manual']['Address Group empty'] = ($this->counters['manual']['Address Group empty'] ?? 0) + 1;
                        $this->countEmptyAddressGroup++;
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
                            $text = "addressgroup '{$objectName}' from DG/VSYS {$locationName} ";
                            $text1 = "has a duplicate member named '{$memberName}'";
                            $text2 = " ... *FIXED*";
                            PH::print_stdout( "    - ".$text.$text1.$text2);
                            $this->logFinding($locationName, $objectName, $text1, true);

                            $nodesToRemove[] = $staticNodeMember;

                            $this->counters['fixed']['Address Group'] = ($this->counters['fixed']['Address Group'] ?? 0) + 1;
                            $this->totalAddressGroupsFixed++;
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
                            $text = "group '{$objectName}' from DG/VSYS {$locationName} ";
                            $text1 = "has itself as member '{$memberName}'";
                            $text2 = " ... *FIXED*";
                            PH::print_stdout( "    - ".$text.$text1.$text2);
                            $this->logFinding($locationName, $objectName, $text1, true);

                            $staticNodeMember->parentNode->removeChild($staticNodeMember);

                            $this->counters['fixed']['Address Group SubGroup'] = ($this->counters['fixed']['Address Group SubGroup'] ?? 0) + 1;
                            $this->totalAddressGroupsSubGroupFixed++;
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
                        $text = "group '{$objectName}' from DG/VSYS {$locationName} ";
                        $text1 = "has its own filter as tag: '{$memberName}'";
                        $text2 = " ... *FIXED*";
                        PH::print_stdout( "    - ".$text.$text1.$text2);
                        $this->logFinding($locationName, $objectName, $text1, true);

                        $node = reset( $tagArray );
                        $node->parentNode->removeChild($node);

                        $this->counters['fixed']['Address Group Dynamic'] = ($this->counters['fixed']['Address Group Dynamic'] ?? 0) + 1;
                        $this->totalDynamicAddressGroupsTagFixed++;
                        continue;
                    }
                    elseif( $filterType == "and" )
                    {
                        foreach( $tagArray as $tag => $value )
                            unset( $filterArray[$tag] );

                        if( count( $filterArray ) == 0 )
                        {
                            $text = "group '{$objectName}' from DG/VSYS {$locationName} ";
                            $text1 = "has its own filter as tag: '{$memberName}'";
                            $text2 = " ... *FIXED*";
                            PH::print_stdout( "    - ".$text.$text1.$text2);
                            $this->logFinding($locationName, $objectName, $text1, true);

                            $value->parentNode->removeChild($value);


                            $this->counters['fixed']['Address Group Dynamic Tag'] = ($this->counters['fixed']['Address Group Dynamic Tag'] ?? 0) + 1;
                            $this->totalDynamicAddressGroupsTagFixed++;
                            continue;
                        }
                    }
                    elseif( $filterType == "or" )
                    {
                        foreach( $tagArray as $tag )
                        {
                            if( in_array( $tag, $filterArray ) )
                            {
                                $text = "group '{$objectName}' from DG/VSYS {$locationName} ";
                                $text1 = "has its own filter as tag: '{$memberName}'";
                                $text2 = " ... *FIXED*";
                                PH::print_stdout( "    - ".$text.$text1.$text2);
                                $this->logFinding($locationName, $objectName, $text1, true);

                                $tagNodeMember->parentNode->removeChild($tagNodeMember);

                                $this->counters['fixed']['Address Group Dynamic Tag'] = ($this->counters['fixed']['Address Group Dynamic Tag'] ?? 0) + 1;
                                $this->totalDynamicAddressGroupsTagFixed++;
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
                        $text = "type 'Address' value: '" . $ip_netmaskNode->nodeValue . "' at XML line #{$objectNode->getLineNo()}";

                        //Todo: check if address object value is same, then delete it
                        //TODO: VALIDATION needed if working as expected

                        if( strpos( $ip_netmaskNode->nodeValue, "/32" ) !== FALSE )
                            $tmp_ipvalue = str_replace( "/32", "", $ip_netmaskNode->nodeValue);
                        else
                            $tmp_ipvalue = $ip_netmaskNode->nodeValue;

                        if( !isset($tmp_addr_array[$tmp_ipvalue]) )
                        {
                            $tmp_addr_array[$tmp_ipvalue] = $tmp_ipvalue;
                            $this->countDuplicateAddressObjects++;
                        }
                        else
                        {
                            $objectNode->parentNode->removeChild($objectNode);

                            $this->logFinding($locationName, $objectName, $text, true);
                            $text .= PH::boldText(" (removed - no manual fix needed)");

                            $this->countDuplicateAddressObjects--;
                            $this->counters['fixed']['Address Object duplicate'] = ($this->counters['fixed']['Address Object duplicate'] ?? 0) + 1;
                            $this->fixedDuplicateAddressObjects++;
                        }
                        PH::print_stdout( "       - ".$text );
                    }
                    elseif( $ip_fqdnNode !== FALSE )
                    {
                        /** @var DOMElement $objectNode */

                        $text = "type 'Address' value: '" . $ip_fqdnNode->nodeValue . "' at XML line #{$objectNode->getLineNo()}";

                        $this->logFinding($locationName, $objectName, $text, false);

                        PH::print_stdout( "       - ".$text );

                        $this->countDuplicateAddressObjects++;
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
                    $text = "type 'AddressGroup' at XML line #{$objectNode->getLineNo()}";

                    //Todo: check if servicegroup object value is same, then delete it
                    //TODO: VALIDATION needed if working as expected

                    if( !isset($tmp_srv_array[$txt]) )
                    {
                        $tmp_srv_array[$txt] = $txt;
                        $this->countDuplicateAddressObjects++;
                    }
                    else
                    {
                        $objectNode->parentNode->removeChild($objectNode);

                        $this->logFinding($locationName, $objectName, $text, true);
                        $text .= PH::boldText(" (removed - no manual fix needed)");

                        $this->countDuplicateAddressObjects--;
                        $this->counters['fixed']['Address Object duplicate'] = ($this->counters['fixed']['Address Object duplicate'] ?? 0) + 1;
                        $this->fixedDuplicateAddressObjects++;
                    }
                    PH::print_stdout( "       - ".$text);
                }
                #$this->countDuplicateAddressObjects--;
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
                        $this->service_app_default_available = true;

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
                $text = "service object '{$objectName}' from DG/VSYS {$locationName} ";
                $text1 = "has '  ' double Spaces in name, this causes problems by copy&past 'set commands' at XML line #{$node->getLineNo()}";

                $this->logFinding($locationName, $objectName, $text1, false);
                $text2 = " ... (*FIX_MANUALLY*)";
                PH::print_stdout( "    - ".$text.$text1.$text2 );

                $this->countServiceObjectsWithDoubleSpaces++;
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

                $text = "    - service object '{$objectName}' from DG/VSYS {$locationName} has wrong characters in name, '".implode('', $findings)."' this causes commit issues  (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}";
                PH::print_stdout( $text);
                $this->logFinding($locationName, $objectName, $text, false);

                $newName = $objectName;
                foreach( $findings as $replace )
                    $newName = str_replace($replace, "_", $newName);

                PH::print_stdout( "       oldname: '".$objectName."' | suggested newname: '".$newName."'\n" );

                $this->countServiceObjectsWithWrongCharacters++;
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for service / servicegroup with application-default as name...");
            foreach( $service_name_appdefault as $objectName => $node )
            {
                //PH::print_stdout( "    - service object '{$objectName}' from DG/VSYS {$locationName} has name 'application-default' this causes problems with the default behaviour of the firewall ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}");
                $text = "    - service object 'application-default' from DG/VSYS {$locationName} has name 'application-default' this causes problems with the default behaviour of the firewall ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}";
                PH::print_stdout( $text);

                $this->logFinding($locationName, $objectName, $text, false);

                $this->countServiceObjectsWithNameappdefault++;
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
                        $text = "    - service object '{$objectName}' from DG/VSYS {$locationName} has missing protocol configuration ... (*FIX_MANUALLY*)";
                        PH::print_stdout( $text );
                        $text = "       - type 'Service' at XML line #{$node->getLineNo()}";
                        PH::print_stdout( $text );

                        $this->logFinding($locationName, $objectName, $text, false);

                        $this->counters['manual']['Service Object misconfigured'] = ($this->counters['manual']['Service Object misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredServiceObjects++;
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
                        #$this->countMissconfiguredServiceObjects++;

                        foreach( $tagNode->childNodes as $tagNodeMember )
                        {
                            /** @var DOMElement $tagNodeMember */
                            if ($tagNodeMember->nodeType != XML_ELEMENT_NODE)
                                continue;


                            $tagName = $tagNodeMember->textContent;
                            if( isset( $tagArray[$tagName] ) )
                            {
                                $text = "service object '{$objectName}' from DG/VSYS {$locationName} ";
                                $text1 = "has duplicate TAG: ".$tagName." configured";

                                $tagNodeMember->parentNode->removeChild($tagNodeMember);

                                $this->logFinding($locationName, $objectName, $text1, true);

                                $text2 = " ... *FIXED*";
                                PH::print_stdout( "    - ".$text.$text1.$text2);

                                $this->counters['fixed']['Service Object SameTag'] = ($this->counters['fixed']['Service Object SameTag'] ?? 0) + 1;
                                $this->fixedServiceObjectsWithSameTag++;
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
                        $text = "    - servicegroup object '{$objectName}' from DG/VSYS {$locationName} has no member ... (*FIX_MANUALLY*)";
                        PH::print_stdout( $text );
                        $text = "       - type 'ServiceGroup' at XML line #{$node->getLineNo()}";
                        PH::print_stdout( $text );

                        $this->logFinding($locationName, $objectName, $text, false);

                        $this->counters['manual']['Service Group empty'] = ($this->counters['manual']['Service Group empty'] ?? 0) + 1;
                        $this->countEmptyServiceGroup++;
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
                            $text = "group '{$objectName}' from DG/VSYS {$locationName} ";
                            $text1 = "has a duplicate member named '{$memberName}'";

                            $nodesToRemove[] = $staticNodeMember;
                            $this->logFinding($locationName, $objectName, $text1, true);

                            $text2 = " ... *FIXED*";
                            PH::print_stdout( "    - ".$text.$text1.$text2 );

                            $this->counters['fixed']['Service Group'] = ($this->counters['fixed']['Service Group'] ?? 0) + 1;
                            $this->totalServiceGroupsFixed++;
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
                            $text = "group '{$objectName}' from DG/VSYS {$locationName} ";
                            $text1 = "has itself as member '{$memberName}'";

                            $staticNodeMember->parentNode->removeChild($staticNodeMember);
                            $this->logFinding($locationName, $objectName, $text, true);

                            $text2 = " ... *FIXED*";
                            PH::print_stdout( "    - ".$text.$text1.$text2 );

                            $this->counters['fixed']['Service Group SubGroup'] = ($this->counters['fixed']['Service Group SubGroup'] ?? 0) + 1;
                            $this->totalServiceGroupsSubGroupFixed++;
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
                    $text = "type 'Service' value: '" . $protocolNode->nodeValue . "' at XML line #{$objectNode->getLineNo()}";

                    //Todo: check if service object value is same, then delete it
                    //TODO: VALIDATION needed if working as expected

                    if( !isset($tmp_srv_array[$protocolNode->nodeValue]) )
                    {
                        $tmp_srv_array[$protocolNode->nodeValue] = $protocolNode->nodeValue;
                        $this->countDuplicateServiceObjects++;
                    }
                    else
                    {
                        $objectNode->parentNode->removeChild($objectNode);

                        $this->logFinding($locationName, $objectName, $text, true);
                        $text .= PH::boldText(" (removed - no manual fix needed)");

                        $this->countDuplicateServiceObjects--;
                        $this->counters['fixed']['Service Object duplicate'] = ($this->counters['fixed']['Service Object duplicate'] ?? 0) + 1;
                        $this->fixedDuplicateServiceObjects++;
                    }
                    PH::print_stdout( "       - ".$text);
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
                    $text = "type 'ServiceGroup' at XML line #{$objectNode->getLineNo()}";

                    //Todo: check if servicegroup object value is same, then delete it
                    //TODO: VALIDATION needed if working as expected

                    /*
                    if( !isset($tmp_srv_array[$protocolNode->nodeValue]) )
                    {
                        $tmp_srv_array[$protocolNode->nodeValue] = $protocolNode->nodeValue;
                        $this->countDuplicateServiceObjects++;
                    }
                    */
                    if( !isset($tmp_srv_array[$txt]) )
                    {
                        $tmp_srv_array[$txt] = $txt;
                        $this->countDuplicateAddressObjects++;
                    }
                    else
                    {
                        $objectNode->parentNode->removeChild($objectNode);

                        $this->logFinding($locationName, $objectName, $text, true);
                        $text .= PH::boldText(" (removed - no manual fix needed)");

                        $this->countDuplicateServiceObjects--;
                        $this->counters['fixed']['Service Object duplicate'] = ($this->counters['fixed']['Service Object duplicate'] ?? 0) + 1;
                        $this->fixedDuplicateServiceObjects++;
                    }
                    PH::print_stdout( "       - ".$text);
                }
                #$this->countDuplicateServiceObjects--;
            }

            //
            //
            //
            //
            //
            //
            $applicationGroups = array();
            $applicationIndex = array();
            $this->checkRemoveDuplicateMembers( $locationNode, $locationName, 'application-group', $applicationGroups, $applicationIndex, $this->totalApplicationGroupsFixed );
//
            //
            //
            //
            //
            //
            $applicationFilters = array();
            $applicationFiltersIndex = array();
            $this->checkRemoveDuplicateMembers( $locationNode, $locationName, 'application-filter', $applicationFilters, $applicationFiltersIndex, $this->totalApplicationFiltersFixed );

            //
            //
            $customURLcategory = array();
            $customURLcategoryIndex = array();
            $locationNode_profiles = DH::findFirstElement('profiles', $locationNode);
            if( $locationNode_profiles !== FALSE )
                $this->checkRemoveDuplicateMembers( $locationNode_profiles, $locationName, 'custom-url-category', $customURLcategory, $customURLcategoryIndex, $this->totalCustomUrlCategoryFixed );

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

                                            $this->logFinding($locationName, $objectName, $text, true);

                                            $text .= PH::boldText(" (removed - no manual fix needed)");
                                            PH::print_stdout( $text );
                                            $this->counters['fixed']['SecRule Service Object duplicate'] = ($this->counters['fixed']['SecRule Service Object duplicate'] ?? 0) + 1;
                                            $this->fixedSecRuleServiceObjects++;
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
                                                $this->logFinding($locationName, $objectName, $text, true);
                                                PH::print_stdout( $text );
                                                $this->counters['fixed']['SecRule Tag Object duplicate'] = ($this->counters['fixed']['SecRule Tag Object duplicate'] ?? 0) + 1;
                                                $this->fixedSecRuleTagObjects++;
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

                                            $this->logFinding($locationName, $objectName, $text, true);
                                            $text .=PH::boldText(" (removed)")."\n";
                                            PH::print_stdout( $text );
                                            $this->counters['fixed']['SecRule Application Object duplicate'] = ($this->counters['fixed']['SecRule Application Object duplicate'] ?? 0) + 1;
                                            $this->fixedSecRuleApplicationObjects++;
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

                                                $this->logFinding($locationName, $objectName, $text, true);
                                                $text .= PH::boldText(" (removed)");
                                                PH::print_stdout( $text );
                                                $this->counters['fixed']['SecRule Category Object duplicate'] = ($this->counters['fixed']['SecRule Category Object duplicate'] ?? 0) + 1;
                                                $this->fixedSecRuleCategoryObjects++;
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

                                            $this->logFinding($locationName, $objectName, $text, true);
                                            $text .= PH::boldText(" (removed)");
                                            PH::print_stdout( $text );
                                            $this->counters['fixed']['SecRule Source Object duplicate'] = ($this->counters['fixed']['SecRule Source Object duplicate'] ?? 0) + 1;
                                            $this->fixedSecRuleSourceObjects++;
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

                                            $this->logFinding($locationName, $objectName, $text, true);
                                            $text .= PH::boldText(" (removed)")."\n";
                                            PH::print_stdout( $text );
                                            $this->counters['fixed']['SecRule Destination Object duplicate'] = ($this->counters['fixed']['SecRule Destination Object duplicate'] ?? 0) + 1;
                                            $this->fixedSecRuleDestinationObjects++;
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
                                            $this->logFinding($locationName, $objectName, $text, true);
                                            $text .= PH::boldText(" (removed)")."\n";
                                            PH::print_stdout( $text );
                                            $this->counters['fixed']['SecRule From Object duplicate'] = ($this->counters['fixed']['SecRule From Object duplicate'] ?? 0) + 1;
                                            $this->fixedSecRuleFromObjects++;
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

                                            $this->logFinding($locationName, $objectName, $text, true);
                                            $text .= PH::boldText(" (removed)")."\n";
                                            PH::print_stdout( $text );
                                            $this->counters['fixed']['SecRule To Object duplicate'] = ($this->counters['fixed']['SecRule To Object duplicate'] ?? 0) + 1;
                                            $this->fixedSecRuleToObjects++;
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

                                                $this->logFinding($locationName, $objectName, $text, true);
                                                $text .= PH::boldText(" (removed)")."\n";
                                                PH::print_stdout( $text );
                                                $this->counters['fixed']['SecRule SourceUser Object duplicate'] = ($this->counters['fixed']['SecRule SourceUser Object duplicate'] ?? 0) + 1;
                                                $this->fixedSecruleSourceUserObjects++;
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
                                    $this->check_wrong_name( $objectName, $objectNode, $natrule_wrong_name );

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

                                            $this->logFinding($locationName, $objectName, $text, true);
                                            $text .= PH::boldText(" (removed)");
                                            PH::print_stdout( $text );
                                            $this->counters['fixed']['NatRule Source Object duplicate'] = ($this->counters['fixed']['NatRule Source Object duplicate'] ?? 0) + 1;
                                            $this->fixedNatRuleSourceObjects++;
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

                                            $this->logFinding($locationName, $objectName, $text, true);
                                            $text .= PH::boldText(" (removed)")."\n";
                                            PH::print_stdout( $text );
                                            $this->counters['fixed']['NatRule Destination Object duplicate'] = ($this->counters['fixed']['NatRule Destination Object duplicate'] ?? 0) + 1;
                                            $this->fixedNatRuleDestinationObjects++;
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
                        $text = "    - Security Rules object '{$objectName}' from DG/VSYS {$locationName} has '  ' double Spaces in name, this causes problems by copy&past 'set commands' ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}";
                        PH::print_stdout( $text);
                        $this->logFinding($locationName, $objectName, $text, false);
                        $this->counters['fixed']['NatRule Name doubleSpace'] = ($this->counters['fixed']['NatRule Name doubleSpace'] ?? 0) + 1;
                        $this->countSecRuleObjectsWithDoubleSpaces++;
                    }

                    PH::print_stdout( " - Scanning for Security Rules with wrong characters in name...");
                    foreach( $secrule_wrong_name as $objectName => $node )
                    {
                        $text = "    - Security Rules object '{$objectName}' from DG/VSYS {$locationName} has wrong characters in name ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}";
                        PH::print_stdout( $text);
                        $this->logFinding($locationName, $objectName, $text, false);
                        $this->counters['fixed']['NatRule Name wrongCharacter'] = ($this->counters['fixed']['NatRule Name wrongCharacter'] ?? 0) + 1;
                        $this->countSecRuleObjectsWithWrongCharacters++;
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
                                $this->logFinding($locationName, $objectName, $text, true);
                                PH::print_stdout( $text );
                            }
                            else
                            {
                                $text .= " - Rulename can not be fixed: '" . $newName . "' is also available";
                                $this->logFinding($locationName, $objectName, $text, false);
                                PH::print_stdout( $text );
                            }

                            $this->counters['manual']['SecRule duplicate'] = ($this->counters['manual']['SecRule duplicate'] ?? 0) + 1;
                            $this->countDuplicateSecRuleObjects++;
                        }
                    }

                    //
                    //
                    //
                    PH::print_stdout( " - Scanning for NAT Rules with double spaces in name...");
                    foreach( $natrule_name as $objectName => $node )
                    {
                        $text = "    - NAT Rules object '{$objectName}' from DG/VSYS {$locationName} has '  ' double Spaces in name, this causes problems by copy&past 'set commands' ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}";
                        PH::print_stdout( $text);
                        $this->logFinding($locationName, $objectName, $text, false);
                        $this->counters['manual']['NatRule Name doubleSpace'] = ($this->counters['manual']['NatRule Name doubleSpace'] ?? 0) + 1;
                        $this->countNATRuleObjectsWithDoubleSpaces++;
                    }
                    PH::print_stdout( " - Scanning for NAT Rules with wrong characters in name...");
                    foreach( $natrule_wrong_name as $objectName => $node )
                    {
                        $text = "    - NAT Rules object '{$objectName}' from DG/VSYS {$locationName} has wrong characters in name ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}";
                        PH::print_stdout( $text);
                        $this->logFinding($locationName, $objectName, $text, false);
                        $this->counters['manual']['NatRule Name wrongCharacter'] = ($this->counters['manual']['NatRule Name wrongCharacter'] ?? 0) + 1;
                        $this->countNATRuleObjectsWithWrongCharacters++;
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
                            $text = "type 'NAT Rules' at XML line #{$objectNode->getLineNo()}";


                            $newName = $key . $objectNode->getAttribute('name');
                            if( !isset($natRuleIndex[$newName]) )
                            {
                                $objectNode->setAttribute('name', $newName);
                                $text .= PH::boldText(" - new name: " . $newName . " (fixed)\n");
                                $this->logFinding($locationName, $objectName, $text, true);
                                PH::print_stdout( "       - ".$text );
                            }
                            else
                            {
                                $text .= " - Rulename can not be fixed: '" . $newName . "' is also available";
                                $this->logFinding($locationName, $objectName, $text, false);
                                PH::print_stdout( "       - ".$text );
                            }

                            $this->counters['manual']['NatRule duplicate'] = ($this->counters['manual']['NatRule duplicate'] ?? 0) + 1;
                            $this->countDuplicateNATRuleObjects++;
                        }
                    }

                    PH::print_stdout( "\n - Scanning for missconfigured From Field in Security Rules...");
                    foreach( $secRuleFromIndex as $objectName => $objectNode )
                    {
                        $text = "found Security Rule named '{$objectName}' that has from 'any' and additional from configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( "   - ".$text );
                        $this->logFinding($locationName, $objectName, $text, false);

                        $this->counters['manual']['SecRule From misconfigured'] = ($this->counters['manual']['SecRule From misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredSecRuleFromObjects++;
                    }

                    PH::print_stdout( " - Scanning for missconfigured To Field in Security Rules...");
                    foreach( $secRuleToIndex as $objectName => $objectNode )
                    {
                        $text = "found Security Rule named '{$objectName}' that has to 'any' and additional to configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( "   - ".$text );
                        $this->logFinding($locationName, $objectName, $text, false);

                        $this->counters['manual']['SecRule To misconfigured'] = ($this->counters['manual']['SecRule To misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredSecRuleToObjects++;
                    }

                    PH::print_stdout( "\n - Scanning for missconfigured Source Field in Security Rules...");
                    foreach( $secRuleSourceIndex as $objectName => $objectNode )
                    {
                        $text = "found Security Rule named '{$objectName}' that has source 'any' and additional source configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( $text);
                        $this->logFinding($locationName, $objectName, $text, false);

                        $this->counters['manual']['SecRule Source misconfigured'] = ($this->counters['manual']['SecRule Source misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredSecRuleSourceObjects++;
                    }

                    PH::print_stdout( " - Scanning for missconfigured Destination Field in Security Rules...");
                    foreach( $secRuleDestinationIndex as $objectName => $objectNode )
                    {
                        $text = "found Security Rule named '{$objectName}' that has destination 'any' and additional destination configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( "   - ".$text);
                        $this->logFinding($locationName, $objectName, $text, false);

                        $this->counters['manual']['SecRule Destination misconfigured'] = ($this->counters['manual']['SecRule Destination misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredSecRuleDestinationObjects++;
                    }

                    PH::print_stdout( " - Scanning for missconfigured Service Field in Security Rules...");
                    foreach( $secRuleServiceIndex as $objectName => $objectNode )
                    {
                        $text = "found Security Rule named '{$objectName}' that has service 'application-default' and an additional service configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( "   - ".$text);
                        $this->logFinding($locationName, $objectName, $text, false);

                        $this->counters['manual']['SecRule Service misconfigured'] = ($this->counters['manual']['SecRule Service misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredSecRuleServiceObjects++;
                    }


                    PH::print_stdout( " - Scanning for missconfigured Application Field in Security Rules...");
                    foreach( $secRuleApplicationIndex as $objectName => $objectNode )
                    {
                        $text = "found Security Rule named '{$objectName}' that has application 'any' and additional application configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( "   - ".$text);
                        $this->logFinding($locationName, $objectName, $text, false);

                        $this->counters['manual']['SecRule Application misconfigured'] = ($this->counters['manual']['SecRule Application misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredSecRuleApplicationObjects++;
                    }

                    PH::print_stdout( " - Scanning for missconfigured Category Field in Security Rules...");
                    foreach( $secRuleCategoryIndex as $objectName => $objectNode )
                    {
                        #PH::print_stdout( "   - found Security Rule named '{$objectName}' that has XML element 'category' but not child element 'member' configured at XML line #{$objectNode->getLineNo()}");
                        $text = "found Security Rule named '{$objectName}' that has category 'any' and additional category configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( "   - ".$text);
                        $this->logFinding($locationName, $objectName, $text, false);

                        $this->counters['manual']['SecRule Category misconfigured'] = ($this->counters['manual']['SecRule Categroy misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredSecRuleCategoryObjects++;
                    }

                    PH::print_stdout( " - Scanning for missconfigured SourceUser Field in Security Rules...");
                    foreach( $secRuleSourceUserIndex as $objectName => $objectNode )
                    {
                        $text = "found Security Rule named '{$objectName}' that has source-user 'any' and additional source-user configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( "   - ".$text);
                        $this->logFinding($locationName, $objectName, $text, false);

                        $this->counters['manual']['SecRule SourceUser misconfigured'] = ($this->counters['manual']['SecRule SourceUser misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredSecruleSourceUserObjects++;
                    }

                    PH::print_stdout( "\n - Scanning for missconfigured Source Field in NAT Rules...");
                    foreach( $natRuleSourceIndex as $objectName => $objectNode )
                    {
                        $text = "found NAT Rule named '{$objectName}' that has source 'any' and additional source configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( "   - ".$text);
                        $this->logFinding($locationName, $objectName, $text, false);

                        $this->counters['manual']['NatRule Source misconfigured'] = ($this->counters['manual']['NatRule Source misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredNatRuleSourceObjects++;
                    }

                    PH::print_stdout( " - Scanning for missconfigured Destination Field in NAT Rules...");
                    foreach( $natRuleDestinationIndex as $objectName => $objectNode )
                    {
                        $text = "found NAT Rule named '{$objectName}' that has destination 'any' and additional destination configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( "   - ".$text);
                        $this->logFinding($locationName, $objectName, $text, false);

                        $this->counters['manual']['NatRule Destination misconfigured'] = ($this->counters['manual']['NatRule Destination misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredNatRuleDestinationObjects++;
                    }

                    if( $this->service_app_default_available )
                    {
                        PH::print_stdout( " - Scanning for Security Rules with 'application-default' set | service object 'application-default' is available ...");
                        foreach( $secRuleServiceAppDefaultIndex as $objectName => $objectNode )
                        {
                            $text = "found Security Rule named '{$objectName}' that is using SERVICE OBJECT at XML line #{$objectNode->getLineNo()}";

                            $this->logFinding($locationName, $objectName, $text, false);
                            PH::print_stdout( "   - ".$text);

                            $this->counters['manual']['SecRule ServiceAppDefault misconfigured'] = ($this->counters['manual']['SecRule ServiceAppDefault misconfigured'] ?? 0) + 1;
                            $this->countMissconfiguredSecRuleServiceAppDefaultObjects++;
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
                    $text = "readOnly DG: ".$locationName." has same addressgroup defined twice: ".$objectAddressGroupName;
                    $readonlyAddressgroups->removeChild($objectAddressGroup);

                    $this->logFinding($locationName, $objectName, $text, true);
                    $text .= PH::boldText(" (removed)");
                    PH::print_stdout("     - ".$text);

                    $this->counters['fixed']['ReadOnly Address Group'] = ($this->counters['fixed']['ReadOnly Address Group'] ?? 0) + 1;
                    $this->fixedReadOnlyAddressGroupobjects++;
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
                                    $text = "type 'Zone' name: '" . $node->getAttribute('name') . "' - '" . $results[0][0] . "' at XML line #{$zone_type->getLineNo()} (*FIX_MANUALLY*)";
                                    PH::print_stdout( "       - ".$text );
                                    $this->logFinding($locationName, $objectName, $text, false);
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
                $text = "readOnly shared has same addressgroup defined twice: ".$objectAddressGroupName;
                $readonlyAddressgroups->removeChild($objectAddressGroup);

                $this->logFinding($locationName, $objectName, $text, true);
                $text .=PH::boldText(" (removed)");
                PH::print_stdout("     - ".$text);

                $this->counters['fixed']['ReadOnly Address Group'] = ($this->counters['fixed']['ReadOnly Address Group'] ?? 0) + 1;
                $this->fixedReadOnlyAddressGroupobjects++;
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
                $text = "readOnly /config/readonly/devices/entry[@name='localhost.localdomain']/device-group has same DeviceGroup defined twice: ".$objectDeviceGroupName;
                $readonlyDeviceGroups->removeChild($objectDeviceGroup);

                $this->logFinding($locationName, $objectName, $text, true);
                $text .=PH::boldText(" (removed)");
                PH::print_stdout("     - ".$text);

                $this->counters['fixed']['ReadOnly Device Group'] = ($this->counters['fixed']['ReadOnly Device Group'] ?? 0) + 1;
                $this->fixedReadOnlyDeviceGroupobjects++;
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
                $text = "readOnly /config/readonly/devices/entry[@name='localhost.localdomain']/template has same Template defined twice: ".$objectTemplateName;
                $readonlyTemplates->removeChild($objectTemplate);

                $this->logFinding($locationName, $objectName, $text, true);
                $text .=PH::boldText(" (removed)");
                PH::print_stdout("     - ".$text);

                $this->counters['fixed']['ReadOnly Template'] = ($this->counters['fixed']['ReadOnly Template'] ?? 0) + 1;
                $this->fixedReadOnlyTemplateobjects++;
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
                $text = "readOnly /config/readonly/devices/entry[@name='localhost.localdomain']/template-stack has same Template-Stack defined twice: ".$objectTemplateName;
                $readonlyTemplateStacks->removeChild($objectTemplateStack);
                $this->logFinding($locationName, $objectName, $text, true);
                $text .=PH::boldText(" (removed)");
                PH::print_stdout("     - ".$text);

                $this->counters['fixed']['ReadOnly TemplateStack'] = ($this->counters['fixed']['ReadOnly TemplateStack'] ?? 0) + 1;
                $this->fixedReadOnlyTemplateStackobjects++;
            }
            else
                $readonlyTemplateStacksArray[$objectTemplateStackName] = $objectTemplateStack;
        }


        PH::print_stdout( "");
        PH::print_stdout( "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####");

        ////////////////////////////////////////////////////////////
        ///scanning for all import/network/interfaces

        PH::print_stdout(" - Scanning for import/network/interface for duplicate entries ...");
        $importNodes = $this->xmlDoc->getElementsByTagName("import");

        foreach ($importNodes as $import)
        {
            $network = DH::findFirstElement("network", $import);
            if ($network)
            {
                $interfaces = DH::findFirstElement("interface", $network);
                if ($interfaces)
                {
                    $this->fixedImportNetworkInterfaceWithSameInterface += $this->removeDuplicateChildNodes($locationName, $objectName, $interfaces, "interface");
                }
            }
        }

        ////////////////////////////////////////////////////////////
        ///scanning for all group-include-list

        PH::print_stdout(" - Scanning for group-include-list for duplicate entries ...");
        $groupLists = $this->xmlDoc->getElementsByTagName("group-include-list");

        foreach ($groupLists as $groupList)
        {
            $this->fixedGroupIncludeListWithSameNode += $this->removeDuplicateChildNodes($locationName, $objectName, $groupList, "group-include-list entry");
        }


        ////////////////////////////////////////////////////////////
        ///scanning for all schedule weekly
        PH::print_stdout(" - Scanning for schedule weekly duplicates ...");

        $weeklyNodes = $this->xmlDoc->getElementsByTagName("weekly");

        foreach ($weeklyNodes as $weekly)
        {
            // Iterate through each day (sunday, monday, etc.)
            foreach ($weekly->childNodes as $dayNode)
            {
                if ($dayNode->nodeType === XML_ELEMENT_NODE) {
                    // Use the function on each day node
                    $this->fixedScheduleCount += $this->removeDuplicateChildNodes($locationName, $objectName, $dayNode, "schedule member");
                }
            }
        }
        ////////////////////////////////////////////////////////////
        PH::print_stdout( "");
        PH::print_stdout( "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####");
        PH::print_stdout();

        PH::print_stdout( "Summary:" );
        if( $this->fixedDuplicateAddressObjects > 0 )
            PH::print_stdout( " - FIXED: duplicate address objects: {$this->fixedDuplicateAddressObjects}");
        if( $this->fixedDuplicateServiceObjects > 0 )
            PH::print_stdout( " - FIXED: duplicate service objects: {$this->fixedDuplicateServiceObjects}");

        if( $this->totalAddressGroupsFixed > 0 )
            PH::print_stdout( "\n - FIXED: duplicate address-group members: {$this->totalAddressGroupsFixed}");
        if( $this->totalServiceGroupsFixed > 0 )
            PH::print_stdout( " - FIXED: duplicate service-group members: {$this->totalServiceGroupsFixed}");
        if( $this->totalAddressGroupsSubGroupFixed > 0 )
            PH::print_stdout( " - FIXED: own address-group as subgroup member: {$this->totalAddressGroupsSubGroupFixed}");
        if( $this->totalDynamicAddressGroupsTagFixed > 0 )
            PH::print_stdout( " - FIXED: own dynamic address-group as tag member: {$this->totalDynamicAddressGroupsTagFixed}");

        if( $this->fixedServiceObjectsWithSameTag > 0 )
            PH::print_stdout( "\n - FIXED: service objects with multiple times same tag: {$this->fixedServiceObjectsWithSameTag}");

        if( $this->totalServiceGroupsSubGroupFixed > 0 )
            PH::print_stdout( "\n - FIXED: own service-group as subgroup members: {$this->totalServiceGroupsSubGroupFixed}");

        if( $this->totalApplicationGroupsFixed > 0 )
            PH::print_stdout( "\n - FIXED: duplicate application-group members: {$this->totalApplicationGroupsFixed}");
        if( $this->totalApplicationFiltersFixed > 0 )
            PH::print_stdout( "\n - FIXED: duplicate application-filter members: {$this->totalApplicationFiltersFixed}");
        if( $this->totalCustomUrlCategoryFixed > 0 )
            PH::print_stdout( " - FIXED: duplicate custom-url-category members: {$this->totalCustomUrlCategoryFixed}");

        PH::print_stdout();

        if( $this->fixedSecRuleFromObjects > 0 )
            PH::print_stdout( "\n - FIXED: SecRule with duplicate from members: {$this->fixedSecRuleFromObjects}");
        if( $this->fixedSecRuleToObjects > 0 )
            PH::print_stdout( " - FIXED: SecRule with duplicate to members: {$this->fixedSecRuleToObjects}");
        if( $this->fixedSecRuleSourceObjects > 0 )
            PH::print_stdout( " - FIXED: SecRule with duplicate source members: {$this->fixedSecRuleSourceObjects}");
        if( $this->fixedSecRuleDestinationObjects > 0 )
            PH::print_stdout( " - FIXED: SecRule with duplicate destination members: {$this->fixedSecRuleDestinationObjects}");
        if( $this->fixedSecRuleServiceObjects > 0 )
            PH::print_stdout( " - FIXED: SecRule with duplicate service members: {$this->fixedSecRuleServiceObjects}");
        if( $this->fixedSecRuleApplicationObjects > 0 )
            PH::print_stdout( " - FIXED: SecRule with duplicate application members: {$this->fixedSecRuleApplicationObjects}");
        if( $this->fixedSecRuleCategoryObjects > 0 )
            PH::print_stdout( " - FIXED: SecRule with duplicate category members: {$this->fixedSecRuleCategoryObjects}");
        if( $this->fixedSecRuleTagObjects > 0 )
            PH::print_stdout( " - FIXED: SecRule with duplicate tag members: {$this->fixedSecRuleTagObjects}");
        if( $this->fixedSecruleSourceUserObjects > 0 )
            PH::print_stdout( " - FIXED: SecRule with duplicate source-user members: {$this->fixedSecruleSourceUserObjects}");

        PH::print_stdout();

        if( $this->fixedNatRuleSourceObjects > 0 )
            PH::print_stdout( " - FIXED: NatRule with duplicate source members: {$this->fixedNatRuleSourceObjects}");
        if( $this->fixedNatRuleDestinationObjects > 0 )
            PH::print_stdout( " - FIXED: NatRule with duplicate destination members: {$this->fixedNatRuleDestinationObjects}");

        PH::print_stdout();

        if( $this->fixedReadOnlyAddressGroupobjects > 0 )
            PH::print_stdout( "\n - FIXED: ReadOnly duplicate AddressGroup : {$this->fixedReadOnlyAddressGroupobjects}");
        if( $this->fixedReadOnlyDeviceGroupobjects > 0 )
            PH::print_stdout( " - FIXED: ReadOnly duplicate DeviceGroup : {$this->fixedReadOnlyDeviceGroupobjects}");
        if( $this->fixedReadOnlyTemplateobjects > 0 )
            PH::print_stdout( " - FIXED: ReadOnly duplicate Template : {$this->fixedReadOnlyTemplateobjects}");
        if( $this->fixedReadOnlyTemplateStackobjects > 0 )
            PH::print_stdout( " - FIXED: ReadOnly duplicate TemplateStack : {$this->fixedReadOnlyTemplateStackobjects}");

        if( $this->fixedImportNetworkInterfaceWithSameInterface > 0 )
            PH::print_stdout( "\n - FIXED: import/network/interface : {$this->fixedImportNetworkInterfaceWithSameInterface}");

        if( $this->fixedGroupIncludeListWithSameNode > 0 )
            PH::print_stdout( "\n - FIXED: group-include-list : {$this->fixedGroupIncludeListWithSameNode}");
        if( $this->fixedScheduleCount > 0 )
            PH::print_stdout( "\n - FIXED: schedule recurring weekly : {$this->fixedScheduleCount}");

        PH::print_stdout( "\n\nIssues that could not be fixed (look in logs for FIX_MANUALLY keyword):");


        if( $this->countDuplicateAddressObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: duplicate address objects: {$this->countDuplicateAddressObjects} (look in the logs )");
        if( $this->countDuplicateServiceObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: duplicate service objects: {$this->countDuplicateServiceObjects} (look in the logs)");
        PH::print_stdout();

        if( $this->countMissconfiguredAddressObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured address objects: {$this->countMissconfiguredAddressObjects} (look in the logs)");
        if( $this->countAddressObjectsWithDoubleSpaces > 0 )
            PH::print_stdout( " - FIX_MANUALLY: address objects with double spaces in name: {$this->countAddressObjectsWithDoubleSpaces} (look in the logs)");
        if( $this->countAddressObjectsWithWrongCharacters > 0 )
            PH::print_stdout( " - FIX_MANUALLY: address objects with wrong Characters in name: {$this->countAddressObjectsWithWrongCharacters} (look in the logs)");
        if( $this->countMissconfiguredAddressRegionObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: address objects with same name as REGION: {$this->countMissconfiguredAddressRegionObjects} (look in the logs)");
        if( $this->countEmptyAddressGroup > 0 )
            PH::print_stdout( " - FIX_MANUALLY: empty address-group: {$this->countEmptyAddressGroup} (look in the logs)");
        PH::print_stdout();

        if( $this->countMissconfiguredServiceObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured service objects: {$this->countMissconfiguredServiceObjects} (look in the logs)");
        if( $this->countServiceObjectsWithDoubleSpaces > 0 )
            PH::print_stdout( " - FIX_MANUALLY: service objects with double spaces in name: {$this->countServiceObjectsWithDoubleSpaces} (look in the logs)");
        if( $this->countServiceObjectsWithWrongCharacters > 0 )
            PH::print_stdout( " - FIX_MANUALLY: service objects with wrong Characters in name: {$this->countServiceObjectsWithWrongCharacters} (look in the logs)");
        if( $this->countServiceObjectsWithNameappdefault > 0 )
            PH::print_stdout( " - FIX_MANUALLY: service objects with name 'application-default': {$this->countServiceObjectsWithNameappdefault} (look in the logs)");
        if( $this->countEmptyServiceGroup > 0 )
            PH::print_stdout( " - FIX_MANUALLY: empty service-group: {$this->countEmptyServiceGroup} (look in the logs)");
        PH::print_stdout();

        if( $this->countSecRuleObjectsWithDoubleSpaces > 0 )
            PH::print_stdout( " - FIX_MANUALLY: Security Rules with double spaces in name: {$this->countSecRuleObjectsWithDoubleSpaces} (look in the logs )");
        if( $this->countSecRuleObjectsWithWrongCharacters > 0 )
            PH::print_stdout( " - FIX_MANUALLY: Security Rules with wrong characters in name: {$this->countSecRuleObjectsWithWrongCharacters} (look in the logs )");
        if( $this->countDuplicateSecRuleObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: duplicate Security Rules: {$this->countDuplicateSecRuleObjects} (look in the logs )");
        if( $this->countNATRuleObjectsWithDoubleSpaces > 0 )
            PH::print_stdout( " - FIX_MANUALLY: NAT Rules with double spaces in name: {$this->countNATRuleObjectsWithDoubleSpaces} (look in the logs )");
        if( $this->countNATRuleObjectsWithWrongCharacters > 0 )
            PH::print_stdout( " - FIX_MANUALLY: NAT Rules with wrong characters in name: {$this->countNATRuleObjectsWithWrongCharacters} (look in the logs )");
        if( $this->countDuplicateNATRuleObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: duplicate NAT Rules: {$this->countDuplicateNATRuleObjects} (look in the logs )");
        PH::print_stdout();

        if( $this->countMissconfiguredSecRuleFromObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured From Field in Security Rules: {$this->countMissconfiguredSecRuleFromObjects} (look in the logs )");
        if( $this->countMissconfiguredSecRuleToObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured To Field in Security Rules: {$this->countMissconfiguredSecRuleToObjects} (look in the logs )");
        if( $this->countMissconfiguredSecRuleSourceObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured Source Field in Security Rules: {$this->countMissconfiguredSecRuleSourceObjects} (look in the logs )");
        if( $this->countMissconfiguredSecRuleDestinationObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured Destination Field in Security Rules: {$this->countMissconfiguredSecRuleDestinationObjects} (look in the logs )");
        if( $this->countMissconfiguredSecRuleServiceObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured Service Field in Security Rules: {$this->countMissconfiguredSecRuleServiceObjects} (look in the logs )");
        if( $this->countMissconfiguredSecRuleApplicationObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured Application Field in Security Rules: {$this->countMissconfiguredSecRuleApplicationObjects} (look in the logs )");
        if( $this->countMissconfiguredSecRuleCategoryObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured Category Field in Security Rules: {$this->countMissconfiguredSecRuleCategoryObjects} (look in the logs )");
        if( $this->countMissconfiguredSecruleSourceUserObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured SourceUser Field in Security Rules: {$this->countMissconfiguredSecruleSourceUserObjects} (look in the logs )");
        PH::print_stdout();
        if( $this->countMissconfiguredNatRuleSourceObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured Source Field in NAT Rules: {$this->countMissconfiguredNatRuleSourceObjects} (look in the logs )");
        if( $this->countMissconfiguredNatRuleDestinationObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: missconfigured Destination Field in NAT Rules: {$this->countMissconfiguredNatRuleDestinationObjects} (look in the logs )");
        PH::print_stdout();

        if( $this->service_app_default_available )
        {
            if( $this->countMissconfiguredSecRuleServiceAppDefaultObjects > 0 )
                PH::print_stdout( " - FIX_MANUALLY: SERVICE OBJECT 'application-default' available and used in Security Rules: {$this->countMissconfiguredSecRuleServiceAppDefaultObjects} (look in the logs )");
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
                    {
                        //application-filter
                        $staticNode = DH::findFirstElement('exclude', $node);

                        if( $staticNode === FALSE )
                            continue;
                    }

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
                        $text = "    - group '{$objectName}' from DG/VSYS {$locationName} has a duplicate member named '{$memberName}'";

                        $staticNode->removeChild($NodeMember);
                        $this->logFinding($locationName, $objectName, $text, true);
                        $text .= " ... *FIXED*";
                        PH::print_stdout( $text );
                        $totalTagNameFixed++;
                        $this->counters['fixed'][$tagName.' duplicate'] = ($this->counters['fixed'][$tagName.' duplicate'] ?? 0) + 1;
                        continue;
                    }

                    $membersIndex[$memberName] = TRUE;
                }
            }
        }
    }

    /**
     * Removes duplicate child elements based on their text content.
     * @return int The number of removed duplicates.
     */
    private function removeDuplicateChildNodes($locationName, $objectName, DOMElement $parent, string $label): int
    {
        $seenEntries = [];
        $toRemove = [];
        $removedCount = 0;

        // Pass 1: Identify duplicates
        foreach ($parent->childNodes as $node)
        {
            if ($node->nodeType !== XML_ELEMENT_NODE)
                continue;

            $nodeValue = trim($node->textContent);

            if (isset($seenEntries[$nodeValue]))
                $toRemove[] = $node;
            else
                $seenEntries[$nodeValue] = true;
        }

        // Pass 2: Remove duplicates
        foreach ($toRemove as $node)
        {
            $nodeName = $node->textContent;
            $xpath = $node->getNodePath();

            $text = "remove $label: '<member>".$nodeName."</member>' from xPath: '".$xpath."' as it is a duplicate entry";


            $node->parentNode->removeChild($node);
            $this->logFinding($locationName, $objectName, $text, true);
            $text .= " ... *FIXED*";
            PH::print_stdout("    - ".$text);

            $removedCount++;
        }

        return $removedCount;
    }



    /**
     * Helper to log findings to both stdout and HTML buffer
     */
    private function logFinding($location, $objectName, $issue, $isFixed = false)
    {
        PH::print_stdout("    - [{$location}] Object: {$objectName} | {$issue} " . ($isFixed ? "*FIXED*" : "*FIX_MANUALLY*"));

        $this->htmlOutput[] = [
            'location' => $location,
            'object' => $objectName,
            'issue' => $issue,
            'status' => $isFixed ? 'Fixed' : 'Manual Fix Required'
        ];

        $this->summaryOutput['total_findings']++;
        if ($isFixed) {
            $this->summaryOutput['fixed']++;
        } else {
            $this->summaryOutput['not_fixed']++;
        }
    }

    private function generateHTMLold()
    {
        $html = "<html><head><style>
            table { border-collapse: collapse; width: 100%; margin-bottom: 30px; font-family: sans-serif; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            .fixed { color: green; font-weight: bold; }
            .manual { color: red; font-weight: bold; }
            h2 { font-family: sans-serif; }
        </style></head><body>";

        // Table 1: Detailed Findings
        $html .= "<h2>Detailed Misconfigurations</h2>";
        $html .= "<table><tr><th>Location</th><th>Object</th><th>Issue Description</th><th>Status</th></tr>";

        if (empty($this->htmlOutput)) {
            $html .= "<tr><td colspan='4'>No misconfigurations found.</td></tr>";
        } else {
            foreach ($this->htmlOutput as $row) {
                $class = ($row['status'] == 'Fixed') ? 'fixed' : 'manual';
                $html .= "<tr>
                    <td>{$row['location']}</td>
                    <td>{$row['object']}</td>
                    <td>{$row['issue']}</td>
                    <td class='{$class}'>{$row['status']}</td>
                </tr>";
            }
        }
        $html .= "</table>";

        // Table 2: Summary
        $html .= "<h2>Summary Report</h2>";
        $html .= "<table>
            <tr><th>Metric</th><th>Count</th></tr>
            <tr><td>Total Issues Found</td><td>{$this->summaryOutput['total_findings']}</td></tr>
            <tr><td>Automatically Fixed</td><td class='fixed'>{$this->summaryOutput['fixed']}</td></tr>
            <tr><td>Remaining (Manual Fix)</td><td class='manual'>{$this->summaryOutput['not_fixed']}</td></tr>
        </table>";

        $html .= "</body></html>";

        file_put_contents("xml_issue_report.html", $html);
        PH::print_stdout("\n** HTML Report generated: xml_issue_report.html **\n");
    }

    private function generateHTML()
    {
        $html = "<html><head><style>
            body { font-family: sans-serif; }
            table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            .fixed { color: green; font-weight: bold; }
            .manual { color: red; font-weight: bold; }
        </style></head><body>";

        // Table 1: Detailed Findings (Row by Row)
        $html .= "<h2>Detailed Misconfigurations</h2>";
        $html .= "<table><tr><th>Location</th><th>Object</th><th>Issue</th><th>Status</th></tr>";
        foreach ($this->htmlOutput as $row) {
            $statusClass = ($row['status'] == 'Fixed') ? 'fixed' : 'manual';
            $html .= "<tr><td>{$row['location']}</td><td>{$row['object']}</td><td>{$row['issue']}</td><td class='{$statusClass}'>{$row['status']}</td></tr>";
        }
        $html .= "</table>";

        // Table 2: Detailed Summary (The part you requested)
        $html .= "<h2>Detailed Metric Summary</h2>";
        $html .= "<table><tr><th>Issue Category</th><th>Count</th><th>Type</th></tr>";

        foreach ($this->counters['fixed'] as $name => $count) {
            $html .= "<tr><td>{$name}</td><td>{$count}</td><td class='fixed'>FIXED</td></tr>";
        }
        foreach ($this->counters['manual'] as $name => $count) {
            $html .= "<tr><td>{$name}</td><td>{$count}</td><td class='manual'>FIX_MANUALLY</td></tr>";
        }
        $html .= "</table>";

        // Table 3: Global Totals
        $html .= "<h2>Global Summary</h2>";
        $html .= "<table><tr><th>Metric</th><th>Count</th></tr>
            <tr><td>Total Issues</td><td>{$this->summaryOutput['total_findings']}</td></tr>
            <tr><td>Total Fixed</td><td class='fixed'>{$this->summaryOutput['fixed']}</td></tr>
            <tr><td>Total Manual</td><td class='manual'>{$this->summaryOutput['not_fixed']}</td></tr>
        </table></body></html>";

        file_put_contents("xml_issue_report.html", $html);
        PH::print_stdout("\n** HTML Report generated: xml_issue_report.html **\n");
    }
}