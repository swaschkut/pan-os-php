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
    public $countDuplicateDecryptRuleObjects = 0;

    public $countSecRuleObjectsWithDoubleSpaces = 0;
    public $countSecRuleObjectsWithWrongCharacters = 0;
    public $countNATRuleObjectsWithDoubleSpaces = 0;
    public $countNATRuleObjectsWithWrongCharacters = 0;

    
    public $countDecryptRuleObjectsWithDoubleSpaces = 0;
    public $countDecryptRuleObjectsWithWrongCharacters = 0;
    
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



    public $countMissconfiguredDecryptRuleSourceObjects=0;
    public $fixedDecryptionRuleSourceObjects=0;
    public $countMissconfiguredDecryptRuleDestinationObjects=0;
    public $fixedDecryptionRuleDestinationObjects=0;
    public $countMissconfiguredDecryptRuleServiceObjects=0;
    public $fixedDecryptionRuleServiceObjects=0;


    public $countMissconfiguredappoverrideRuleSourceObjects=0;
    public $fixedappoverrideRuleSourceObjects=0;
    public $countMissconfiguredappoverrideRuleDestinationObjects=0;
    public $fixedappoverrideRuleDestinationObjects=0;


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
    public $fixedExcludeAccessRouteWithSameNode = 0;
    public $fixedRedistRulesWithSameNode = 0;
    public $fixedZoneWithSameNode = 0;

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

        if( isset(PH::$args['projectfolder']) )
        {
            $this->projectFolder = PH::$args['projectfolder'];
            if (!file_exists($this->projectFolder)) {
                mkdir($this->projectFolder, 0777, true);
            }
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
            $decryptrule_name = array();
            $decryptrule_wrong_name = array();

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
                $objectType = "address";
                $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                $text1 = "has lower precedence as REGION object";
                $text1 .= " at XML line #{$node->getLineNo()}";
                $text2 = " ... (*FIX_MANUALLY*)";
                PH::print_stdout( "    - ".$text.$text1.$text2);
                $this->logFinding($locationName, $objectName, $objectType, $text1, false);

                $this->counters['manual']['Address Region misconfiguration'] = ($this->counters['manual']['Address Region misconfiguration'] ?? 0) + 1;
                $this->countMissconfiguredAddressRegionObjects++;
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for address / addressgroup with double spaces in name...");
            foreach( $address_name as $objectName => $node )
            {
                $objectType = "address";
                $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                $text1 = "has '  ' double Spaces in name, this causes problems by copy&past 'set commands'";
                $text1 .= " at XML line #{$node->getLineNo()}";
                $text2 = " ... (*FIX_MANUALLY*)";
                PH::print_stdout( "    - ".$text.$text1.$text2);
                $this->logFinding($locationName, $objectName, $objectType, $text1, false);

                $this->counters['manual'][$objectType.' Objects doubleSpace'] = ($this->counters['manual'][$objectType.' Objects doubleSpace'] ?? 0) + 1;
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

                $objectType = "address";
                $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                $text1 = "has wrong characters in name, '".implode('', $findings)."' this causes commit issues";
                $text1 .= " at XML line #{$node->getLineNo()}";
                $text2 = " ... (*FIX_MANUALLY*)";
                PH::print_stdout( "    - ".$text.$text1.$text2);
                $this->logFinding($locationName, $objectName, $objectType, $text1, false);

                $newName = $objectName;
                foreach( $findings as $replace )
                    $newName = str_replace($replace, "_", $newName);

                PH::print_stdout( "       oldname: '".$objectName."' | suggested newname: '".$newName."'\n" );
                //xml-issue can not work on objects here :-)
                //not possible to replace all references at this stage
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
                        $objectType = "address";
                        $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                        $text1 = "has missing IP configuration";
                        $text1 .= " at XML line #{$node->getLineNo()}";
                        $text2 = " ... (*FIX_MANUALLY*)";
                        PH::print_stdout( "    - ".$text.$text1.$text2);
                        $this->logFinding($locationName, $objectName, $objectType, $text1, false);

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
                        $objectType = "addressgroup";
                        $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                        $text1 = "has no member";
                        $text1 .= " at XML line #{$node->getLineNo()}";
                        $text2 = " ... (*FIX_MANUALLY*)";
                        PH::print_stdout( "    - ".$text.$text1.$text2);
                        $this->logFinding($locationName, $objectName, $objectType, $text1, false);

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
                            $objectType = "addressgroup";
                            $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                            $text1 = "has a duplicate member named '{$memberName}'";

                            $this->logFinding($locationName, $objectName, $objectType, $text1, true);

                            $text2 = " ... *FIXED*";
                            PH::print_stdout( "    - ".$text.$text1.$text2);

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
                            $staticNodeMember->parentNode->removeChild($staticNodeMember);

                            $objectType = "addressgroup";
                            $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                            $text1 = "has itself as member '{$memberName}'";

                            $text2 = " ... *FIXED*";
                            PH::print_stdout( "    - ".$text.$text1.$text2);

                            $this->logFinding($locationName, $objectName, $objectType, $text1, true);

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
                        $node = reset( $tagArray );
                        $node->parentNode->removeChild($node);

                        $objectType = "addressgroup";
                        $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                        $text1 = "has its own filter as tag: '{$memberName}'";

                        $text2 = " ... *FIXED*";
                        PH::print_stdout( "    - ".$text.$text1.$text2);

                        $this->logFinding($locationName, $objectName, $objectType, $text1, true);

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
                            $value->parentNode->removeChild($value);

                            $objectType = "addressgroup";
                            $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                            $text1 = "has its own filter as tag: '{$memberName}'";

                            $text2 = " ... *FIXED*";
                            PH::print_stdout( "    - ".$text.$text1.$text2);

                            $this->logFinding($locationName, $objectName, $objectType, $text1, true);

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
                                $tagNodeMember->parentNode->removeChild($tagNodeMember);

                                $objectType = "addressgroup";
                                $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                                $text1 = "has its own filter as tag: '{$memberName}'";

                                $text2 = " ... *FIXED*";
                                PH::print_stdout( "    - ".$text.$text1.$text2);

                                $this->logFinding($locationName, $objectName, $objectType, $text1, true);

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

                $objectType = "address";
                $text = $objectType." '{$objectName}' that exists " . $dupCount . " time";
                $text2 = " ... (*FIX_MANUALLY*)";
                PH::print_stdout( "   - ".$text.$text2);

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
                        $text = "type 'Address' value: '" . $ip_netmaskNode->nodeValue . "'";
                        $text .= " at XML line #{$objectNode->getLineNo()}";

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

                            $this->logFinding($locationName, $objectName, $objectType, $text, true);
                            $text .= PH::boldText(" (removed)");

                            $this->countDuplicateAddressObjects--;
                            $this->counters['fixed']['Address Object duplicate'] = ($this->counters['fixed']['Address Object duplicate'] ?? 0) + 1;
                            $this->fixedDuplicateAddressObjects++;
                        }
                        PH::print_stdout( "       - ".$text );
                    }
                    elseif( $ip_fqdnNode !== FALSE )
                    {
                        /** @var DOMElement $objectNode */

                        $text = "type 'Address' value: '" . $ip_fqdnNode->nodeValue . "' ";
                        $text .= "at XML line #{$objectNode->getLineNo()}";

                        $this->logFinding($locationName, $objectName, $objectType, $text, false);

                        PH::print_stdout( "       - ".$text );

                        $this->counters['manual']['Address Object duplicate'] = ($this->counters['manual']['Address Object duplicate'] ?? 0) + 1;

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
                    $objectType = "addressgroup";
                    $text = $objectType." ";
                    $text .= "at XML line #{$objectNode->getLineNo()}";

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

                        $this->logFinding($locationName, $objectName, $objectType, $text, true);
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
                $objectType = "service";
                $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                $text1 = "has '  ' double Spaces in name, this causes problems by copy&past 'set commands'";
                $text1 .= " at XML line #{$node->getLineNo()}";

                $this->logFinding($locationName, $objectName, $objectType, $text1, false);
                $text2 = " ... (*FIX_MANUALLY*)";
                PH::print_stdout( "    - ".$text.$text1.$text2 );

                $this->counters['manual'][$objectType.' Objects doubleSpace'] = ($this->counters['manual'][$objectType.' Objects doubleSpace'] ?? 0) + 1;
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

                $objectType = "service";
                $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                $text1 = "has wrong characters in name, '".implode('', $findings)."' this causes commit issues";
                $text1 .= " at XML line #{$node->getLineNo()}";
                $this->logFinding($locationName, $objectName, $objectType, $text, false);
                $text2 = " ... (*FIX_MANUALLY*)";
                PH::print_stdout( "    - ".$text.$text1.$text2 );

                $newName = $objectName;
                foreach( $findings as $replace )
                    $newName = str_replace($replace, "_", $newName);

                PH::print_stdout( "       oldname: '".$objectName."' | suggested newname: '".$newName."'\n" );

                $this->counters['manual']['Service Objects wrongCharacters'] = ($this->counters['manual']['Service Objects wrongCharacters'] ?? 0) + 1;

                $this->countServiceObjectsWithWrongCharacters++;
            }

            //
            //
            //
            PH::print_stdout( " - Scanning for service / servicegroup with application-default as name...");
            foreach( $service_name_appdefault as $objectName => $node )
            {
                //PH::print_stdout( "    - service object '{$objectName}' from DG/VSYS {$locationName} has name 'application-default' this causes problems with the default behaviour of the firewall ... (*FIX_MANUALLY*) at XML line #{$node->getLineNo()}");
                $objectType = "service";
                $text = $objectType." 'application-default' from DG/VSYS {$locationName} ";
                $text1 = "has name 'application-default' this causes problems with the default behaviour of the firewall";
                $text1 .= " at XML line #{$node->getLineNo()}";
                $text2 = " ... (*FIX_MANUALLY*)";
                PH::print_stdout( "    - ".$text.$text1.$text2 );

                $this->logFinding($locationName, $objectName, $objectType, $text1, false);

                $this->counters['manual']['Service Objects appdefault'] = ($this->counters['manual']['Service Objects appdefault'] ?? 0) + 1;

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
                        $objectType = "service";
                        $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                        $text1 = "has missing protocol configuration";
                        $text1 .= " at XML line #{$node->getLineNo()}";
                        $text2 = " ... (*FIX_MANUALLY*)";
                        PH::print_stdout( "    - ".$text.$text1.$text2 );

                        $this->logFinding($locationName, $objectName, $objectType, $text1, false);

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
                                $tagNodeMember->parentNode->removeChild($tagNodeMember);

                                $objectType = "service";
                                $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                                $text1 = "has duplicate TAG: ".$tagName." configured";

                                $this->logFinding($locationName, $objectName, $objectType, $text1, true);

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
                        $objectType = "servicegroup";
                        $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                        $text1 = "has no member";
                        $text1 .= " at XML line #{$node->getLineNo()}";
                        $text2 = " ... (*FIX_MANUALLY*)";
                        PH::print_stdout( "    - ".$text.$text1.$text2 );

                        $this->logFinding($locationName, $objectName, $objectType, $text1, false);

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
                            $objectType = "servicegroup";
                            $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                            $text1 = "has a duplicate member named '{$memberName}'";

                            $nodesToRemove[] = $staticNodeMember;
                            $this->logFinding($locationName, $objectName, $objectType, $text1, true);

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
                            $staticNodeMember->parentNode->removeChild($staticNodeMember);

                            $objectType = "servicegroup";
                            $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                            $text1 = "has itself as member '{$memberName}'";

                            $this->logFinding($locationName, $objectName, $objectType, $text, true);

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
                    $objectType = "service";
                    $text = $objectType."  value: '" . $protocolNode->nodeValue . "' at XML line #{$objectNode->getLineNo()}";

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

                        $this->logFinding($locationName, $objectName, $objectType, $text, true);
                        $text .= PH::boldText(" (removed)");

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
                    $objectType = "servicegroup";
                    $text = $objectType."  at XML line #{$objectNode->getLineNo()}";

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

                        $this->logFinding($locationName, $objectName, $objectType, $text, true);
                        $text .= PH::boldText(" (removed)");

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

                $decryptRules = array();
                $decryptRuleIndex = array();
                $appoverrideRules = array();
                $appoverrideRuleIndex = array();

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

                $decryptRuleSourceIndex = array();
                $decryptRuleDestinationIndex = array();
                $decryptRuleServiceIndex = array();

                $appoverrideRuleSourceIndex = array();
                $appoverrideRuleDestinationIndex = array();

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
                                            $objectNode_services->removeChild($objectService);

                                            //Secrule service has twice same service added
                                            $objectType = "SecRule";
                                            $text = $objectType." '".$objectName."' has same service defined twice: ".$objectServiceName;
                                            $this->logFinding($locationName, $objectName, $objectType, $text, true);
                                            $text2 = PH::boldText(" (removed)");
                                            PH::print_stdout( "     - ".$text.$text2 );

                                            $this->counters['fixed'][$objectType.' Service Object duplicate'] = ($this->counters['fixed'][$objectType.' Service Object duplicate'] ?? 0) + 1;
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
                                                $objectNode_tags->removeChild($objectTag);

                                                //Secrule service has twice same service added
                                                $objectType = "SecRule";
                                                $text = $objectType." ".$objectName." has same tag defined twice: ".$objectTagName;
                                                $this->logFinding($locationName, $objectName, $objectType, $text, true);
                                                $text2 = PH::boldText(" (removed)");
                                                PH::print_stdout( "     - ".$text.$text2 );

                                                $this->counters['fixed'][$objectType.' Tag Object duplicate'] = ($this->counters['fixed'][$objectType.' Tag Object duplicate'] ?? 0) + 1;
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
                                            $objectNode_applications->removeChild($objectApplication);

                                            $objectType = "SecRule";
                                            $text = $objectType." ".$objectName." has same application defined twice: ".$objectApplicationName;
                                            $this->logFinding($locationName, $objectName, $objectType, $text, true);
                                            $text2 = PH::boldText(" (removed)");
                                            PH::print_stdout( "     - ".$text.$text2 );

                                            $this->counters['fixed'][$objectType.' Application Object duplicate'] = ($this->counters['fixed'][$objectType.' Application Object duplicate'] ?? 0) + 1;
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
                                                $objectNode_category->removeChild($objectCategory);

                                                $objectType = "SecRule";
                                                $text = $objectType." ".$objectName." has same category defined twice: ".$objectCategoryName;
                                                $this->logFinding($locationName, $objectName, $objectType, $text, true);
                                                $text2 = PH::boldText(" (removed)");
                                                PH::print_stdout( "     - ".$text.$text2 );

                                                $this->counters['fixed'][$objectType.' Category Object duplicate'] = ($this->counters['fixed'][$objectType.' Category Object duplicate'] ?? 0) + 1;
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
                                            $objectNode_sources->removeChild($objectSource);

                                            $objectType = "SecRule";
                                            $text = $objectType." ".$objectName." has same source defined twice: ".$objectSourceName;
                                            $this->logFinding($locationName, $objectName, $objectType, $text, true);
                                            $text2 = PH::boldText(" (removed)");
                                            PH::print_stdout( "     - ".$text.$text2 );

                                            $this->counters['fixed'][$objectType.' Source Object duplicate'] = ($this->counters['fixed'][$objectType.' Source Object duplicate'] ?? 0) + 1;
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
                                            $objectNode_destinations->removeChild($objectDestination);

                                            $objectType = "SecRule";
                                            $text = $objectType." ".$objectName." has same destination defined twice: ".$objectDestinationName;
                                            $this->logFinding($locationName, $objectName, $objectType, $text, true);
                                            $text2 = PH::boldText(" (removed)");
                                            PH::print_stdout( "     - ".$text.$text2 );

                                            $this->counters['fixed'][$objectType.' Destination Object duplicate'] = ($this->counters['fixed'][$objectType.' Destination Object duplicate'] ?? 0) + 1;
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
                                            $objectNode_froms->removeChild($objectFrom);

                                            $objectType = "SecRule";
                                            $text = $objectType." ".$objectName." has same from defined twice: ".$objectFromName;
                                            $this->logFinding($locationName, $objectName, $objectType, $text, true);
                                            $text2 = PH::boldText(" (removed)");
                                            PH::print_stdout( "     - ".$text.$text2 );

                                            $this->counters['fixed'][$objectType.' From Object duplicate'] = ($this->counters['fixed'][$objectType.' From Object duplicate'] ?? 0) + 1;
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
                                            $objectNode_tos->removeChild($objectTo);

                                            $objectType = "SecRule";
                                            $text = $objectType." ".$objectName." has same to defined twice: ".$objectToName;
                                            $this->logFinding($locationName, $objectName, $objectType, $text, true);
                                            $text2 = PH::boldText(" (removed)");
                                            PH::print_stdout( "     - ".$text.$text2 );

                                            $this->counters['fixed'][$objectType.' To Object duplicate'] = ($this->counters['fixed'][$objectType.' To Object duplicate'] ?? 0) + 1;
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
                                                $objectNode_source_users->removeChild($objectSourceUser);

                                                $objectType = "SecRule";
                                                $text = $objectType." ".$objectName." has same source-user defined twice: ".$objectSourceUserName;
                                                $this->logFinding($locationName, $objectName, $objectType, $text, true);
                                                $text2 = PH::boldText(" (removed)");
                                                PH::print_stdout( "     - ".$text.$text2 );

                                                $this->counters['fixed'][$objectType.' SourceUser Object duplicate'] = ($this->counters['fixed'][$objectType.' SourceUser Object duplicate'] ?? 0) + 1;
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
                                            $objectNode_sources->removeChild($objectSource);

                                            $objectType = "NatRule";
                                            $text = $objectType." ".$objectName." has same source defined twice: ".$objectSourceName;
                                            $this->logFinding($locationName, $objectName, $objectType, $text, true);
                                            $text2 = PH::boldText(" (removed)");
                                            PH::print_stdout( "     - ".$text.$text2 );

                                            $this->counters['fixed'][$objectType.' Source Object duplicate'] = ($this->counters['fixed'][$objectType.' Source Object duplicate'] ?? 0) + 1;
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
                                            $objectNode_destinations->removeChild($objectDestination);

                                            $objectType = "NatRule";
                                            $text = $objectType." ".$objectName." has same destination defined twice: ".$objectDestinationName;
                                            $this->logFinding($locationName, $objectName, $objectType, $text, true);
                                            $text2 = PH::boldText(" (removed)");
                                            PH::print_stdout( "     - ".$text.$text2 );

                                            $this->counters['fixed'][$objectType.' Destination Object duplicate'] = ($this->counters['fixed'][$objectType.' Destination Object duplicate'] ?? 0) + 1;
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
                        elseif( $objectNode_ruletype->nodeName == "decryption" )
                        {

                            $objectTypeNode = DH::findFirstElement('rules', $objectNode_ruletype);
                            if( $objectTypeNode !== FALSE )
                            {
                                foreach( $objectTypeNode->childNodes as $objectNode )
                                {
                                    $RuleSource = array();
                                    $RuleDestination = array();
                                    $RuleService = array();

                                    /** @var DOMElement $objectNode */
                                    if( $objectNode->nodeType != XML_ELEMENT_NODE )
                                        continue;

                                    $objectName = $objectNode->getAttribute('name');

                                    $this->check_name( $objectName, $objectNode, $decryptrule_name );
                                    $this->check_wrong_name( $objectName, $objectNode, $decryptrule_wrong_name );

                                    $decryptRules[$objectName][] = $objectNode;

                                    if( !isset($RuleIndex[$objectName]) )
                                        $RuleIndex[$objectName] = array('regular' => array(), 'group' => array());

                                    $decryptRuleIndex[$objectName]['regular'][] = $objectNode;


                                    //check if source has 'any' and additional
                                    $objectNode_sources = DH::findFirstElement('source', $objectNode);
                                    $demo = iterator_to_array($objectNode_sources->childNodes);
                                    foreach( $demo as $objectSource )
                                    {
                                        /** @var DOMElement $objectSource */
                                        if( $objectSource->nodeType != XML_ELEMENT_NODE )
                                            continue;

                                        $objectSourceName = $objectSource->textContent;
                                        if( isset($decryptRuleSource[$objectSourceName]) )
                                        {
                                            $objectNode_sources->removeChild($objectSource);

                                            $objectType = "DecryptionRule";
                                            $text = $objectType." ".$objectName." has same source defined twice: ".$objectSourceName;
                                            $this->logFinding($locationName, $objectName, $objectType, $text, true);
                                            $text2 = PH::boldText(" (removed)");
                                            PH::print_stdout( "     - ".$text.$text2 );

                                            $this->counters['fixed'][$objectType.' Source Object duplicate'] = ($this->counters['fixed'][$objectType.' Source Object duplicate'] ?? 0) + 1;
                                            $this->fixedDecryptionRuleSourceObjects++;
                                        }
                                        else
                                        {
                                            $decryptRuleSource[$objectSourceName] = $objectSource;
                                            #PH::print_stdout( $objectName.'add to array: '.$objectSourceName );
                                        }

                                    }
                                    if( isset($decryptRuleSource['any']) and count($decryptRuleSource) > 1 )
                                    {
                                        $decryptRuleSourceIndex[$objectName] = $decryptRuleSource['any'];
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
                                        if( isset($decryptRuleDestination[$objectDestinationName]) )
                                        {
                                            $objectNode_destinations->removeChild($objectDestination);

                                            $objectType = "DecryptionRule";
                                            $text = $objectType." ".$objectName." has same destination defined twice: ".$objectDestinationName;
                                            $this->logFinding($locationName, $objectName, $objectType, $text, true);
                                            $text2 = PH::boldText(" (removed)");
                                            PH::print_stdout( "     - ".$text.$text2 );

                                            $this->counters['fixed'][$objectType.' Destination Object duplicate'] = ($this->counters['fixed'][$objectType.' Destination Object duplicate'] ?? 0) + 1;
                                            $this->fixedDecryptionRuleDestinationObjects++;
                                        }
                                        else
                                            $decryptRuleDestination[$objectDestinationName] = $objectDestination;
                                    }


                                    if( isset($decryptRuleDestination['any']) and count($decryptRuleDestination) > 1 )
                                    {
                                        $decryptRuleDestinationIndex[$objectName] = $decryptRuleDestination['any'];
                                        #PH::print_stdout( "     - Rule: '".$objectName."' has application 'any' + something else defined.") ;
                                    }

                                    //Todo:
                                    //check if service has 'application-default' and additional
                                    $objectNode_services = DH::findFirstElement('service', $objectNode);
                                    if( $objectNode_services === False )
                                        continue;
                                    $demo = iterator_to_array($objectNode_services->childNodes);
                                    foreach( $demo as $objectService )
                                    {
                                        /** @var DOMElement $objectService */
                                        if( $objectService->nodeType != XML_ELEMENT_NODE )
                                            continue;

                                        $objectServiceName = $objectService->textContent;
                                        if( isset($decryptRuleServices[$objectServiceName]) )
                                        {
                                            $objectNode_services->removeChild($objectService);

                                            //Secrule service has twice same service added
                                            $objectType = "DecryptionRule";
                                            $text = $objectType." '".$objectName."' has same service defined twice: ".$objectServiceName;
                                            $this->logFinding($locationName, $objectName, $objectType, $text, true);
                                            $text2 = PH::boldText(" (removed)");
                                            PH::print_stdout( "     - ".$text.$text2 );

                                            $this->counters['fixed'][$objectType.' Service Object duplicate'] = ($this->counters['fixed'][$objectType.' Service Object duplicate'] ?? 0) + 1;
                                            $this->fixedDecryptionRuleServiceObjects++;
                                        }
                                        else
                                            $decryptRuleServices[$objectServiceName] = $objectService;
                                    }
                                }

                            }


                            PH::print_stdout( " - parsed " . count($decryptRules) . " decryption Rules");
                            PH::print_stdout( "");
                        }
                        elseif( $objectNode_ruletype->nodeName == "application-override" )
                        {
                            $objectTypeNode = DH::findFirstElement('rules', $objectNode_ruletype);
                            if( $objectTypeNode !== FALSE )
                            {
                                foreach( $objectTypeNode->childNodes as $objectNode )
                                {
                                    $appoverrideRuleSource = array();
                                    $appoverrideRuleDestination = array();

                                    /** @var DOMElement $objectNode */
                                    if( $objectNode->nodeType != XML_ELEMENT_NODE )
                                        continue;

                                    $objectName = $objectNode->getAttribute('name');

                                    $this->check_name( $objectName, $objectNode, $appoverriderule_name );
                                    $this->check_wrong_name( $objectName, $objectNode, $appoverriderule_wrong_name );

                                    $appoverrideRules[$objectName][] = $objectNode;

                                    if( !isset($appoverrideRuleIndex[$objectName]) )
                                        $appoverrideRuleIndex[$objectName] = array('regular' => array(), 'group' => array());

                                    $appoverrideRuleIndex[$objectName]['regular'][] = $objectNode;


                                    //check if source has 'any' and additional
                                    $objectNode_sources = DH::findFirstElement('source', $objectNode);
                                    $demo = iterator_to_array($objectNode_sources->childNodes);
                                    foreach( $demo as $objectSource )
                                    {
                                        /** @var DOMElement $objectSource */
                                        if( $objectSource->nodeType != XML_ELEMENT_NODE )
                                            continue;

                                        $objectSourceName = $objectSource->textContent;
                                        if( isset($appoverrideRuleSource[$objectSourceName]) )
                                        {
                                            $objectNode_sources->removeChild($objectSource);

                                            $objectType = "AppOverrideRule";
                                            $text = $objectType." ".$objectName." has same source defined twice: ".$objectSourceName;
                                            $this->logFinding($locationName, $objectName, $objectType, $text, true);
                                            $text2 = PH::boldText(" (removed)");
                                            PH::print_stdout( "     - ".$text.$text2 );

                                            $this->counters['fixed'][$objectType.' Source Object duplicate'] = ($this->counters['fixed'][$objectType.' Source Object duplicate'] ?? 0) + 1;
                                            $this->fixedappoverrideRuleSourceObjects++;
                                        }
                                        else
                                        {
                                            $appoverrideRuleSource[$objectSourceName] = $objectSource;
                                            #PH::print_stdout( $objectName.'add to array: '.$objectSourceName );
                                        }

                                    }
                                    if( isset($appoverrideRuleSource['any']) and count($appoverrideRuleSource) > 1 )
                                    {
                                        $appoverrideRuleSourceIndex[$objectName] = $appoverrideRuleSource['any'];
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
                                        if( isset($appoverrideRuleDestination[$objectDestinationName]) )
                                        {
                                            $objectNode_destinations->removeChild($objectDestination);

                                            $objectType = "AppOverrideRule";
                                            $text = $objectType." ".$objectName." has same destination defined twice: ".$objectDestinationName;
                                            $this->logFinding($locationName, $objectName, $objectType, $text, true);
                                            $text2 = PH::boldText(" (removed)");
                                            PH::print_stdout( "     - ".$text.$text2 );

                                            $this->counters['fixed'][$objectType.' Destination Object duplicate'] = ($this->counters['fixed'][$objectType.' Destination Object duplicate'] ?? 0) + 1;
                                            $this->fixedappoverrideRuleDestinationObjects++;
                                        }
                                        else
                                            $appoverrideRuleDestination[$objectDestinationName] = $objectDestination;
                                    }

                                    if( isset($appoverrideRuleDestination['any']) and count($appoverrideRuleDestination) > 1 )
                                    {
                                        $appoverrideRuleDestinationIndex[$objectName] = $appoverrideRuleDestination['any'];
                                        #PH::print_stdout( "     - Rule: '".$objectName."' has application 'any' + something else defined.") ;
                                    }

                                }

                            }


                            PH::print_stdout( " - parsed " . count($appoverrideRules) . " Application-Override Rules");
                            PH::print_stdout( "");
                        }
                    }

                    //
                    //
                    //
                    PH::print_stdout( " - Scanning for Security Rules with double spaces in name...");
                    foreach( $secrule_name as $objectName => $node )
                    {
                        $objectType = "SecRule";
                        $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                        $text1 = "has '  ' double Spaces in name, this causes problems by copy&past 'set commands'";
                        $text1 .= " at XML line #{$node->getLineNo()}";
                        $text2 = " ... (*FIX_MANUALLY*)";

                        $this->logFinding($locationName, $objectName, $objectType, $text1, false);
                        PH::print_stdout( "    - ".$text.$text1.$text2);

                        $this->counters['manual'][$objectType.' Name doubleSpace'] = ($this->counters['manual'][$objectType.' Name doubleSpace'] ?? 0) + 1;
                        $this->countSecRuleObjectsWithDoubleSpaces++;
                    }

                    PH::print_stdout( " - Scanning for Security Rules with wrong characters in name...");
                    foreach( $secrule_wrong_name as $objectName => $node )
                    {
                        $objectType = "SecRule";
                        $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                        $text1 = "has wrong characters in name";
                        $text1 .= " at XML line #{$node->getLineNo()}";
                        $text2 = " ... (*FIX_MANUALLY*)";

                        $this->logFinding($locationName, $objectName, $objectType, $text1, false);
                        PH::print_stdout( "    - ".$text.$text1.$text2);

                        $this->counters['fixed'][$objectType.' Name wrongCharacter'] = ($this->counters['fixed'][$objectType.' Name wrongCharacter'] ?? 0) + 1;
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
                            $objectType = "SecRule";
                            $text = $objectType." at XML line #{$objectNode->getLineNo()}";

                            $newName = $key . $objectNode->getAttribute('name');
                            if( !isset($secRuleIndex[$newName]) )
                            {
                                $objectNode->setAttribute('name', $newName);
                                $text2 = " - new name: " . $newName . " (fixed)";
                                $this->logFinding($locationName, $objectName, $objectType, $text.$text2, true);
                                $text2 = PH::boldText($text2);
                                PH::print_stdout( "       - ".$text.$text2 );
                            }
                            else
                            {
                                $text .= " - Rulename can not be fixed: '" . $newName . "' is also available";
                                $this->logFinding($locationName, $objectName, $objectType, $text, false);
                                PH::print_stdout( "       - ".$text );
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
                        $objectType = "NatRule";
                        $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                        $text1 = "has '  ' double Spaces in name, this causes problems by copy&past 'set commands'";

                        $text1 .= " at XML line #{$node->getLineNo()}";
                        $text2 = " ... (*FIX_MANUALLY*)";

                        $this->logFinding($locationName, $objectName, $objectType, $text1, false);
                        PH::print_stdout( "    - ".$text.$text1.$text2);

                        $this->counters['manual']['NatRule Name doubleSpace'] = ($this->counters['manual']['NatRule Name doubleSpace'] ?? 0) + 1;
                        $this->countNATRuleObjectsWithDoubleSpaces++;
                    }
                    PH::print_stdout( " - Scanning for NAT Rules with wrong characters in name...");
                    foreach( $natrule_wrong_name as $objectName => $node )
                    {
                        $objectType = "NatRule";
                        $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                        $text1 = "has wrong characters in name";
                        $text1 .= " at XML line #{$node->getLineNo()}";
                        $text2 = " ... (*FIX_MANUALLY*)";
                        $this->logFinding($locationName, $objectName, $objectType, $text.$text1, false);

                        PH::print_stdout( "    - ".$text.$text1.$text2);

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
                            $objectType = "NatRule";
                            $text = $objectType." at XML line #{$objectNode->getLineNo()}";


                            $newName = $key . $objectNode->getAttribute('name');
                            if( !isset($natRuleIndex[$newName]) )
                            {
                                $objectNode->setAttribute('name', $newName);
                                $text .= PH::boldText(" - new name: " . $newName . " (fixed)\n");
                                $this->logFinding($locationName, $objectName, $objectType, $text, true);
                                PH::print_stdout( "       - ".$text );
                            }
                            else
                            {
                                $text .= " - Rulename can not be fixed: '" . $newName . "' is also available";
                                $this->logFinding($locationName, $objectName, $objectType, $text, false);
                                PH::print_stdout( "       - ".$text );
                            }

                            $this->counters['manual']['NatRule duplicate'] = ($this->counters['manual']['NatRule duplicate'] ?? 0) + 1;
                            $this->countDuplicateNATRuleObjects++;
                        }
                    }

                    //
                    //
                    //
                    PH::print_stdout( " - Scanning for Decryption Rules with double spaces in name...");
                    foreach( $decryptrule_name as $objectName => $node )
                    {
                        $objectType = "DecryptRule";
                        $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                        $text1 = "has '  ' double Spaces in name, this causes problems by copy&past 'set commands'";

                        $text1 .= " at XML line #{$node->getLineNo()}";
                        $text2 = " ... (*FIX_MANUALLY*)";

                        $this->logFinding($locationName, $objectName, $objectType, $text1, false);
                        PH::print_stdout( "    - ".$text.$text1.$text2);

                        $this->counters['manual'][$objectType.' Name doubleSpace'] = ($this->counters['manual'][$objectType.' Name doubleSpace'] ?? 0) + 1;
                        $this->countDecryptRuleObjectsWithDoubleSpaces++;
                    }
                    PH::print_stdout( " - Scanning for Decryption Rules with wrong characters in name...");
                    foreach( $decryptrule_wrong_name as $objectName => $node )
                    {
                        $objectType = "DecryptionRule";
                        $text = $objectType." '{$objectName}' from DG/VSYS {$locationName} ";
                        $text1 = "has wrong characters in name";
                        $text1 .= " at XML line #{$node->getLineNo()}";
                        $text2 = " ... (*FIX_MANUALLY*)";
                        $this->logFinding($locationName, $objectName, $objectType, $text.$text1, false);

                        PH::print_stdout( "    - ".$text.$text1.$text2);

                        $this->counters['manual'][$objectType.' Name wrongCharacter'] = ($this->counters['manual'][$objectType.' Name wrongCharacter'] ?? 0) + 1;
                        $this->countDecryptRuleObjectsWithWrongCharacters++;
                    }

                    PH::print_stdout( "\n - Scanning for duplicate Decryption Rules...");
                    foreach( $decryptRuleIndex as $objectName => $objectNodes )
                    {
                        $dupCount = count($objectNodes['regular']);

                        if( $dupCount < 2 )
                            continue;

                        PH::print_stdout( "   - found Decryption Rule named '{$objectName}' that exists " . $dupCount . " time:");
                        $tmp_natrule_array = array();
                        foreach( $objectNodes['regular'] as $key => $objectNode )
                        {

                            /** @var DOMElement $objectNode */
                            $objectType = "DecryptionRule";
                            $text = $objectType." at XML line #{$objectNode->getLineNo()}";


                            $newName = $key . $objectNode->getAttribute('name');
                            if( !isset($natRuleIndex[$newName]) )
                            {
                                $objectNode->setAttribute('name', $newName);
                                $text .= PH::boldText(" - new name: " . $newName . " (fixed)\n");
                                $this->logFinding($locationName, $objectName, $objectType, $text, true);
                                PH::print_stdout( "       - ".$text );
                            }
                            else
                            {
                                $text .= " - Rulename can not be fixed: '" . $newName . "' is also available";
                                $this->logFinding($locationName, $objectName, $objectType, $text, false);
                                PH::print_stdout( "       - ".$text );
                            }

                            $this->counters['manual'][$objectType.' duplicate'] = ($this->counters['manual'][$objectType.' duplicate'] ?? 0) + 1;
                            $this->countDuplicateDecryptRuleObjects++;
                        }
                    }

                    //
                    //
                    //

                    PH::print_stdout( "\n - Scanning for misconfigured From Field in Security Rules...");
                    foreach( $secRuleFromIndex as $objectName => $objectNode )
                    {
                        $objectType = "SecRule";
                        $text = $objectType." named '{$objectName}' that has from 'any' and additional from configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( "   - ".$text );
                        $this->logFinding($locationName, $objectName, $objectType, $text, false);

                        $this->counters['manual']['SecRule From misconfigured'] = ($this->counters['manual']['SecRule From misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredSecRuleFromObjects++;
                    }

                    PH::print_stdout( " - Scanning for misconfigured To Field in Security Rules...");
                    foreach( $secRuleToIndex as $objectName => $objectNode )
                    {
                        $objectType = "SecRule";
                        $text = $objectType." named '{$objectName}' that has to 'any' and additional to configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( "   - ".$text );
                        $this->logFinding($locationName, $objectName, $objectType, $text, false);

                        $this->counters['manual']['SecRule To misconfigured'] = ($this->counters['manual']['SecRule To misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredSecRuleToObjects++;
                    }

                    PH::print_stdout( "\n - Scanning for misconfigured Source Field in Security Rules...");
                    foreach( $secRuleSourceIndex as $objectName => $objectNode )
                    {
                        $objectType = "SecRule";
                        $text = $objectType." named '{$objectName}' that has source 'any' and additional source configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( $text);
                        $this->logFinding($locationName, $objectName, $objectType, $text, false);

                        $this->counters['manual']['SecRule Source misconfigured'] = ($this->counters['manual']['SecRule Source misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredSecRuleSourceObjects++;
                    }

                    PH::print_stdout( " - Scanning for misconfigured Destination Field in Security Rules...");
                    foreach( $secRuleDestinationIndex as $objectName => $objectNode )
                    {
                        $objectType = "SecRule";
                        $text = $objectType." named '{$objectName}' that has destination 'any' and additional destination configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( "   - ".$text);
                        $this->logFinding($locationName, $objectName, $objectType, $text, false);

                        $this->counters['manual']['SecRule Destination misconfigured'] = ($this->counters['manual']['SecRule Destination misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredSecRuleDestinationObjects++;
                    }

                    PH::print_stdout( " - Scanning for misconfigured Service Field in Security Rules...");
                    foreach( $secRuleServiceIndex as $objectName => $objectNode )
                    {
                        $objectType = "SecRule";
                        $text = $objectType." named '{$objectName}' that has service 'application-default' and an additional service configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( "   - ".$text);
                        $this->logFinding($locationName, $objectName, $objectType, $text, false);

                        $this->counters['manual']['SecRule Service misconfigured'] = ($this->counters['manual']['SecRule Service misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredSecRuleServiceObjects++;
                    }


                    PH::print_stdout( " - Scanning for misconfigured Application Field in Security Rules...");
                    foreach( $secRuleApplicationIndex as $objectName => $objectNode )
                    {
                        $objectType = "SecRule";
                        $text = $objectType." named '{$objectName}' that has application 'any' and additional application configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( "   - ".$text);
                        $this->logFinding($locationName, $objectName, $objectType, $text, false);

                        $this->counters['manual']['SecRule Application misconfigured'] = ($this->counters['manual']['SecRule Application misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredSecRuleApplicationObjects++;
                    }

                    PH::print_stdout( " - Scanning for misconfigured Category Field in Security Rules...");
                    foreach( $secRuleCategoryIndex as $objectName => $objectNode )
                    {
                        #PH::print_stdout( "   - found Security Rule named '{$objectName}' that has XML element 'category' but not child element 'member' configured at XML line #{$objectNode->getLineNo()}");
                        $objectType = "SecRule";
                        $text = $objectType." named '{$objectName}' that has category 'any' and additional category configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( "   - ".$text);
                        $this->logFinding($locationName, $objectName, $objectType, $text, false);

                        $this->counters['manual']['SecRule Category misconfigured'] = ($this->counters['manual']['SecRule Categroy misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredSecRuleCategoryObjects++;
                    }

                    PH::print_stdout( " - Scanning for misconfigured SourceUser Field in Security Rules...");
                    foreach( $secRuleSourceUserIndex as $objectName => $objectNode )
                    {
                        $objectType = "SecRule";
                        $text = $objectType." named '{$objectName}' that has source-user 'any' and additional source-user configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( "   - ".$text);
                        $this->logFinding($locationName, $objectName, $objectType, $text, false);

                        $this->counters['manual']['SecRule SourceUser misconfigured'] = ($this->counters['manual']['SecRule SourceUser misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredSecruleSourceUserObjects++;
                    }

                    PH::print_stdout( "\n - Scanning for misconfigured Source Field in NAT Rules...");
                    foreach( $natRuleSourceIndex as $objectName => $objectNode )
                    {
                        $objectType = "NatRule";
                        $text = $objectType." named '{$objectName}' that has source 'any' and additional source configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( "   - ".$text);
                        $this->logFinding($locationName, $objectName, $objectType, $text, false);

                        $this->counters['manual']['NatRule Source misconfigured'] = ($this->counters['manual']['NatRule Source misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredNatRuleSourceObjects++;
                    }

                    PH::print_stdout( " - Scanning for misconfigured Destination Field in NAT Rules...");
                    foreach( $natRuleDestinationIndex as $objectName => $objectNode )
                    {
                        $objectType = "NatRule";
                        $text = $objectType." named '{$objectName}' that has destination 'any' and additional destination configured at XML line #{$objectNode->getLineNo()}";
                        PH::print_stdout( "   - ".$text);
                        $this->logFinding($locationName, $objectName, $objectType, $text, false);

                        $this->counters['manual']['NatRule Destination misconfigured'] = ($this->counters['manual']['NatRule Destination misconfigured'] ?? 0) + 1;
                        $this->countMissconfiguredNatRuleDestinationObjects++;
                    }

                    if( $this->service_app_default_available )
                    {
                        PH::print_stdout( " - Scanning for Security Rules with 'application-default' set | service object 'application-default' is available ...");
                        foreach( $secRuleServiceAppDefaultIndex as $objectName => $objectNode )
                        {
                            $objectType = "SecRule";
                            $text = $objectType." named '{$objectName}' that is using SERVICE OBJECT at XML line #{$objectNode->getLineNo()}";

                            $this->logFinding($locationName, $objectName, $objectType, $text, false);
                            PH::print_stdout( "   - ".$text);

                            $this->counters['manual']['SecRule ServiceAppDefault misconfigured'] = ($this->counters['manual']['SecRule ServiceAppDefault misconfigured'] ?? 0) + 1;
                            $this->countMissconfiguredSecRuleServiceAppDefaultObjects++;
                        }
                    }
                }
            }


            $dgPath = "/config/readonly/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='".$locationName."']";

            $this->ReadonlyRemoveDuplicateElements($dgPath, "address-group","Address Group", $locationName,
                "readOnly DG: " . $locationName // This matches your specific log format
            );

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
                                    $objectType = "zone";
                                    $text = $objectType." '" . $node->getAttribute('name') . "' - '" . $results[0][0] . "' ";
                                    $text .= "at XML line #{$zone_type->getLineNo()}";
                                    $text2 = " ... (*FIX_MANUALLY*)";

                                    $this->logFinding($locationName, $objectName, $objectType, $text.$text1, false);
                                    PH::print_stdout( "       - ".$text.$text1.$text2 );

                                    $this->counters['manual']['Zone wrong type'] = ($this->counters['manual']['Zone wrong type'] ?? 0) + 1;
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

        $localhostPath = "/config/readonly/devices/entry[@name='localhost.localdomain']";

        // 1. Address Groups
        $this->ReadonlyRemoveDuplicateElements("/config/readonly/shared", "address-group", "Address Group");

        // 2. Device Groups
        $this->ReadonlyRemoveDuplicateElements($localhostPath, "device-group", "Device Group");

        // 3. Templates
        $this->ReadonlyRemoveDuplicateElements($localhostPath, "template", "Template");

        // 4. Template Stacks
        $this->ReadonlyRemoveDuplicateElements($localhostPath, "template-stack", "TemplateStack");


        //Todo: counting missing
        $this->ReadonlyRemoveDuplicateElements("/config/readonly/devices/entry[@name='localhost.localdomain']/plugins/cloud_services/mobile-users/onboarding/entry",
            "entry",            // We are looking for duplicate <entry> tags
            "Onboarding Entry",
            "readonly",
            "Cloud Services Onboarding",
            true                // Set to TRUE because 'entry' nodes are direct children of the XPath
        );


        ///////////


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
                    $this->fixedImportNetworkInterfaceWithSameInterface += $this->removeDuplicateChildNodes( $interfaces, "interface");
                }
            }
        }

        ////////////////////////////////////////////////////////////
        ///scanning for all group-include-list

        $objectType = "group-include-list";
        PH::print_stdout(" - Scanning for {$objectType} for duplicate entries ...");
        $groupLists = $this->xmlDoc->getElementsByTagName($objectType);

        foreach ($groupLists as $groupList)
        {
            $this->fixedGroupIncludeListWithSameNode += $this->removeDuplicateChildNodes( $groupList, "group-include-list entry");
        }

        ////////////////////////////////////////////////////////////
        ///scanning for all exclude-access-route

        $objectType = "exclude-access-route";
        PH::print_stdout(" - Scanning for {$objectType} for duplicate entries ...");
        $groupLists = $this->xmlDoc->getElementsByTagName($objectType);

        foreach ($groupLists as $groupList)
        {
            $this->fixedExcludeAccessRouteWithSameNode += $this->removeDuplicateChildNodes( $groupList, "exclude-access-route entry");
        }

        ////////////////////////////////////////////////////////////
        ///scanning for all redist-rules

        $objectType = "redist-rules";
        PH::print_stdout(" - Scanning for {$objectType} for duplicate entries ...");
        $groupLists = $this->xmlDoc->getElementsByTagName($objectType);

        foreach ($groupLists as $groupList)
        {
            $this->fixedRedistRulesWithSameNode += $this->removeDuplicateChildNodes( $groupList, "redist-rules entry");
        }


        ////////////////////////////////////////////////////////////
        ///scanning for all vsys/zone

        PH::print_stdout(" - Scanning for zone for duplicate entries ...");
        $zoneNodes = $this->xmlDoc->getElementsByTagName("zone");

        foreach ($zoneNodes as $zone)
        {
            $this->fixedZoneWithSameNode += $this->removeDuplicateChildNodes( $zone, "zone");
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
                    $this->fixedScheduleCount += $this->removeDuplicateChildNodes( $dayNode, "schedule member");
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

        PH::print_stdout( "----------");

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

        PH::print_stdout( "----------");

        if( $this->fixedNatRuleSourceObjects > 0 )
            PH::print_stdout( " - FIXED: NatRule with duplicate source members: {$this->fixedNatRuleSourceObjects}");
        if( $this->fixedNatRuleDestinationObjects > 0 )
            PH::print_stdout( " - FIXED: NatRule with duplicate destination members: {$this->fixedNatRuleDestinationObjects}");

        PH::print_stdout( "----------");
        
        if( $this->fixedDecryptionRuleSourceObjects > 0 )
            PH::print_stdout( " - FIXED: DecryptionRule with duplicate source members: {$this->fixedDecryptionRuleSourceObjects}");
        if( $this->fixedDecryptionRuleDestinationObjects > 0 )
            PH::print_stdout( " - FIXED: DecryptionRule with duplicate destination members: {$this->fixedDecryptionRuleDestinationObjects}");
        if( $this->fixedDecryptionRuleServiceObjects > 0 )
            PH::print_stdout( " - FIXED: DecryptionRule with duplicate service members: {$this->fixedDecryptionRuleServiceObjects}");
        
        PH::print_stdout( "----------");

        if( $this->fixedappoverrideRuleSourceObjects > 0 )
            PH::print_stdout( " - FIXED: AppOverrideRule with duplicate source members: {$this->fixedappoverrideRuleSourceObjects}");
        if( $this->fixedappoverrideRuleDestinationObjects > 0 )
            PH::print_stdout( " - FIXED: AppOverrideRule with duplicate destination members: {$this->fixedappoverrideRuleDestinationObjects}");

        PH::print_stdout( "----------");

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
        if( $this->fixedExcludeAccessRouteWithSameNode > 0 )
            PH::print_stdout( "\n - FIXED: exclude-access-route : {$this->fixedExcludeAccessRouteWithSameNode}");
        if( $this->fixedRedistRulesWithSameNode > 0 )
            PH::print_stdout( "\n - FIXED: redist-rules : {$this->fixedRedistRulesWithSameNode}");

        if( $this->fixedZoneWithSameNode > 0 )
            PH::print_stdout( "\n - FIXED: zone : {$this->fixedZoneWithSameNode}");

        if( $this->fixedScheduleCount > 0 )
            PH::print_stdout( "\n - FIXED: schedule recurring weekly : {$this->fixedScheduleCount}");

        PH::print_stdout( "\n\nIssues that could not be fixed (look in logs for FIX_MANUALLY keyword):");


        if( $this->countDuplicateAddressObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: duplicate address objects: {$this->countDuplicateAddressObjects} (look in the logs )");
        if( $this->countDuplicateServiceObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: duplicate service objects: {$this->countDuplicateServiceObjects} (look in the logs)");
        PH::print_stdout( "----------");

        if( $this->countMissconfiguredAddressObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: misconfigured address objects: {$this->countMissconfiguredAddressObjects} (look in the logs)");
        if( $this->countAddressObjectsWithDoubleSpaces > 0 )
            PH::print_stdout( " - FIX_MANUALLY: address objects with double spaces in name: {$this->countAddressObjectsWithDoubleSpaces} (look in the logs)");
        if( $this->countAddressObjectsWithWrongCharacters > 0 )
            PH::print_stdout( " - FIX_MANUALLY: address objects with wrong Characters in name: {$this->countAddressObjectsWithWrongCharacters} (look in the logs)");
        if( $this->countMissconfiguredAddressRegionObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: address objects with same name as REGION: {$this->countMissconfiguredAddressRegionObjects} (look in the logs)");
        if( $this->countEmptyAddressGroup > 0 )
            PH::print_stdout( " - FIX_MANUALLY: empty address-group: {$this->countEmptyAddressGroup} (look in the logs)");
        PH::print_stdout( "----------");

        if( $this->countMissconfiguredServiceObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: misconfigured service objects: {$this->countMissconfiguredServiceObjects} (look in the logs)");
        if( $this->countServiceObjectsWithDoubleSpaces > 0 )
            PH::print_stdout( " - FIX_MANUALLY: service objects with double spaces in name: {$this->countServiceObjectsWithDoubleSpaces} (look in the logs)");
        if( $this->countServiceObjectsWithWrongCharacters > 0 )
            PH::print_stdout( " - FIX_MANUALLY: service objects with wrong Characters in name: {$this->countServiceObjectsWithWrongCharacters} (look in the logs)");
        if( $this->countServiceObjectsWithNameappdefault > 0 )
            PH::print_stdout( " - FIX_MANUALLY: service objects with name 'application-default': {$this->countServiceObjectsWithNameappdefault} (look in the logs)");
        if( $this->countEmptyServiceGroup > 0 )
            PH::print_stdout( " - FIX_MANUALLY: empty service-group: {$this->countEmptyServiceGroup} (look in the logs)");
        PH::print_stdout( "----------");

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

        if( $this->countDecryptRuleObjectsWithDoubleSpaces > 0 )
            PH::print_stdout( " - FIX_MANUALLY: Decryption Rules with double spaces in name: {$this->countDecryptRuleObjectsWithDoubleSpaces} (look in the logs )");
        if( $this->countDecryptRuleObjectsWithWrongCharacters > 0 )
            PH::print_stdout( " - FIX_MANUALLY: Decryption Rules with wrong characters in name: {$this->countDecryptRuleObjectsWithWrongCharacters} (look in the logs )");
        if( $this->countDuplicateDecryptRuleObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: duplicate Decryption Rules: {$this->countDuplicateDecryptRuleObjects} (look in the logs )");
        PH::print_stdout( "----------");

        if( $this->countMissconfiguredSecRuleFromObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: misconfigured From Field in Security Rules: {$this->countMissconfiguredSecRuleFromObjects} (look in the logs )");
        if( $this->countMissconfiguredSecRuleToObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: misconfigured To Field in Security Rules: {$this->countMissconfiguredSecRuleToObjects} (look in the logs )");
        if( $this->countMissconfiguredSecRuleSourceObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: misconfigured Source Field in Security Rules: {$this->countMissconfiguredSecRuleSourceObjects} (look in the logs )");
        if( $this->countMissconfiguredSecRuleDestinationObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: misconfigured Destination Field in Security Rules: {$this->countMissconfiguredSecRuleDestinationObjects} (look in the logs )");
        if( $this->countMissconfiguredSecRuleServiceObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: misconfigured Service Field in Security Rules: {$this->countMissconfiguredSecRuleServiceObjects} (look in the logs )");
        if( $this->countMissconfiguredSecRuleApplicationObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: misconfigured Application Field in Security Rules: {$this->countMissconfiguredSecRuleApplicationObjects} (look in the logs )");
        if( $this->countMissconfiguredSecRuleCategoryObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: misconfigured Category Field in Security Rules: {$this->countMissconfiguredSecRuleCategoryObjects} (look in the logs )");
        if( $this->countMissconfiguredSecruleSourceUserObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: misconfigured SourceUser Field in Security Rules: {$this->countMissconfiguredSecruleSourceUserObjects} (look in the logs )");
        PH::print_stdout( "----------");
        if( $this->countMissconfiguredNatRuleSourceObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: misconfigured Source Field in NAT Rules: {$this->countMissconfiguredNatRuleSourceObjects} (look in the logs )");
        if( $this->countMissconfiguredNatRuleDestinationObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: misconfigured Destination Field in NAT Rules: {$this->countMissconfiguredNatRuleDestinationObjects} (look in the logs )");
        PH::print_stdout( "----------");

        if( $this->service_app_default_available )
        {
            if( $this->countMissconfiguredSecRuleServiceAppDefaultObjects > 0 )
                PH::print_stdout( " - FIX_MANUALLY: SERVICE OBJECT 'application-default' available and used in Security Rules: {$this->countMissconfiguredSecRuleServiceAppDefaultObjects} (look in the logs )");
            PH::print_stdout();
        }


        ////////////////////////////////////////////////////////////
        PH::print_stdout( "");
        PH::print_stdout( "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####");
        PH::print_stdout();

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
        $objectType = $tagName;
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
                        $staticNode->removeChild($NodeMember);

                        $text = "group '{$objectName}' from DG/VSYS {$locationName} ";
                        $text1 = "has a duplicate member named '{$memberName}'";

                        $this->logFinding($locationName, $objectName, $objectType, $text1, true);

                        $text2 = " ... *FIXED*";
                        PH::print_stdout( "    - ".$text.$text1.$text2 );

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
    private function removeDuplicateChildNodes(DOMElement $parent, string $label): int
    {
        $seenValues = [];
        $toRemove = [];
        $removedCount = 0;

        foreach ($parent->childNodes as $node)
        {
            if ($node->nodeType !== XML_ELEMENT_NODE) {
                continue;
            }

            /** @var DOMElement $node */

            // 1. Try to get the 'name' attribute (for <entry name="...">)
            // 2. If empty, fall back to textContent (for <member>value</member>)
            $identifier = $node->getAttribute('name');
            if ($identifier === '') {
                $identifier = trim($node->textContent);
            }

            if (isset($seenValues[$identifier])) {
                $toRemove[] = $node;
            } else {
                $seenValues[$identifier] = true;
            }
        }

        foreach ($toRemove as $node)
        {
            // Re-identify for the log message
            $logName = $node->getAttribute('name');
            if ($logName === '') {
                $logName = trim($node->textContent);
            }

            $xpath = $node->getNodePath();

            if ($node->parentNode) {
                $node->parentNode->removeChild($node);

                $text = "remove $label: '{$logName}' from xPath: '{$xpath}' as it is a duplicate";
                $this->logFinding("general", $logName, $label, $text, true);

                $counterKey = "general {$label}";
                $this->counters['fixed'][$counterKey] = ($this->counters['fixed'][$counterKey] ?? 0) + 1;

                PH::print_stdout("    - " . $text . PH::boldText(" ... *FIXED*"));
                $removedCount++;
            }
        }

        return $removedCount;
    }


    /**
     * @param string $xpath The search path
     * @param string $objectType The element tag name to look for (e.g., 'template')
     * @param string $displayName The name used for counters and logs (e.g., 'Template')
     * @param string $locationName Usually 'readonly'
     */
    //this is likely for the readonly seciont
    private function ReadonlyRemoveDuplicateElements(string $xpath, string $objectType, string $displayName, string $locationName = "readonly", $logContext = null, $isEntryDeduplication = false): void
    {
        PH::print_stdout(" - Scanning for {$xpath} for duplicate {$objectType} ...");

        $nodes = DH::findXPath($xpath, $this->xmlDoc);

        if( count($nodes) === 0)
        {
            return;
        }

        $itemsToProcess = array();

        if ($isEntryDeduplication) {
            // We are deduplicating the entries found directly by XPath
            $itemsToProcess = $nodes;
        } else {
            // Standard mode: Find the container first (like your previous examples)
            $container = DH::findFirstElement($objectType, $nodes[0]);
            if (!$container)
                return;
            $itemsToProcess = iterator_to_array($container->childNodes);
        }

        $seenNames = array();
        $toRemove = array();


        foreach ($itemsToProcess as $node)
        {
            if ($node->nodeType !== XML_ELEMENT_NODE)
                continue;


            /** @var DOMElement $node */
            $name = $node->getAttribute('name');

            if( isset($seenNames[$name]) ) {
                $toRemove[] = $node;
            } else {
                $seenNames[$name] = $node;
            }
        }

        foreach ($toRemove as $node) {
            $name = $node->getAttribute('name');
            $contextText = $logContext ? $logContext : "{$locationName} {$xpath}";
            $text = "{$contextText} has same {$objectType} defined twice: {$name}";

            if ($node->parentNode) {
                $node->parentNode->removeChild($node);

                $this->logFinding($locationName, $name, $objectType, $text, true);
                PH::print_stdout("     - " . $text . PH::boldText(" (removed)"));

                $counterKey = "ReadOnly {$displayName}";
                $this->counters['fixed'][$counterKey] = ($this->counters['fixed'][$counterKey] ?? 0) + 1;

                $propertyName = "fixedReadOnly" . str_replace([' ', '-'], '', $displayName) . "objects";
                if (property_exists($this, $propertyName)) {
                    $this->$propertyName++;
                }
            }
        }
    }


    /**
     * Helper to log findings to both stdout and HTML buffer
     */
    private function logFinding($location, $objectName, $objectType, $issue, $isFixed = false)
    {
        PH::print_stdout("    - [{$location}] Object: {$objectName} Type: {$objectType} | {$issue} " . ($isFixed ? PH::boldText("*FIXED*") : PH::boldText("*FIX_MANUALLY*") ));

        $this->htmlOutput[] = [
            'location' => $location,
            'object' => $objectName,
            'objecttype' => $objectType,
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
        $html .= "<table><tr><th>Location</th><th>Object</th><th>ObjectType</th><th>Issue Description</th><th>Status</th></tr>";

        if (empty($this->htmlOutput)) {
            $html .= "<tr><td colspan='4'>No misconfigurations found.</td></tr>";
        } else {
            foreach ($this->htmlOutput as $row) {
                $class = ($row['status'] == 'Fixed') ? 'fixed' : 'manual';
                $html .= "<tr>
                    <td>{$row['location']}</td>
                    <td>{$row['object']}</td>
                    <td>{$row['objecttype']}</td>
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
            <tr><td>Total Manual</td><td class='manual'>{$this->summaryOutput['not_fixed']}</td></tr>";
        $html .= "</table>";


        // Table 1: Detailed Findings (Row by Row)
        $html .= "<h2>Detailed Misconfigurations</h2>";
        $html .= "<table><tr><th>Location</th><th>Object</th><th>ObjectType</th><th>Issue</th><th>Status</th></tr>";
        foreach ($this->htmlOutput as $row) {
            $statusClass = ($row['status'] == 'Fixed') ? 'fixed' : 'manual';
            $html .= "<tr><td>{$row['location']}</td><td>{$row['object']}</td><td>{$row['objecttype']}</td><td>{$row['issue']}</td><td class='{$statusClass}'>{$row['status']}</td></tr>";
        }
        $html .= "</table>";



        $html .= "</body></html>";

        $html_file_name = "xml_issue_report.html";
        if( $this->projectFolder !== null )
            $html_file_name = $this->projectFolder."/".$html_file_name;

        file_put_contents($html_file_name, $html);
        PH::print_stdout("\n** HTML Report generated: '".$html_file_name."' **\n");
    }
}