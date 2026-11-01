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
    public $fixedDuplicateSecRuleObjects = 0;
    public $fixedDuplicateNATRuleObjects = 0;
    public $fixedDuplicateDecryptRuleObjects = 0;
    public $fixedDuplicateAppOverrideRuleObjects = 0;
    public $fixedDuplicateAuthRuleObjects = 0;
    public $fixedAuthRuleSourceObjects = 0;
    public $fixedAuthRuleDestinationObjects = 0;
    public $countDuplicateNATRuleObjects = 0;
    public $countDuplicateDecryptRuleObjects = 0;
    public $countDuplicateAppOverrideRuleObjects = 0;
    public $countDuplicateAuthRuleObjects = 0;

    public $countSecRuleObjectsWithDoubleSpaces = 0;
    public $countSecRuleObjectsWithWrongCharacters = 0;
    public $countNATRuleObjectsWithDoubleSpaces = 0;
    public $countNATRuleObjectsWithWrongCharacters = 0;

    
    public $countDecryptRuleObjectsWithDoubleSpaces = 0;
    public $countDecryptRuleObjectsWithWrongCharacters = 0;

    public $countAppOverrideRuleObjectsWithDoubleSpaces = 0;
    public $countAppOverrideRuleObjectsWithWrongCharacters = 0;

    public $countAuthRuleObjectsWithDoubleSpaces = 0;
    public $countAuthRuleObjectsWithWrongCharacters = 0;

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
    public $countAddressGroupsSubGroupManual = 0;
    public $countServiceGroupsSubGroupManual = 0;

    /** @var DOMElement[] location name => its node (shared, vsys, device group, container, cloud) */
    public $locationNodesByName = array();
    /** @var array cache: location name => object kind => object name => TRUE (address / service objects, not groups) */
    public $objectNamesCache = array();

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
    public $fixedGPappConfigWithSameValue = 0;

    public $fixedZoneWithSameNode = 0;

    public $fixedScheduleCount = 0;

    public $totalApplicationGroupsFixed = 0;
    public $totalApplicationFiltersFixed = 0;
    public $totalCustomUrlCategoryFixed = 0;

    public $countRulesWithAppDefault = 0;

    public $address_region = array();
    public $address_name = array();

    /** PAN-OS limit for a rule name (schema: attr-req name maxlen="63" for every rule type) */
    const RULE_NAME_MAXLEN = 63;

    /**
     * The rule types checkRules() handles, one entry each; the checks are the same for every type.
     *  - objectType / title / singular: used in the log, the HTML report and the counter keys
     *  - doubleSpace / wrongChar / duplicateManual / duplicateFixed: the summary counters (properties) of the type
     *  - fields: member lists whose duplicate members are removed:
     *      label (log text), counter (counter key "<objectType> <counter> Object duplicate"), property (summary counter),
     *      quote (the log quotes the rule name)
     *  - anyFields: member lists where 'any' plus another member is reported (*FIX_MANUALLY*)
     *  - appDefault: service 'application-default' plus another service is reported, and 'application-default'
     *      alone when a service object of that name exists
     */
    public $ruleTypeDefinitions = array(
        'security' => array(
            'objectType' => 'SecRule', 'title' => 'Security Rules', 'singular' => 'Security Rule',
            'doubleSpace' => 'countSecRuleObjectsWithDoubleSpaces', 'wrongChar' => 'countSecRuleObjectsWithWrongCharacters',
            'duplicateManual' => 'countDuplicateSecRuleObjects', 'duplicateFixed' => 'fixedDuplicateSecRuleObjects',
            'fields' => array(
                'service' => array( 'label' => 'SERVICE', 'counter' => 'Service', 'property' => 'fixedSecRuleServiceObjects', 'quote' => TRUE ),
                'tag' => array( 'label' => 'TAG', 'counter' => 'Tag', 'property' => 'fixedSecRuleTagObjects' ),
                'application' => array( 'label' => 'APPLICATION', 'counter' => 'Application', 'property' => 'fixedSecRuleApplicationObjects' ),
                'category' => array( 'label' => 'CATEGORY', 'counter' => 'Category', 'property' => 'fixedSecRuleCategoryObjects' ),
                'source' => array( 'label' => 'SOURCE', 'counter' => 'Source', 'property' => 'fixedSecRuleSourceObjects' ),
                'destination' => array( 'label' => 'DESTINATION', 'counter' => 'Destination', 'property' => 'fixedSecRuleDestinationObjects' ),
                'from' => array( 'label' => 'FROM zone', 'counter' => 'From', 'property' => 'fixedSecRuleFromObjects' ),
                'to' => array( 'label' => 'TO zone', 'counter' => 'To', 'property' => 'fixedSecRuleToObjects' ),
                'source-user' => array( 'label' => 'SOURCE-USER', 'counter' => 'SourceUser', 'property' => 'fixedSecruleSourceUserObjects' ),
            ),
            // order = order of the report
            'anyFields' => array(
                'from' => array( 'counter' => 'SecRule From misconfigured', 'property' => 'countMissconfiguredSecRuleFromObjects' ),
                'to' => array( 'counter' => 'SecRule To misconfigured', 'property' => 'countMissconfiguredSecRuleToObjects' ),
                'source' => array( 'counter' => 'SecRule Source misconfigured', 'property' => 'countMissconfiguredSecRuleSourceObjects' ),
                'destination' => array( 'counter' => 'SecRule Destination misconfigured', 'property' => 'countMissconfiguredSecRuleDestinationObjects' ),
                'service' => array( 'counter' => 'SecRule Service misconfigured', 'property' => 'countMissconfiguredSecRuleServiceObjects', 'any' => 'application-default' ),
                'application' => array( 'counter' => 'SecRule Application misconfigured', 'property' => 'countMissconfiguredSecRuleApplicationObjects' ),
                'category' => array( 'counter' => 'SecRule Category misconfigured', 'property' => 'countMissconfiguredSecRuleCategoryObjects' ),
                'source-user' => array( 'counter' => 'SecRule SourceUser misconfigured', 'property' => 'countMissconfiguredSecruleSourceUserObjects' ),
            ),
            'appDefault' => TRUE,
        ),
        'nat' => array(
            'objectType' => 'NatRule', 'title' => 'NAT Rules', 'singular' => 'NAT Rule',
            'doubleSpace' => 'countNATRuleObjectsWithDoubleSpaces', 'wrongChar' => 'countNATRuleObjectsWithWrongCharacters',
            'duplicateManual' => 'countDuplicateNATRuleObjects', 'duplicateFixed' => 'fixedDuplicateNATRuleObjects',
            'fields' => array(
                'source' => array( 'label' => 'SOURCE', 'counter' => 'Source', 'property' => 'fixedNatRuleSourceObjects' ),
                'destination' => array( 'label' => 'DESTINATION', 'counter' => 'Destination', 'property' => 'fixedNatRuleDestinationObjects' ),
            ),
            'anyFields' => array(
                'source' => array( 'counter' => 'NatRule Source misconfigured', 'property' => 'countMissconfiguredNatRuleSourceObjects' ),
                'destination' => array( 'counter' => 'NatRule Destination misconfigured', 'property' => 'countMissconfiguredNatRuleDestinationObjects' ),
            ),
        ),
        'decryption' => array(
            'objectType' => 'DecryptionRule', 'title' => 'Decryption Rules', 'singular' => 'Decryption Rule',
            'doubleSpace' => 'countDecryptRuleObjectsWithDoubleSpaces', 'wrongChar' => 'countDecryptRuleObjectsWithWrongCharacters',
            'duplicateManual' => 'countDuplicateDecryptRuleObjects', 'duplicateFixed' => 'fixedDuplicateDecryptRuleObjects',
            'fields' => array(
                'source' => array( 'label' => 'SOURCE', 'counter' => 'Source', 'property' => 'fixedDecryptionRuleSourceObjects' ),
                'destination' => array( 'label' => 'DESTINATION', 'counter' => 'Destination', 'property' => 'fixedDecryptionRuleDestinationObjects' ),
                'service' => array( 'label' => 'SERVICE', 'counter' => 'Service', 'property' => 'fixedDecryptionRuleServiceObjects', 'quote' => TRUE ),
            ),
        ),
        'application-override' => array(
            'objectType' => 'AppOverrideRule', 'title' => 'Application-Override Rules', 'singular' => 'Application-Override Rule',
            'doubleSpace' => 'countAppOverrideRuleObjectsWithDoubleSpaces', 'wrongChar' => 'countAppOverrideRuleObjectsWithWrongCharacters',
            'duplicateManual' => 'countDuplicateAppOverrideRuleObjects', 'duplicateFixed' => 'fixedDuplicateAppOverrideRuleObjects',
            'fields' => array(
                'source' => array( 'label' => 'SOURCE', 'counter' => 'Source', 'property' => 'fixedappoverrideRuleSourceObjects' ),
                'destination' => array( 'label' => 'DESTINATION', 'counter' => 'Destination', 'property' => 'fixedappoverrideRuleDestinationObjects' ),
            ),
        ),
        'authentication' => array(
            'objectType' => 'AuthenticationRule', 'title' => 'Authentication Rules', 'singular' => 'Authentication Rule',
            'doubleSpace' => 'countAuthRuleObjectsWithDoubleSpaces', 'wrongChar' => 'countAuthRuleObjectsWithWrongCharacters',
            'duplicateManual' => 'countDuplicateAuthRuleObjects', 'duplicateFixed' => 'fixedDuplicateAuthRuleObjects',
            'fields' => array(
                'source' => array( 'label' => 'SOURCE', 'counter' => 'Source', 'property' => 'fixedAuthRuleSourceObjects' ),
                'destination' => array( 'label' => 'DESTINATION', 'counter' => 'Destination', 'property' => 'fixedAuthRuleDestinationObjects' ),
            ),
        ),
    );

    // full configuration scan (fullConfigDuplicateScan)
    public $fixedFullScanMergedContainers = 0;
    public $fixedFullScanEntries = 0;
    public $countFullScanEntries = 0;
    public $fixedFullScanMembers = 0;
    public $fixedFullScanElements = 0;
    public $countFullScanElements = 0;

    /**
     * Member lists where the same value may occur more than once on purpose, so the full scan leaves their
     * duplicate <member> alone:
     *  - aspath-prepend (route-map set, advanced routing): every member prepends that AS number once more;
     *    three times 135399 means prepend 135399 three times
     */
    public $fullScanKeepDuplicateMembers = array( 'aspath-prepend' );

    /**
     * Routing configuration xml-issue never changes on its own. A duplicate found there - by the full scan or a fixed
     * check - is reported (*FIX_MANUALLY*), not removed or merged: repetition and order can be part of the routing
     * policy, and a silent change to routing is riskier than a finding someone works through. Element names of the
     * subtree roots:
     *  - virtual-router: legacy routing engine (protocol bgp / ospf / ospfv3 / rip, routing-table, redist-profile, ...)
     *  - logical-router: advanced routing engine (vrf bgp / ospf / ospfv3 / rip, routing-table, ecmp, multicast, ...)
     *  - routing-profile: advanced routing profiles and filters (bgp, ospf, route-maps, as-path / community lists, ...)
     *  - bgp (and bgp-...): BGP wherever else it occurs
     */
    public $protectedRoutingElements = array( 'virtual-router', 'logical-router', 'routing-profile', 'bgp' );
    public $countProtectedRoutingDuplicates = 0;
    /** remember: routing duplicates already reported (several steps see them, as nothing is changed there) */
    public $reportedRoutingDuplicates = array();

    /**
     * Containers whose duplicate <entry> names a dedicated check above already reports (renamed, or FIX_MANUALLY):
     * the full scan does not report them a second time. Patterns are matched against the parent's path without @name.
     */
    public $fullScanSkipEntryContainers = array(
        '#^/config/shared/(address|address-group|service|service-group)$#',
        '#^/config/devices/entry/(vsys|device-group|container|device/cloud)/entry/(address|address-group|service|service-group)$#',
        '#^/config/(shared|devices/entry/(vsys|device-group|container|device/cloud)/entry)/(rulebase|pre-rulebase|post-rulebase)/(security|nat|decryption|application-override|authentication)/rules$#',
    );

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
        //full configuration scan, part 1: a container element that occurs twice under the same parent
        //(e.g. two <address> under one vsys) is merged first, so that every check below sees all of its content
        $this->fullConfigMergeDuplicateContainers();
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

        $this->locationNodesByName = $locationNodes;

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




            $zoneObjects = array();
            $zoneIndex = array();

            $address_region = array();
            $address_name = array();
            $address_wrong_name = array();
            $service_name = array();
            $service_wrong_name = array();
            $service_name_appdefault = array();

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
                    if( $dynamicNode === FALSE && ( $staticNode === FALSE || !$this->fullScanHasChildElements( $staticNode ) ) )
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
            $this->checkGroupSelfMember( $locationName, "address", $addressGroups );


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
                    if( $staticNode === FALSE || !$this->fullScanHasChildElements( $staticNode ) )
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
            $this->checkGroupSelfMember( $locationName, "service", $serviceGroups );


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


            //
            // rules of every type, over rulebase / pre-rulebase / post-rulebase
            //
            $this->checkRules( $locationNode, $locationName );


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
        ///scanning for all gp-app-config/config/entry/value

        PH::print_stdout(" - Scanning for gp-app-config/config/entry/value for duplicate entries ...");
        $importNodes = $this->xmlDoc->getElementsByTagName("gp-app-config");

        foreach ($importNodes as $import)
        {
            $network = DH::findFirstElement("config", $import);
            if ($network)
            {
                foreach( $network->childNodes as $entry )
                {
                    /** @var DOMElement $entry */
                    if( $entry->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $value = DH::findFirstElement("value", $entry);

                    $this->fixedGPappConfigWithSameValue += $this->removeDuplicateChildNodes( $value, "gp-app-config");
                }

            }
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
        ///full configuration scan: duplicates in every other part of the XML
        PH::print_stdout( "");
        PH::print_stdout( "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####");
        $this->fullConfigDuplicateScan();

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

        if( $this->fixedAuthRuleSourceObjects > 0 )
            PH::print_stdout( " - FIXED: AuthenticationRule with duplicate source members: {$this->fixedAuthRuleSourceObjects}");
        if( $this->fixedAuthRuleDestinationObjects > 0 )
            PH::print_stdout( " - FIXED: AuthenticationRule with duplicate destination members: {$this->fixedAuthRuleDestinationObjects}");

        PH::print_stdout( "----------");

        if( $this->fixedDuplicateSecRuleObjects > 0 )
            PH::print_stdout( " - FIXED: duplicate Security Rules renamed: {$this->fixedDuplicateSecRuleObjects}");
        if( $this->fixedDuplicateNATRuleObjects > 0 )
            PH::print_stdout( " - FIXED: duplicate NAT Rules renamed: {$this->fixedDuplicateNATRuleObjects}");
        if( $this->fixedDuplicateDecryptRuleObjects > 0 )
            PH::print_stdout( " - FIXED: duplicate Decryption Rules renamed: {$this->fixedDuplicateDecryptRuleObjects}");
        if( $this->fixedDuplicateAppOverrideRuleObjects > 0 )
            PH::print_stdout( " - FIXED: duplicate App-Override Rules renamed: {$this->fixedDuplicateAppOverrideRuleObjects}");
        if( $this->fixedDuplicateAuthRuleObjects > 0 )
            PH::print_stdout( " - FIXED: duplicate Authentication Rules renamed: {$this->fixedDuplicateAuthRuleObjects}");

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

        if( $this->fixedGPappConfigWithSameValue > 0 )
            PH::print_stdout( "\n - FIXED: gp-app-config : {$this->fixedGPappConfigWithSameValue}");


        if( $this->fixedScheduleCount > 0 )
            PH::print_stdout( "\n - FIXED: schedule recurring weekly : {$this->fixedScheduleCount}");

        if( $this->fixedFullScanMergedContainers > 0 )
            PH::print_stdout( "\n - FIXED: full scan - duplicate containers merged : {$this->fixedFullScanMergedContainers}");
        if( $this->fixedFullScanEntries > 0 )
            PH::print_stdout( " - FIXED: full scan - identical duplicate entries : {$this->fixedFullScanEntries}");
        if( $this->fixedFullScanMembers > 0 )
            PH::print_stdout( " - FIXED: full scan - duplicate members : {$this->fixedFullScanMembers}");
        if( $this->fixedFullScanElements > 0 )
            PH::print_stdout( " - FIXED: full scan - identical duplicate elements : {$this->fixedFullScanElements}");

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
        if( $this->countAddressGroupsSubGroupManual > 0 )
            PH::print_stdout( " - FIX_MANUALLY: address-group with itself as member, where an address object of that name exists: {$this->countAddressGroupsSubGroupManual} (look in the logs)");
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
        if( $this->countServiceGroupsSubGroupManual > 0 )
            PH::print_stdout( " - FIX_MANUALLY: service-group with itself as member, where a service object of that name exists: {$this->countServiceGroupsSubGroupManual} (look in the logs)");
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


        if( $this->countAppOverrideRuleObjectsWithDoubleSpaces > 0 )
            PH::print_stdout( " - FIX_MANUALLY: App-Override Rules with double spaces in name: {$this->countAppOverrideRuleObjectsWithDoubleSpaces} (look in the logs )");
        if( $this->countAppOverrideRuleObjectsWithWrongCharacters > 0 )
            PH::print_stdout( " - FIX_MANUALLY: App-Override Rules with wrong characters in name: {$this->countAppOverrideRuleObjectsWithWrongCharacters} (look in the logs )");
        if( $this->countDuplicateAppOverrideRuleObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: duplicate App-Override Rules: {$this->countDuplicateAppOverrideRuleObjects} (look in the logs )");

        if( $this->countAuthRuleObjectsWithDoubleSpaces > 0 )
            PH::print_stdout( " - FIX_MANUALLY: Authentication Rules with double spaces in name: {$this->countAuthRuleObjectsWithDoubleSpaces} (look in the logs )");
        if( $this->countAuthRuleObjectsWithWrongCharacters > 0 )
            PH::print_stdout( " - FIX_MANUALLY: Authentication Rules with wrong characters in name: {$this->countAuthRuleObjectsWithWrongCharacters} (look in the logs )");
        if( $this->countDuplicateAuthRuleObjects > 0 )
            PH::print_stdout( " - FIX_MANUALLY: duplicate Authentication Rules: {$this->countDuplicateAuthRuleObjects} (look in the logs )");
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

        if( $this->countFullScanEntries > 0 )
            PH::print_stdout( " - FIX_MANUALLY: full scan - entries with the same name but different content: {$this->countFullScanEntries} (look in the logs )");
        if( $this->countFullScanElements > 0 )
            PH::print_stdout( " - FIX_MANUALLY: full scan - elements that occur twice with different content: {$this->countFullScanElements} (look in the logs )");
        if( $this->countProtectedRoutingDuplicates > 0 )
            PH::print_stdout( " - FIX_MANUALLY: routing (virtual-router / logical-router / routing-profile / BGP) duplicates, not changed automatically: {$this->countProtectedRoutingDuplicates} (look in the logs )");
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

    /**
     * Full configuration scan for duplicates the dedicated checks above do not cover.
     *
     * PAN-OS XML repeats a sibling element name only as a list item: <entry name="..."> (unique by name) or <member>
     * (unique by value). Every other element occurs once under its parent (checked against the PAN-OS schema: every
     * <array> holds 'entry' or 'member'). So no list of XPaths is needed:
     *  - learn:    walk the whole document; group each parent's children by entry name, member value or element name
     *  - check:    a group with more than one node is a duplicate
     *  - fix:      a member, or an entry / element identical to the first one, is removed (*FIXED*);
     *              an entry / element that differs from the first one is kept (*FIX_MANUALLY*)
     *  - remember: logFinding() and counters per XPath pattern; containers whose duplicate entries a dedicated check
     *              already reports ($fullScanSkipEntryContainers) are skipped
     *  - output:   the summary lines and the HTML report
     * It runs after the dedicated checks, so it only finds what they left. Containers that occur twice were already
     * merged by fullConfigMergeDuplicateContainers() at the start.
     */
    private function fullConfigDuplicateScan()
    {
        PH::print_stdout( " - Scanning the full configuration for duplicate entries / members / elements ..." );

        $root = $this->xmlDoc->documentElement;
        if( $root === null )
            return;

        // learn + check + fix, parent by parent (iterative: configurations can be deep)
        $stack = array( $root );
        while( count( $stack ) > 0 )
        {
            /** @var DOMElement $parent */
            $parent = array_pop( $stack );

            $groups = array();
            foreach( $parent->childNodes as $child )
            {
                if( $child->nodeType !== XML_ELEMENT_NODE )
                    continue;
                /** @var DOMElement $child */
                if( $child->nodeName === 'entry' )
                {
                    if( !$child->hasAttribute( 'name' ) )
                        continue;   // list item without a name: nothing to compare
                    $key = "entry\0" . $child->getAttribute( 'name' );
                }
                elseif( $child->nodeName === 'member' )
                    $key = "member\0" . trim( $child->textContent );
                else
                    $key = "element\0" . $child->nodeName;
                $groups[$key][] = $child;
            }

            foreach( $groups as $key => $nodes )
            {
                if( count( $nodes ) < 2 )
                    continue;

                list( $kind, $identifier ) = explode( "\0", $key, 2 );
                if( $kind === 'entry' && $this->fullScanIsSkippedContainer( $parent ) )
                    continue;
                if( $kind === 'member' && in_array( $parent->nodeName, $this->fullScanKeepDuplicateMembers, TRUE ) )
                    continue;   // repeated on purpose (e.g. AS path prepend)
                if( $this->isProtectedRouting( $parent ) )
                {
                    $first = $nodes[0];
                    $what = ( $kind === 'entry' ) ? "<entry name='{$identifier}'>" : ( ( $kind === 'member' ) ? "<member>{$identifier}</member>" : "<{$identifier}>" );
                    foreach( array_slice( $nodes, 1 ) as $node )
                        $this->reportProtectedRoutingDuplicate( $parent, $what, $identifier, $node, $first, "duplicate" );
                    continue;
                }

                $this->fullScanHandleDuplicates( $parent, $kind, $identifier, $nodes );
            }

            foreach( $parent->childNodes as $child )
                if( $child->nodeType === XML_ELEMENT_NODE )
                    $stack[] = $child;
        }
    }

    /**
     * Full configuration scan, part 1 - runs before every other check.
     * A container (an element, other than entry / member, that has child elements) occurring twice under the same
     * parent, e.g. two <address> under one vsys or two <layer3> under one interface, is merged into the first one:
     * PAN-OS-PHP and the checks below read only the first. Its children are moved over in document order; duplicates
     * this creates among them are handled by fullConfigDuplicateScan() at the end (or by the dedicated checks).
     *  - learn: walk the document; group each parent's children by element name
     *  - check: a group of two or more containers
     *  - fix: move the later containers' children into the first, remove the later containers (*FIXED*)
     *  - remember / output: logFinding(), counters, summary line
     */
    private function fullConfigMergeDuplicateContainers()
    {
        PH::print_stdout( " - Scanning the full configuration for container elements that occur twice (merge) ..." );

        $root = $this->xmlDoc->documentElement;
        if( $root === null )
            return;

        $stack = array( $root );
        while( count( $stack ) > 0 )
        {
            /** @var DOMElement $parent */
            $parent = array_pop( $stack );

            $groups = array();
            foreach( $parent->childNodes as $child )
            {
                if( $child->nodeType !== XML_ELEMENT_NODE )
                    continue;
                if( $child->nodeName === 'entry' || $child->nodeName === 'member' )
                    continue;
                $groups[$child->nodeName][] = $child;
            }

            foreach( $groups as $tagName => $nodes )
            {
                if( count( $nodes ) < 2 )
                    continue;

                $containers = array();
                foreach( $nodes as $node )
                    if( $this->fullScanHasChildElements( $node ) )
                        $containers[] = $node;
                if( count( $containers ) < 2 )
                    continue;   // leaf elements (text values) are judged at the end by fullConfigDuplicateScan()

                $first = array_shift( $containers );
                if( $this->isProtectedRouting( $parent ) )
                {
                    foreach( $containers as $node )
                        $this->reportProtectedRoutingDuplicate( $parent, "<{$tagName}>", $tagName, $node, $first, "occurs twice" );
                    continue;
                }
                foreach( $containers as $node )
                {
                    /** @var DOMElement $node */
                    $line = $node->getLineNo();
                    while( $node->firstChild !== null )
                        $first->appendChild( $node->firstChild );
                    $parent->removeChild( $node );

                    $pattern = $this->fullScanPattern( $parent );
                    $text = "<{$tagName}> occurs twice under '{$pattern}' (XML line #{$first->getLineNo()} and #{$line}): only the first is read - merged into the first";
                    $this->logFinding( $this->fullScanReadablePath( $parent ), $tagName, "full scan container", $text, true );

                    $counterKey = "full scan duplicate container {$pattern}/{$tagName}";
                    $this->counters['fixed'][$counterKey] = ( $this->counters['fixed'][$counterKey] ?? 0 ) + 1;
                    $this->fixedFullScanMergedContainers++;
                }
            }

            foreach( $parent->childNodes as $child )
                if( $child->nodeType === XML_ELEMENT_NODE )
                    $stack[] = $child;
        }
    }

    /** TRUE when the node is inside a routing subtree ($protectedRoutingElements) */
    private function isProtectedRouting( DOMNode $node )
    {
        for( $n = $node; $n !== null && $n->nodeType === XML_ELEMENT_NODE; $n = $n->parentNode )
        {
            if( in_array( $n->nodeName, $this->protectedRoutingElements, TRUE ) || strpos( $n->nodeName, 'bgp-' ) === 0 )
                return TRUE;
        }
        return FALSE;
    }

    /** a duplicate in routing configuration: reported, never changed */
    private function reportProtectedRoutingDuplicate( DOMElement $parent, $what, $identifier, DOMElement $node, DOMElement $first, $verb )
    {
        $key = spl_object_hash( $node );
        if( isset( $this->reportedRoutingDuplicates[$key] ) )
            return;
        $this->reportedRoutingDuplicates[$key] = $node;   // keeps the node alive, so the hash stays unique

        $pattern = $this->fullScanPattern( $parent );
        $text = "{$what} {$verb} under '{$pattern}' (XML line #{$first->getLineNo()} and #{$node->getLineNo()}): routing configuration is not changed automatically - please check";
        $this->logFinding( $this->fullScanReadablePath( $parent ), $identifier, "routing", $text, false );

        $counterKey = "routing duplicate {$pattern}";
        $this->counters['manual'][$counterKey] = ( $this->counters['manual'][$counterKey] ?? 0 ) + 1;
        $this->countProtectedRoutingDuplicates++;
    }

    private function fullScanHasChildElements( DOMElement $node )
    {
        foreach( $node->childNodes as $child )
            if( $child->nodeType === XML_ELEMENT_NODE )
                return TRUE;
        return FALSE;
    }

    private function fullScanHandleDuplicates( DOMElement $parent, $kind, $identifier, $nodes )
    {
        $pattern = $this->fullScanPattern( $parent );
        $location = $this->fullScanReadablePath( $parent );
        $first = array_shift( $nodes );
        $firstCanonical = $this->fullScanCanonical( $first );

        foreach( $nodes as $node )
        {
            /** @var DOMElement $node */
            $line = $node->getLineNo();
            if( $kind === 'entry' )
                $what = "<entry name='{$identifier}'>";
            elseif( $kind === 'member' )
                $what = "<member>{$identifier}</member>";
            else
                $what = "<{$identifier}>";

            $identical = ( $kind === 'member' ) || ( $this->fullScanCanonical( $node ) === $firstCanonical );

            if( $identical )
            {
                $parent->removeChild( $node );
                $text = "duplicate {$what} under '{$pattern}' at XML line #{$line}, identical to line #{$first->getLineNo()} - removed";
                $this->logFinding( $location, $identifier, "full scan {$kind}", $text, true );

                $counterKey = "full scan duplicate {$kind} {$pattern}";
                $this->counters['fixed'][$counterKey] = ( $this->counters['fixed'][$counterKey] ?? 0 ) + 1;

                if( $kind === 'entry' )
                    $this->fixedFullScanEntries++;
                elseif( $kind === 'member' )
                    $this->fixedFullScanMembers++;
                else
                    $this->fixedFullScanElements++;
            }
            else
            {
                $text = "duplicate {$what} under '{$pattern}' at XML line #{$line} differs from line #{$first->getLineNo()} - which one is right?";
                $this->logFinding( $location, $identifier, "full scan {$kind}", $text, false );

                $counterKey = "full scan duplicate {$kind} {$pattern}";
                $this->counters['manual'][$counterKey] = ( $this->counters['manual'][$counterKey] ?? 0 ) + 1;

                if( $kind === 'entry' )
                    $this->countFullScanEntries++;
                else
                    $this->countFullScanElements++;
            }
        }
    }

    private function fullScanIsSkippedContainer( DOMElement $parent )
    {
        $pattern = $this->fullScanPattern( $parent );
        foreach( $this->fullScanSkipEntryContainers as $regex )
            if( preg_match( $regex, $pattern ) )
                return TRUE;
        return FALSE;
    }

    /** the element's path without @name, e.g. /config/devices/entry/vsys/entry/zone */
    private function fullScanPattern( DOMNode $node )
    {
        $parts = array();
        for( $n = $node; $n !== null && $n->nodeType === XML_ELEMENT_NODE; $n = $n->parentNode )
            $parts[] = $n->nodeName;
        return '/' . implode( '/', array_reverse( $parts ) );
    }

    /** the element's path with @name, e.g. /config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone */
    private function fullScanReadablePath( DOMNode $node )
    {
        $parts = array();
        for( $n = $node; $n !== null && $n->nodeType === XML_ELEMENT_NODE; $n = $n->parentNode )
        {
            /** @var DOMElement $n */
            $part = $n->nodeName;
            if( $n->hasAttribute( 'name' ) )
                $part .= "[@name='" . $n->getAttribute( 'name' ) . "']";
            $parts[] = $part;
        }
        return '/' . implode( '/', array_reverse( $parts ) );
    }

    /** canonical XML of a node, whitespace between elements ignored */
    private function fullScanCanonical( DOMElement $node )
    {
        return preg_replace( '/>\s+</', '><', trim( $node->C14N() ) );
    }

    public function supportedArguments()
    {

        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['apitimeout'] = array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to answer, increase this value (default=60)');

    }

    /**
     * Rules of every type in one location, the same checks for each type ($ruleTypeDefinitions):
     *  - learn:    every rule of every type, over rulebase, pre-rulebase and post-rulebase
     *  - check:    double spaces / wrong characters in the name; duplicate members; 'any' plus another member;
     *              rule names used twice, also between pre-rulebase and post-rulebase
     *  - fix:      duplicate members removed; a duplicate rule name is renamed (the first rule keeps its name)
     *  - remember: logFinding(), counters, the summary properties of the type
     *  - output:   the summary lines and the HTML report
     */
    private function checkRules( DOMElement $locationNode, $locationName )
    {
        $rulebases = array();
        foreach( array( 'rulebase', 'pre-rulebase', 'post-rulebase' ) as $rulebaseName )
        {
            $node = DH::findFirstElement( $rulebaseName, $locationNode );
            if( $node !== FALSE )
                $rulebases[$rulebaseName] = $node;
        }
        if( count( $rulebases ) == 0 )
            return;

        $data = array();
        foreach( $this->ruleTypeDefinitions as $ruleType => $def )
            $data[$ruleType] = array( 'rules' => array(), 'doubleSpace' => array(), 'wrongChar' => array(), 'any' => array(), 'appDefaultOnly' => array() );

        // learn, check and fix per rule
        foreach( $rulebases as $rulebaseName => $rulebaseNode )
        {
            PH::print_stdout( "" );
            PH::print_stdout( "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####" );
            PH::print_stdout( "[" . $rulebaseName . "]" );

            foreach( $this->ruleTypeDefinitions as $ruleType => $def )
            {
                $typeNode = DH::findFirstElement( $ruleType, $rulebaseNode );
                if( $typeNode === FALSE )
                    continue;
                $rulesNode = DH::findFirstElement( 'rules', $typeNode );

                $count = 0;
                if( $rulesNode !== FALSE )
                    foreach( $rulesNode->childNodes as $ruleNode )
                    {
                        if( $ruleNode->nodeType != XML_ELEMENT_NODE )
                            continue;
                        /** @var DOMElement $ruleNode */
                        $count++;
                        $this->checkRule( $locationName, $rulebaseName, $ruleType, $def, $ruleNode, $data[$ruleType] );
                    }

                PH::print_stdout( " - parsed " . $count . " " . $def['title'] );
                PH::print_stdout( "" );
            }
        }

        // remember + output, per type over all rulebases
        foreach( $this->ruleTypeDefinitions as $ruleType => $def )
            $this->reportRuleNames( $locationName, $def, $data[$ruleType] );

        foreach( $this->ruleTypeDefinitions as $ruleType => $def )
            foreach( $def['anyFields'] ?? array() as $field => $anyDef )
            {
                $anyValue = $anyDef['any'] ?? 'any';
                PH::print_stdout( " - Scanning for misconfigured " . ucfirst( $field ) . " Field in " . $def['title'] . "..." );
                foreach( $data[$ruleType]['any'][$field] ?? array() as $finding )
                {
                    list( $ruleName, $node ) = $finding;
                    $text = $def['objectType'] . " named '{$ruleName}' that has {$field} '{$anyValue}' and additional {$field} configured at XML line #{$node->getLineNo()}";
                    PH::print_stdout( "   - " . $text );
                    $this->logFinding( $locationName, $ruleName, $def['objectType'], $text, false );

                    $this->counters['manual'][$anyDef['counter']] = ( $this->counters['manual'][$anyDef['counter']] ?? 0 ) + 1;
                    $this->{$anyDef['property']}++;
                }
            }

        if( $this->service_app_default_available )
        {
            PH::print_stdout( " - Scanning for Security Rules with 'application-default' set | service object 'application-default' is available ..." );
            foreach( $data['security']['appDefaultOnly'] as $finding )
            {
                list( $ruleName, $node ) = $finding;
                $text = "SecRule named '{$ruleName}' that is using SERVICE OBJECT at XML line #{$node->getLineNo()}";
                $this->logFinding( $locationName, $ruleName, 'SecRule', $text, false );
                PH::print_stdout( "   - " . $text );

                $this->counters['manual']['SecRule ServiceAppDefault misconfigured'] = ( $this->counters['manual']['SecRule ServiceAppDefault misconfigured'] ?? 0 ) + 1;
                $this->countMissconfiguredSecRuleServiceAppDefaultObjects++;
            }
        }
    }

    /** one rule: learn its name, remove duplicate members, remember 'any' plus another member */
    private function checkRule( $locationName, $rulebaseName, $ruleType, $def, DOMElement $ruleNode, &$data )
    {
        $ruleName = $ruleNode->getAttribute( 'name' );

        $this->check_name( $ruleName, $ruleNode, $data['doubleSpace'] );
        $this->check_wrong_name( $ruleName, $ruleNode, $data['wrongChar'] );
        $data['rules'][$ruleName][] = array( 'node' => $ruleNode, 'rulebase' => $rulebaseName );

        foreach( $def['fields'] as $field => $fieldDef )
        {
            $members = $this->ruleFieldRemoveDuplicateMembers( $locationName, $def['objectType'], $ruleName, $ruleNode, $field, $fieldDef );
            if( $members === null || count( $members ) < 2 )
                continue;

            if( $field == 'source' && isset( $members['any'] ) )
                PH::print_stdout( "     - Rule: '" . $ruleName . "' has source 'any' + something else defined." );

            if( isset( $def['anyFields'][$field] ) )
            {
                $anyValue = $def['anyFields'][$field]['any'] ?? 'any';
                if( isset( $members[$anyValue] ) )
                    $data['any'][$field][] = array( $ruleName, $members[$anyValue] );
            }
        }

        if( !empty( $def['appDefault'] ) )
        {
            $services = DH::findFirstElement( 'service', $ruleNode );
            if( $services !== FALSE )
            {
                $values = array();
                foreach( $services->childNodes as $member )
                    if( $member->nodeType == XML_ELEMENT_NODE )
                        $values[$member->textContent] = $member;
                if( count( $values ) == 1 && isset( $values['application-default'] ) )
                    $data['appDefaultOnly'][] = array( $ruleName, $values['application-default'] );
            }
        }
    }

    /**
     * Removes duplicate <member> of one rule field.
     * @return DOMElement[]|null  the remaining members by value; null when the rule has no such field
     */
    private function ruleFieldRemoveDuplicateMembers( $locationName, $objectType, $ruleName, DOMElement $ruleNode, $field, $fieldDef )
    {
        $fieldNode = DH::findFirstElement( $field, $ruleNode );
        if( $fieldNode === FALSE )
            return null;

        $members = array();
        foreach( iterator_to_array( $fieldNode->childNodes ) as $member )
        {
            /** @var DOMElement $member */
            if( $member->nodeType != XML_ELEMENT_NODE )
                continue;

            $value = $member->textContent;
            if( !isset( $members[$value] ) )
            {
                $members[$value] = $member;
                continue;
            }

            $fieldNode->removeChild( $member );

            $quote = empty( $fieldDef['quote'] ) ? "" : "'";
            $text = $objectType . " " . $quote . $ruleName . $quote . " has same " . $fieldDef['label'] . " defined twice: " . $value;
            $this->logFinding( $locationName, $ruleName, $objectType, $text, true );
            PH::print_stdout( "     - " . $text . PH::boldText( " (removed)" ) );

            $counterKey = $objectType . ' ' . $fieldDef['counter'] . ' Object duplicate';
            $this->counters['fixed'][$counterKey] = ( $this->counters['fixed'][$counterKey] ?? 0 ) + 1;
            $this->{$fieldDef['property']}++;
        }
        return $members;
    }

    /** names of one rule type: double spaces, wrong characters, and names used twice (over all rulebases) */
    private function reportRuleNames( $locationName, $def, &$data )
    {
        $objectType = $def['objectType'];

        PH::print_stdout( " - Scanning for " . $def['title'] . " with double spaces in name..." );
        foreach( $data['doubleSpace'] as $ruleName => $node )
        {
            $text = $objectType . " '{$ruleName}' from DG/VSYS {$locationName} ";
            $text1 = "has '  ' double Spaces in name, this causes problems by copy&past 'set commands' at XML line #{$node->getLineNo()}";
            $this->logFinding( $locationName, $ruleName, $objectType, $text1, false );
            PH::print_stdout( "    - " . $text . $text1 . " ... (*FIX_MANUALLY*)" );

            $this->counters['manual'][$objectType . ' Name doubleSpace'] = ( $this->counters['manual'][$objectType . ' Name doubleSpace'] ?? 0 ) + 1;
            $this->{$def['doubleSpace']}++;
        }

        PH::print_stdout( " - Scanning for " . $def['title'] . " with wrong characters in name..." );
        foreach( $data['wrongChar'] as $ruleName => $node )
        {
            $text = $objectType . " '{$ruleName}' from DG/VSYS {$locationName} ";
            $text1 = "has wrong characters in name at XML line #{$node->getLineNo()}";
            $this->logFinding( $locationName, $ruleName, $objectType, $text1, false );
            PH::print_stdout( "    - " . $text . $text1 . " ... (*FIX_MANUALLY*)" );

            $this->counters['manual'][$objectType . ' Name wrongCharacter'] = ( $this->counters['manual'][$objectType . ' Name wrongCharacter'] ?? 0 ) + 1;
            $this->{$def['wrongChar']}++;
        }

        PH::print_stdout( " - Scanning for duplicate " . $def['title'] . "..." );

        // every name of this rule type in this location, over all rulebases; renamed rules are added as they get their name
        $usedNames = array();
        foreach( $data['rules'] as $ruleName => $occurrences )
            $usedNames[(string)$ruleName] = TRUE;

        foreach( $data['rules'] as $ruleName => $occurrences )
        {
            if( count( $occurrences ) < 2 )
                continue;
            $ruleName = (string)$ruleName;

            $where = array();
            foreach( $occurrences as $occurrence )
                $where[] = $occurrence['rulebase'];
            PH::print_stdout( "   - found " . $def['singular'] . " named '{$ruleName}' that exists " . count( $occurrences ) . " time: " . implode( ", ", $where ) );

            $first = array_shift( $occurrences );
            PH::print_stdout( "       - " . $objectType . " at XML line #{$first['node']->getLineNo()} [{$first['rulebase']}] keeps the name" );

            foreach( $occurrences as $occurrence )
            {
                /** @var DOMElement $node */
                $node = $occurrence['node'];
                $text = $objectType . " '{$ruleName}' at XML line #{$node->getLineNo()} [{$occurrence['rulebase']}]";

                $newName = $this->freeRuleName( $ruleName, $usedNames );
                if( $newName !== null )
                {
                    $node->setAttribute( 'name', $newName );
                    $usedNames[$newName] = TRUE;

                    $text2 = " - new name: " . $newName;
                    $this->logFinding( $locationName, $ruleName, $objectType, $text . $text2, true );
                    PH::print_stdout( "       - " . $text . PH::boldText( $text2 . " (fixed)" ) );

                    $this->counters['fixed'][$objectType . ' duplicate'] = ( $this->counters['fixed'][$objectType . ' duplicate'] ?? 0 ) + 1;
                    $this->{$def['duplicateFixed']}++;
                }
                else
                {
                    $text .= " - Rulename can not be fixed: no free name found";
                    $this->logFinding( $locationName, $ruleName, $objectType, $text, false );
                    PH::print_stdout( "       - " . $text );

                    $this->counters['manual'][$objectType . ' duplicate'] = ( $this->counters['manual'][$objectType . ' duplicate'] ?? 0 ) + 1;
                    $this->{$def['duplicateManual']}++;
                }
            }
        }
    }

    /**
     * A rule name not used yet: $name_1, $name_2, ...; $name is shortened so that the result fits RULE_NAME_MAXLEN.
     * @return string|null  null when no free name is found
     */
    private function freeRuleName( $name, $usedNames )
    {
        for( $i = 1; $i < 1000; $i++ )
        {
            $suffix = "_" . $i;
            $base = $name;
            if( mb_strlen( $base . $suffix ) > self::RULE_NAME_MAXLEN )
                $base = mb_substr( $base, 0, self::RULE_NAME_MAXLEN - mb_strlen( $suffix ) );
            $candidate = $base . $suffix;
            if( !isset( $usedNames[$candidate] ) )
                return $candidate;
        }
        return null;
    }

    /**
     * A group that has itself as member (address-group <static>, service-group <members>).
     *  - learn:    the group's members
     *  - check:    a member with the group's own name
     *  - fix:      when no address / service object of that name is visible from this location, the member is removed
     *              (*FIXED*); when one is (this location, a parent device group, shared or predefined), the member
     *              probably means that object: it is kept and reported (*FIX_MANUALLY*: rename the group)
     *  - remember / output: logFinding(), counters, summary; a group left without member is reported (*FIX_MANUALLY*)
     * @param string $kind 'address' or 'service'
     * @param array $groups group name => DOMElement[]
     */
    private function checkGroupSelfMember( $locationName, $kind, $groups )
    {
        $objectType = $kind . "group";
        $listTag = ( $kind == "address" ) ? "static" : "members";
        $counterName = ( $kind == "address" ) ? "Address Group" : "Service Group";

        PH::print_stdout( " - Scanning for {$kind} groups with own membership as subgroup..." );
        foreach( $groups as $groupName => $nodes )
        {
            $groupName = (string)$groupName;
            foreach( $nodes as $node )
            {
                /** @var DOMElement $node */
                $listNode = DH::findFirstElement( $listTag, $node );
                if( $listNode === FALSE )
                    continue;

                $selfMembers = array();
                foreach( $listNode->childNodes as $member )
                    if( $member->nodeType == XML_ELEMENT_NODE && $member->textContent === $groupName )
                        $selfMembers[] = $member;
                if( count( $selfMembers ) == 0 )
                    continue;

                $text = $objectType . " '{$groupName}' from DG/VSYS {$locationName} ";
                $objectLocation = $this->locationWithObjectNamed( $locationName, $kind, $groupName );

                if( $objectLocation !== null )
                {
                    $text1 = "has itself as member '{$groupName}' at XML line #{$node->getLineNo()}; the member probably means the {$kind} object '{$groupName}' in '{$objectLocation}': rename the group and keep the member";
                    PH::print_stdout( "    - " . $text . $text1 . " ... (*FIX_MANUALLY*)" );
                    $this->logFinding( $locationName, $groupName, $objectType, $text1, false );

                    $this->counters['manual'][$counterName . ' SubGroup'] = ( $this->counters['manual'][$counterName . ' SubGroup'] ?? 0 ) + 1;
                    if( $kind == "address" )
                        $this->countAddressGroupsSubGroupManual++;
                    else
                        $this->countServiceGroupsSubGroupManual++;
                    continue;
                }

                foreach( $selfMembers as $member )
                {
                    $listNode->removeChild( $member );

                    $text1 = "has itself as member '{$groupName}' at XML line #{$node->getLineNo()} - removed";
                    PH::print_stdout( "    - " . $text . $text1 . " ... *FIXED*" );
                    $this->logFinding( $locationName, $groupName, $objectType, $text1, true );

                    $this->counters['fixed'][$counterName . ' SubGroup'] = ( $this->counters['fixed'][$counterName . ' SubGroup'] ?? 0 ) + 1;
                    if( $kind == "address" )
                        $this->totalAddressGroupsSubGroupFixed++;
                    else
                        $this->totalServiceGroupsSubGroupFixed++;
                }

                if( !$this->fullScanHasChildElements( $listNode ) )
                {
                    $text1 = "has no member left after removing itself at XML line #{$node->getLineNo()}: PAN-OS does not accept an empty group";
                    PH::print_stdout( "    - " . $text . $text1 . " ... (*FIX_MANUALLY*)" );
                    $this->logFinding( $locationName, $groupName, $objectType, $text1, false );

                    $this->counters['manual'][$counterName . ' empty'] = ( $this->counters['manual'][$counterName . ' empty'] ?? 0 ) + 1;
                    if( $kind == "address" )
                        $this->countEmptyAddressGroup++;
                    else
                        $this->countEmptyServiceGroup++;
                }
            }
        }
    }

    /**
     * Where an address / service object (not a group) named $name is visible from $locationName:
     * the location itself, its parent device groups (Panorama), shared, predefined.
     * @return string|null the location name, 'predefined', or null
     */
    private function locationWithObjectNamed( $locationName, $kind, $name )
    {
        foreach( $this->locationScope( $locationName ) as $scopeName )
        {
            $names = $this->objectNamesInLocation( $scopeName, $kind );
            if( isset( $names[$name] ) )
                return $scopeName;
        }

        if( $kind == "service" && ( $name === "service-http" || $name === "service-https" ) )
            return "predefined";

        return null;
    }

    /** the location, its parent device groups (from readonly parent-dg), then shared */
    private function locationScope( $locationName )
    {
        $scope = array();
        $seen = array();
        $current = $locationName;
        while( $current !== null && $current !== 'shared' && !isset( $seen[$current] ) )
        {
            $seen[$current] = TRUE;
            $scope[] = $current;

            $parent = null;
            if( $this->configType == 'panorama' )
            {
                $nodes = DH::findXPath( "/config/readonly/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $current . "']/parent-dg", $this->xmlDoc );
                if( count( $nodes ) > 0 && trim( $nodes[0]->textContent ) !== '' )
                    $parent = trim( $nodes[0]->textContent );
            }
            $current = $parent;
        }
        $scope[] = 'shared';
        return $scope;
    }

    /** names of the address / service objects (not groups) of one location */
    private function objectNamesInLocation( $locationName, $kind )
    {
        if( isset( $this->objectNamesCache[$locationName][$kind] ) )
            return $this->objectNamesCache[$locationName][$kind];

        $names = array();
        $locationNode = $this->locationNodesByName[$locationName] ?? null;
        if( $locationNode !== null )
        {
            $container = DH::findFirstElement( $kind, $locationNode );
            if( $container !== FALSE )
                foreach( $container->childNodes as $entry )
                    if( $entry->nodeType == XML_ELEMENT_NODE && $entry->nodeName == 'entry' )
                        $names[$entry->getAttribute( 'name' )] = TRUE;
        }
        $this->objectNamesCache[$locationName][$kind] = $names;
        return $names;
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
        if( $this->isProtectedRouting( $parent ) )
        {
            // routing configuration (e.g. bgp/redist-rules): report only
            $seen = array();
            foreach( $parent->childNodes as $node )
            {
                if( $node->nodeType !== XML_ELEMENT_NODE )
                    continue;
                /** @var DOMElement $node */
                $identifier = $node->getAttribute( 'name' );
                if( $identifier === '' )
                    $identifier = trim( $node->textContent );
                if( isset( $seen[$identifier] ) )
                    $this->reportProtectedRoutingDuplicate( $parent, "{$label} '{$identifier}'", $identifier, $node, $seen[$identifier], "duplicate" );
                else
                    $seen[$identifier] = $node;
            }
            return 0;
        }

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
            $text = "{$contextText} has same ".strtoupper($objectType)." defined twice: {$name}";

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