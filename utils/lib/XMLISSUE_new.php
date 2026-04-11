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

    // HTML Output properties
    public $htmlOutput = [];
    public $summaryOutput = [
        'total_findings' => 0,
        'fixed' => 0,
        'not_fixed' => 0
    ];

    /**
     * Helper to log findings to both stdout and HTML buffer
     */
    private function logFinding($location, $objectName, $issue, $isFixed = false)
    {
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

    public function utilStart()
    {
        $this->usageMsg = PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=api://[MGMT-IP-Address] ";

        PH::processCliArgs();
        $this->help(PH::$args);
        $this->init_arguments();

        if( isset(PH::$args['out']) )
        {
            $this->configOutput = PH::$args['out'];
            if( !is_string($this->configOutput) || strlen($this->configOutput) < 1 )
                $this->display_error_usage_exit('"out" argument is not a valid string');
        }

        $this->load_config();
        $this->main();

        // Generate the HTML report before finishing
        $this->generateHTML();
        $this->save_our_work( true );
    }

    public function main()
    {
        $xpath = new DOMXpath($this->xmlDoc);
        $elements = $xpath->query("//deleted");
        foreach( $elements as $element ) { $element->parentNode->removeChild($element); }

        // Preload Regions
        $filename = dirname(__FILE__) . '/../../lib/object-classes/predefined.xml';
        $xmlDoc_region = new DOMDocument();
        $xmlDoc_region->load($filename, XML_PARSE_BIG_LINES);
        $cursor = DH::findXPathSingleEntryOrDie('/predefined/region', $xmlDoc_region);
        foreach( $cursor->childNodes as $region_entry ) {
            if( $region_entry->nodeType != XML_ELEMENT_NODE ) continue;
            $region_name = DH::findAttribute('name', $region_entry);
            $this->region_array[$region_name] = $region_entry;
        }

        /** @var DOMElement[] $locationNodes */
        $locationNodes = array();
        $tmp_shared_node = DH::findXPathSingleEntry('/config/shared', $this->xmlDoc);
        if( $tmp_shared_node !== false ) $locationNodes['shared'] = $tmp_shared_node;

        if( $this->configType == 'panos' )
            $tmpNodes = DH::findXPath('/config/devices/entry/vsys/entry', $this->xmlDoc);
        elseif( $this->configType == 'panorama' )
            $tmpNodes = DH::findXPath('/config/devices/entry/device-group/entry', $this->xmlDoc);

        foreach( $tmpNodes as $node ) $locationNodes[$node->getAttribute('name')] = $node;

        foreach( $locationNodes as $locationName => $locationNode )
        {
            PH::print_stdout( "** PARSING '{$locationName}' **");

            // --- ADDRESS SCAN ---
            $addressObjects = array(); $addressGroups = array(); $addressIndex = array();
            $address_region = array(); $address_name = array(); $address_wrong_name = array();

            $objectTypeNode = DH::findFirstElement('address', $locationNode);
            if( $objectTypeNode !== FALSE ) {
                foreach( $objectTypeNode->childNodes as $objectNode ) {
                    if( $objectNode->nodeType != XML_ELEMENT_NODE ) continue;
                    $objectName = $objectNode->getAttribute('name');
                    $this->check_region( $objectName, $objectNode, $address_region );
                    $this->check_name( $objectName, $objectNode, $address_name );
                    $this->check_wrong_name( $objectName, $objectNode, $address_wrong_name );
                    $addressObjects[$objectName][] = $objectNode;
                }
            }

            // Reporting Findings for Address Objects
            foreach( $address_region as $objectName => $node ) {
                $this->logFinding($locationName, $objectName, "Same name as REGION object", false);
            }
            foreach( $address_name as $objectName => $node ) {
                $this->logFinding($locationName, $objectName, "Double spaces in name", false);
            }
            foreach( $address_wrong_name as $objectName => $node ) {
                $this->logFinding($locationName, $objectName, "Invalid characters in name", false);
            }

            // Scanning for duplicate members in Address Groups (Auto-Fixed)
            $addrGrpNode = DH::findFirstElement('address-group', $locationNode);
            if($addrGrpNode) {
                foreach($addrGrpNode->childNodes as $node) {
                    if($node->nodeType != XML_ELEMENT_NODE) continue;
                    $objectName = $node->getAttribute('name');
                    $staticNode = DH::findFirstElement('static', $node);
                    if(!$staticNode) continue;
                    $membersIndex = [];
                    foreach(iterator_to_array($staticNode->childNodes) as $member) {
                        if($member->nodeType != XML_ELEMENT_NODE) continue;
                        $memberName = $member->textContent;
                        if(isset($membersIndex[$memberName])) {
                            $this->logFinding($locationName, $objectName, "Duplicate member: {$memberName}", true);
                            $member->parentNode->removeChild($member);
                        } else { $membersIndex[$memberName] = true; }
                    }
                }
            }

            // --- SERVICE SCAN ---
            $service_name = []; $service_wrong_name = []; $service_name_appdefault = [];
            $objectTypeNode = DH::findFirstElement('service', $locationNode);
            if( $objectTypeNode !== FALSE ) {
                foreach( $objectTypeNode->childNodes as $objectNode ) {
                    if( $objectNode->nodeType != XML_ELEMENT_NODE ) continue;
                    $objectName = $objectNode->getAttribute('name');
                    $this->check_name( $objectName, $objectNode, $service_name );
                    $this->check_wrong_name( $objectName, $objectNode, $service_wrong_name );
                    $this->check_service_name_appdefault( $objectName, $objectNode, $service_name_appdefault );
                }
            }

            foreach($service_name as $name => $node) $this->logFinding($locationName, $name, "Service name double spaces", false);
            foreach($service_wrong_name as $name => $node) $this->logFinding($locationName, $name, "Service name invalid characters", false);
            foreach($service_name_appdefault as $name => $node) $this->logFinding($locationName, $name, "Service name conflicts with application-default", false);
        }
    }

    private function generateHTML()
    {
        $html = "<html><head><title>XML Configuration Issue Report</title><style>
            body { font-family: sans-serif; padding: 20px; }
            table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }
            th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
            th { background-color: #f2f2f2; }
            .fixed { color: green; font-weight: bold; }
            .manual { color: red; font-weight: bold; }
            tr:nth-child(even) { background-color: #fafafa; }
        </style></head><body>";

        $html .= "<h2>1. Detailed Misconfigurations Found</h2>";
        $html .= "<table><thead><tr><th>Location</th><th>Object</th><th>Issue Description</th><th>Status</th></tr></thead><tbody>";

        if (empty($this->htmlOutput)) {
            $html .= "<tr><td colspan='4'>No misconfigurations found. Everything looks good!</td></tr>";
        } else {
            foreach ($this->htmlOutput as $row) {
                $statusClass = ($row['status'] == 'Fixed') ? 'fixed' : 'manual';
                $html .= "<tr>
                    <td>" . htmlspecialchars($row['location']) . "</td>
                    <td>" . htmlspecialchars($row['object']) . "</td>
                    <td>" . htmlspecialchars($row['issue']) . "</td>
                    <td class='{$statusClass}'>" . htmlspecialchars($row['status']) . "</td>
                </tr>";
            }
        }
        $html .= "</tbody></table>";

        $html .= "<h2>2. Executive Summary</h2>";
        $html .= "<table><thead><tr><th>Metric</th><th>Count</th></tr></thead><tbody>
            <tr><td>Total Issues Identified</td><td>{$this->summaryOutput['total_findings']}</td></tr>
            <tr><td>Automatically Resolved (Fixed)</td><td class='fixed'>{$this->summaryOutput['fixed']}</td></tr>
            <tr><td>Issues Requiring Attention (Not Fixed)</td><td class='manual'>{$this->summaryOutput['not_fixed']}</td></tr>
        </tbody></table>";

        $html .= "</body></html>";

        file_put_contents("xml_issue_report.html", $html);
        PH::print_stdout("\n** HTML Report successfully created: xml_issue_report.html **\n");
    }
}