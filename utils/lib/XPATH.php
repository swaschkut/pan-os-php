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

class XPATH extends UTIL
{
    public $jsonArray = array();

    private $fullxpath = false;
    private $xpath = null;
    private $displayXMLnode = false;
    private $displayAPIcommand = false;
    private $displayXMLlineno = false;
    private $displayAttributeName = false;
    private $action = "display";

    private $qualifiedNodeName = false;
    private $nameattribute = false;

    public function utilStart()
    {
        $this->usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml ".
            "        \"filter-node=certificate\"\n".
            "        \"[filter-nameattribute=address_object_name]\"\n".
            "        \"[filter-text=xml-node-text]\"\n".
            "        \"[filter-text_regex=xml-node-text]\"\n".
            "        \"[filter-xpath=/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/update-server]\"\n".
            "        \"[display-fullxpath]\"\n".
            "        \"[display-xmlnode]\"\n".
            "        \"[display-xmllineno]\"\n".
            "        \"[display-attributename]\"\n".
            "        \"[display-api-command]\"\n".
            "php ".basename(__FILE__)." help          : more help messages\n";

        $this->add_supported_arguments();
        
        $this->prepareSupportedArgumentsArray();


        PH::processCliArgs();
        $this->help(PH::$args);
        $this->init_arguments();


        #$this->load_config();


        $this->main();

    }

    public function main()
    {
        global $jsonArray;

        if( isset( PH::$args['actions'] ) )
        {
            //Todo: 20241022: swaschkut / no clue what I planned to do there
            $supportedActions = array( 'display', 'remove', 'set-text', 'manipulate', 'display-api-command' );
            $this->action = PH::$args['actions'];

            if( !in_array( $this->action, $supportedActions )
                && strpos( $this->action, 'set-text:' ) === FALSE && strpos( $this->action, 'manipulate:' ) === FALSE
            )
                    derr( "action: ". $this->action. " not supported", null, false );

            if( strpos( $this->action, 'manipulate:' ) !== FALSE )
            {
                //read file from:
                $tmpArray = explode( ":", $this->action );
                if( isset($tmpArray[1]) )
                {
                    $strJsonFileContents = file_get_contents($tmpArray[1]);
                    $jsonArray = json_decode($strJsonFileContents, true);
                    if( $jsonArray === null )
                        derr( "invalid JSON file provided", null, FALSE );
                }
                else
                    derr("actions=manipulation:FILENAME.json - used; but JSON file not correct mentioned", null, False);
            }
        }


        if( !isset( PH::$args['filter-node'] ) && !isset( PH::$args['filter-nameattribute'] ) && !isset( PH::$args['filter-xpath'] ) && !isset( PH::$args['filter-text'] ) && !isset( PH::$args['filter-text_regex'] ) )
            $this->display_error_usage_exit('"filter-node" argument is not set: example "certificate"');
        elseif( !isset( PH::$args['filter-node'] ) && isset( PH::$args['filter-nameattribute'] ) )
            $this->qualifiedNodeName = "entry";
        elseif( isset( PH::$args['filter-text'] ) )
            $this->qualifiedNodeName = '//*[text()="'.PH::$args['filter-text'].'"]';
        elseif( isset( PH::$args['filter-text_regex'] ) )
            $this->qualifiedNodeName = '//*[text()[contains(.,"'.PH::$args['filter-text_regex'].'")]]';
        elseif( !isset( PH::$args['filter-xpath'] ) )
            $this->qualifiedNodeName = PH::$args['filter-node'];

        if( isset( PH::$args['filter-xpath'] ) )
            $this->xpath = PH::$args['filter-xpath'];
        elseif( isset( PH::$args['filter-text'] ) || isset( PH::$args['filter-text_regex'] ) )
            $this->xpath = $this->qualifiedNodeName;

        if( isset( PH::$args['display-fullxpath'] ) )
            $this->fullxpath = true;

        if( isset( PH::$args['display-xmlnode'] ) )
            $this->displayXMLnode = true;

        if( isset( PH::$args['display-api-command'] ) )
        {
            $this->displayXMLnode = true;
            $this->displayAPIcommand = true;
        }


        if( isset( PH::$args['display-xmllineno'] ) )
            $this->displayXMLlineno = true;

        if( isset( PH::$args['filter-nameattribute'] ) )
            $this->nameattribute = PH::$args['filter-nameattribute'];
        else
            $this->nameattribute = null;

        if( isset( PH::$args['display-nameattribute'] ) )
            $this->displayAttributeName = true;
        ########################################################################################################################

        if( !isset( PH::$args['filter-xpath'] ) && !isset( PH::$args['filter-text'] ) && !isset( PH::$args['filter-text_regex'] ) )
        {
            //todo: missing connector support
            //$this->getXpathDisplayMain();
            $tmp_string = "";
            DH::getXpathDisplayMain( $tmp_string, $this->xmlDoc, $this->qualifiedNodeName, $this->nameattribute, $this->xpath, $this->displayXMLnode, $this->displayAttributeName, $this->displayXMLlineno, $this->fullxpath, $this->displayAPIcommand, $this->pan );
            PH::print_stdout( $tmp_string );

            PH::print_stdout();
        }
        else
        {
            /*
            if( $this->pan->connector !==  null )
            {
                $this->pan->connector->refreshSystemInfos();

                PH::print_stdout();
                PH::print_stdout( "##########################################" );
                PH::print_stdout( 'MASTER device serial: '.$this->pan->connector->info_serial );
                PH::print_stdout();

                PH::$JSON_TMP['serial'] = $this->pan->connector->info_serial;
                PH::print_stdout(PH::$JSON_TMP, false, "master device");
                PH::$JSON_TMP = array();

                if( $this->configType == 'panos' )
                {
                    if( $this->pan->connector->serial != "" )
                    {
                        $fw_con = $this->pan->connector->cloneForPanoramaManagedDevice($this->pan->connector->serial);
                        $fw_con->refreshSystemInfos();
                        if( $this->debugAPI )
                            $fw_con->setShowApiCalls( $this->debugAPI );
                        if( $displayAttributeName )
                            $this->getXpathDisplay( $xpath, $this->pan->connector->serial, true, $action);
                        else
                            $this->getXpathDisplay( $xpath, $this->pan->connector->serial, false, $action);
                    }
                    else
                    {
                        $this->pan->connector->refreshSystemInfos();
                        if( $displayAttributeName )
                            $this->getXpathDisplay( $xpath, $this->pan->connector->serial, true, $action);
                        else
                            $this->getXpathDisplay( $xpath, $this->pan->connector->info_serial, false, $action);
                    }
                }
                elseif( $this->configType == 'panorama' )
                {
                    $device_serials = $this->pan->connector->panorama_getConnectedFirewallsSerials();

                    $i=0;
                    foreach( $device_serials as $child )
                    {
                        $fw_con = $this->pan->connector->cloneForPanoramaManagedDevice($child['serial']);
                        $fw_con->refreshSystemInfos();
                        if( $this->debugAPI )
                            $fw_con->setShowApiCalls( $this->debugAPI );

                        $string = " - SERIAL: ".$child['serial'];
                        $string .= "  -  ".$child['hostname']." - ";
                        $string .= $fw_con->info_mgmtip;

                        PH::print_stdout( $string );
                        $i++;

                        if( $displayAttributeName )
                            $this->getXpathDisplay( $xpath, $child['serial'], true, $action);
                        else
                            $this->getXpathDisplay( $xpath, $child['serial'],false, $action);
                    }
                }
            }
            else
            {
            */
                if( $this->displayAttributeName )
                {
                    $tmp_string = "";
                    DH::getXpathDisplay( $tmp_string, $this->xmlDoc, $this->qualifiedNodeName, "test", true);
                    PH::print_stdout( $tmp_string );
                }
                else
                {
                    $tmp_string = "";
                    DH::getXpathDisplay( $tmp_string, $this->xmlDoc, $this->qualifiedNodeName, "test", false);
                    PH::print_stdout( $tmp_string );
                }
            //}
        }

        if( $this->action == "remove" || strpos( $this->action, 'set-text:' ) !== FALSE || strpos( $this->action, 'manipulate:' ) !== FALSE )
        {
            //todo: save output
            //check if out is set
            if( isset( PH::$args['out'] ) )
            {
                $lineReturn = TRUE;
                $indentingXml = 0;
                $indentingXmlIncreament = 1;

                $xml = &DH::dom_to_xml($this->xmlDoc->documentElement, $indentingXml, $lineReturn, -1, $indentingXmlIncreament + 1);

                file_put_contents(PH::$args['out'], $xml);
            }
            else
                derr( "action=remove used - but argument 'out=FILENAME' is not set " );
        }
    }

    function add_supported_arguments()
    {
        $this->supportedArguments = array();
        $this->supportedArguments[] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments[] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments[] = Array('niceName' => 'help', 'shortHelp' => 'this message');

        $this->supportedArguments[] = Array('niceName' => 'filter-node', 'shortHelp' => 'specify the filter-node to get all xPath within this configuration file');
        $this->supportedArguments[] = Array('niceName' => 'filter-xpath', 'shortHelp' => 'specify the xpath to get the value defined on this config');
        $this->supportedArguments[] = Array('niceName' => 'filter-nameattribute', 'shortHelp' => 'specify the nameattribute to get only XMLnode where nameattribute match');
        $this->supportedArguments[] = Array('niceName' => 'filter-text', 'shortHelp' => 'specify the textContent to get only XMLnode where text is match exactly');
        $this->supportedArguments[] = Array('niceName' => 'filter-text_regex', 'shortHelp' => 'specify the textContent to get only XMLnode where text is containing');

        $this->supportedArguments[] = Array('niceName' => 'display-fullxpath', 'shortHelp' => 'display full xpath for templates');
        $this->supportedArguments[] = Array('niceName' => 'display-NameAttribute', 'shortHelp' => 'display not full Xpath content, only attribute name');
        $this->supportedArguments[] = Array('niceName' => 'display-xmlnode', 'shortHelp' => 'display XML node configuration');
        $this->supportedArguments[] = Array('niceName' => 'display-xmlLineNo', 'shortHelp' => 'display LineNo of XML node ');
        
    }

    function getXpathDisplayMain( $xmlDoc, $qualifiedNodeName, $nameattribute, $xpath, $displayXMLnode, $displayAttributeName, $displayXMLlineno, $fullxpath, $displayAPIcommand, $pan )
    {
        $nodeList = $xmlDoc->getElementsByTagName($qualifiedNodeName);
        $nodeArray = iterator_to_array($nodeList);

        $templateEntryArray = array();
        foreach( $nodeArray as $item )
        {
            if( $nameattribute !== null )
            {
                $XMLnameAttribute = DH::findAttribute("name", $item);
                if( $XMLnameAttribute === FALSE )
                    continue;

                if( $XMLnameAttribute !== $nameattribute )
                    continue;
            }
            $text = DH::elementToPanXPath($item);
            $replace_template = "/config/devices/entry[@name='localhost.localdomain']/template/";

            if( $xpath !== null && strpos($text, $xpath) === FALSE )
                continue;

            if( strpos($text, $replace_template) !== FALSE )
            {
                $tmpArray['xpath'] = $text;
                $text = str_replace($replace_template, "", $text);

                $templateXpathArray = explode("/", $text);

                $templateName = str_replace("entry[@name='", "", $templateXpathArray[0]);
                $templateName = str_replace("']", "", $templateName);

                $replace = "entry[@name='" . $templateName . "']";
                $text = str_replace($replace, "", $text);

                $tmpArray['text'] = $text;
                $tmpArray['node'] = $item;
                $tmpArray['line'] = $item->getLineNo();

                $templateEntryArray['template'][$templateName][] = $tmpArray;

            }
            else
            {
                $tmpArray['text'] = $text;
                $tmpArray['node'] = $item;
                $tmpArray['line'] = $item->getLineNo();

                $templateEntryArray['misc'][] = $tmpArray;
            }

        }


        if( isset($templateEntryArray['template']) )
        {
            foreach( $templateEntryArray['template'] as $templateName => $templateEntry )
            {
                PH::print_stdout();
                PH::print_stdout("TEMPLATE: " . $templateName);
                foreach( $templateEntry as $item )
                {
                    $xpath = $item['xpath'];
                    PH::print_stdout();
                    PH::print_stdout("---------");
                    if( !$displayXMLnode && !$displayAttributeName )
                        PH::print_stdout( "   * XPATH: ".$xpath );

                    if( $displayXMLlineno )
                        PH::print_stdout( "   * line: ".$item['line'] );

                    if( $fullxpath )
                        PH::print_stdout("     |" . $xpath . "|");

                    if( $displayXMLnode )
                    {
                        //$this->getXpathDisplay("test", false);
                        DH::getXpathDisplay( $xmlDoc, $qualifiedNodeName, "test", false);
                    }

                    if( $displayAttributeName )
                    {
                        //$this->getXpathDisplay("test", true);
                        DH::getXpathDisplay( $xmlDoc, $qualifiedNodeName, "test", true);
                    }

                }
            }
        }

        if( isset($templateEntryArray['misc']) )
        {
            PH::print_stdout("MISC:");

            foreach( $templateEntryArray['misc'] as $miscEntry )
            {
                $xpath = $miscEntry['text'];
                PH::print_stdout();
                PH::print_stdout("---------");

                if( !$displayXMLnode && !$displayAttributeName )
                    PH::print_stdout( "   * XPATH: ".$xpath );

                if( $displayXMLlineno )
                    PH::print_stdout( "   * line: ".$miscEntry['line'] );

                if( $displayXMLnode )
                {
                    //$this->getXpathDisplay( "test", false);
                    DH::getXpathDisplay( $xmlDoc, $qualifiedNodeName, "test", false);
                }
                if( $displayAttributeName )
                {
                    //$this->getXpathDisplay( "test", true);
                    DH::getXpathDisplay( $xmlDoc, $qualifiedNodeName, "test", true);
                }


                if( $displayAPIcommand )
                {
                    $splitXPATH = explode( "/", PH::$JSON_TMP["test"]["xpath"] );
                    array_pop($splitXPATH);
                    $newXpath = "";
                    foreach( $splitXPATH as $entry )
                    {
                        $newXpath .= "/".$entry;
                    }
                    $newXpath = str_replace("//", "/", $newXpath);
                    $newValue = str_replace("\n", "", PH::$JSON_TMP["test"]["value"]);

                    if( $pan->connector !==  null )
                    {
                        $FIREWALL_IP = $pan->connector->apihost;
                        $APIkey = $pan->connector->apikey;
                    }
                    else
                    {
                        $FIREWALL_IP = "{FW-MGMT-IP}\n";
                        $APIkey = "{API-KEY}\n";
                    }


                    PH::print_stdout("----------------");
                    PH::print_stdout( "https://".$FIREWALL_IP."/api/?"."key=".$APIkey."\n&type=config&action=set&xpath=".$newXpath."\n&element=".$newValue );
                    PH::print_stdout("----------------");
                }
            }
        }
    }

    function getXpathDisplay( $serial, $entry = false)
    {
        $string = "";

        //Todo: swaschkut 20250104 - can this be combined with DH::getXpathDisplay
        global $jsonArray;

        $text_contains_search = false;

        PH::$JSON_TMP[$serial]['serial'] = $serial;
        //check Xpath
        $xpathResult = DH::findXPath( $this->xpath, $this->xmlDoc);

        $string .= "\n";
        $tmp_string = "* XPATH: ".$this->xpath;
        $string .= $tmp_string."\n";
        //PH::print_stdout( $tmp_string );

        if( strpos($this->xpath, "[text()") !== FALSE )
            $text_contains_search = true;

        PH::$JSON_TMP[$serial]['xpath'] = $this->xpath;

        foreach( $xpathResult as $xpath1 )
        {
            if($text_contains_search)
            {
                /** @var DOMElement $xpath1 */
                //PH::print_stdout();
                $string .= "\n";

                $nodePath = $xpath1->getNodePath();
                $tmp_string = "   * XPATH: ".$nodePath;
                $string .= $tmp_string."\n";
                //PH::print_stdout( $tmp_string );

                $tmpArray = explode("]", $nodePath);
                $tmp_path = "";
                foreach( $tmpArray as $key => $path_tmp )
                {
                    if( strpos($path_tmp, "[") === FALSE )
                        continue;

                    if( !empty($path_tmp) )
                    {
                        $newstring = substr($path_tmp, -7);
                        if( strpos( $newstring, "[" ) !== false )
                            $tmp_path .= $path_tmp."]";

                        $xpathResult = DH::findXPath( $tmp_path, $this->xmlDoc);
                        if( $xpathResult[0]->hasAttribute('name') )
                        {
                            $tmp_string = "    - "."entry[@name='".$xpathResult[0]->getAttribute('name')."']";
                            $string .= $tmp_string."\n";
                            #PH::print_stdout( $tmp_string );
                        }
                        else
                        {
                            $tmp_string = "    - ".$xpathResult[0]->nodeName;
                            $string .= $tmp_string."\n";
                            #PH::print_stdout( $tmp_string );
                        }
                    }
                }
            }

            $newdoc = new DOMDocument;
            $node = $newdoc->importNode($xpath1, true);
            $newdoc->appendChild($node);

            if( $entry === false )
            {
                $lineReturn = TRUE;
                $indentingXmlIncreament = 3;
                $indentingXml = 0;
                $xml = &DH::dom_to_xml($newdoc->documentElement, $indentingXml, $lineReturn, -1, $indentingXmlIncreament);

                $tmp_string = "      * VALUE: ";
                $string .= $tmp_string."\n";
                //PH::print_stdout( $tmp_string );
                $tmp_string = "        ".$xml;
                $string .= $tmp_string."\n";
                //PH::print_stdout( $tmp_string );
                PH::$JSON_TMP[$serial]['value'] = $xml;
            }
            else
            {
                foreach( $node->childNodes as $child )
                {
                    if( $child->nodeType != XML_ELEMENT_NODE )
                        continue;
                    if( $child->getAttribute('name') !== "" )
                    {
                        $tmp_string = "     - name: ". $child->getAttribute('name');
                        $string .= $tmp_string."\n";
                        //PH::print_stdout( $tmp_string );
                    }

                }
            }

            if( $this->action === "remove" )
            {
                PH::print_stdout("remove xpath!!!");
                $xpath1->parentNode->removeChild($xpath1);
            }

            if( strpos( $this->action, 'set-text:' ) !== FALSE )
            {
                $array = explode( ":", $this->action );
                if( isset( $array[1] ) )
                {
                    $tmpText = $array[1];
                    $tmp_string = "set xpath Text: ".$array[1];
                    $string .= $tmp_string."\n";
                    #PH::print_stdout($tmp_string);
                    $xpath1->textContent = $array[1];

                    DH::DEBUGprintDOMDocument($xpath1);
                }
            }

            if( strpos( $this->action, 'manipulate:' ) !== FALSE )
            {
                print_r($jsonArray);
            }
        }

        if( count($xpathResult) == 0 )
        {
            $tmp_string = "   * VALUE: not set";
            $string .= $tmp_string."\n";
            #PH::print_stdout( $tmp_string );
            PH::$JSON_TMP[$serial]['value'] = "---";
        }

        $string .= "\n";
        PH::print_stdout($string);
    }
}