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

class UPLOAD extends UTIL
{
    public $loadConfigAfterUpload = FALSE;
    public $extraFiltersOut = null;


    //Todo: optimisation needed to use class UTIL available parent methods

    public function utilStart()
    {
        $this->usageMsg = PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=api://[MGMT-IP-Address]\n".
            "JSON file structure:\n".
            "{
                \"preserve-xpath\": [
                \"/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/ip-address\",
                \"/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/hostname\",
                \"/config/devices/entry[@name='localhost.localdomain']/deviceconfig/high-availability\"
            ]
            }\n";



        $this->prepareSupportedArgumentsArray();

        //from utilInit
        PH::processCliArgs();
        $this->help(PH::$args);
        $this->arg_validation();

        if( isset(PH::$args['in']) )
        {
            if( strpos( PH::$args['in'], "api://") !== false && !isset(PH::$args['out']) )
            {
                $this->display_error_usage_exit('"out" argument is missing');
            }
        }

        //from init_arguments - which is triggered by utilInit
        $this->inDebugapiArgument();
        $this->inputValidation();


        $this->main();


        
    }

    public function main()
    {
        #$this->xmlDoc->formatOutput = true;
        #$this->xmlDoc->preserveWhiteSpace = false;

        $configPartOfTemplate = array();
        #Todo: swaschkut 20241004 - validate
        $configPartOfTemplate[] = "reports";
        $configPartOfTemplate[] = "report-group";
        $configPartOfTemplate[] = "display-name";
        $configPartOfTemplate[] = "botnet";
        $configPartOfTemplate[] = "content-preview";


        $configPartOfTemplate[] = "import";
        $configPartOfTemplate[] = "zone";
        $configPartOfTemplate[] = "server-profile";
        $configPartOfTemplate[] = "dns-proxy";
        $configPartOfTemplate[] = "admin-role";
        $configPartOfTemplate[] = "certificate";
        $configPartOfTemplate[] = "certificate-profile";
        $configPartOfTemplate[] = "ssl-tls-service-profile";
        $configPartOfTemplate[] = "authentication-profile";
        $configPartOfTemplate[] = "alg-override";
        $configPartOfTemplate[] = "local-user-database";
        $configPartOfTemplate[] = "redistribution-agent";
        $configPartOfTemplate[] = "group-mapping";
        $configPartOfTemplate[] = "global-protect";
        $configPartOfTemplate[] = "authentication-sequence";
        $configPartOfTemplate[] = "redistribution-collector";
        $configPartOfTemplate[] = "ts-agent";

        if( isset(PH::$args['loadafterupload']) )
            $this->loadConfigAfterUpload = TRUE;

        //needed as UPLOAD must calculate FILE/API also for configOutput
        if( isset(PH::$args['out']) )
        {
            $this->configOutput = PH::$args['out'];
            if( !is_string($this->configOutput) || strlen($this->configOutput) < 1 )
                $this->display_error_usage_exit('"out" argument is not a valid string');
        }

        if( isset(PH::$args['fromxpath']) )
        {
            if( !isset(PH::$args['toxpath']) )
            {
                $this->display_error_usage_exit("'fromXpath' option must be used with 'toXpath'");
            }
            $fromXpath = PH::$args['fromxpath'];
            //$fromXpath = str_replace('"', "'", PH::$args['fromxpath']);

            if( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' )
            {
                $tmp_dirname = $this->dirname_cleanup_win();

                $fromXpath = str_replace($tmp_dirname, "", $fromXpath);
                PH::print_stdout( "|" . $fromXpath . "|");
            }
        }
        if( isset(PH::$args['toxpath']) )
        {
            $toXpath = str_replace('"', "'", PH::$args['toxpath']);
            if( $this->loadConfigAfterUpload )
                $this->loadConfigAfterUpload = FALSE;

            if( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' )
            {
                $tmp_dirname = $this->dirname_cleanup_win();

                $toXpath = str_replace($tmp_dirname, "", $toXpath);
                PH::print_stdout( "|" . $toXpath . "|");
            }
        }

        if( isset(PH::$args['apiTimeout']) )
            $this->apiTimeoutValue = PH::$args['apiTimeout'];

        if( isset(PH::$args['extrafiltersout']) )
        {
            $this->extraFiltersOut = explode('|', PH::$args['extrafiltersout']);
        }



        PH::print_stdout( " - Opening/downloading original configuration...");


        if( $this->extraFiltersOut !== null )
        {
            PH::print_stdout( " * extraFiltersOut was specified and holds '" . count($this->extraFiltersOut) . " queries'");
            foreach( $this->extraFiltersOut as $filter )
            {
                PH::print_stdout( "  - processing XPath '''{$filter} ''' ");
                $xpathQ = new DOMXPath($this->xmlDoc);
                $results = $xpathQ->query($filter);

                if( $results->length == 0 )
                    PH::print_stdout( " 0 results found!");
                else
                {
                    PH::print_stdout( " {$results->length} matching nodes found!");
                    foreach( $results as $node )
                    {
                        /** @var DOMElement $node */
                        $panXpath = DH::elementToPanXPath($node);
                        PH::print_stdout( "     - deleting $panXpath");
                        $node->parentNode->removeChild($node);
                    }
                }
                unset($xpathQ);
            }
        }


        if( isset($fromXpath) )
        {
            PH::print_stdout( " * fromXPath is specified with value '" . $fromXpath . "'");
            $foundInputXpathList = DH::findXPath($fromXpath, $this->xmlDoc);

            if( $foundInputXpathList === FALSE )
                derr("invalid xpath syntax");

            if( $foundInputXpathList->length == 0 )
                derr("xpath returned empty results");

            PH::print_stdout( "    * found " . $foundInputXpathList->length . " results from Xpath:");

            foreach( $foundInputXpathList as $xpath )
            {
                PH::print_stdout( "       - " . DH::elementToPanXPath($xpath) );
            }

            PH::print_stdout( "");
        }


//
// SOMETHING SPECIAL FOR UPLOAD SCRIPT - ALSO OUTPUT CAN HAVE FILE OR API MODE
// What kind of config output do we have.
//     File or API ?
//
        $this->configOutput = PH::processIOMethod($this->configOutput, FALSE);

        if( $this->configOutput['status'] == 'fail' )
        {
            fwrite(STDERR, "\n\n**ERROR** " . $this->configOutput['msg'] . "\n\n");
            exit(1);
        }

        if( $this->configOutput['type'] == 'file' )
        {
            if( isset($toXpath) )
            {
                mwarning( "this is BETA code - please handle carefully", null, FALSE );
                sleep(5);
                #derr("toXpath options was used, it's incompatible with a file output. Make a feature request !!!  ;)");

                $argv2 = array();
                $argc2 = array();
                PH::$args = array();
                PH::$argv = array();
                $argv2[0] = "test";

                if( !file_exists( $this->configOutput['filename'] ) )
                {
                    PH::print_stdout( " - strpos|".strpos( $toXpath, "/config/devices/entry/vsys" )."|");
                    if( strpos( $toXpath, "/vsys/entry[" ) !== false )
                    {
                        #$doc2->load( dirname(__FILE__) . "/../parser/panos_baseconfig.xml", XML_PARSE_BIG_LINES);
                        $filename_load = dirname(__FILE__) . "/../../migration/parser/panos_baseconfig.xml";
                        $argv2[] = "in=".$filename_load;
                    }
                    else
                    {
                        #$doc2->load( dirname(__FILE__) . "/../parser/panorama_baseconfig.xml", XML_PARSE_BIG_LINES);
                        $filename_load = dirname(__FILE__) . "/../../migration/parser/panorama_baseconfig.xml";
                        $argv2[] = "in=".$filename_load;
                    }

                }
                elseif( file_exists( $this->configOutput['filename'] ) )
                {
                    PH::print_stdout( " - {$this->configOutput['filename']} ... ");

                    $argv2[] = "in=".$this->configOutput['filename'];
                }
                $util2 = new UTIL("custom", $argv2, $argc2, __FILE__, $this->supportedArguments, $this->usageMsg);
                $util2->utilInit();
                $util2->load_config();

                PH::print_stdout( " * toXPath is specified with value '" . $toXpath . "'");
                PH::print_stdout( " - toXpath from above");

                $foundOutputXpathList = DH::findXPath($toXpath, $util2->xmlDoc);

                if( $foundOutputXpathList === FALSE )
                    derr("invalid xpath syntax");

                if( $foundOutputXpathList->length == 0 )
                {
                    #$foundOutputXpathList = $this->recursive_XML( $util2->xmlDoc, $toXpath );
                }


                if( strpos( $toXpath, "/device-group/entry[" ) != false )
                {
                    $dg_name = str_replace( "/config/devices/entry/device-group/entry[@name='", "", $toXpath );
                    $dg_name_tmp = explode( "']", $dg_name );
                    #$dg_name = str_replace("']", "", $dg_name);
                    $dg_name = $dg_name_tmp[0];
                    print "DG: ".$dg_name."\n";
                    sleep(2);

                    //validate if DGname already exist
                    $newDG = $util2->pan->findDeviceGroup($dg_name);
                    if( $newDG !== null )
                        derr( "this tool only support XML node move to a newly created Device-Group based on toXpath" );
                    $newDG = $util2->pan->createDeviceGroup( $dg_name );

                    $explode = explode( "/", $toXpath );

                    $string = "";
                    for( $i = 0; $i < 6; $i++ )
                    {
                        if( $i == 2 )
                            $string .= "readonly/";

                        $string .= $explode[$i];

                        if( $i == 4 )
                            $path = $string;

                        if( $i+1 < 6 )
                            $string .= "/";
                    }
                    PH::print_stdout( " - DG: ".$string );
                    PH::print_stdout( " - path: ".$path );
                    //how to update -> /config/readonly/max-internal-id - handle different PAN-OS
                    //how to create -> /config/readonly/devices/entry/device-group/XYZ

                    #mwarning( "Panorama used, but readonly section is not yet supported for update" );
                }
                elseif( strpos( $toXpath, "/template/entry[" ) != false )
                {
                    //Todo: validate if Template is already there, if not create it

                    //import of multiple parts must be possible into template
                    //- ...../config/devices/entry[@name='localhost.localdomain']/network
                    //- ...../config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys10']
                }
                elseif( strpos( $toXpath, "/template-stack/entry[" ) != false )
                {
                    //Todo: validate if template-stack is already available
                }

                if( $foundOutputXpathList->length != 1 )
                    #derr("toXpath returned too many results");

                #PH::print_stdout( "    * found " . $foundOutputXpathList->length . " results from Xpath:");

                foreach( $foundOutputXpathList as $xpath )
                {
#                    PH::print_stdout("       - " . DH::elementToPanXPath($xpath));
                }
                foreach( $foundInputXpathList as $xpath )
                {
                    $tmpArray = explode( "/", DH::elementToPanXPath($xpath) );
                    $variable = end($tmpArray);

                    #PH::print_stdout("       import");
                    PH::print_stdout("       - import: '" . DH::elementToPanXPath($xpath))."'";

                    #DH::DEBUGprintDOMDocument($xpath);
                    $node = $util2->xmlDoc->importNode($xpath, TRUE);
                    #PH::print_stdout("       append");

                    if( strpos( $toXpath, "/device-group/entry[" ) != false )
                    {
                        //Todo: swaschkut 20241005 check also how to reduce duplicate code, see below for API import
                        if (in_array($variable, $configPartOfTemplate)) {
                            mwarning("import into Panorama DeviceGroup not possible - XMLnode '" . $variable . "' found. Template relevant", null, FALSE);
                            continue;
                        }

                        $mainNode = DH::findFirstElement($variable, $newDG->xmlroot);
                        if ($mainNode !== false)
                            $newDG->xmlroot->removeChild($mainNode);


                        if ($variable == "rulebase")
                        {
                            #DH::DEBUGprintDOMDocument($node);
                            mwarning("import into Panorama DeviceGroup but XMLnode 'rulebase' found. renamed to 'pre-rulebase'", null, FALSE);

                            $mainNode = DH::findFirstElement("pre-rulebase", $newDG->xmlroot);
                            if ($mainNode !== false)
                                $newDG->xmlroot->removeChild($mainNode);
                            $mainNode = DH::findFirstElementOrCreate("pre-rulebase", $newDG->xmlroot);

                            foreach ($node->childNodes as $childNode) {
                                if ($childNode->nodeType != XML_ELEMENT_NODE)
                                    continue;

                                if ($childNode->nodeName != "default-security-rules") {
                                    #DH::DEBUGprintDOMDocument($childNode);
                                    $node2 = $util2->xmlDoc->importNode($childNode, TRUE);

                                    $mainNode->appendChild($node2);
                                } else {
                                    $mainPostNode = DH::findFirstElement("post-rulebase", $newDG->xmlroot);
                                    if ($mainPostNode !== false)
                                        $newDG->xmlroot->removeChild($mainPostNode);
                                    $mainPostNode = DH::findFirstElementOrCreate("post-rulebase", $newDG->xmlroot);
                                    $mainPostNode->appendChild($node2);
                                }

                            }
                        }
                        else
                            $newDG->xmlroot->appendChild($node);
                    }
                    elseif( strpos( $toXpath, "/template/entry[" ) != false )
                    {
                        //Todo: not defined if I like to import into Panorama Template
                        //Todo: check also how to reduce duplicate code, see below for API import


                        if( strpos( $toXpath, "config/devices/entry[@name='localhost.localdomain']/network" ) != false )
                        {

                        }
                        elseif( strpos( $toXpath, "/global-protect/" ) != false )
                        {

                        }
                        elseif( !in_array($variable, $configPartOfTemplate))
                        {
                            mwarning("import into Panorama Template not possible - XMLnode '" . $variable . "' found. DeviceGroup relevant", null, FALSE);
                            continue;
                        }
                        elseif( $variable == "botnet" || $variable == "alg-override" || $variable == "reports" || $variable == "report-group" || $variable == "display-name" || $variable == "content-preview" )
                        {
                            mwarning("import into Panorama Template not possible - XMLnode '" . $variable . "' found. where to import???", null, FALSE);
                            continue;
                        }

                        //Todo:
                        //different cases for offline import:
                        //find full xpath after template name: ../template/entry[@name='PA-5410_CC']/....

                        // find/create TO xpath: e.g. "../config/devices/entry[@name='localhost.localdomain']/network"
                        // import all child

                        // ..../template/entry[@name='PA-5410_CC']/..
                        //   ../config/shared
                        // import all child

                        //  ..../template/entry[@name='PA-5410_CC']/...
                        //   ../config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys10']
                        // import all child

                    }
                    elseif( strpos( $toXpath, "/template-stack/entry[" ) != false )
                    {
                        //Todo: not defined if I like to import into Panorama Template-Stack// needed
                    }
                    else
                    {
                        //Todo: not defined if I like to import into NGFW
                    }
                }



                /** @var DOMElement $entryNode */
                /*
                $entryNode = $foundOutputXpathList[0];

                //Todo: what happen if xpath is already available; e.g. import of objects into DG/address; actual it creates another DG/address(objects), address(objects)
                PH::print_stdout( "import" );
                $node = $doc2->importNode($foundInputXpathList[0], true);
                PH::print_stdout( "append" );
                $entryNode->appendChild( $node );
                */

                PH::print_stdout( " - Now saving configuration to ");
                PH::print_stdout( " - {$this->configOutput['filename']}... " );
                $util2->xmlDoc->save($this->configOutput['filename']);
            }
            else
            {
                if( isset(PH::$args['preservemgmtconfig']) ||
                    isset(PH::$args['preservemgmtusers']) ||
                    isset(PH::$args['preservemgmtsystem']) ||
                    isset(PH::$args['preserve-xpath-jsonfile']) )
                {
                    PH::print_stdout( " - Option 'preserveXXXXX was used, we will first download the running config of target device...");

                    if( !file_exists( $this->configOutput['filename'] ) )
                    {
                        derr( "argument preserverXXX - can only be used against an existing file defined in 'out=FILE.xml'" );
                    }
                    else
                    {
                        $runningConfig = new DOMDocument();
                        $runningConfig->formatOutput = TRUE;
                        PH::print_stdout( " - Reading XML file from disk... ".$this->configOutput['filename'] );
                        if( !$runningConfig->load($this->configOutput['filename'], XML_PARSE_BIG_LINES) )
                            derr("error while reading xml config file");
                    }



                    $xpathQrunning = new DOMXPath($runningConfig);
                    $xpathQlocal = new DOMXPath($this->xmlDoc);

                    $xpathQueryList = array();

                    if( isset(PH::$args['preservemgmtconfig']) ||
                        isset(PH::$args['preservemgmtusers']) )
                    {
                        $xpathQueryList[] = '/config/mgt-config/users';
                    }

                    if( isset(PH::$args['preservemgmtconfig']) ||
                        isset(PH::$args['preservemgmtsystem']) )
                    {
                        $xpathQueryList[] = '/config/devices/entry/deviceconfig/system';
                    }


                    if( isset(PH::$args['preservemgmtconfig']) )
                    {
                        $xpathQueryList[] = '/config/mgt-config';
                        $xpathQueryList[] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig";
                        $xpathQueryList[] = '/config/shared/authentication-profile';
                        $xpathQueryList[] = '/config/shared/authentication-sequence';
                        $xpathQueryList[] = '/config/shared/certificate';
                        $xpathQueryList[] = '/config/shared/log-settings';
                        $xpathQueryList[] = '/config/shared/local-user-database';
                        $xpathQueryList[] = '/config/shared/admin-role';
                    }

                    if( isset(PH::$args['preserve-xpath-jsonfile']) )
                    {
                        $json = file_get_contents(PH::$args['preserve-xpath-jsonfile']);

                        // Check if the file was read successfully
                        if ($json === false) {
                            die('Error reading the JSON file');
                        }
                        // Decode the JSON file
                        $json_data = json_decode($json, true);

                        //load JSON file to array
                        foreach( $json_data['preserve-xpath'] as $entry )
                        {
                            $xpathQueryList[] = $entry;
                        }
                    }

                    foreach( $xpathQueryList as $xpathQuery )
                    {
                        $xpathResults = $xpathQrunning->query($xpathQuery);
                        if( $xpathResults->length > 1 )
                        {
                            //var_dump($xpathResults);
                            derr('more than one one results found for xpath query: ' . $xpathQuery);
                        }
                        if( $xpathResults->length == 0 )
                            $runningNodeFound = FALSE;
                        else
                            $runningNodeFound = TRUE;

                        $xpathResultsLocal = $xpathQlocal->query($xpathQuery);
                        if( $xpathResultsLocal->length > 1 )
                        {
                            //var_dump($xpathResultsLocal);
                            derr('none or more than one one results found for xpath query: ' . $xpathQuery);
                        }
                        if( $xpathResultsLocal->length == 0 )
                            $localNodeFound = FALSE;
                        else
                            $localNodeFound = TRUE;

                        if( $localNodeFound == FALSE && $runningNodeFound == FALSE )
                        {
                            continue;
                        }

                        if( $localNodeFound && $runningNodeFound )
                        {
                            $localParentNode = $xpathResultsLocal->item(0)->parentNode;
                            $localParentNode->removeChild($xpathResultsLocal->item(0));
                            $newNode = $this->xmlDoc->importNode($xpathResults->item(0), TRUE);
                            $localParentNode->appendChild($newNode);
                            continue;
                        }

                        if( $localNodeFound == FALSE && $runningNodeFound )
                        {
                            $newXpath = explode('/', $xpathQuery);
                            if( count($newXpath) < 2 )
                                derr('unsupported, debug xpath query: ' . $xpathQuery);


                            #this is needed if xpath is containing e.g. entry[@name='ethernet1/19']
                            if( is_numeric( $newXpath[count($newXpath) - 1][0] ) )
                            {
                                unset($newXpath[count($newXpath) - 1]);
                                unset($newXpath[count($newXpath) - 1]);
                            }
                            else
                                unset($newXpath[count($newXpath) - 1]);

                            $newXpath = implode('/', $newXpath);

                            $xpathResultsLocal = $xpathQlocal->query($newXpath);
                            if( $xpathResultsLocal->length != 1 )
                            {
                                derr('unsupported, debug xpath query: ' . $newXpath);
                            }

                            $newNode = $this->xmlDoc->importNode($xpathResults->item(0), TRUE);
                            $localParentNode = $xpathResultsLocal->item(0);
                            $localParentNode->appendChild($newNode);


                            continue;
                        }

                        //derr('unsupported');
                    }

                }

                if( isset(PH::$args['injectuseradmin2']) )
                {
                    $usersNode = DH::findXPathSingleEntryOrDie('/config/mgt-config/users', $this->xmlDoc);
                    $newUserNode = DH::importXmlStringOrDie($this->xmlDoc, '<entry name="admin2"><phash>$1$bgnqjgob$HmenJzuuUAYmETzsMcdfJ/</phash><permissions><role-based><superuser>yes</superuser></role-based></permissions></entry>');

                    $checkAdmin2 = DH::findFirstElementByNameAttr( "entry", "admin2", $usersNode );
                    if( $checkAdmin2 === null || $checkAdmin2 === false )
                    {
                        $usersNode->appendChild($newUserNode);
                        PH::print_stdout( " - Injected 'admin2' with 'admin' password");
                    }
                    else
                        PH::print_stdout( " - Injected 'admin2' skipped - already available");

                }

                PH::print_stdout( " - Now saving configuration to ");
                PH::print_stdout( " - {$this->configOutput['filename']}... ");
                $this->xmlDoc->save($this->configOutput['filename']);
            }

        }
        elseif( $this->configOutput['type'] == 'api' )
        {
            if( $this->debugAPI )
                $this->configOutput['connector']->setShowApiCalls(TRUE);

            if( isset($toXpath) )
            {
                PH::print_stdout( " - Sending SET command to API...");
                if( isset($toXpath) )
                {
                    $stringToSend = '';
                    $rule_stringToSend = '';
                    $postrule_stringToSend = '';
                    foreach( $foundInputXpathList as $xpath )
                    {
                        if( strpos( $toXpath, "/device-group/entry[" ) != false )
                        {
                            $tmpArray = explode( "/", DH::elementToPanXPath($xpath) );
                            $variable = end($tmpArray);

                            if( in_array($variable, $configPartOfTemplate) )
                            {
                                mwarning("import into Panorama DeviceGroup not possible - XMLnode '".$variable."' found. Template relevant", null, FALSE);
                                continue;
                            }

                            if( $variable == "rulebase" )
                            {
                                $XMLnode_default_security = DH::findFirstElement("default-security-rules", $xpath);
                                if( $XMLnode_default_security !== null && $XMLnode_default_security !== FALSE )
                                {
                                    $tmppost_stringToSend = DH::dom_to_xml($XMLnode_default_security, -1, FALSE);
                                    $postrule_stringToSend = "<post-rulebase>".$tmppost_stringToSend."</post-rulebase>";

                                    $xpath->removeChild($XMLnode_default_security);
                                }

                                $tmp_stringToSend = DH::dom_to_xml($xpath, -1, FALSE);
                                $rule_stringToSend = str_replace("rulebase", "pre-rulebase", $tmp_stringToSend);

                            }
                            else
                                $stringToSend .= DH::dom_to_xml($xpath, -1, FALSE);
                        }
                        elseif( strpos( $toXpath, "/template/entry[" ) != false )
                        {
                            $tmpArray = explode("/", DH::elementToPanXPath($xpath));
                            $variable = end($tmpArray);

                            if( strpos( $toXpath, "config/devices/entry[@name='localhost.localdomain']/network" ) != false )
                            {

                            }
                            elseif( strpos( $toXpath, "/global-protect/" ) != false )
                            {

                            }
                            elseif( !in_array($variable, $configPartOfTemplate))
                            {
                                mwarning("import into Panorama Template not possible - XMLnode '" . $variable . "' found. DeviceGroup relevant", null, FALSE);
                                continue;
                            }
                            elseif( $variable == "botnet" || $variable == "alg-override" || $variable == "reports" || $variable == "report-group" || $variable == "display-name" )
                            {
                                mwarning("import into Panorama Template not possible - XMLnode '" . $variable . "' found. where to import???", null, FALSE);
                                continue;
                            }

                            $stringToSend .= DH::dom_to_xml($xpath, -1, FALSE);
                        }
                        elseif( strpos( $toXpath, "/template-stack/entry[" ) != false )
                        {
                            $stringToSend .= DH::dom_to_xml($xpath, -1, FALSE);
                        }
                        else
                            $stringToSend .= DH::dom_to_xml($xpath, -1, FALSE);
                    }

                    $stringToSend .= $rule_stringToSend;
                    $stringToSend .= $postrule_stringToSend;
                }
                else
                    $stringToSend = DH::dom_to_xml(DH::firstChildElement($this->xmlDoc), -1, FALSE);

                $this->configOutput['connector']->sendSetRequest($toXpath, $stringToSend);

            }
            else
            {
                if( isset(PH::$args['preservemgmtconfig']) ||
                    isset(PH::$args['preservemgmtusers']) ||
                    isset(PH::$args['preservemgmtsystem']) )
                {
                    PH::print_stdout( " - Option 'preserveXXXXX was used, we will first download the running config of target device...");
                    $runningConfig = $this->configOutput['connector']->getRunningConfig();


                    $xpathQrunning = new DOMXPath($runningConfig);
                    $xpathQlocal = new DOMXPath($this->xmlDoc);

                    $xpathQueryList = array();

                    if( isset(PH::$args['preservemgmtconfig']) ||
                        isset(PH::$args['preservemgmtusers']) )
                    {
                        $xpathQueryList[] = '/config/mgt-config/users';
                    }

                    if( isset(PH::$args['preservemgmtconfig']) ||
                        isset(PH::$args['preservemgmtsystem']) )
                    {
                        $xpathQueryList[] = '/config/devices/entry/deviceconfig/system';
                    }


                    if( isset(PH::$args['preservemgmtconfig']) )
                    {
                        $xpathQueryList[] = '/config/mgt-config';
                        $xpathQueryList[] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig";
                        $xpathQueryList[] = '/config/shared/authentication-profile';
                        $xpathQueryList[] = '/config/shared/authentication-sequence';
                        $xpathQueryList[] = '/config/shared/certificate';
                        $xpathQueryList[] = '/config/shared/log-settings';
                        $xpathQueryList[] = '/config/shared/local-user-database';
                        $xpathQueryList[] = '/config/shared/admin-role';
                    }

                    foreach( $xpathQueryList as $xpathQuery )
                    {
                        $xpathResults = $xpathQrunning->query($xpathQuery);
                        if( $xpathResults->length > 1 )
                        {
                            //var_dump($xpathResults);
                            derr('more than one one results found for xpath query: ' . $xpathQuery);
                        }
                        if( $xpathResults->length == 0 )
                            $runningNodeFound = FALSE;
                        else
                            $runningNodeFound = TRUE;

                        $xpathResultsLocal = $xpathQlocal->query($xpathQuery);
                        if( $xpathResultsLocal->length > 1 )
                        {
                            //var_dump($xpathResultsLocal);
                            derr('none or more than one one results found for xpath query: ' . $xpathQuery);
                        }
                        if( $xpathResultsLocal->length == 0 )
                            $localNodeFound = FALSE;
                        else
                            $localNodeFound = TRUE;

                        if( $localNodeFound == FALSE && $runningNodeFound == FALSE )
                        {
                            continue;
                        }

                        if( $localNodeFound && $runningNodeFound )
                        {
                            $localParentNode = $xpathResultsLocal->item(0)->parentNode;
                            $localParentNode->removeChild($xpathResultsLocal->item(0));
                            $newNode = $this->xmlDoc->importNode($xpathResults->item(0), TRUE);
                            $localParentNode->appendChild($newNode);
                            continue;
                        }

                        if( $localNodeFound == FALSE && $runningNodeFound )
                        {
                            $newXpath = explode('/', $xpathQuery);
                            if( count($newXpath) < 2 )
                                derr('unsupported, debug xpath query: ' . $xpathQuery);

                            unset($newXpath[count($newXpath) - 1]);
                            $newXpath = implode('/', $newXpath);

                            $xpathResultsLocal = $xpathQlocal->query($newXpath);
                            if( $xpathResultsLocal->length != 1 )
                            {
                                derr('unsupported, debug xpath query: ' . $newXpath);
                            }

                            $newNode = $this->xmlDoc->importNode($xpathResults->item(0), TRUE);
                            $localParentNode = $xpathResultsLocal->item(0);
                            $localParentNode->appendChild($newNode);


                            continue;
                        }

                        //derr('unsupported');
                    }

                }

                if( isset(PH::$args['injectuseradmin2']) )
                {
                    $usersNode = DH::findXPathSingleEntryOrDie('/config/mgt-config/users', $this->xmlDoc);
                    $newUserNode = DH::importXmlStringOrDie($this->xmlDoc, '<entry name="admin2"><phash>$1$bgnqjgob$HmenJzuuUAYmETzsMcdfJ/</phash><permissions><role-based><superuser>yes</superuser></role-based></permissions></entry>');

                    $checkAdmin2 = DH::findFirstElementByNameAttr( "entry", "admin2", $usersNode );
                    if( $checkAdmin2 === null || $checkAdmin2 === false )
                    {
                        $usersNode->appendChild($newUserNode);
                        PH::print_stdout( " - Injected 'admin2' with 'admin' password");
                    }
                    else
                        PH::print_stdout( " - Injected 'admin2' skipped - already available");

                    ##########################################
                    $usersNode = DH::findXPathSingleEntryOrDie('/config/mgt-config/users', $this->xmlDoc);
                    $newUserNode = DH::importXmlStringOrDie($this->xmlDoc, '<entry name="admin3"><phash>$5$bedagqyb$E9k/oF22IMhkJ.88NU6BCX8Dws2l6wYkvZyWHSs1eK4</phash><permissions><role-based><superuser>yes</superuser></role-based></permissions></entry>');

                    $checkAdmin2 = DH::findFirstElementByNameAttr( "entry", "admin3", $usersNode );
                    if( $checkAdmin2 === null || $checkAdmin2 === false )
                    {
                        $usersNode->appendChild($newUserNode);
                        PH::print_stdout( " - Injected 'admin3' with 'Admin123.Admin' password");
                    }
                    else
                        PH::print_stdout( " - Injected 'admin3' skipped - already available");
                }

                if( $this->debugAPI )
                    $this->configOutput['connector']->setShowApiCalls(TRUE);

                if( $this->configOutput['filename'] !== null )
                    $saveName = $this->configOutput['filename'];
                else
                    $saveName = 'stage0.xml';

                PH::print_stdout( " - Now saving/uploading that configuration to ");
                PH::print_stdout( " - {$this->configOutput['connector']->apihost}/$saveName ... ");
                $this->configOutput['connector']->uploadConfiguration(DH::firstChildElement($this->xmlDoc), $saveName, FALSE);

            }
        }
        else
            derr('not supported yet');


        if( $this->loadConfigAfterUpload && $this->configInput['type'] != 'api' )
        {
            PH::print_stdout( " - Loading config in the firewall (will display warnings if any) ...");
            /** @var PanAPIConnector $targetConnector */
            $targetConnector = $this->configOutput['connector'];
            $xmlResponse = $targetConnector->sendCmdRequest('<load><config><from>' . $saveName . '</from></config></load>', TRUE, 600);

            if( $xmlResponse === null )
            {
                derr('unexpected error !');
            }

            $xmlResponse = DH::firstChildElement($xmlResponse);

            if( $xmlResponse === FALSE )
                derr('unexpected error !');





            $msgElement = DH::findFirstElement('msg', $xmlResponse);
            $msgElement = DH::findFirstElement('line', $msgElement);
            $msgElement = DH::findFirstElement('msg', $msgElement);

            if( $msgElement !== FALSE )
            {
                foreach( $msgElement->childNodes as $key => $msg )
                {
                    if( $msg->nodeType != 1 )
                        continue;

                    PH::print_stdout( " - " . $msg->nodeValue );
                }
            }
        }
    }

    public function supportedArguments()
    {

        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['fromxpath'] = array('niceName' => 'fromXpath', 'shortHelp' => 'select which part of the config to inject in destination');
        $this->supportedArguments['toxpath'] = array('niceName' => 'toXpath', 'shortHelp' => 'inject xml directly in some parts of the candidate config');
        $this->supportedArguments['loadafterupload'] = array('niceName' => 'loadAfterUpload', 'shortHelp' => 'load configuration after upload happened');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['apitimeout'] = array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to answer, increase this value (default=60)');
        $this->supportedArguments['preservemgmtconfig'] = array('niceName' => 'preserveMgmtConfig', 'shortHelp' => "tries to preserve most of management settings like IP address, admins and passwords etc. note it's not a smart feature and may break your config a bit and requires manual fix in GUI before you can actually commit");
        $this->supportedArguments['preservemgmtusers'] = array('niceName' => 'preserveMgmtUsers', 'shortHelp' => "preserve administrators so they are not overwritten and you don't loose access after a commit");
        $this->supportedArguments['preservemgmtsystem'] = array('niceName' => 'preserveMgmtSystem', 'shortHelp' => 'preserves what is in /config/devices/entry/deviceconfig/system');
        $this->supportedArguments['preserve-xpath-jsonfile'] = array('niceName' => 'preserve-Xpath-jsonfile', 'shortHelp' => 'preserves all Xpath what is in define JSON file');
        $this->supportedArguments['injectuseradmin2'] = array('niceName' => 'injectUserAdmin2', 'shortHelp' => 'adds user "admin2" with password "admin" in administrators');
        $this->supportedArguments['extrafiltersout'] = array('niceName' => 'extraFiltersOut', 'shortHelp' => 'list of xpath separated by | character that will be stripped from the XML before going to output');
    }

    function dirname_cleanup_win()
    {
        $tmp_dirname = dirname(__FILE__);
        $tmp_dirname = str_replace("\\", "/", $tmp_dirname);

        #PH::print_stdout( $tmp_dirname );

        $tmp_search = "pan-os-php/utils";
        $tmp_replace = "git";

        $tmp_dirname = str_replace($tmp_search, $tmp_replace, $tmp_dirname);

        return $tmp_dirname;
    }

    //duplicate code
    function display_usage_and_exit($shortMessage = FALSE, $warningString = "")
    {
        PH::print_stdout( PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=file.xml|api://... out=file.xml|api://... [more arguments]");

        PH::print_stdout( PH::boldText("\nExamples:") );
        PH::print_stdout( " - php " . basename(__FILE__) . " help          : more help messages" );
        PH::print_stdout( " - php " . basename(__FILE__) . " in=api://192.169.50.10/running-config out=local.xml'" );
        PH::print_stdout( " - php " . basename(__FILE__) . " in=local.xml out=api://192.169.50.10 preserveMgmtsystem injectUserAdmin2" );
        PH::print_stdout( " - php " . basename(__FILE__) . " in=local.xml out=api://192.169.50.10 toXpath=/config/shared/address" );

        PH::print_stdout( " - php " . basename(__FILE__) . " in=local.xml out=api://192.168.50.10" );
        PH::print_stdout( "            'fromXpath=/config/devices/entry[@name=\"localhost.localdomain\"]/vsys/entry[@name=\"vsys1\"]/*[name()=\"address\" or name()=\"address-group\" or name()=\"service\" or name()=\"service-group\" or name()=\"tag\"]'" );
        PH::print_stdout( "            'toXpath=/config/devices/entry[@name=\"localhost.localdomain\"]/vsys/entry[@name=\"vsys1\"]' shadow-apikeynohidden" );

        PH::print_stdout( " - php " . basename(__FILE__) . " in=staging/proserv-xpath.xml out=api://192.168.50.10 'fromXpath=/config/tag/*' 'toXpath=/config/devices/entry/device-group/entry[@name=\"DG-NAME\"]/tag' apiTimeout=2000" );
        PH::print_stdout( " - php " . basename(__FILE__) . " in=staging/proserv-xpath.xml out=api://192.168.50.13 'fromXpath=/config/*[name()=\"rules\"]' 'toXpath=/config/devices/entry/device-group/entry[@name=\"DG-NAME\"]/pre-rulebase/security' apiTimeout=2000" );

        PH::print_stdout( " - php " . basename(__FILE__) . " in=staging/proserv-xpath.xml out=api://192.168.50.10");
        PH::print_stdout( "            'fromXpath=/config/devices/entry/device-group/entry[@name=\"DG-NAME\"]/*[name()=\"address\" or name()=\"address-group\" or name()=\"service\" or name()=\"service-group\" or name()=\"tag\"]'" );
        PH::print_stdout( "            'toXpath=/config/devices/entry/device-group/entry[@name=\"DG-NAME\"]' apiTimeout=2000" );

        if( !$shortMessage )
        {
            PH::print_stdout( PH::boldText("\nListing available arguments") );

            ksort($this->supportedArguments);
            foreach( $this->supportedArguments as &$arg )
            {
                $text = " - " . PH::boldText($arg['niceName']);
                if( isset($arg['argDesc']) )
                    $text .= '=' . $arg['argDesc'];
                //."=";
                if( isset($arg['shortHelp']) )
                    $text .= "\n     " . $arg['shortHelp'];
                PH::print_stdout($text);
            }

            PH::print_stdout();
        }
        if( !empty($warningString) )
            mwarning( $warningString, null, false );
        exit(1);
    }

    function recursive_XML( &$doc2, $toXpath, $test = 0 )
    {
        PH::print_stdout( $test);
        $test++;

        $explode = explode( "/", $toXpath );

        $string = "";
        for( $i = 0; $i < count( $explode )-1; $i++ )
        {
            $string .= $explode[$i];
            if( $i+1 < count( $explode )-1 )
                $string .= "/";
        }
        PH::print_stdout( " - find string: ".$string);
        $foundOutputXpathList = DH::findXPath($string, $doc2);

        PH::print_stdout( " - length: ".$foundOutputXpathList->length);
        if( $foundOutputXpathList->length == 1 )
        {
            /** @var DOMElement $entryNode */
            $entryNode = $foundOutputXpathList[0];

            $string = str_replace( "]", "", $explode[ count( $explode )-1 ]  );
            $str_array = explode( "[", $string);

            PH::print_stdout( " - create Element: ".$str_array[0]);
            $newNode = $doc2->createElement( $str_array[0] );

            if( isset($str_array[1]) && strpos( $str_array[1], "@" ) !== false )
            {
                $string = str_replace( "@", "", $str_array[1] );

                $str_array = explode( "=", $string );
                $name = $str_array[0];
                $value = str_replace( "'", "", $str_array[1] );

                PH::print_stdout( " - set Attribute: Name: ".$name." value: ".$value);
                $newNode->setAttribute( $name, $value );
            }
            $entryNode->appendChild( $newNode );
        }

        $foundOutputXpathList = DH::findXPath($toXpath, $doc2);

        if( $foundOutputXpathList->length == 0 )
            $foundOutputXpathList = $this->recursive_XML( $doc2, $string, $test );

        return $foundOutputXpathList;
    }

}