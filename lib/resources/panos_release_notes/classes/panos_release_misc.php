<?php

set_include_path(get_include_path() . PATH_SEPARATOR . dirname(__FILE__) . '/../../../../');
#require_once dirname(__FILE__)."/../../../lib/pan_php_framework.php";
#require_once dirname(__FILE__)."/../../../utils/lib/UTIL.php";


require_once dirname(__FILE__) . "/../../../../lib/misc-classes/DH.php";
require_once dirname(__FILE__) . "/../../../../lib/misc-classes/PH.php";

class panos_release_misc
{
    static function request_html( $type = "known" )
    {
        $debug = true;

        PH::print_stdout( "Download HTML files" );
        $panOSversion_array = array();

        //-------------------------------------
        $panOSversion_array[10] = array();
        $panOSversion_array[10][1] = array();
        $panOS_version = &$panOSversion_array[10][1];
        $panOS_version[0] = false;
        $panOS_version[1] = false;
        $panOS_version[2] = false;
        $panOS_version[3] = false;
        $panOS_version[4] = false;
        $panOS_version[5] = false;
        $panOS_version[6] = false;
        $panOS_version[7] = false;
        $panOS_version[8] = false;
        $panOS_version[9] = false;
        $panOS_version[10] = false;
        $panOS_version[11] = false;
        $panOS_version[12] = false;
        $panOS_version[13] = false;
        $panOS_version[14] = true;


        $panOSversion_array[10][2] = array();
        $panOS_version = &$panOSversion_array[10][2];
        $panOS_version[0] = false;
        $panOS_version[1] = false;
        $panOS_version[2] = false;
        $panOS_version[3] = false;
        $panOS_version[4] = false;
        $panOS_version[5] = false;
        $panOS_version[6] = false;
        $panOS_version[7] = false;
        $panOS_version[8] = false;
        $panOS_version[9] = false;
        $panOS_version[10] = false;
        $panOS_version[11] = false;
        $panOS_version[12] = false;
        $panOS_version[13] = true;

//-------------------------------------------------------
        $panOSversion_array[11] = array();
        $panOSversion_array[11][1] = array();
        $panOS_version = &$panOSversion_array[11][1];
        $panOS_version[0] = false;
        $panOS_version[1] = false;
        $panOS_version[2] = false;
        $panOS_version[3] = false;
        $panOS_version[4] = true;
        $panOS_version[5] = true;
        $panOS_version[6] = true;
        $panOS_version[7] = true;
        $panOS_version[8] = true;


        $panOSversion_array[11][2] = array();
        $panOS_version = &$panOSversion_array[11][2];
        $panOS_version[0] = true;
        $panOS_version[1] = true;
        $panOS_version[2] = true;
        $panOS_version[3] = true;
        $panOS_version[4] = true;
        $panOS_version[5] = true;


        $release_notes_links = array();
        foreach ($panOSversion_array as $Version => $majorVersionArray) {
            foreach ($majorVersionArray as $majorVersion => $minorVersionArray) {
                foreach ($minorVersionArray as $minorVersion => $enabled)
                {
                    #if( $enabled ) {
                    $mainVersion = $Version . "-" . $majorVersion;
                    $subVersion = $mainVersion . "-" . $minorVersion;

                    if( $type == "known" )
                    {
                        $string = "https://docs.paloaltonetworks.com/pan-os/" . $mainVersion . "/pan-os-release-notes/pan-os-" . $subVersion . "-known-and-addressed-issues/pan-os-" . $subVersion . "-known-issues";
                        $release_notes_links[] = $string;
                        $return = panos_release_misc::requestKnownIssueHTML($string, $debug);
                        if(!$return)
                            break;
                    }
                    elseif( $type == "addressed" )
                    {
                        //missing stuff is -h releases
                        $string = "https://docs.paloaltonetworks.com/pan-os/" . $mainVersion . "/pan-os-release-notes/pan-os-" . $subVersion . "-known-and-addressed-issues/pan-os-" . $subVersion . "-addressed-issues";
                        $release_notes_links[] = $string;
                        $return = panos_release_misc::requestAddressedIssueHTML($string, $debug);
                        if(!$return)
                            break;

                        $maxHVersion = 20;
                        for( $i = 1; $i < $maxHVersion; $i++ )
                        {
                            //pan-os-11-2-4-known-and-addressed-issues/pan-os-11-2-4-addressed-issues
                            //pan-os-11-2-4-known-and-addressed-issues/pan-os-11-2-4-h6-addressed-issues


                            $string = "https://docs.paloaltonetworks.com/pan-os/" . $mainVersion . "/pan-os-release-notes/pan-os-" . $subVersion . "-known-and-addressed-issues/pan-os-" . $subVersion . "-h".$i."-addressed-issues";
                            $release_notes_links[] = $string;
                            $return = panos_release_misc::requestAddressedIssueHTML($string, $debug);
                            if(!$return)
                                continue;
                        }
                    }
                    #}
                }
            }
        }



    }

    static function requestKnownIssueHTML($url, $debug = false)
    {
        #print $url."\n";

        // Use basename() function to return the base name of file
        $file_name = basename($url);
        $directory = dirname(__FILE__) . "/../known_issues/";
        // Use file_get_contents() function to get the file
        // from url and use file_put_contents() function to
        // save the file by using base name

        if (!file_exists($directory . 'html')) {
            mkdir($directory . 'html', 0777, true);
        }

        if($debug)
            PH::print_stdout($file_name);

        PH::enableExceptionSupport();
        try
        {
            $response = @file_get_contents($url);
        }
        catch(Exception $e)
        {
            return false;
        }
        PH::disableExceptionSupport();

        if (file_put_contents($directory . "html/" . $file_name, $response)) {
            #print "File downloaded successfully\n";
            return true;
        } else {
            print "File downloading failed.\n";
            return false;
        }
    }

    static function requestAddressedIssueHTML($url, $debug = false)
    {
        #print $url."\n";

        // Use basename() function to return the base name of file
        $file_name = basename($url);
        $directory = dirname(__FILE__) . "/../addressed_issues/";
        // Use file_get_contents() function to get the file
        // from url and use file_put_contents() function to
        // save the file by using base name

        if (!file_exists($directory . 'html')) {
            mkdir($directory . 'html', 0777, true);
        }

        if($debug)
            PH::print_stdout($file_name);

        //validate

        PH::enableExceptionSupport();
        try
        {
            $response = @file_get_contents($url);
        }
        catch(Exception $e)
        {
            return false;
        }
        PH::disableExceptionSupport();

        if (file_put_contents($directory . "html/" . $file_name, $response))
        {
            #print "File downloaded successfully\n";
            return true;
        }
        else {
            print "File downloading failed.\n";
            return false;
        }
    }

    static function displayJSON( $type = "known")
    {
        $debug = false;

        PH::print_stdout( "Create JSON files" );

        $directory = dirname(__FILE__) . "/../".$type."_issues/";

//$directory = 'html';
        $scanned_directory = array_diff(scandir($directory . "html"), array('..', '.'));

        foreach ($scanned_directory as $filename)
        {
            if( $debug )
                PH::print_stdout($filename);

            $panOSVersion = $filename;
            #$html_orig = file_get_contents("pan-os-" . $panOSVersion . "-known-issues");
            $panOSVersion = str_replace("pan-os-", "", $panOSVersion);
            $panOSVersion = str_replace("-".$type."-issues", "", $panOSVersion);

            $html_orig = file_get_contents($directory . "/html/" . $filename);
            $html_orig = str_replace("--!>", "-->", $html_orig);

            //working for know issues
            $stringSTART = '<div class="book-pdf-content">';
            $stringEND = "<!-- DOCS-1561 Usabilla In-Page Widget -->";


            $startPos = strpos($html_orig, $stringSTART);
            #PH::print_stdout("startPOS: ".$startPos);
            $endPos = strpos($html_orig, $stringEND, $startPos);
            #PH::print_stdout("endPOS: ".$endPos);

            $html = substr($html_orig, $startPos, $endPos - $startPos + strlen($endPos));

            $dom = new DOMDocument;
            $dom->validateOnParse = false;

            #PH::print_stdout("TEST SVEN");
            #PH::print_stdout($html);

            if( empty($html) )
            {
                PH::print_stdout("HTML empty");
                exit();
                continue;
            }


            //known
            //* ** ERROR ** * Died on user notice or warning!! Error: DOMDocument::loadHTML(): Opening and ending tag mismatch: li and div in Entity, line: 780 on /Users/swaschku/Documents/scripting/pan-os-php/lib/resources/panos_release_notes/classes/panos_release_misc.php:200

            //addressed
            //* ** ERROR ** * Died on user notice or warning!! Error: DOMDocument::loadHTML(): AttValue: " expected in Entity, line: 8516 on /Users/swaschku/Documents/scripting/pan-os-php/lib/resources/panos_release_notes/classes/panos_release_misc.php:209
            libxml_use_internal_errors(true);
            @$dom->loadHTML($html);
            libxml_use_internal_errors(false);


            $nodeList = $dom->getElementsByTagName("div");
            $nodeArray = iterator_to_array($nodeList);


            #$tableData = array($panOSVersion);
            $tableData = array();
            $tableData[$panOSVersion] = array();
            $data = &$tableData[$panOSVersion];

            foreach ($nodeArray as $item)
            {
                $XMLnameAttribute = DH::findAttribute("class", $item);
                if ($XMLnameAttribute === false)
                    continue;

                if (strpos($XMLnameAttribute, "book-pdf-content") === false)
                    continue;


                $newdoc = new DOMDocument;
                $node = $newdoc->importNode($item, true);
                $newdoc->appendChild($node);
                $nodeList = $newdoc->getElementsByTagName("tr");
                $nodeArray1 = iterator_to_array($nodeList);

                foreach ($nodeArray1 as $item1)
                {
                    $newdoc2 = new DOMDocument;
                    $node2 = $newdoc2->importNode($item1, true);
                    $newdoc2->appendChild($node2);
                    $nodeList2 = $newdoc2->getElementsByTagName("td");
                    $nodeArray2 = iterator_to_array($nodeList2);

                    $entryArray = array();
                    foreach ($nodeArray2 as $key => $item2)
                    {
                        if ($key == 0)
                        {
                            #DH::DEBUGprintDOMDocument($item2);
                            $nodeListDIV = $item2->getElementsByTagName("div");
                            #$tmp_div_node = DH::findFirstElement("div", $item2);
                            $tmp_div_node = $nodeListDIV->item(0);
                            if ($tmp_div_node !== false and $tmp_div_node !== null)
                            {
                                $tmp_b_node = DH::findFirstElement("b", $tmp_div_node);
                                if ($tmp_b_node !== false)
                                {
                                    $header = $tmp_b_node->textContent;
                                    $header = trim($header);
                                }
                                else
                                {
                                    $header = $tmp_div_node->textContent;
                                    $header = trim($header);
                                }

                            }
                            elseif ($tmp_div_node !== false)
                            {
                                #print "EMPTY!!!!\n";
                                #DH::DEBUGprintDOMDocument($item2);

                            }
                            elseif (!empty($item2->textContent))
                            {
                                $header = $item2->textContent;
                                $header = trim($header);
                            }


                            //search second DIV
                            $tmp_seconddiv_node = $nodeListDIV->item(1);
                            if ($tmp_seconddiv_node !== null) {
                                #DH::DEBUGprintDOMDocument($tmp_seconddiv_node);
                                #exit();

                                $str = str_replace(PHP_EOL, ' ', $tmp_seconddiv_node->textContent);
                                $str = str_replace("  ", ' ', $str);
                                $str = preg_replace('/\s+/', ' ', $str);

                                $entryArray[$header]['solved'] = $str;
                            }

                        } else {
                            $str = str_replace(PHP_EOL, ' ', $item2->textContent);
                            $str = str_replace("  ", ' ', $str);
                            $str = preg_replace('/\s+/', ' ', $str);

                            $entryArray[$header]['info'][] = $str;
                        }

                    }

                    $data[] = $entryArray;
                }


            }


            if (!file_exists($directory . 'json')) {
                mkdir($directory . 'json', 0777, true);
            }

            if (file_put_contents($directory . "json/" . $filename, json_encode($tableData, JSON_PRETTY_PRINT))) #if (file_put_contents("json/" . $filename, json_encode($tableData) ))
            {
                #print "json/" . $filename."\n";
                #print "JSON file created successfully\n";
            } else {
                print "File json creation failed.\n";
            }
        }
    }
}