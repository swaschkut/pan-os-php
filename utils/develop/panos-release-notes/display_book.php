<?php

set_include_path(get_include_path() . PATH_SEPARATOR . dirname(__FILE__) . '/../');
#require_once dirname(__FILE__)."/../../../lib/pan_php_framework.php";
#require_once dirname(__FILE__)."/../../../utils/lib/UTIL.php";


require_once dirname(__FILE__)."/../../../lib/misc-classes/DH.php";
require_once dirname(__FILE__)."/../../../lib/misc-classes/PH.php";

$directory = dirname(__FILE__) . "/../../../lib/resources/panos_release_notes/known_issues/";

//$directory = 'html';
$scanned_directory = array_diff(scandir($directory."html"), array('..', '.'));

foreach( $scanned_directory as $filename )
{
    $panOSVersion = $filename;
    #$html_orig = file_get_contents("pan-os-" . $panOSVersion . "-known-issues");
    $panOSVersion = str_replace( "pan-os-", "", $panOSVersion );
    $panOSVersion = str_replace( "-known-issues", "", $panOSVersion );

    $html_orig = file_get_contents( $directory."/html/".$filename );

    $stringSTART = '<div class="book-pdf-content">';
    $stringEND = "<!-- DOCS-1561 Usabilla In-Page Widget -->";


    $startPos = strpos($html_orig, $stringSTART);
    $endPos = strpos($html_orig, $stringEND);

    $html = substr($html_orig, $startPos, $endPos - $startPos + strlen($endPos));


    $dom = new DOMDocument;
    $dom->validateOnParse = false;
    @$dom->loadHTML($html);

    $nodeList = $dom->getElementsByTagName("div");
    $nodeArray = iterator_to_array($nodeList);


#$tableData = array($panOSVersion);
    $tableData = array();
    $tableData[$panOSVersion] = array();
    $data = &$tableData[$panOSVersion];

    foreach ($nodeArray as $item) {
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

        foreach ($nodeArray1 as $item1) {
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
                            $header = $tmp_b_node->textContent;
                        else
                        {
                            $header = $tmp_div_node->textContent;
                        }

                    }
                    elseif ($tmp_div_node !== false)
                    {
                        #print "EMPTY!!!!\n";
                        #DH::DEBUGprintDOMDocument($item2);

                    }
                    elseif (!empty($item2->textContent))
                        $header = $item2->textContent;

                    //search second DIV
                    $tmp_seconddiv_node = $nodeListDIV->item(1);
                    if ($tmp_seconddiv_node !== null)
                    {
                        #DH::DEBUGprintDOMDocument($tmp_seconddiv_node);
                        #exit();

                        $str = str_replace(PHP_EOL, ' ', $tmp_seconddiv_node->textContent);
                        $str = str_replace("  ", ' ', $str);
                        $str = preg_replace('/\s+/', ' ', $str);

                        $entryArray[$header]['solved'] = $str;
                    }

                }
                else
                {
                    $str = str_replace(PHP_EOL, ' ', $item2->textContent);
                    $str = str_replace("  ", ' ', $str);
                    $str = preg_replace('/\s+/', ' ', $str);

                    $entryArray[$header]['info'][] = $str;
                }

            }

            $data[] = $entryArray;
        }


    }


    if (!file_exists($directory.'json')) {
        mkdir($directory.'json', 0777, true);
    }

    if (file_put_contents($directory."json/" . $filename, json_encode($tableData, JSON_PRETTY_PRINT) ))
    #if (file_put_contents("json/" . $filename, json_encode($tableData) ))
    {
        #print "json/" . $filename."\n";
        #print "JSON file created successfully\n";
    }
    else
    {
        print "File json creation failed.\n";
    }
}