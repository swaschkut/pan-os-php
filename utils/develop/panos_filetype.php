<?php

set_include_path(get_include_path() . PATH_SEPARATOR . dirname(__FILE__) . '/../');
require_once dirname(__FILE__)."/../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../utils/lib/UTIL.php";




$filename = dirname(__FILE__) . '/../../lib/object-classes/predefined.xml';



$xmlDoc = new DOMDocument();
$xmlDoc->load($filename, XML_PARSE_BIG_LINES);


$filetype = DH::findXPathSingleEntryOrDie('/predefined/tdb/file-type', $xmlDoc);

$wif_dlp_filetype = DH::findXPathSingleEntryOrDie('/predefined/tdb/wif-dlp-file-type', $xmlDoc);



$all_fileNameArray = array();
$fileNameArray = array();


foreach($filetype->childNodes as $node)
{
    if( $node->nodeType != XML_ELEMENT_NODE )
        continue;

    /*
     * <entry id="125" name="7z">
                 <category>Archives</category>
                 <characteristics>
                    <member>Block</member>
                 </characteristics>
                 <file-type-ident>yes</file-type-ident>
                 <threat-name>7z File Detected</threat-name>
                 <full-name>7 Zip Archive</full-name>
              </entry>
     */
    $name = DH::findAttribute( "name", $node );
    $file_type_ident_Node = DH::findFirstElement("file-type-ident", $node);
    $threat_name_Node = DH::findFirstElement("threat-name", $node);
    $full_name_Node = DH::findFirstElement("full-name", $node);
    $threat_name = "--not set--";
    if( $threat_name_Node !== false )
        $threat_name = $threat_name_Node->textContent;
    $full_name = "--not set--";
    if( $full_name_Node !== false )
        $full_name = $full_name_Node->textContent;

    $all_fileNameArray[$name] = array( "name" => $name, "threatName" => $threat_name, "fullName" => $full_name );

    //find in other XMLnode
    $wif_dlp_filetype_node = DH::findFirstElementByNameAttr("entry", $name, $wif_dlp_filetype);
    if( $wif_dlp_filetype_node !== null )
    {
        $filetype_sigs_node = DH::findFirstElement("filetype-sigs", $wif_dlp_filetype_node);
        $sigsArray = array();
        foreach($filetype_sigs_node->childNodes as $sigs)
        {
            if ($sigs->nodeType != XML_ELEMENT_NODE)
                continue;

            $sigsArray[] = $sigs->textContent;
        }

        $all_fileNameArray[$name]['sigs'] = $sigsArray;
    }

}

//20250211 - 226 filetype
print count($all_fileNameArray)."\n";

$i = 0;
foreach($all_fileNameArray as $name => $fileArray)
{
    if( isset($all_fileNameArray[$name]) )
    {
        $fileNameArray[$name] = array('fullName' => $all_fileNameArray[$name]["fullName"]);
        $i++;
    }
}

#print count($fileNameArray)."\n";
#print_r($fileNameArray);


$checkFileArray = array('7z','bat','chm','class','cpl','dll','hlp','hta','jar','ocx','pif','scr','torrent','vbe','wsf');

foreach($checkFileArray as $name => $fileName)
{
    if( isset($fileNameArray[$fileName]) )
    {
        print_r($fileNameArray[$fileName]);
    }
    else
        print "File: ".$fileName." not found in List\n";
}

$tmp_string = " ( device_name eq 'PA-WER-1420-1' )";
//and ( name-of-threatid contains 'Windows' )
foreach($checkFileArray as $name => $fileName)
{
    if( isset($fileNameArray[$fileName]) )
    {
        #$tmp_string .= "and ( name-of-threatid contains '".$fileNameArray[$fileName]['fullName']);
    }
    else
        print "File: ".$fileName." not found in List\n";
}