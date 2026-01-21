<?php


require_once("lib/pan_php_framework.php");

/*
anti-spyware-profiles - not finalised
Array
(
    [id] => 0efd7122-489d-48fe-84cf-a9889fad0d3d
    [name] => best-practice
    [folder] => All
    [snippet] => predefined-snippet
    [description] => Best practice anti-spyware security profile
    [cloud_inline_analysis] => 1
    [mica_engine_spyware_enabled] => Array
        (
            [0] => Array
                (
                    [name] => HTTP Command and Control detector
                    [inline_policy_action] => reset-both
                )

            [1] => Array
                (
                    [name] => HTTP2 Command and Control detector
                    [inline_policy_action] => reset-both
                )

            [2] => Array
                (
                    [name] => SSL Command and Control detector
                    [inline_policy_action] => reset-both
                )

            [3] => Array
                (
                    [name] => Unknown-TCP Command and Control detector
                    [inline_policy_action] => reset-both
                )

            [4] => Array
                (
                    [name] => Unknown-UDP Command and Control detector
                    [inline_policy_action] => reset-both
                )

        )

    [rules] => Array
        (
            [0] => Array
                (
                    [name] => simple-critical
                    [action] => Array
                        (
                            [reset_both] => Array
                                (
                                )

                        )

                    [severity] => Array
                        (
                            [0] => critical
                        )

                    [threat_name] => any
                    [category] => any
                    [packet_capture] => single-packet
                )

            [1] => Array
                (
                    [name] => simple-high
                    [action] => Array
                        (
                            [reset_both] => Array
                                (
                                )

                        )

                    [severity] => Array
                        (
                            [0] => high
                        )

                    [threat_name] => any
                    [category] => any
                    [packet_capture] => single-packet
                )

            [2] => Array
                (
                    [name] => simple-medium
                    [action] => Array
                        (
                            [reset_both] => Array
                                (
                                )

                        )

                    [severity] => Array
                        (
                            [0] => medium
                        )

                    [threat_name] => any
                    [category] => any
                    [packet_capture] => single-packet
                )

            [3] => Array
                (
                    [name] => simple-informational
                    [action] => Array
                        (
                        )

                    [severity] => Array
                        (
                            [0] => informational
                        )

                    [threat_name] => any
                    [category] => any
                    [packet_capture] => disable
                )

            [4] => Array
                (
                    [name] => simple-low
                    [action] => Array
                        (
                        )

                    [severity] => Array
                        (
                            [0] => low
                        )

                    [threat_name] => any
                    [category] => any
                    [packet_capture] => disable
                )

        )

)
 */




$spyware_array = array();

$spyware_array['id'] = '0efd71$spyware_array22-489d-48fe-84cf-a9889fad0d3d';
$spyware_array['name'] = 'best-practice';
$spyware_array['folder'] = 'All';
$spyware_array['snippet'] = 'predefined-snippet';
$spyware_array['description'] = 'Best practice anti-spyware security profile';
$spyware_array['cloud_inline_analysis'] = '1';


$mica_array = array();

$mica_array[0] = Array
(
    'name' => 'HTTP Command and Control detector',
    'inline_policy_action' => 'reset-both'
);

$mica_array[1] = Array
(
    'name' => 'HTTP2 Command and Control detector',
    'inline_policy_action' => 'reset-both'
);

$mica_array[2] = Array
(
    'name' => 'SSL Command and Control detector',
    'inline_policy_action' => 'reset-both'
);

$mica_array[3] = Array
(
    'name' => 'Unknown-TCP Command and Control detector',
    'inline_policy_action' => 'reset-both'
);

$mica_array[4] = Array
(
    'name' => 'Unknown-UDP Command and Control detector',
    'inline_policy_action' => 'reset-both'
);

$spyware_array['mica_engine_spyware_enabled'] = $mica_array;

$spyware_array['rules'] = Array(
    0 => Array(
        'name' => 'simple-critical',
        'action' => Array('reset_both' => Array()),
        'severity' => Array( 0 => 'critical'),
        'threat_name' => 'any',
        'category' => 'any',
        'packet_capture' => 'single-packet'
    ),
    1 => Array(
        'name' => 'simple-high',
        'action' => Array('reset_both' => Array() ),
        'severity' => Array(0 => 'high' ),
        'threat_name' => 'any',
        'category' => 'any',
        'packet_capture' => 'single-packet'
    )
);




#print_r($spyware_array);
$xml = new DOMDocument;
$xmlString = "<entry></entry>";
$xml->loadXML( $xmlString);
$entry = $xml->firstChild;

$xmlEntry = arrayToXML( $entry, $spyware_array);

DH::DEBUGprintDOMDocument( $xmlEntry );

function arrayToXML( $element, $array )
{
    $xml = new DOMDocument;
    $xmlString = "<entry></entry>";
    $xml->loadXML( $xmlString);
    $entry = $xml->firstChild;
    #DH::DEBUGprintDOMDocument($rootXML);

    /*
    if( !is_array($array) )
    {
        #print $array."\n";
        #exit();

        $xml = new DOMDocument;
        $xmlString = "<".$array."/>";
        $xml->loadXML( $xmlString);
        $entry = $xml->firstChild;
    }
    else
    {
    */
        foreach( $array as $key => $value )
        {
            if( $key == "id"
                || $key == "folder"
                || $key == "snippet"
                || $key == "description"
            )
                continue;

            if( $key == "name" )
            {
                $entry->setAttribute( 'name', $value );
            }
            else
            {
                $element = DH::createElement( $entry, $key);
                #print_r( $value );
                if( is_array($value) )
                {
                    foreach( $value as $subkey => $subvalue )
                    {
                        if( is_array($subvalue) )
                        {
                            $subelement = arrayToXML( $element, $subvalue );
                            $element2 = $xml->importNode($subelement, true);
                            $element->appendChild( $element2 );
                        }
                        else
                        {
                            $element->textContent = $subvalue;
                            #print "test\n";
                            #print_r($subvalue);
                            #print "\n---\n";
                        }
                    }
                }
                else
                {
                    $element->textContent = $value;

                    #print "no array 2\n";
                    #print_r($value);
                    #print "\n---\n";
                }
            }
        //}
    }




    return $entry;
}