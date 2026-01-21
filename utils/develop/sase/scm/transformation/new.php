<?php
require_once("lib/pan_php_framework.php");


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


// ... Your $spyware_array definition goes here ...



/**
 * Recursively converts an array to XML elements
 */
function arrayToXml($dom, $parentNode, $data)
{
    foreach ($data as $key => $value)
    {
        // Skip metadata keys not needed in the final XML tags
        if (in_array($key, ['id', 'name', 'folder', 'snippet', 'description']))
            continue;

        // Handle naming convention: convert underscores to dashes
        $tagName = str_replace('_', '-', $key);

        if( is_array($value) )
        {
            // Check if this is a list of entries (numeric keys)
            if( isset($value[0]) && is_array($value[0]) )
            {
                $container = $dom->createElement($tagName);
                $parentNode->appendChild($container);

                foreach ($value as $item)
                {
                    $entry = $dom->createElement('entry');
                    // If the item has a 'name', use it as an attribute
                    if (isset($item['name']))
                    {
                        $entry->setAttribute('name', $item['name']);
                        unset($item['name']); // Remove so it doesn't become a child tag
                    }
                    $container->appendChild($entry);
                    arrayToXml($dom, $entry, $item);
                }
            }
            else
            {
                // Regular associative nested array
                $element = $dom->createElement($tagName);
                $parentNode->appendChild($element);
                arrayToXml($dom, $element, $value);
            }
        }
        else
        {
            // It's a flat value
            // Custom logic for specific values like cloud-inline-analysis
            if( $value == '1' || $value == '0' )
                $value = ($value == '1') ? 'yes' : 'no';

            if( is_numeric($tagName) )
                $tagName = "member";

            $element = $dom->createElement($tagName, htmlspecialchars($value));
            $parentNode->appendChild($element);
        }
    }
}

function prepareMethodForImport( $data, &$dom, &$rootEntry)
{
    $dom = new DOMDocument('1.0', 'utf-8');
    $dom->formatOutput = true;

    // Create the root entry element
    $rootEntry = $dom->createElement('entry');
    $dom->appendChild($rootEntry);

    $entry = $dom->firstChild;
    if( isset($data['name'] ) )
        $entry->setAttribute( 'name', $data['name'] );
    if( isset($data['id'] ) )
        $entry->setAttribute( 'uuid', $data['id'] );
}


$dom = null;
$rootEntry = null;
prepareMethodForImport( $spyware_array, $dom, $rootEntry );

// Start the conversion
arrayToXml($dom, $rootEntry, $spyware_array);

// Output the result
DH::DEBUGprintDOMDocument($dom->firstChild);
