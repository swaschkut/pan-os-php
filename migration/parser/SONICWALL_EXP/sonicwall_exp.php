<?php

function parseSonicWallFlatConfig($filename): array
{
    $lines = file($filename, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $parsed = [];

    foreach ($lines as $line) {
        $line = trim($line);
        if (strpos($line, '=') === false) continue;

        list($rawKey, $rawValue) = explode('=', $line, 2);
        $value = urldecode($rawValue); // decode %20 etc.

        if (preg_match('/^([a-zA-Z]+)([a-zA-Z]+)_(\d+)$/', $rawKey, $matches)) {
            // e.g., zoneObjId_0 => [group = zoneObj, field = Id, index = 0]
            $group = $matches[1] . $matches[2]; // zone + Obj => zoneObj
            $field = $matches[2]; // Obj
            $index = $matches[3];

            // Extract the true key (strip zoneObj prefix)
            $fieldName = substr($rawKey, strlen($group) + 1); // Id, Properties, etc.

            $parsed[$group][$index][$fieldName] = $value;
        } else {
            // handle globals like: cli_idleTimeout=300
            $parsed['global'][$rawKey] = $value;
        }
    }

    return $parsed;
}

// Usage
$config = parseSonicWallFlatConfig('config_1.txt');
print_r($config['zoneObj']); // Example: dump all zones

print_r($config);
