<?php

function parseSonicWallConfigSmart($filename, $objectPrefixes = []) {
    $lines = file($filename, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $config = [];

    foreach ($lines as $line) {
        $line = trim($line);
        if (strpos($line, '=') === false) continue;

        list($key, $value) = explode('=', $line, 2);
        $value = urldecode($value); // decode %20 etc.

        // Check if key starts with one of the desired prefixes
        foreach ($objectPrefixes as $prefix) {
            // match keys like: zoneObjId_0, addro_zone_1, etc.
            if (preg_match("/^" . preg_quote($prefix, '/') . "([A-Za-z0-9]*)_(\d+)$/", $key, $matches)) {
                $field = $matches[1]; // part after prefix (e.g., Id, zone, etc.)
                $index = $matches[2];

                if (!isset($config[$prefix][$index])) {
                    $config[$prefix][$index] = [];
                }

                $config[$prefix][$index][$field] = $value;
                continue 2; // move to next line once matched
            }
        }

        // Everything else = global config
        $config['global'][$key] = $value;
    }

    return $config;
}

// ✅ Define your object prefixes as provided
$prefixes = [
    'schedObj', 'sched_', 'zoneObj', 'addrObj', 'addro_', 'svcObj', 'so_', 'userObj', 'uo_', 'userGroupObj',
    'bwObj', 'cfs', 'lldpProf', 'dns', 'dhcp', 'ldap', 'ipsec', 'policy', 'iface', 'eth', 'linkAggr', 'prefs_'
];

// 🔧 Example usage
$config = parseSonicWallConfigSmart('config_1.txt', $prefixes);

// 🧪 Print examples
#echo "=== ZONE OBJECTS ===\n";
#print_r($config['zoneObj'] ?? []);

#echo "\n=== SCHEDULE OBJECTS ===\n";
#print_r($config['schedObj'] ?? []);

#echo "\n=== ADDRESS OBJECTS ===\n";
#print_r($config['addro_'] ?? []);

print_r($config);
