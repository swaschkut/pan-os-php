<?php

/**
 * Interactive Standalone LDAP Group Membership Checker
 * Supports Direct and Nested/Transitive AD Group Resolution
 */

require_once dirname(__FILE__)."/../../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../../utils/lib/UTIL.php";

// ==========================================
// HELPER FUNCTIONS FOR INTERACTIVE CLI
// ==========================================

function prompt(string $promptText, string $default = ''): string {
    if ($default !== '') {
        echo "{$promptText} [{$default}]: ";
    } else {
        echo "{$promptText}: ";
    }
    $handle = fopen("php://stdin", "r");
    $input = trim(fgets($handle));
    fclose($handle);
    return ($input === '' && $default !== '') ? $default : $input;
}

function promptPassword(string $promptText = "Enter LDAP Password: "): string {
    echo $promptText;
    if (stristr(PHP_OS, 'WIN')) {
        $handle = fopen("php://stdin", "r");
        $password = trim(fgets($handle));
        fclose($handle);
    } else {
        system('stty -echo');
        $handle = fopen("php://stdin", "r");
        $password = trim(fgets($handle));
        fclose($handle);
        system('stty echo');
        echo "\n";
    }
    return $password;
}

/**
 * Extracts friendly CN name from a full Distinguished Name (DN)
 */
function getCnFromDn(string $dn): string {
    if (preg_match('/^CN=([^,]+)/i', $dn, $matches)) {
        return $matches[1];
    }
    return $dn;
}

/**
 * Discovers Domain Controller hostnames via DNS SRV records
 */
function discoverLdapServers(string $domain, bool $useLdaps = true): array {
    echo "🔎 Querying DNS SRV records for domain: {$domain}...\n";
    
    $records = @dns_get_record("_ldap._tcp.{$domain}", DNS_SRV);
    $discovered = [];
    
    if (!empty($records)) {
        foreach ($records as $rec) {
            $scheme = $useLdaps ? 'ldaps://' : 'ldap://';
            $port   = $useLdaps ? '636' : '389';
            $uri    = "{$scheme}{$rec['target']}:{$port}";
            
            if (!in_array($uri, $discovered)) {
                $discovered[] = $uri;
            }
        }
    }
    
    return $discovered;
}

// Ignore self-signed certificate warnings for internal LDAPS
putenv('LDAPTLS_REQCERT=allow');

// ==========================================
// INTERACTIVE INPUTS
// ==========================================
echo "==========================================\n";
echo "   LDAP / AD Group Membership Validator   \n";
echo "==========================================\n\n";

$domain         = prompt("AD Domain Name", "paloaltonetworks.local");

// Discover DCs via DNS SRV lookup
$discoveredServers = discoverLdapServers($domain, true);

if (!empty($discoveredServers)) {
    echo "✅ Discovered " . count($discoveredServers) . " Domain Controller(s):\n";
    foreach ($discoveredServers as $idx => $srv) {
        echo "   [" . ($idx + 1) . "] {$srv}\n";
    }
    $defaultServer = $discoveredServers[0];
} else {
    echo "⚠️  No DNS SRV records found. Falling back to default URI.\n";
    $defaultServer = "ldaps://{$domain}:636";
}

$ldapServer     = prompt("\nSelected LDAP Server URI", $defaultServer);
$ldapUser       = prompt("Bind User (UPN or DN)", "svwaschkut@{$domain}");

// Check if available via .panconfigkeystore
$connector = PanAPIConnector::findOrCreateConnectorFromHost( 'ldap-password' );
$ldapPassword = $connector->apikey;
#$ldapPassword   = promptPassword("Bind Password: ");

$baseDn         = prompt("Base DN", "OU=PAN,DC=" . implode(',DC=', explode('.', $domain)));
$filtercriteria = prompt("Filter Attribute", "sAMAccountName");
$targetUser     = prompt("Target User to check groups for", "svwaschkut");

$dnBase = str_replace(';', ',', $baseDn);

// ==========================================
// 1. INITIALIZATION & BIND
// ==========================================
echo "\nConnecting to LDAP server: {$ldapServer}...\n";

$ldapconn = @ldap_connect($ldapServer);

if (!$ldapconn) {
    die("❌ Error: Could not parse LDAP server URI.\n");
}

ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, 0);

echo "Attempting bind as: {$ldapUser}...\n";

$ldapbind = @ldap_bind($ldapconn, $ldapUser, $ldapPassword);

if (!$ldapbind) {
    $error = ldap_error($ldapconn);
    die("❌ LDAP bind failed! Error: {$error}\n");
}

echo "✅ LDAP bind successful!\n\n";

// ==========================================
// 2. SEARCH TARGET USER
// ==========================================
$userFilter = "({$filtercriteria}={$targetUser})";
echo "🔎 Searching for user '{$targetUser}' with filter: {$userFilter}...\n";

$sr = @ldap_search($ldapconn, $dnBase, $userFilter, ["dn", "cn", "memberof"]);

if (!$sr) {
    die("❌ User search query failed: " . ldap_error($ldapconn) . "\n");
}

$entries = ldap_get_entries($ldapconn, $sr);

if ($entries['count'] === 0) {
    die("❌ User '{$targetUser}' not found under Base DN '{$dnBase}'.\n");
}

$userEntry = $entries[0];
$userDn    = $userEntry['dn'];
$userCn    = $userEntry['cn'][0] ?? $targetUser;

echo "✅ User Found: {$userCn}\n";
echo "   DN: {$userDn}\n\n";

// ==========================================
// 3. RETRIEVE DIRECT GROUPS (memberOf)
// ==========================================
$directGroups = [];

if (isset($userEntry['memberof'])) {
    for ($i = 0; $i < $userEntry['memberof']['count']; $i++) {
        $directGroups[] = $userEntry['memberof'][$i];
    }
}

echo "------------------------------------------\n";
echo "📌 Direct Group Memberships (" . count($directGroups) . ")\n";
echo "------------------------------------------\n";

if (!empty($directGroups)) {
    foreach ($directGroups as $groupDn) {
        $groupCn = getCnFromDn($groupDn);
        echo "  • {$groupCn}\n";
        echo "    └─ DN: {$groupDn}\n";
    }
} else {
    echo "  (No direct group memberships found via 'memberOf')\n";
}

// ==========================================
// 4. RETRIEVE NESTED / TRANSITIVE GROUPS
// ==========================================
// AD Matching Rule OID 1.2.840.113556.1.4.1941 resolves entire group hierarchy
//$nestedFilter = "(member:1.2.840.113556.1.4.1941:=" . $userDn . ")";
$nestedFilter = "(member=" . $userDn . ")";

echo "\n------------------------------------------\n";
echo "🔄 All Groups Including Nested/Transitive\n";
echo "------------------------------------------\n";
echo "🔎 Executing LDAP_MATCHING_RULE_IN_CHAIN query...\n";

$srNested = @ldap_search($ldapconn, $dnBase, $nestedFilter, ["cn", "dn"]);

if ($srNested) {
    $nestedEntries = ldap_get_entries($ldapconn, $srNested);
    $totalNested   = $nestedEntries['count'];

    echo "✅ Total Groups Discovered (Direct + Indirect): {$totalNested}\n\n";

    for ($i = 0; $i < $totalNested; $i++) {
        $gDn = $nestedEntries[$i]['dn'];
        $gCn = $nestedEntries[$i]['cn'][0] ?? getCnFromDn($gDn);
        
        $isDirect = in_array($gDn, $directGroups);
        $typeLabel = $isDirect ? "[Direct]" : "[Nested / Transitive]";

        echo "  • {$gCn} {$typeLabel}\n";
        echo "    └─ DN: {$gDn}\n";
    }
} else {
    echo "⚠️ Failed to execute nested group query: " . ldap_error($ldapconn) . "\n";
}

// ==========================================
// CLEANUP
// ==========================================
ldap_unbind($ldapconn);
echo "\n==========================================\n";
echo "Group validation completed.\n";