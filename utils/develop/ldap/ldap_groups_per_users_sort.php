<?php

/**
 * Interactive Standalone LDAP Common Group Membership Checker
 * Resolves nested groups via client-side recursion and sorts common groups
 * by total member count in ascending order (fewest members first).
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

function getCnFromDn(string $dn): string {
    if (preg_match('/^CN=([^,]+)/i', $dn, $matches)) {
        return $matches[1];
    }
    return $dn;
}

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

/**
 * Recursively fetches all direct and nested groups using client-side queue
 */
function fetchAllGroupsRecursively($ldapconn, array $initialGroupDns): array {
    $allGroups = []; // DN => CN
    $queue     = $initialGroupDns;
    $visited   = [];

    while (!empty($queue)) {
        $currentGroupDn = array_shift($queue);

        if (isset($visited[$currentGroupDn])) {
            continue;
        }
        $visited[$currentGroupDn] = true;

        $groupCn = getCnFromDn($currentGroupDn);
        $allGroups[$currentGroupDn] = $groupCn;

        $readResult = @ldap_read($ldapconn, $currentGroupDn, "(objectClass=*)", ["memberof"]);
        if ($readResult) {
            $entries = ldap_get_entries($ldapconn, $readResult);
            if (isset($entries[0]['memberof'])) {
                for ($i = 0; $i < $entries[0]['memberof']['count']; $i++) {
                    $parentDn = $entries[0]['memberof'][$i];
                    if (!isset($visited[$parentDn])) {
                        $queue[] = $parentDn;
                    }
                }
            }
        }
    }

    return $allGroups;
}

putenv('LDAPTLS_REQCERT=allow');

// ==========================================
// INTERACTIVE INPUTS
// ==========================================
echo "==========================================\n";
echo "   LDAP / AD Common Group Checker         \n";
echo "==========================================\n\n";

$domain         = prompt("AD Domain Name", "paloaltonetworks.local");
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
$targetInput    = prompt("Target Users (comma-separated)", "user1, user2, user3");
$useTransitive  = prompt("Include Nested/Transitive Groups? (yes/no)", "yes");

$dnBase = str_replace(';', ',', $baseDn);

$rawUsers = explode(',', $targetInput);
$targetUsers = array_values(array_filter(array_map('trim', $rawUsers)));

if (empty($targetUsers)) {
    die("❌ Error: No target users specified.\n");
}

$includeNested = in_array(strtolower(trim($useTransitive)), ['yes', 'y', '1', 'true']);

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
// 2. FETCH GROUPS FOR EACH TARGET USER
// ==========================================
$userGroupMap       = []; 
$userDirectGroupMap = []; 
$groupDetailsMap    = []; 

echo "==========================================\n";
echo "🔎 Fetching Group Memberships\n";
echo "==========================================\n";

foreach ($targetUsers as $username) {
    echo "\nProcessing User: {$username}...\n";
    $userFilter = "({$filtercriteria}={$username})";

    $sr = @ldap_search($ldapconn, $dnBase, $userFilter, ["dn", "cn", "memberof"]);
    if (!$sr) {
        echo "  ❌ User search failed for '{$username}': " . ldap_error($ldapconn) . "\n";
        continue;
    }

    $entries = ldap_get_entries($ldapconn, $sr);

    if ($entries['count'] === 0) {
        echo "  ⚠️  User '{$username}' not found under Base DN '{$dnBase}'. Skipping.\n";
        continue;
    }

    $userEntry = $entries[0];
    $userDn    = $userEntry['dn'];
    $userCn    = $userEntry['cn'][0] ?? $username;

    echo "  ✅ User Found: {$userCn} (DN: {$userDn})\n";

    $directGroups = [];
    if (isset($userEntry['memberof'])) {
        for ($i = 0; $i < $userEntry['memberof']['count']; $i++) {
            $gDn = $userEntry['memberof'][$i];
            $directGroups[] = $gDn;
            $groupDetailsMap[$gDn] = getCnFromDn($gDn);
        }
    }
    $userDirectGroupMap[$username] = $directGroups;

    if ($includeNested && !empty($directGroups)) {
        $allUserGroupsMap = fetchAllGroupsRecursively($ldapconn, $directGroups);
        $userGroupMap[$username] = array_keys($allUserGroupsMap);
        
        foreach ($allUserGroupsMap as $gDn => $gCn) {
            $groupDetailsMap[$gDn] = $gCn;
        }
    } else {
        $userGroupMap[$username] = $directGroups;
    }

    echo "  • Found " . count($userGroupMap[$username]) . " total group(s) for {$username}.\n";
}

// ==========================================
// 3. CALCULATE INTERSECTION & SORT BY MEMBER COUNT
// ==========================================
echo "\n==========================================\n";
echo "📊 Common Group Membership Analysis\n";
echo "==========================================\n";

if (empty($userGroupMap)) {
    die("❌ No valid target users were evaluated.\n");
}

$processedUsers = array_keys($userGroupMap);
echo "Evaluated Users (" . count($processedUsers) . "): " . implode(', ', $processedUsers) . "\n\n";

$commonGroups = null;
foreach ($userGroupMap as $username => $groups) {
    if ($commonGroups === null) {
        $commonGroups = $groups;
    } else {
        $commonGroups = array_intersect($commonGroups, $groups);
    }
}

$commonGroups = array_values(array_unique($commonGroups ?? []));

if (!empty($commonGroups)) {
    echo "✅ Found " . count($commonGroups) . " common group(s) shared by ALL users.\n";
    echo "🔎 Fetching member counts and sorting groups ascending (fewest members first)...\n\n";

    $sortedGroups = [];

    foreach ($commonGroups as $gDn) {
        $memberCount = 0;

        // Perform fast direct read on the group object to count members
        $readResult = @ldap_read($ldapconn, $gDn, "(objectClass=*)", ["member"]);
        if ($readResult) {
            $entries = ldap_get_entries($ldapconn, $readResult);
            if (isset($entries[0]['member']['count'])) {
                $memberCount = $entries[0]['member']['count'];
            }
        }

        $sortedGroups[] = [
            'dn'           => $gDn,
            'cn'           => $groupDetailsMap[$gDn] ?? getCnFromDn($gDn),
            'member_count' => $memberCount,
        ];
    }

    // Sort array by member_count ascending
    usort($sortedGroups, function ($a, $b) {
        return $a['member_count'] <=> $b['member_count'];
    });

    // Display output
    foreach ($sortedGroups as $index => $group) {
        $gDn   = $group['dn'];
        $gCn   = $group['cn'];
        $count = $group['member_count'];

        echo " [" . ($index + 1) . "] {$gCn} (Total Members: {$count})\n";
        echo "     └─ DN: {$gDn}\n";

        $status = [];
        foreach ($processedUsers as $username) {
            $isDirect = in_array($gDn, $userDirectGroupMap[$username] ?? []);
            $status[] = "{$username}: " . ($isDirect ? "Direct" : "Nested");
        }
        echo "     └─ Details: (" . implode(' | ', $status) . ")\n\n";
    }
} else {
    echo "❌ No common groups found where ALL target users are members.\n";
}

// ==========================================
// CLEANUP
// ==========================================
ldap_unbind($ldapconn);
echo "==========================================\n";
echo "Group validation completed.\n";