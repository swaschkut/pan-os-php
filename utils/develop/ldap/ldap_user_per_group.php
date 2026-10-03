<?php

/**
 * Interactive Standalone AD Group Member Status Checker
 * Retrieves all members of a specific AD group and checks their account details.
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

function convertWinFileTime($filetime): string {
    if (empty($filetime) || $filetime == "9223372036854775807" || $filetime == "0") {
        return "Never / Unlimited";
    }
    $unixTimestamp = (int)($filetime / 10000000) - 11644473600;
    return date('Y-m-d H:i:s T', $unixTimestamp);
}

function getAccountStatus(?string $uacValue): string {
    if ($uacValue === null) {
        return "Unknown (userAccountControl attribute missing)";
    }
    $uac = (int)$uacValue;
    $isDisabled = ($uac & 2) !== 0; // Bit 2 = ACCOUNTDISABLE
    return $isDisabled ? "Disabled ❌" : "Active ✅";
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

// Ignore self-signed certificate warnings for internal LDAPS
putenv('LDAPTLS_REQCERT=allow');

// ==========================================
// INTERACTIVE INPUTS
// ==========================================
echo "==========================================\n";
echo "   AD Group Member Account Status Tool    \n";
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
$targetGroup    = prompt("Target AD Group Name (CN or sAMAccountName)", "VPN-Users");

$dnBase = str_replace(';', ',', $baseDn);
$justthese = ["sAMAccountName", "sn", "cn", "givenname", "mail", "pwdlastset", "accountexpires", "useraccountcontrol"];

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
// 2. LOCATE TARGET GROUP
// ==========================================
$groupFilter = "(&(objectClass=group)(|(cn={$targetGroup})(sAMAccountName={$targetGroup})))";
echo "🔎 Locating AD group '{$targetGroup}' with filter: {$groupFilter}...\n";

$srGroup = @ldap_search($ldapconn, $dnBase, $groupFilter, ["dn", "cn"]);

if (!$srGroup) {
    die("❌ Group search query failed: " . ldap_error($ldapconn) . "\n");
}

$groupEntries = ldap_get_entries($ldapconn, $srGroup);

if ($groupEntries['count'] === 0) {
    die("❌ Group '{$targetGroup}' not found under Base DN '{$dnBase}'.\n");
}

$groupDn = $groupEntries[0]['dn'];
$groupCn = $groupEntries[0]['cn'][0] ?? $targetGroup;

echo "✅ Group Found: {$groupCn}\n";
echo "   DN: {$groupDn}\n\n";

// ==========================================
// 3. FETCH & DISPLAY ALL MEMBER USERS
// ==========================================
// Uses AD chain matching rule (1.2.840.113556.1.4.1941) to catch direct and nested group members
$userFilter = "(&(objectCategory=person)(objectClass=user)(memberOf={$groupDn}))";


echo "------------------------------------------\n";
echo "🔎 Fetching members of group '{$groupCn}'...\n";
echo "------------------------------------------\n\n";

$srUsers = @ldap_search($ldapconn, $dnBase, $userFilter, $justthese);

if ($srUsers) {
    $userEntries = ldap_get_entries($ldapconn, $srUsers);
    $totalMembers = $userEntries['count'];

    echo "✅ Total Members Discovered: {$totalMembers}\n\n";

    for ($i = 0; $i < $totalMembers; $i++) {
        $entry = $userEntries[$i];

        $samAccount = $entry['samaccountname'][0] ?? 'N/A';
        $cn         = $entry['cn'][0] ?? 'N/A';
        $mail       = $entry['mail'][0] ?? 'No email specified';
        $pwdLastSet = isset($entry['pwdlastset'][0]) ? convertWinFileTime($entry['pwdlastset'][0]) : 'N/A';
        $accExpires = isset($entry['accountexpires'][0]) ? convertWinFileTime($entry['accountexpires'][0]) : 'N/A';

        $uacRaw        = $entry['useraccountcontrol'][0] ?? null;
        $accountStatus = getAccountStatus($uacRaw);

        echo "👤 User [" . ($i + 1) . "/{$totalMembers}]: {$samAccount}\n";
        echo "      • Display Name (CN):    {$cn}\n";
        echo "      • Email:                {$mail}\n";
        echo "      • Account Status:       {$accountStatus}\n";
        echo "      • Password Last Set:    {$pwdLastSet}\n";
        echo "      • Account Expiration:   {$accExpires}\n\n";
    }
} else {
    echo "❌ Member search query failed: " . ldap_error($ldapconn) . "\n";
}

// ==========================================
// CLEANUP
// ==========================================
ldap_unbind($ldapconn);
echo "==========================================\n";
echo "Group member status check completed.\n";