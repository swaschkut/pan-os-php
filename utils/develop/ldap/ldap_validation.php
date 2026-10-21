<?php

/**
 * Interactive Standalone LDAP Test & AD Detail Script
 * Includes Automatic SRV DNS Lookup for Domain Controllers
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

/**
 * Discover LDAP/AD Domain Controllers via DNS SRV Records
 */
function discoverLdapServers(string $domain, bool $useLdaps = true): array {
    echo "🔎 Querying DNS SRV records for domain: {$domain}...\n";
    
    // Standard AD SRV record for discovering DCs
    $records = @dns_get_record("_ldap._tcp.{$domain}", DNS_SRV);
    $discovered = [];
    
    if (!empty($records)) {
        foreach ($records as $rec) {
            $host = $rec['target'];
            
            if ($useLdaps) {
                // Construct LDAPS URI explicitly on Port 636 using discovered DC hostnames
                $uri = "ldaps://{$host}:636";
            } else {
                $uri = "ldap://{$host}:389";
            }
            
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
echo "    LDAP / Active Directory Test Tool     \n";
echo "==========================================\n\n";

$domain         = prompt("AD Domain Name", "paloaltonetworks.local");

// Automatic Server Discovery via DNS SRV Records
$discoveredServers = discoverLdapServers($domain);

if (!empty($discoveredServers)) {
    echo "✅ Found " . count($discoveredServers) . " Domain Controller(s) via DNS:\n";
    foreach ($discoveredServers as $idx => $srv) {
        echo "   [" . ($idx + 1) . "] {$srv}\n";
    }
    $defaultServer = $discoveredServers[0];
} else {
    echo "⚠️  No DNS SRV records found. Falling back to domain name directly.\n";
    $defaultServer = "ldaps://{$domain}";
}

$ldapServer     = prompt("\nSelected LDAP Server URI", $defaultServer);
$ldapUser       = prompt("Bind User (UPN or DN)", "svwaschkut@{$domain}");

// Check if available via .panconfigkeystore
$connector = PanAPIConnector::findOrCreateConnectorFromHost( 'ldap-password' );
$ldapPassword = $connector->apikey;
#$ldapPassword   = promptPassword("Bind Password: ");

$baseDn         = prompt("Base DN", "OU=PAN,DC=" . implode(',DC=', explode('.', $domain)));
$filtercriteria = prompt("Filter Attribute", "sAMAccountName");

$usersInput     = prompt("Users to test (comma-separated)", "svwaschkut");
$usersToTest    = array_map('trim', explode(',', $usersInput));

$dnBase = str_replace(';', ',', $baseDn);
$justthese = ["ou", "sn", "cn", "givenname", "mail", "pwdlastset", "accountexpires", "useraccountcontrol", $filtercriteria];

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
// 2. MAIN USER CHECK LOGIC
// ==========================================
foreach ($usersToTest as $user) {
    $person = $user;
    if (strpos($person, "\\") !== false) {
        $parts = explode("\\", $person);
        $person = $parts[1];
    }

    $currentFilter = "({$filtercriteria}={$person})";
    echo "🔎 Searching for user '{$person}' using filter: {$currentFilter}...\n";

    $sr = @ldap_search($ldapconn, $dnBase, $currentFilter, $justthese);

    if ($sr) {
        $info = ldap_get_entries($ldapconn, $sr);

        if ($info['count'] > 0) {
            echo "   ✅ User found!\n";
            $entry = $info[0];

            $cn = $entry['cn'][0] ?? 'N/A';
            $mail = $entry['mail'][0] ?? 'No email specified';
            $pwdLastSet = isset($entry['pwdlastset'][0]) ? convertWinFileTime($entry['pwdlastset'][0]) : 'N/A';
            $accExpires = isset($entry['accountexpires'][0]) ? convertWinFileTime($entry['accountexpires'][0]) : 'N/A';

            // Prüfen, ob das Ablaufdatum in der Vergangenheit liegt
            if (!empty($rawExpires) && $rawExpires != "9223372036854775807" && $rawExpires != "0") {
                $expireUnix = (int)($rawExpires / 10000000) - 11644473600;
                if ($expireUnix < time()) {
                    $accExpires .= " ❌";
                }
            }

            $uacRaw = $entry['useraccountcontrol'][0] ?? null;
            $accountStatus = getAccountStatus($uacRaw);

            echo "      • Display Name (CN):    {$cn}\n";
            echo "      • Email:                {$mail}\n";
            echo "      • Account Status:       {$accountStatus}\n";
            echo "      • Password Last Set:    {$pwdLastSet}\n";
            echo "      • Account Expiration:   {$accExpires}\n\n";
        } else {
            echo "   ❌ User '{$person}' not found in directory.\n\n";
        }
    } else {
        echo "   ❌ Search query failed: " . ldap_error($ldapconn) . "\n\n";
    }
}

// ==========================================
// CLEANUP
// ==========================================
ldap_unbind($ldapconn);
echo "Test execution completed.\n";