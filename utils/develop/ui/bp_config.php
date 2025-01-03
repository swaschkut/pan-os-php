<?php
session_start();
include "test/db_conn.php";
if( isset($_SESSION['folder']) && isset($_SESSION['id']) )
{
    $panconfkeystoreFILE = $_SESSION['folder']."/.panconfkeystore";
    $projectFOLDER = $_SESSION['folder'];
}
else
{
    $tmpFOLDER = '/../../api/v1/project';
    $panconfkeystoreFILE = dirname(__FILE__) . $tmpFOLDER.'/.panconfkeystore';
    $projectFOLDER = dirname(__FILE__) . $tmpFOLDER;
}

?>
<!--
/**
 * ISC License
 *
 * Copyright (c) 2024, Sven Waschkut - pan-os-php@waschkut.net
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
-->

<!DOCTYPE html>
<html>

<head>
    <title>PAN-OS-PHP UI</title>

    <link rel="stylesheet"
          href="../../common/html/bootstrap.min.css"
          crossorigin="anonymous"
    >
    <script type="text/javascript"
            src="../../common/html/jquery.min.js"
    ></script>

    <script type="text/javascript"
            src="../../common/html/bootstrap.min.js"
    ></script>



    <script type="text/javascript"
            src="json_array.js"
    ></script>


    <script type="text/javascript"
            src="ui_function.js"
    ></script>

    <script type="text/javascript"
            src="js.js"
    ></script>

</head>

<body>


<div style="border:0px solid #000000; padding: 10px; width:100%">

    <div class="menu" style="border:1px solid black; padding: 10px;">
        <table class="table table-bordered" style="width:100%">
            <tr>
            <tr>
                <td><a href="index.php">MAIN page</a></td>
                <td><a href="bp_config.php">BP config page</a></td>
                <td><a href="bp_secprof.php">BP secprof page</a></td>
                <td><a href="single.php">single command</a></td>
                <td><a href="playbook.php">JSON PLAYBOOK</a></td>
                <td><a href="preparation.php">upload file / store APIkey</a></td>
                <td><a href="help.php">action / filter help</a></td>
                <?php
                if( isset($_SESSION['folder']) && isset($_SESSION['id']) )
                {
                    echo '<td>logged in as: <a href="test/home.php">'.$_SESSION['name'].'</a>  |  <a href="test/logout.php">LOGOUT</a></td>';
                }
                ?>
            </tr>
        </table>
    </div>

    <div class="load-json" style="border:1px solid #000000; padding: 10px; width:100%">
        <table class="table table-bordered" style="width:100%">
            <tr>
                <td style="width:50%" >
                    load BP config from JSON-file:

                    <input type="button" value="Clear TextArea" onclick="eraseTextBP();">
                    <input type="button" value="update JSON Table" onclick="updateTableBP();">
                    <input type="button" value="clear JSON Table" onclick="clearTableBP();">
                    <form method="post">
                        <textarea disabled id="js-textareaBP" style="width:100%" ></textarea>
                        <input type="file" id="js-fileBP" accept=".txt,.json" onclick="this.value=null">
                    </form>
                </td>
                <td>
                    store BP config to JSON-file:
                    <input type="text" id="json-outputBP" value="bp_config.json" />
                    <button class="btn btn-md btn-primary" id="storeBtnBP" type="button">download BP config JSON file</button>
                    <div>
                        <textarea type="text" disabled id="json-display-outBP" name="json-display-outBP" style="width:100%" ></textarea>
                    </div>
                </td>
            </tr>
        </table>
    </div>

    <form id="user_form" target="_blank" name="user_form" method="post" enctype="multipart/form-data">

        <div class="table-responsive" style="border:1px solid black; padding: 10px; width:100%">
            <table id="myTable" class="table table-bordered" style="width:100%">
                <thead>
                <tr>
                    <th class="text-center">Remove Row</th>
                    <th class="text-center" style="width:80%">SCRIPT</th>
                </tr>
                </thead>
                <form id="json-storeBP">
                    <tbody id="tbodyBP">

                    </tbody>
                </form>
            </table>
            <button class="btn btn-md btn-primary"
                    id="addBtnBP" type="button">
                new RowBP
            </button>
        </div>
    </form>


</div>


<script>
    // JSON data (as per your example)
    const jsonData = [
{
"check": "true",
"xpath": "deviceconfig/system/login-banner",
"value": "You have accessed a protected system. Log off immediately if you are not an authorized user.",
"variable-name": "{{ LOGIN-BANNER-TEXT }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/system/timezone",
"value": "Europe/Berlin",
"variable-name": "{{ TIMEZONE }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/auto-acquire-commit-lock",
"value": "no",
"variable-name": "{{ COMMIT-LOCK }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/idle-timeout",
"value": "30",
"variable-name": "{{ IDLE-TIMEOUT }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/api/key/lifetime",
"value": "0",
"variable-name": "{{ API_KEY_LIFETIME }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/api/key/certificate",
"value": "api_key_cert",
"variable-name": "{{ API_KEY_CERT }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/admin-lockout/failed-attempts",
"value": "5",
"variable-name": "{{ USER-FAILED-ATTEMPTS }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/admin-lockout/lockout-time",
"value": "10",
"variable-name": "{{ USER-LOCKOUT-TIME }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/rule-require-tag",
"value": "no",
"variable-name": "{{ POLICY-REQUIRE-TAG }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/rule-require-description",
"value": "no",
"variable-name": "{{ POLICY-REQUIRE-DESCRIPTION }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/rule-require-audit-comment",
"value": "no",
"variable-name": "{{ POLICY-REQUIRE-AUDIT-COMMENT }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/wildcard-topdown-match-mode",
"value": "yes",
"variable-name": "{{ POLICY-WILDCARD-TOP-DOWN-MATCH }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/rule-hit-count",
"value": "yes",
"variable-name": "{{ POLICY-HIT-USAGE }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/appusage-policy",
"value": "yes",
"variable-name": "{{ POLICY-APP-USAGE }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/max-rows-in-csv-export",
"value": "1048576",
"variable-name": "{{ MAX-ROWS-CSV-EXPORT }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/log-revert-operations",
"value": "yes",
"variable-name": "{{ CONFIG-LOG-FOR-REVERT-OPERATIONS }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/enable-log-high-dp-load",
"value": "yes",
"variable-name": "{{ LOG-HIGH-DP-LOAD }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/system/panorama/local-panorama/panorama-server",
"value": "1.2.3.4",
"variable-name": "{{ PANORAMA-SERVER-1 }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/system/panorama/local-panorama/panorama-server-2",
"value": "1.2.3.5",
"variable-name": "{{ PANORAMA-SERVER-2 }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/device-monitoring/enabled",
"value": "yes",
"variable-name": "{{ DEVICE-MONITORING-DATA-TO-PANORAMA }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/disable-commit-recovery",
"value": "no",
"variable-name": "{{ COMMIT-RECOVERY-DISABLE }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/commit-recovery-retry",
"value": "3",
"variable-name": "{{ COMMIT-RECOVERY-ATTEMPTS }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/management/commit-recovery-timeout",
"value": "5",
"variable-name": "{{ COMMIT-RECOVERY-RETRIES }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/system/motd-and-banner/motd-enable",
"value": "no",
"variable-name": "{{ LOGIN-BANNER-ENABLE }}",
"comment": ""
},
{
"check": "true",
"xpath": "mgt-config/password-complexity/enabled",
"value": "yes",
"variable-name": "{{ PW-COMPLEXITY-ENABLED }}",
"comment": ""
},
{
"check": "true",
"xpath": "mgt-config/password-complexity/minimum-length",
"value": "12",
"variable-name": "{{ PW-MIN-LENGTH }}",
"comment": ""
},
{
"check": "true",
"xpath": "mgt-config/password-complexity/minimum-uppercase-letters",
"value": "1",
"variable-name": "{{ PW-MIN-UPPERCASE }}",
"comment": ""
},
{
"check": "true",
"xpath": "mgt-config/password-complexity/minimum-lowercase-letters",
"value": "1",
"variable-name": "{{ PW-MIN-LOWERCASE }}",
"comment": ""
},
{
"check": "true",
"xpath": "mgt-config/password-complexity/minimum-numeric-letters",
"value": "1",
"variable-name": "{{ PW-MIN-NUMERICS }}",
"comment": ""
},
{
"check": "true",
"xpath": "mgt-config/password-complexity/minimum-special-characters",
"value": "1",
"variable-name": "{{ PW-MIN-SPECIAL-CHAR }}",
"comment": ""
},
{
"check": "true",
"xpath": "mgt-config/password-complexity/block-repeated-characters",
"value": "3",
"variable-name": "{{ PW-BLOCK-REPEATED-CHARS }}",
"comment": ""
},
{
"check": "true",
"xpath": "mgt-config/password-complexity/block-username-inclusion",
"value": "yes",
"variable-name": "{{ PW-BLOCK-USERNAME-INCL }}",
"comment": ""
},
{
"check": "true",
"xpath": "mgt-config/password-complexity/new-password-differs-by-characters",
"value": "3",
"variable-name": "{{ PW-NEW-PW-DIFFER-BY-CHAR }}",
"comment": ""
},
{
"check": "true",
"xpath": "mgt-config/password-complexity/password-change-on-first-login",
"value": "no",
"variable-name": "{{ PW-REQUIRE-CHANGE-FIRST-LOGIN }}",
"comment": ""
},
{
"check": "true",
"xpath": "mgt-config/password-complexity/password-history-count",
"value": "24",
"variable-name": "{{ PW-PREVENT-REUSE-LIMIT }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/system/service/disable-snmp",
"value": "no",
"variable-name": "",
"comment": ""
},
{
"check": "false",
"xpath": "deviceconfig/system/snmp-setting/snmp-system/contact",
"value": "SNMP-CONTACT",
"variable-name": "",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/system/snmp-setting/snmp-system/send-event-specific-traps",
"value": "yes",
"variable-name": "",
"comment": ""
},
{
"check": "false",
"xpath": "deviceconfig/system/snmp-setting/access-setting/version",
"value": "v3",
"variable-name": "",
"comment": "NOT NEEDED"
},
{
"check": "false",
"xpath": "deviceconfig/system/snmp-setting/access-setting/version/v3/views/READ-ALL/view/VIEW01/oid",
"value": ".1",
"variable-name": "",
"comment": ""
},
{
"check": "false",
"xpath": "deviceconfig/system/snmp-setting/access-setting/version/v3/views/READ-ALL/view/VIEW01/mask",
"value": "0x80",
"variable-name": "",
"comment": ""
},
{
"check": "false",
"xpath": "deviceconfig/system/snmp-setting/access-setting/version/v3/views/READ-ALL/view/VIEW01/option",
"value": "include",
"variable-name": "",
"comment": ""
},
{
"check": "false",
"xpath": "deviceconfig/system/snmp-setting/access-setting/version/v3/users/SNMP-USER/view",
"value": "READ-ALL",
"variable-name": "",
"comment": ""
},
{
"check": "false",
"xpath": "deviceconfig/system/snmp-setting/access-setting/version/v3/users/SNMP-USER/authproto",
"value": "SNMPV3-AUTH-PROTOCOL",
"variable-name": "",
"comment": ""
},
{
"check": "false",
"xpath": "deviceconfig/system/snmp-setting/access-setting/version/v3/users/SNMP-USER/authpwd",
"value": "SNMPV3-AUTH-PW",
"variable-name": "",
"comment": ""
},
{
"check": "false",
"xpath": "deviceconfig/system/snmp-setting/access-setting/version/v3/users/SNMP-USER/privproto",
"value": "SNMPV3-PRIV-PROTOCOL",
"variable-name": "",
"comment": ""
},
{
"check": "false",
"xpath": "deviceconfig/system/snmp-setting/access-setting/version/v3/users/SNMP-USER/privpwd",
"value": "SNMPV3-PRIV-PW",
"variable-name": "",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/system/update-server",
"value": "updates.paloaltonetworks.com",
"variable-name": "{{ MGMT-UPDATE-SERVER }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/system/dns-setting/servers/primary",
"value": "1.2.3.4",
"variable-name": "{{ MGMT-DNS-PRIMARY }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/system/dns-setting/servers/secondary",
"value": "5.6.7.8",
"variable-name": "{{ MGMT-DNS-SECONDARY }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/system/ntp-servers/primary-ntp-server/ntp-server-address",
"value": "1.2.3.4",
"variable-name": "{{ MGMT-NTP-PRIMARY }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/system/ntp-servers/secondary-ntp-server/ntp-server-address",
"value": "5.6.7.8",
"variable-name": "{{ MGMT-NTP-SECONDARY }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/system/device-telemetry/threat-prevention",
"value": "no",
"variable-name": "{{ TELEMETRY-THREAT-DATA }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/system/device-telemetry/device-health-performance",
"value": "no",
"variable-name": "{{ TELEMETRY-HEALTH-DATA }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/system/device-telemetry/product-usage",
"value": "no",
"variable-name": "{{ TELEMETRY-PRODUCT-USAGE }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/system/device-telemetry/region",
"value": "de",
"variable-name": "{{ TELEMETRY-REGION }}",
"comment": ""
},
{
"check": "true",
"xpath": "vsys/entry[@name='vsys1']/setting/ssl-decrypt/allow-forward-decrypted-content",
"value": "yes",
"variable-name": "{{ CONTENT-FORWARD-DECRYPTED-CONTENT }}",
"comment": "jit should be this set setting ssl-decrypt allow-forward-decrypted-content"
},
{
"check": "true",
"xpath": "deviceconfig/setting/application/bypass-exceed-queue",
"value": "no",
"variable-name": "{{ CONTENT-FWD-TCP-EXCEED-APP-ID-QUEUE }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/ctd/tcp-bypass-exceed-queue",
"value": "no",
"variable-name": "{{ CONTENT-FWD-TCP-EXCEED-CONTENT-INSPECT-QUEUE }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/ctd/udp-bypass-exceed-queue",
"value": "no",
"variable-name": "{{ CONTENT-FWD-UDP-EXCEED-CONTENT-INSPECT-QUEUE }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/ctd/allow-http-range",
"value": "yes",
"variable-name": "{{ CONTENT-HTTP-PARTIAL-RESPONSE }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/wildfire/public-cloud-server",
"value": "de.wildfire.paloaltonetworks.com",
"variable-name": "{{ WF-PUBLIC-CLOUD }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/wildfire/file-size-limit/entry[@name='pe']/size-limit",
"value": "16",
"variable-name": "{{ WF-FILESIZE-PE }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/wildfire/file-size-limit/entry[@name='apk']/size-limit",
"value": "30",
"variable-name": "{{ WF-FILESIZE-APK }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/wildfire/file-size-limit/entry[@name='pdf']/size-limit",
"value": "3072",
"variable-name": "{{ WF-FILESIZE-PDF }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/wildfire/file-size-limit/entry[@name='ms-office']/size-limit",
"value": "16384",
"variable-name": "{{ WF-FILESIZE-MS-OFFICE }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/wildfire/file-size-limit/entry[@name='jar']/size-limit",
"value": "5",
"variable-name": "{{ WF-FILESIZE-JAR }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/wildfire/file-size-limit/entry[@name='flash']/size-limit",
"value": "5",
"variable-name": "{{ WF-FILESIZE-FLASH }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/wildfire/file-size-limit/entry[@name='MacOSX']/size-limit",
"value": "10",
"variable-name": "{{ WF-FILESIZE-OSX }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/wildfire/file-size-limit/entry[@name='archive']/size-limit",
"value": "50",
"variable-name": "{{ WF-FILESIZE-ARCHIVE }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/wildfire/file-size-limit/entry[@name='linux']/size-limit",
"value": "50",
"variable-name": "{{ WF-FILESIZE-LINUX }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/wildfire/file-size-limit/entry[@name='script']/size-limit",
"value": "20",
"variable-name": "{{ WF-FILESIZE-SCRIPT }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/wildfire/report-benign-file",
"value": "no",
"variable-name": "{{ WF-REPORT-BENIGN }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/wildfire/report-grayware-file",
"value": "yes",
"variable-name": "{{ WF-REPORT-GRAYWARE }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/tcp/bypass-exceed-oo-queue",
"value": "no",
"variable-name": "{{ TCP-FWD-EXCEED-OUT-OF-ORDER-QUEUE }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/tcp/allow-challenge-ack",
"value": "no",
"variable-name": "{{ TCP-ALLOW-CHALLANGE-ACK }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/tcp/check-timestamp-option",
"value": "yes",
"variable-name": "{{ TCP-DROP-NULL-TIMESTAMP }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/tcp/asymmetric-path",
"value": "drop",
"variable-name": "{{ TCP-ASYMMETRIC-PATH }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/tcp/urgent-data",
"value": "clear",
"variable-name": "{{ TCP-URGENT-DATA-FLAG }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/tcp/drop-zero-flag",
"value": "yes",
"variable-name": "{{ TCP-DROP-WITHOUT-FLAG }}",
"comment": ""
},
{
"check": "true",
"xpath": "deviceconfig/setting/tcp/strip-mptcp-option",
"value": "yes",
"variable-name": "{{ TCP-STRIP-MPTCP-OPTION }}",
"comment": ""
}
];

    function updateTableBP( )
    {
        //data = $("#js-textareaBP").val()
        //createTableFromJSON_bp( JSON.stringify(data, null, 2) );
    }

    function clearTableBP()
    {
        $("#myTable tr").remove();
    }

    createTableFromJSON_bp(  JSON.stringify(jsonData, null, 2) );

</script>

</body>

</html>