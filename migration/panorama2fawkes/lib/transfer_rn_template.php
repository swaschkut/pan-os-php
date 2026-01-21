<?php
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

trait transfer_rn_template
{
    static public $TPL_USERID_DEFAULT_MATCH_LIST_ENTRY_CFG;
    static public $FAWKES_DEF_IKE_CRYPTO;
    static public $FAWKES_DEF_IPSEC_CRYPTO;
    static public $product_map_info = array();
    static public $MONITOR_PROFILE_TUNNEL;
    static public $MONITOR_PROFILE_DEFAULT;



    function rn_createVariables()
    {
        //$this->panorama_doc

        $TPL_USERID_DEFAULT_MATCH_LIST_ENTRY_CFG =
        '
        <entry name="userid-gpcs-default">
              <filter>All Logs</filter>
              <send-to-panorama>yes</send-to-panorama>
        </entry>
    ';
        self::$TPL_USERID_DEFAULT_MATCH_LIST_ENTRY_CFG = self::stringToXml( $TPL_USERID_DEFAULT_MATCH_LIST_ENTRY_CFG );

$FAWKES_DEF_IKE_CRYPTO =
'
    <entry name="PaloAlto-Networks-IKE-Crypto">
        <hash>
            <member>sha1</member>
        </hash>
        <dh-group>
            <member>group2</member>
        </dh-group>
        <encryption>
            <member>aes-128-cbc</member>
            <member>3des</member>
        </encryption>
        <lifetime>
            <hours>8</hours>
        </lifetime>
    </entry>
    ';
        self::$FAWKES_DEF_IKE_CRYPTO = self::stringToXml( $FAWKES_DEF_IKE_CRYPTO );

$FAWKES_DEF_IPSEC_CRYPTO =
'
    <entry name="PaloAlto-Networks-IPSec-Crypto">
        <esp>
            <authentication>
                <member>sha1</member>
            </authentication>
            <encryption>
                <member>aes-128-cbc</member>
                <member>3des</member>
            </encryption>
        </esp>
        <lifetime>
            <hours>1</hours>
        </lifetime>
        <dh-group>group2</dh-group>
    </entry>
    ';
        self::$FAWKES_DEF_IPSEC_CRYPTO = self::stringToXml( $FAWKES_DEF_IPSEC_CRYPTO );

$product_map_info = array(
        "Other Devices" => array("name" => "Others" ),
        "Cisco-ISR" => array("name" => "CiscoISR" ),
        "Cisco-ASA" => array("name" => "CiscoASA" ),
        "Citrix" => array("name" => "Citrix" ),
        "CloudGenix" => array("name" => "CloudGenix" ),
        "SilverPeak" => array("name" => "SilverPeak" ),
        "Riverbed" => array("name" => "Riverbed" ),
        "Palo Alto Networks" => array("name" => "PAN" )
    );
        self::$product_map_info = $product_map_info;

$MONITOR_PROFILE_TUNNEL =
'
    <entry name="tunnel">
    <interval>3</interval>
    <threshold>5</threshold>
    <action>fail-over</action>
    </entry>
    ';
        self::$MONITOR_PROFILE_TUNNEL = self::stringToXml( $MONITOR_PROFILE_TUNNEL );


$MONITOR_PROFILE_DEFAULT =
'
    <entry name="default">
    <interval>3</interval>
    <threshold>5</threshold>
    <action>fail-over</action>
    </entry>
    ';
        self::$MONITOR_PROFILE_DEFAULT = self::stringToXml( $MONITOR_PROFILE_DEFAULT );
    }

    function migrate_rn_template( $tpl_cfg, $plugin_xmlroot )
    {
        self::rn_createVariables();

        #$this->template_path_settings( $tpl_cfg, $plugin_xmlroot );
        $this->template_path_settings( $tpl_cfg, $plugin_xmlroot, "new" );


        # adding network/profiles/monitor-profile entries
        $tpl_config_device_network_profiles_node = DH::findFirstElementOrCreate( "profiles", self::$tpl_config_device_network_node );
        $tpl_config_device_network_profiles_monitor_node = DH::findFirstElementOrCreate( "monitor-profile", $tpl_config_device_network_profiles_node );

        $tmp_node = self::$MONITOR_PROFILE_TUNNEL;
        $node = $this->panorama_doc->importNode($tmp_node, TRUE);
        $tpl_config_device_network_profiles_monitor_node->appendChild( $node );

        $tmp_node = self::$MONITOR_PROFILE_DEFAULT;
        $node = $this->panorama_doc->importNode($tmp_node, TRUE);
        $tpl_config_device_network_profiles_monitor_node->appendChild( $node );

    }
}