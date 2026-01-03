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

trait transfer_sn_template
{

    function migrate_sn_template( $tpl_cfg, $plugin_xmlroot )
    {
        //same for SN and RN
        self::rn_createVariables();

        #$this->template_path_settings( $tpl_cfg, $plugin_xmlroot );
        $this->template_path_settings( $tpl_cfg, $plugin_xmlroot, "new" );
        


        //Todo: all above same now for SN/RN/MU
        

        //same as RN
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