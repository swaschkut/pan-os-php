<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
 * Copyright (c) 2019, Palo Alto Networks Inc.
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


ZoneProtectionProfileCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (ZoneProtectionProfileCallContext $context) {
        $object = $context->object;

        $object->display_references(7);
    },
);

ZoneProtectionProfileCallContext::$supportedActions['display'] = array(
    'name' => 'display',
    'MainFunction' => function (ZoneProtectionProfileCallContext $context) {
        /** @var ZoneProtectionProfile $object */
        $object = $context->object;
        $tmp_txt = "     * " . get_class($object) . " '{$object->name()}'   ( type: " . $object->type . " )";

        PH::print_stdout( "\n     - FLOOD:");
        #print_r($object->flood);
        foreach( $object->flood as $key => $flood )
        {
            PH::print_stdout( "      * ".$key );
            $tmp_string = "";
            if( isset($flood['red']) )
            {
                #PH::print_stdout( "        - red:" );
                if( isset($flood['red']['alarm-rate']) )
                    $tmp_string .= " - alarm-rate: ".$flood['red']['alarm-rate'];
                if( isset($flood['red']['activate-rate']) )
                    $tmp_string .= " - activate-rate: ".$flood['red']['activate-rate'];
                if( isset($flood['red']['maximal-rate']) )
                    $tmp_string .= " - maximal-rate: ".$flood['red']['maximal-rate'];
            }
            if( isset($flood['enable']) )
                $tmp_string .= " - enable: '".$flood['enable']."'";

            if( !empty($tmp_string) )
                PH::print_stdout( "        ".$tmp_string." ");
        }

        PH::print_stdout( "\n     - SCAN:");
        foreach( $object->scan as $key => $scan )
        {
            PH::print_stdout( "      * ".$key );
            $tmp_string = "";
            if( isset($scan['action']) )
                $tmp_string .= " - action: ".$scan['action'];

            if( isset($scan['track-by']) )
                $tmp_string .= " - track-by: ".$scan['track-by'];
            if( isset($scan['duration']) )
                $tmp_string .= " - duration: ".$scan['duration'];

            if( isset($scan['interval']) )
                $tmp_string .= " - interval: ".$scan['interval'];
            if( isset($scan['threshold']) )
                $tmp_string .= " - threshold: ".$scan['threshold'];

            if( !empty($tmp_string) )
                PH::print_stdout( "        ".$tmp_string." ");
        }

        $tmp_string = "";

        if( $object->discard_ip_spoof !== FALSE )
            $tmp_string .= " - discard-ip-spoof: '".$object->discard_ip_spoof."'";
        if( $object->discard_malformed_option !== FALSE )
            $tmp_string .= " - discard-malformed-option: '".$object->discard_malformed_option."'";
        if( $object->remove_tcp_timestamp !== FALSE )
            $tmp_string .= " - remove-tcp-timestamp: '".$object->remove_tcp_timestamp."'";
        if( $object->strip_tcp_fast_open_and_data !== FALSE )
            $tmp_string .= " - strip-tcp-fast-open-and-data: '".$object->strip_tcp_fast_open_and_data."'";
        if( $object->strip_mptcp_option !== FALSE )
            $tmp_string .= " - strip-mptcp-option: '".$object->strip_mptcp_option."'";

        if( !empty($tmp_string) )
        {
            PH::print_stdout( "\n     - ADDITIONAL :");
            PH::print_stdout( "        ".$tmp_string." ");
        }

    },
);

