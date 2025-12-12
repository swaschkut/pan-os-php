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

ZoneProtectionProfileCallContext::$supportedActions[] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (ZoneProtectionProfileCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (ZoneProtectionProfileCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (ZoneProtectionProfileCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;

        $lines = '';


        $addWhereUsed = FALSE;
        $addUsedInLocation = FALSE;
        $addTotalUse = FALSE;

        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = TRUE;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = TRUE;
        if( isset($optionalFields['TotalUse']) )
            $addTotalUse = TRUE;

        #$headers = '<th>ID</th><th>location</th><th>name</th><th>color</th><th>description</th>';
        $headers = '<th>ID</th><th>template</th><th>location</th><th>name</th><th>content</th>';

        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';
        if( $addTotalUse )
            $headers .= '<th>total use</th>';

        $count = 0;
        if( isset($context->objectList) )
        {
            foreach( $context->objectList as $object )
            {
                $count++;

                /** @var Tag $object */
                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $context->encloseFunction( (string)$count );

                if( get_class($object->owner->owner) == "PANConf" )
                {
                    if( isset($object->owner->owner->owner) && $object->owner->owner->owner !== null && (get_class($object->owner->owner->owner) == "Template" || get_class($context->subSystem->owner) == "TemplateStack" ) )
                    {
                        $lines .= $context->encloseFunction($object->owner->owner->owner->name());
                        $lines .= $context->encloseFunction($object->owner->owner->name());
                    }
                    else
                    {
                        $lines .= $context->encloseFunction("---");
                        $lines .= $context->encloseFunction($object->owner->owner->name());
                    }
                }

                #$lines .= $context->encloseFunction(PH::getLocationString($object));

                $lines .= $context->encloseFunction($object->name());


                $tmp_array = array();
                $tmp_flood_array = array();
                $tmp_flood_array[] = "FLOOD:";


                foreach( $object->flood as $key => $flood )
                {
                    $tmp_flood_array[] = "* ".$key."\n";
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
                        $tmp_flood_array[] = $tmp_string;
                }

                $tmp_flood_array[] = "";
                $tmp_flood_array[] = "SCAN:";
                foreach( $object->scan as $key => $scan )
                {
                    $tmp_flood_array[] = "* ".$key."\n";
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
                        $tmp_flood_array[] = $tmp_string;
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
                    $tmp_flood_array[] = "";
                    $tmp_flood_array[] = "ADDITIONAL :";
                    $tmp_flood_array[] = $tmp_string;
                }

                $lines .= $context->encloseFunction($tmp_flood_array);

                if( $addWhereUsed )
                {
                    $refTextArray = array();
                    foreach( $object->getReferences() as $ref )
                        $refTextArray[] = $ref->_PANC_shortName();

                    $lines .= $context->encloseFunction($refTextArray);
                }
                if( $addUsedInLocation )
                {
                    $refTextArray = array();
                    foreach( $object->getReferences() as $ref )
                    {
                        $location = PH::getLocationString($object->owner);
                        $refTextArray[$location] = $location;
                    }

                    $lines .= $context->encloseFunction($refTextArray);
                }
                if( $addTotalUse)
                {
                    $refCount = $object->countReferences();
                    if( $refCount == 0 )
                        $refCount = "---";
                    else
                        $refCount = (string)$refCount ;
                    $lines .= $context->encloseFunction( $refCount );
                }

                $lines .= "</tr>\n";
            }
        }

        $content = file_get_contents(dirname(__FILE__) . '/html/export-template.html');
        $content = str_replace('%TableHeaders%', $headers, $content);

        $content = str_replace('%lines%', $lines, $content);

        $jscontent = file_get_contents(dirname(__FILE__) . '/html/jquery.min.js');
        $jscontent .= "\n";
        $jscontent .= file_get_contents(dirname(__FILE__) . '/html/jquery.stickytableheaders.min.js');
        $jscontent .= "\n\$('table').stickyTableHeaders();\n";

        $content = str_replace('%JSCONTENT%', $jscontent, $content);

        file_put_contents($filename, $content);
    },
    'args' => array('filename' => array('type' => 'string', 'default' => '*nodefault*'),
        'additionalFields' =>
            array('type' => 'pipeSeparatedList',
                'subtype' => 'string',
                'default' => '*NONE*',
                'choices' => array('WhereUsed', 'UsedInLocation', 'TotalUse' ),
                'help' =>
                    "pipe(|) separated list of additional field to include in the report. The following is available:\n" .
                    "  - WhereUsed : list places where object is used (rules, groups ...)\n" .
                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n" .
                    "  - TotalUse : list a counter how often this object is used\n"
            )
    )
);