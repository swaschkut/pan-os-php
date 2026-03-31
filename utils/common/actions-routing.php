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



RoutingCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( RoutingCallContext $context )
    {
        $virtualRouter = $context->object;
        PH::print_stdout("     * ".get_class($virtualRouter)." '{$virtualRouter->name()}'" );
        PH::$JSON_TMP['sub']['object'][$virtualRouter->name()]['name'] = $virtualRouter->name();
        PH::$JSON_TMP['sub']['object'][$virtualRouter->name()]['type'] = get_class($virtualRouter);


        foreach( $virtualRouter->staticRoutes() as $staticRoute )
        {
            $text = $staticRoute->display( $virtualRouter, true );
            PH::print_stdout( $text );
        }

        PH::print_stdout();
    },

    //Todo: display routes to zone / Interface IP
);


RoutingCallContext::$supportedActions[] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (RoutingCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (RoutingCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (RoutingCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;

        $lines = '';


        $addWhereUsed = FALSE;
        $addUsedInLocation = FALSE;

        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = TRUE;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = TRUE;


        $headers = '<th>ID</th><th>Template</th><th>location</th><th>name</th>';

        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';

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
                'choices' => array('WhereUsed', 'UsedInLocation'),
                'help' =>
                    "pipe(|) separated list of additional field to include in the report. The following is available:\n" .
                    "  - WhereUsed : list places where object is used (rules, groups ...)\n" .
                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n")
    )
);
RoutingCallContext::$supportedActions[] = array_merge(RoutingCallContext::$supportedActions[array_key_last(RoutingCallContext::$supportedActions)], array('name' => 'exportToHtml'));

RoutingCallContext::$supportedActions['display'] = Array(
    'name' => 'display-route-table-fast',
    'MainFunction' => function ( RoutingCallContext $context )
    {
        $virtualRouter = $context->object;
        PH::print_stdout("     * ".get_class($virtualRouter)." '{$virtualRouter->name()}'" );

        if( get_class($virtualRouter) == "LogicalRouter")
            $cmd = "<show><advanced-routing><route><logical-router>".$virtualRouter->name()."</logical-router></route></advanced-routing></show>";
        else
            $cmd = "<show><routing><route><virtual-router>".$virtualRouter->name()."</virtual-router></route></routing></show>";

        $connector = findConnectorOrDie($virtualRouter);
        $response = $connector->sendOpRequest($cmd, TRUE);

        $result = DH::findFirstElement("result", $response);
        $json = DH::findFirstElement("json", $result);

        $filename = $connector->apihost."_".$virtualRouter->name().".txt";
        file_put_contents($filename, $json->textContent);




        $data = json_decode($json->textContent, true);

        if (!isset($data[$virtualRouter->name()]))
            derr("Error: ".$virtualRouter->name()." VRF not found in JSON data.\n", null, false );

        // 1. Define column headers and widths
        $mask = "| %-18s | %-10s | %-18s | %-15s | %-8s | %-8s | %-10s |\n";
        $line = "+" . str_repeat("-", 20) . "+" . str_repeat("-", 12) . "+" . str_repeat("-", 20) . "+" . str_repeat("-", 17) . "+" . str_repeat("-", 10) . "+" . str_repeat("-", 10) . "+" . str_repeat("-", 12) . "+\n";

        // 2. Print Header
        echo $line;
        printf($mask, 'Prefix', 'Protocol', 'Interface', 'NextHop', 'Distance', 'Metric', 'Uptime');
        echo $line;

        // 3. Iterate through routes
        foreach ($data[$virtualRouter->name()] as $prefix => $routeEntries)
        {
            foreach ($routeEntries as $entry)
            {
                // Extract basic fields
                $protocol = $entry['protocol'] ?? 'N/A';
                $distance = $entry['distance'] ?? '0';
                $metric   = $entry['metric'] ?? '0';
                $uptime   = $entry['uptime'] ?? 'N/A';

                // Handle cases where there might be multiple nexthops for one prefix
                if (!empty($entry['nexthops']))
                {
                    foreach ($entry['nexthops'] as $nh)
                    {
                        $nexthopIP = $nh['ip'] ?? 'Direct';
                        $interface = $nh['interfaceName'] ?? 'N/A';

                        printf($mask, $prefix, $protocol, $interface, $nexthopIP, $distance, $metric, $uptime);
                    }
                }
                else
                {
                    // Default if no nexthops array exists
                    printf($mask, $prefix, $protocol, 'N/A', 'N/A', $distance, $metric, $uptime);
                }
            }
        }

        echo $line;
    },
);