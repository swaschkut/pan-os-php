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



StaticRouteCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( StaticRouteCallContext $context )
    {
        $staticRoute = $context->object;
        PH::print_stdout("     * ".get_class($staticRoute)." '{$staticRoute->name()}'" );
        PH::$JSON_TMP['sub']['object'][$staticRoute->owner->name()]['name'] = $staticRoute->name();
        PH::$JSON_TMP['sub']['object'][$staticRoute->owner->name()]['type'] = get_class($staticRoute);

        $text = $staticRoute->display( $staticRoute->owner );
        PH::print_stdout( $text );
    },
);

StaticRouteCallContext::$supportedActions['delete'] = Array(
    'name' => 'delete',
    'MainFunction' => function ( StaticRouteCallContext $context )
    {
        $context->object->remove();
    },
);

StaticRouteCallContext::$supportedActions['exportToExcel'] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (StaticRouteCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (StaticRouteCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (StaticRouteCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;

        $addWhereUsed = FALSE;
        $addUsedInLocation = FALSE;
        $addResolveGroupIPCoverage = FALSE;
        $addNestedMembers = FALSE;



        $headers = '<th>ID</th><th>template</th><th>location</th><th>router</th><th>name</th><th>destination</th><th>next-hop IP</th>';
        $headers .= '<th>next-hop VR</th><th>metric</th><th>next-hop type</th><th>next-hop Interface</th>';

        $lines = '';

        $count = 0;
        if( isset($context->objectList) )
        {
            foreach( $context->objectList as $object )
            {
                $count++;

                /** @var Zone $object */
                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $context->encloseFunction( (string)$count );

                if( $object->owner->owner->owner->owner  !== null && get_class( $object->owner->owner->owner->owner ) == "Template" )
                {
                    $lines .= $context->encloseFunction($object->owner->owner->owner->owner->name());
                    $lines .= $context->encloseFunction($object->owner->owner->name());
                }
                else
                {
                    $lines .= $context->encloseFunction( "" );
                    $lines .= $context->encloseFunction($object->owner->owner->name());
                }


                $lines .= $context->encloseFunction($object->owner->name());

                $lines .= $context->encloseFunction($object->name());



                if($object->destination() !== null)
                {
                    $string_destination = $object->destination();
                    if( $object->destinationObject() !== "" && $object->destinationObject() !== null )
                        $string_destination .= " [".$object->destinationObject()->name()."]";


                    $tmpText = $object->destination();
                    if( $object->destinationObject() !== "" && $object->destinationObject() !== null )
                        $tmpText =  $object->destinationObject()->name();
                    $lines .= $context->encloseFunction( $tmpText );
                }
                else
                    $lines .= $context->encloseFunction("");


                if( $object->nexthopIP() !== null )
                {
                    $string_nexthopIP = $object->nexthopIP();
                    if( $object->nexthopIPobject() !== "" && $object->nexthopIPobject() !== null )
                        $string_nexthopIP .= " [".$object->nexthopIPobject()->name()."]";

                    $tmpText = $object->nexthopIP();
                    if( $object->nexthopIPobject() !== "" && $object->nexthopIPobject() !== null )
                        $tmpText =  $object->nexthopIPobject()->name();
                    $lines .= $context->encloseFunction( $tmpText );
                }
                else
                    $lines .= $context->encloseFunction("");

                if( $object->nexthopVR() != null )
                {
                    $lines .= $context->encloseFunction(  $object->nexthopVR() );
                }
                else
                    $lines .= $context->encloseFunction("");

                if( $object->metric() !== null )
                {
                    $lines .= $context->encloseFunction(  $object->metric() );
                }
                else
                    $lines .= $context->encloseFunction("");

                if( $object->nexthopType() == "discard" )
                {
                    $lines .= $context->encloseFunction(  "discard" );
                }
                else
                    $lines .= $context->encloseFunction("");

                if( $object->nexthopInterface() != null )
                {
                    $lines .= $context->encloseFunction(  $object->nexthopInterface()->name() );
                }
                else
                    $lines .= $context->encloseFunction("");



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


        file_put_contents($filename, $content);
    },
    'args' => array('filename' => array('type' => 'string', 'default' => '*nodefault*'),
        'additionalFields' =>
            array('type' => 'pipeSeparatedList',
                'subtype' => 'string',
                'default' => '*NONE*',
                'choices' => array('WhereUsed', 'UsedInLocation', 'ResolveIP', 'NestedMembers'),
                'help' =>
                    "pipe(|) separated list of additional fields (ie: Arg1|Arg2|Arg3...) to include in the report. The following is available:\n" .
                    "  - NestedMembers: lists all members, even the ones that may be included in nested groups\n" .
                    "  - ResolveIP\n" .
                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n" .
                    "  - WhereUsed : list places where object is used (rules, groups ...)\n"
            )
    )

);
