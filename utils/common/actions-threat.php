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


ThreatCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (ThreatCallContext $context) {
        $object = $context->object;

        #$object->display_references(7);

        $strpad = str_pad('', 7);
        PH::print_stdout( $strpad . "* Displaying referencers for " . $object->toString() );
        $ip_exception_counter = 0;
        foreach( $object->refrules as $o )
        {
            PH::print_stdout( $strpad . '  - ' . $o->toString() );

            /** @var AntiSpywareProfile|VulnerabilityProfile $reference*/
            if( isset($o->threatException) )
            {
                foreach($o->threatException as $threatName => $threatException)
                {
                    if( $threatName == $object->name() )
                    {
                        asort($threatException['exempt-ip']);
                        if( count($threatException['exempt-ip']) > 0)
                            PH::print_stdout($strpad . '     - ' . "excemption-IP count: ".count($threatException['exempt-ip'])." | '".implode(',',$threatException['exempt-ip'])."'");
                        else
                            PH::print_stdout($strpad . '     - ' . "excemption-IP count: 0" );
                    }
                }
            }
        }
    },
);



ThreatCallContext::$supportedActions[] = array(
    'name' => 'display',
    'GlobalInitFunction' => function (ThreatCallContext $context) {
        $context->counter_spyware = 0;
        $context->counter_vulnerability = 0;

    },
    'MainFunction' => function (ThreatCallContext $context) {
        $threat = $context->object;

        $threat->display($context->padding);

        if( $threat->type() == "vulnerability" )
            $context->counter_vulnerability++;
        elseif( $threat->type() == "spyware" )
            $context->counter_spyware++;

    },
    'GlobalFinishFunction' => function (ThreatCallContext $context) {
        PH::print_stdout("spyware: ".$context->counter_spyware );
        PH::print_stdout("vulnerability: ".$context->counter_vulnerability );

        PH::$JSON_TMP['sub']['summary']['spyware'] = $context->counter_spyware;
        PH::$JSON_TMP['sub']['summary']['vulnerability'] = $context->counter_vulnerability;
    }
);

ThreatCallContext::$supportedActions[] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (ThreatCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (ThreatCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (ThreatCallContext $context) {
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


        $headers = '<th>ID</th><th>location</th><th>type</th><th>name</th><th>Threatname</th><th>category</th><th>severity</th><th>default-action</th>';

        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
        {
            $headers .= '<th>location used</th>';
            $headers .= '<th>exemption IP</th>';
        }


        $count = 0;
        if( isset($context->objectList) )
        {
            foreach( $context->objectList as $object )
            {
                $count++;

                /** @var Threat $object */
                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $context->encloseFunction( (string)$count );

                $lines .= $context->encloseFunction(PH::getLocationString($object));

                $lines .= $context->encloseFunction(get_class($object));

                $lines .= $context->encloseFunction($object->name());

                $lines .= $context->encloseFunction($object->threatname());

                $lines .= $context->encloseFunction($object->category());

                $lines .= $context->encloseFunction($object->severity());

                $lines .= $context->encloseFunction($object->defaultAction());

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
                    $refExcemptionArray = array();
                    foreach( $object->getReferences() as $ref )
                    {
                        $location = PH::getLocationString($object->owner);
                        $refTextArray[$location] = $location;

                        /** @var AntiSpywareProfile|VulnerabilityProfile $reference*/
                        if( isset($ref->threatException) )
                        {
                            foreach($ref->threatException as $threatName => $threatException)
                            {
                                if( $threatName == $object->name() )
                                {
                                    asort($threatException['exempt-ip']);
                                    if( count($threatException['exempt-ip']) > 0)
                                        $refExcemptionArray[] = "count: ".count($threatException['exempt-ip'])." | '".implode(',',$threatException['exempt-ip'])."'";
                                    else
                                        $refExcemptionArray[] = "count: 0";
                                }
                            }
                        }
                    }

                    $lines .= $context->encloseFunction($refTextArray);

                    $lines .= $context->encloseFunction($refExcemptionArray);
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

ThreatCallContext::$supportedActions[] = array(
    'name' => 'display-xml',
    'MainFunction' => function (ThreatCallContext $context)
    {
        $threat = $context->object;

        DH::DEBUGprintDOMDocument($threat->xmlroot);

    }
);