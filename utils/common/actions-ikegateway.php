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

IKEgatewayCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( IKEgatewayCallContext $context )
    {
        $object = $context->object;


        $text = $context->padding."  -preSharedKey: " . $object->preSharedKey . " ";

        if( $context->arguments['psk-cleartext'] )
        {
            $crypto = new PanosCrypto();

            try
            {
                // Determine the key to use
                $masterKey = ($context->arguments['master-key'] !== "--default--")
                    ? $context->arguments['master-key']
                    : null;

                // Attempt decryption
                $psk_cleartext = $crypto->decrypt($object->preSharedKey, $masterKey);

            } catch (Exception $e) {
                $psk_cleartext = "WRONG MASTER-KEY";
            }

            if( !empty($psk_cleartext) )
                $text .= "['".$psk_cleartext."'] ";
        }


        $text .= "-version: " . $object->version . " ";

        $text .= "-proposal: " . str_pad($object->proposal, 25) . " ";

        $text .= "-exchange-mode: " . str_pad($object->exchangemode, 25);
        PH::print_stdout($text);


        $text = $context->padding."  -localAddress: " . $object->localAddress . " ";
        $text .= "-localInterface: " . $object->localInterface . " ";
        $text .= "-peerAddress: " . $object->peerAddress . " ";

        $text .= "-localID: " . $object->localID . " ";
        $text .= "-peerID: " . $object->peerID . " ";

        $text .= "-NatTraversal: " . $object->natTraversal . " ";
        $text .= "-fragmentation: " . $object->fragmentation . " ";

        $text .= "-disabled: " . $object->disabled;
        PH::print_stdout($text);


        if( PH::$shadow_displayxmlnode )
        {
            PH::print_stdout(  "" );
            DH::DEBUGprintDOMDocument($context->object->xmlroot);
            PH::print_stdout();
        }


    },
    'args' => array(
        'psk-cleartext' => array('type' => 'bool', 'default' => FALSE),
        'master-key' => array('type' => 'string', 'default' => "--default--"),
    ),

);

IKEgatewayCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (IKEgatewayCallContext $context) {
        $object = $context->object;

        $object->display_references(7);
    },
);

IKEgatewayCallContext::$supportedActions[] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (IKEgatewayCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (IKEgatewayCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (IKEgatewayCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;

        $lines = '';


        $addWhereUsed = FALSE;
        $addUsedInLocation = FALSE;
        $showPSKcleartext = FALSE;

        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = TRUE;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = TRUE;

        if( isset($optionalFields['PSKcleartext']) )
            $showPSKcleartext = TRUE;

        $headers = '<th>ID</th><th>template</th><th>location</th><th>name</th><th>PSK</th><th>cleartext</th>';

        $headers .= '<th>version</th><th>proposal</th><th>exchange-mode</th>';
        $headers .= '<th>localAddress</th><th>localInterface</th><th>peerAddress</th>';
        $headers .= '<th>localID</th><th>peerID</th><th>NatTraversal</th><th>fragmentation</th><th>disabled</th>';


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
                    if( isset($object->owner->owner)
                        && $object->owner->owner !== null
                        && (
                            get_class($object->owner->owner) == "Template"
                            || get_class($context->subSystem) == "TemplateStack" )
                    )
                    {
                        #$lines .= $context->encloseFunction($object->owner->owner->owner->name());
                        $lines .= $context->encloseFunction($object->owner->owner->name());

                        $tmp_vsys = $object->owner->owner->network->findVsysInterfaceOwner($object->name());
                        if( $tmp_vsys !==  null )
                            $lines .= $context->encloseFunction($tmp_vsys->name());
                        else
                            $lines .= $context->encloseFunction(get_class($object->owner->owner));
                    }
                    else
                    {
                        $lines .= $context->encloseFunction("---");

                        $tmp_vsys = $object->owner->owner->network->findVsysInterfaceOwner($object->name());
                        if( $tmp_vsys !==  null )
                            $lines .= $context->encloseFunction($tmp_vsys->name());
                        else
                        {
                            #$lines .= $context->encloseFunction($object->owner->owner->name());
                            $lines .= $context->encloseFunction(get_class($object->owner->owner));
                        }
                    }
                }

                //$lines .= $context->encloseFunction(PH::getLocationString($object));

                $lines .= $context->encloseFunction($object->name());

                $lines .= $context->encloseFunction($object->preSharedKey);

                $crypto = new PanosCrypto();
                try
                {
                    // Determine the key to use
                    //$masterKey = ($context->arguments['master-key'] !== "--default--")
                    //    ? $context->arguments['master-key']
                    //    : null;

                    // Attempt decryption
                    //$psk_cleartext = $crypto->decrypt($object->preSharedKey, $masterKey);
                    $psk_cleartext = $crypto->decrypt($object->preSharedKey);

                } catch (Exception $e) {
                    $psk_cleartext = "WRONG MASTER-KEY";
                }

                if( !empty($psk_cleartext) && $psk_cleartext != "WRONG MASTER-KEY" )
                {
                    if( $showPSKcleartext )
                        $lines .= $context->encloseFunction($psk_cleartext);
                    else
                        $lines .= $context->encloseFunction("[PSK cleartext possible]");
                }

                else
                    $lines .= $context->encloseFunction("---");




                $lines .= $context->encloseFunction($object->version);
                $lines .= $context->encloseFunction($object->proposal);

                $lines .= $context->encloseFunction($object->exchangemode);


                $lines .= $context->encloseFunction($object->localAddress);
                $lines .= $context->encloseFunction($object->localInterface);
                $lines .= $context->encloseFunction($object->peerAddress);

                $lines .= $context->encloseFunction($object->localID);
                $lines .= $context->encloseFunction($object->peerID);

                $lines .= $context->encloseFunction($object->natTraversal);
                $lines .= $context->encloseFunction($object->fragmentation);

                $lines .= $context->encloseFunction($object->disabled);



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
                'choices' => array('WhereUsed', 'UsedInLocation', 'PSKcleartext'),
                'help' =>
                    "pipe(|) separated list of additional field to include in the report. The following is available:\n" .
                    "  - WhereUsed : list places where object is used (rules, groups ...)\n" .
                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n" .
                    "  - PSKcleartext : show IKE gateway PSK in cleartext\n")
    )
);
IKEgatewayCallContext::$supportedActions[] = array_merge(IKEgatewayCallContext::$supportedActions[count(IKEgatewayCallContext::$supportedActions)-1], array('name' => 'exportToHtml'));
