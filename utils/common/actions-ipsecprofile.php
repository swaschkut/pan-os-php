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

IPsecprofileCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( IPsecprofileCallContext $context )
    {
        $object = $context->object;
        //PH::print_stdout("     * ".get_class($object)." '{$object->name()}'" );

        PH::print_stdout( $context->padding. " - protocol: " . $object->ipsecProtocol );
        $text = $context->padding."      encryption: " . implode( ",",$object->encryption ) . " - authentication: " . implode( ",", $object->authentication ) . " - dhgroup: " . $object->dhgroup;

        if( $object->lifetime_seconds != "" )
            $text .= " - lifetime: " . $object->lifetime_seconds . " seconds";
        elseif( $object->lifetime_minutes != "" )
            $text .= " - lifetime: " . $object->lifetime_minutes . " minutes";
        elseif( $object->lifetime_hours != "" )
            $text .= " - lifetime: " . $object->lifetime_hours . " hours";
        elseif( $object->lifetime_days != "" )
            $text .= " - lifetime: " . $object->lifetime_days . " days";


        if( $object->lifesize_kb != "" )
            $text .= " - lifesize: " . $object->lifesize_kb . " kb";
        elseif( $object->lifesize_mb != "" )
            $text .= " - lifesize: " . $object->lifesize_mb . " mb";
        elseif( $object->lifesize_gb != "" )
            $text .= " - lifesize: " . $object->lifesize_gb . " gb";
        elseif( $object->lifesize_tb != "" )
            $text .= " - lifesize: " . $object->lifesize_tb . " tb";

        PH::print_stdout($text);


        if( PH::$shadow_displayxmlnode )
        {
            PH::print_stdout(  "" );
            DH::DEBUGprintDOMDocument($context->object->xmlroot);
            PH::print_stdout();
        }

    },

);

IPsecprofileCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (IPsecprofileCallContext $context) {
        $object = $context->object;

        $object->display_references(7);
    },
);

IPsecprofileCallContext::$supportedActions[] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (IPsecprofileCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (IPsecprofileCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (IPsecprofileCallContext $context) {
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


        $headers = '<th>ID</th><th>template</th><th>location</th><th>name</th>';

        $headers .= '<th>ipsecProtocol</th><th>encryption</th><th>authentication</th><th>dhgroup</th>';

        $headers .= '<th>lifetime</th><th>lifesize</th><th>used count</th>';


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

                /** @var IkeCryptoProfil $object */
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
                            $lines .= $context->encloseFunction(get_class($object->owner->owner));
                    }
                }

                $lines .= $context->encloseFunction($object->name());

                $lines .= $context->encloseFunction($object->ipsecProtocol);

                $lines .= $context->encloseFunction($object->encryption);

                $lines .= $context->encloseFunction($object->authentication);

                $lines .= $context->encloseFunction($object->dhgroup);


                if( $object->lifetime_seconds != "" )
                    $text =  $object->lifetime_seconds . " seconds";
                elseif( $object->lifetime_minutes != "" )
                    $text =  $object->lifetime_minutes . " minutes";
                elseif( $object->lifetime_hours != "" )
                    $text =  $object->lifetime_hours . " hours";
                elseif( $object->lifetime_days != "" )
                    $text =  $object->lifetime_days . " days";
                $lines .= $context->encloseFunction($text);

                if( $object->lifesize_kb != "" )
                    $text =  $object->lifesize_kb . " kb";
                elseif( $object->lifesize_mb != "" )
                    $text =  $object->lifesize_mb . " mb";
                elseif( $object->lifesize_gb != "" )
                    $text =  $object->lifesize_gb . " gb";
                elseif( $object->lifesize_tb != "" )
                    $text =  $object->lifesize_tb . " tb";
                $lines .= $context->encloseFunction($text);

                $lines .= $context->encloseFunction((string)count($object->getReferences()));


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
IPsecprofileCallContext::$supportedActions[] = array_merge(IPsecprofileCallContext::$supportedActions[array_key_last(IPsecprofileCallContext::$supportedActions)], array('name' => 'exportToHtml'));

IPsecprofileCallContext::$supportedActions['delete'] = array(
    'name' => 'delete',
    'MainFunction' => function (IPsecprofileCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            $string = "this object is used by other objects and cannot be deleted (use deleteForce to try anyway)";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        if( $context->isAPI )
            $object->owner->API_removeProfile($object);
        else
            $object->owner->removeProfile($object);
    },
);

IPsecprofileCallContext::$supportedActions['deleteforce'] = array(
    'name' => 'deleteForce',
    'MainFunction' => function (IPsecprofileCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            $string = "this object seems to be used so deletion may fail.";
            PH::ACTIONstatus( $context, "WARNING", $string);
        }
        if( $context->isAPI )
            $object->owner->API_removeProfile($object);
        else
            $object->owner->removeProfile($object);
    },
);

