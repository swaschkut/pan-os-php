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

IKEprofileCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( IKEprofileCallContext $context )
    {
        $object = $context->object;
        //PH::print_stdout("     * ".get_class($object)." '{$object->name()}'" );

        $text = $context->padding."  hash: " . implode( ",", $object->hash) . " - dhgroup: " . implode( ",",$object->dhgroup ) . " - encryption: " . implode( ",", $object->encryption ) . " - ";
        if( $object->lifetime_seconds != "" )
            $text .= $object->lifetime_seconds . " seconds";
        elseif( $object->lifetime_minutes != "" )
            $text .= $object->lifetime_minutes . " minutes";
        elseif( $object->lifetime_hours != "" )
            $text .= $object->lifetime_hours . " hours";
        elseif( $object->lifetime_days != "" )
            $text .= $object->lifetime_days . " days";

        PH::print_stdout($text);

        if( PH::$shadow_displayxmlnode )
        {
            PH::print_stdout(  "" );
            DH::DEBUGprintDOMDocument($context->object->xmlroot);
            PH::print_stdout();
        }
    },

);

IKEprofileCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (IKEprofileCallContext $context) {
        $object = $context->object;

        $object->display_references(7);
    },
);

IKEprofileCallContext::$supportedActions[] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (IKEprofileCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (IKEprofileCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (IKEprofileCallContext $context) {
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

        $headers .= '<th>hash</th><th>dhgroup</th><th>encryption</th><th>lifetime</th><th>used count</th>';

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

                $lines .= $context->encloseFunction($object->name());

                $lines .= $context->encloseFunction($object->hash);

                $lines .= $context->encloseFunction($object->dhgroup);

                $lines .= $context->encloseFunction($object->encryption);

                if( $object->lifetime_seconds != "" )
                    $text = $object->lifetime_seconds . " seconds";

                elseif( $object->lifetime_minutes != "" )
                    $text = $object->lifetime_minutes . " minutes";

                elseif( $object->lifetime_hours != "" )
                    $text = $object->lifetime_hours . " hours";

                elseif( $object->lifetime_days != "" )
                    $text = $object->lifetime_days . " days";
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

        require_once dirname(__FILE__) . '/../lib/ExportToHtmlHelper.php';
        ExportToHtmlHelper::writeHtmlExport($filename, $headers, $lines);
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
IKEprofileCallContext::$supportedActions[] = array_merge(IKEprofileCallContext::$supportedActions[array_key_last(IKEprofileCallContext::$supportedActions)], array('name' => 'exportToHtml'));

IKEprofileCallContext::$supportedActions['delete'] = array(
    'name' => 'delete',
    'MainFunction' => function (IKEprofileCallContext $context) {
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

IKEprofileCallContext::$supportedActions['delete-force'] = array(
    'name' => 'delete-Force',
    'MainFunction' => function (IKEprofileCallContext $context) {
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
IKEprofileCallContext::$supportedActions['deleteforce'] = array_merge(IKEprofileCallContext::$supportedActions['delete-force'], 
    array(
        'name' => 'deleteForce',
        'deprecated' => 'this action "deleteForce" is deprecated, you should use "delete-Fore" instead!',
        'help' => 'this action "deleteForce" is deprecated, you should use "delete-Fore" instead!'
    )
);
