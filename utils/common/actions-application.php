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

//Todo: introduce actions:
//      display
//      set custom timeout, tcp-timeout, udp-timeout, tcp_half_closed_timeout, tcp_time_wait_timeout
//      enable app-id

ApplicationCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (ApplicationCallContext $context) {
        $object = $context->object;

        $object->display_references(7);
    },
);



ApplicationCallContext::$supportedActions['display'] = array(
    'name' => 'display',
    'GlobalInitFunction' => function (ApplicationCallContext $context)
    {
        $context->counter_containers = 0;
        $context->tmpcounter = 0;
        $context->counter_predefined = 0;
        $context->counter_dependencies = 0;

        $context->counter_custom_app = 0;
        $context->counter_app_filter = 0;
        $context->counter_app_group = 0;

        $context->counter_decoder = 0;
        $context->tmp_decoder = array();

        $context->print_container = true;
        $context->print_dependencies = true;
        $context->print_explicit = true;
        $context->print_implicit = true;


    },
    'MainFunction' => function (ApplicationCallContext $context) {
        $app = $context->object;

        $txt_counter = "";
        $counter = "";
        if( $app->isContainer() )
            $counter = count( $app->containerApps() );
        elseif( $app->isApplicationGroup() )
            $counter = count( $app->groupApps() );
        elseif( $app->isApplicationFilter() )
            $counter = count( $app->filteredApps() );

        if( !empty($counter) )
            $txt_counter = "app_counter: ".$counter;
        PH::print_stdout( $context->padding . "* " . get_class($app) . " '{$app->name()}' ".$txt_counter );
        PH::$JSON_TMP['sub']['object'][$app->name()]['name'] = $app->name();
        PH::$JSON_TMP['sub']['object'][$app->name()]['type'] = get_class($app);

        //TMP
        if(  isset($app->decoder ))
        {
            foreach($app->decoder as $decoder)
            {
                if( !in_array( $decoder, $context->tmp_decoder ) )
                {
                    $context->tmp_decoder[$decoder] = $decoder;
                    $context->counter_decoder++;
                }
            }
        }

        if( $app->isContainer() )
        {
            $context->counter_containers++;
            if( $context->print_container )
            {
                $tmparray = array();
                PH::$JSON_TMP['sub']['object'][$app->name()]['container'] = $tmparray;

                PH::print_stdout( $context->padding." - is container: " );
                foreach( $app->containerApps() as $app1 )
                {
                    $tmparray = array();
                    #PH::print_stdout( "     ->" . $app1->type . " | " );
                    $app1->print_appdetails( $context->padding, true, $tmparray );
                    PH::$JSON_TMP['sub']['object'][$app->name()]['container']['app'][] = $tmparray;

                    PH::print_stdout();
                }
            }
        }
        elseif( $app->isApplicationGroup() )
        {
            foreach( $app->groupApps() as $app1 )
            {
                $tmparray = array();
                #PH::print_stdout( "     ->" . $app1->type . " | " );
                $app1->print_appdetails( $context->padding, true, $tmparray );
                PH::$JSON_TMP['sub']['object'][$app->name()]['group']['app'][] = $tmparray;
                PH::print_stdout();
            }
        }
        elseif( $app->isApplicationFilter() )
        {
            foreach( $app->filteredApps() as $app1 )
            {
                $tmparray = array();
                #PH::print_stdout( "     ->" . $app1->type . " | " );
                $app1->print_appdetails( $context->padding, true, $tmparray );
                PH::$JSON_TMP['sub']['object'][$app->name()]['filter']['app'][] = $tmparray;
                PH::print_stdout();
            }
        }
        else
        {
            $tmparray = array();
            PH::print_stdout( $context->padding." - ".$app->type );
            $printflag = true;
            $app->print_appdetails( $context->padding, $printflag, $tmparray );
            PH::$JSON_TMP['sub']['object'][$app->name()]['app'][] = $tmparray;
        }

        if( $app->type == 'tmp' )
            $context->tmpcounter++;

        if( $app->type == 'predefined' )
            $context->counter_predefined++;


        if( $app->isApplicationCustom() )
        {
            $context->counter_custom_app++;
            if( $app->custom_signature )
            {
                PH::print_stdout( "custom_signature is set" );
                PH::$JSON_TMP['sub']['object'][$app->name()]['custom_signature'] = "available";
            }

        }

        if( $app->isApplicationFilter() )
            $context->counter_app_filter++;


        if( $app->isApplicationGroup() )
            $context->counter_app_group++;


        // Explicit / Implicti difference
        $app_explicit = array();
        $app_implicit = array();
        if( isset($app->explicitUse) )
        {
            foreach( $app->explicitUse as $explApp )
            {
                $app_explicit[$explApp->name()] = $explApp;
            }
        }

        if( isset($app->implicitUse) )
        {
            foreach( $app->implicitUse as $implApp )
            {
                $app_implicit[$implApp->name()] = $implApp;
            }
        }

        $dependency_app = array();
        foreach( $app_implicit as $implApp )
        {
            if( isset($app_explicit[$implApp->name()]) )
            {
                PH::print_stdout( $context->padding. str_pad($app->name(), 30) . " has app-id: " . str_pad($implApp->name(), 20) . " as explicit and implicit used" );
                PH::$JSON_TMP['sub']['object'][$app->name()]['explicitANDimplicit'][] = $implApp->name();
                if( isset($app->implicitUse) && $context->print_dependencies )
                {
                    if( !isset($dependency_app[$app->name()]) )
                    {
                        if( count($app->calculateDependencies()) > 0 )
                        {
                            $dependency_app[$app->name()] = $app->name();
                            $text = str_pad($app->name(), 30);
                            $text .= "     dependencies: ";
                            $context->counter_dependencies++;
                        }

                        foreach( $app->calculateDependencies() as $dependency )
                        {
                            $text .= $dependency->name() . ",";
                            PH::$JSON_TMP['sub']['object'][$app->name()]['dependencies'][] = $dependency->name();
                        }
                        if( count($app->calculateDependencies()) > 0 )
                        {
                            PH::print_stdout( $context->padding. $text );
                        }
                    }
                }
            }
        }


        foreach( $app_explicit as $implApp )
        {
            if( !isset($app_implicit[$implApp->name()]) )
            {
                if( count($app_implicit) > 0 )
                {
                    PH::print_stdout( $context->padding . str_pad($app->name(), 30) . " has app-id: " . str_pad($implApp->name(), 20) . " as explicit but NOT implicit used" );
                    PH::$JSON_TMP['sub']['object'][$app->name()]['explicitNOTimplicit'][] = $implApp->name();
                }

            }
        }

        foreach( $app_implicit as $implApp )
        {
            if( !isset($app_explicit[$implApp->name()]) )
            {
                PH::print_stdout( $context->padding . str_pad($app->name(), 30) . " has app-id: " . str_pad($implApp->name(), 20) . " as implicit but NOT explicit used" );
                PH::$JSON_TMP['sub']['object'][$app->name()]['implicitNOTexplicit'][] = $implApp->name();
            }
        }

        #PH::print_stdout( "#############################################" );
    },
    'GlobalFinishFunction' => function (ApplicationCallContext $context) {
        PH::print_stdout( "tmp_counter: ".$context->tmpcounter."" );
        PH::print_stdout( "predefined_counter: ".$context->counter_predefined."" );
        PH::print_stdout( "dependency_app_counter: ".$context->counter_dependencies."" );

        PH::print_stdout( "container_counter: ".$context->counter_containers."" );

        PH::print_stdout( "custom_app_counter: ".$context->counter_custom_app."" );
        PH::print_stdout( "app_filter_counter: ".$context->counter_app_filter."" );
        PH::print_stdout( "app_group_counter: ".$context->counter_app_group."" );
        PH::print_stdout( "decoder_counter: ".$context->counter_decoder."" );


        PH::$JSON_TMP['tmp_counter'] = $context->tmpcounter;
        PH::$JSON_TMP['predefined_counter'] = $context->counter_predefined;
        PH::$JSON_TMP['dependency_app_counter'] = $context->counter_dependencies;

        PH::$JSON_TMP['container_counter'] = $context->counter_containers;

        PH::$JSON_TMP['custom_app_counter'] = $context->counter_custom_app;
        PH::$JSON_TMP['app_filter_counter'] = $context->counter_app_filter;
        PH::$JSON_TMP['app_group_counter'] = $context->counter_app_group;
        PH::$JSON_TMP['decoder_counter'] = $context->counter_decoder;

        PH::print_stdout( PH::$JSON_TMP, false, "appcounter" );
        PH::$JSON_TMP = array();
    }
);

ApplicationCallContext::$supportedActions[] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (ApplicationCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (ApplicationCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (ApplicationCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;

        $addWhereUsed = FALSE;
        $addUsedInLocation = FALSE;


        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = TRUE;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = TRUE;


        $headers = '<th>ID</th><th>subID</th><th>type</th><th>object-type</th><th>location</th><th>name</th>';
        $headers .= '<th>category</th><th>subCategory</th><th>risk</th><th>technology</th><th>apptag</th><th>characteristics</th><th>standardPorts</th><th>options</th><th>description</th>';

        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';


        $lines = '';

        $count = 0;
        if( isset($context->objectList) )
        {
            foreach( $context->objectList as $object )
            {
                $count++;

                /** @var App $object */
                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $context->encloseFunction( (string)$count );
                $lines .= $context->encloseFunction( "" );

                $lines .= $context->encloseFunction( $object->type() );

                $objType = "application";
                if( $object->isContainer() )
                    $objType = "container";
                elseif( $object->isApplicationCustom() )
                    $objType = "application-custom";
                elseif( $object->isApplicationGroup() )
                    $objType = "application-group";
                elseif( $object->isApplicationFilter() )
                    $objType = "application-filter";

                $lines .= $context->encloseFunction( $objType );

                if( isset($object->owner) && isset($object->owner->owner) )
                {
                    if($object->owner->owner->isPanorama() || $object->owner->owner->isFirewall() )
                        $lines .= $context->encloseFunction('shared');
                    else
                        $lines .= $context->encloseFunction($object->owner->owner->name());
                }
                else
                    $lines .= $context->encloseFunction("---");


                $lines .= $context->encloseFunction($object->name());

                //Todo: add more information about app-id

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

                if( !$object->isContainer() and !$object->isApplicationCustom() and !$object->isApplicationGroup() and !$object->isApplicationFilter() )
                    $object->spreadsheetAppDetails( $context,$lines);

                if( $object->isApplicationFilter() )
                {
                    if( isset($object->app_filter_details['category']) )
                        $lines .= $context->encloseFunction($object->app_filter_details['category']);
                    else
                        $lines .= $context->encloseFunction( "--" );
                    if( isset($object->app_filter_details['subcategory']) )
                        $lines .= $context->encloseFunction($object->app_filter_details['subcategory']);
                    else
                        $lines .= $context->encloseFunction( "--" );
                    if( isset($object->app_filter_details['risk']) )
                        $lines .= $context->encloseFunction($object->app_filter_details['risk']);
                    else
                        $lines .= $context->encloseFunction( "--" );
                    if( isset($object->app_filter_details['technology']) )
                        $lines .= $context->encloseFunction($object->app_filter_details['technology']);
                    else
                        $lines .= $context->encloseFunction( "--" );
                    if( isset($object->app_filter_details['tagging']) )
                        $lines .= $context->encloseFunction($object->app_filter_details['tagging']);
                    else
                        $lines .= $context->encloseFunction( "--" );

                    $tmp = array_keys($object->_characteristics);
                    $lines .= $context->encloseFunction($tmp);


                }


                $lines .= "</tr>\n";

                $count1 = 0;
                if( $object->isContainer() )
                {
                    foreach( $object->containerApps() as $app )
                    {
                        $count1++;
                        $app->spreadsheetContainerGroupFilter( $context, $count, $count1, $lines);
                        $app->spreadsheetAppDetails( $context,$lines);

                        $lines .= "</tr>\n";
                    }
                }
                elseif( $object->isApplicationGroup() )
                {
                    foreach( $object->groupApps() as $app )
                    {
                        $count1++;
                        $app->spreadsheetContainerGroupFilter( $context, $count, $count1, $lines);
                        $app->spreadsheetAppDetails( $context,$lines);

                        $lines .= "</tr>\n";
                    }
                }
                elseif( $object->isApplicationFilter() )
                {
                    foreach( $object->filteredApps() as $app )
                    {
                        $count1++;
                        $app->spreadsheetContainerGroupFilter( $context, $count, $count1, $lines);
                        $app->spreadsheetAppDetails( $context,$lines);

                        $lines .= "</tr>\n";
                    }
                }
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
                    "pipe(|) separated list of additional fields (ie: Arg1|Arg2|Arg3...) to include in the report. The following is available:\n" .
                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n" .
                    "  - WhereUsed : list places where object is used (rules, groups ...)\n"
            )
    )

);

ApplicationCallContext::$supportedActions['move'] = array(
    'name' => 'move',
    'MainFunction' => function (ApplicationCallContext $context) {
        $object = $context->object;

        if( !$object->isApplicationCustom() && !$object->isApplicationFilter() && !$object->isApplicationGroup() )
        {
            $string = "this is NOT a custom application object. TYPE: ".$object->type."";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $localLocation = 'shared';

        if( !$object->owner->owner->isPanorama() && !$object->owner->owner->isFirewall() )
            $localLocation = $object->owner->owner->name();

        $targetLocation = $context->arguments['location'];
        $targetStore = null;

        if( $localLocation == $targetLocation )
        {
            $string = "because original and target destinations are the same: $targetLocation";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $targetLocation == 'shared' )
        {
            $targetStore = $rootObject->appStore;
        }
        else
        {
            $findSubSystem = $rootObject->findSubSystemByName($targetLocation);
            if( $findSubSystem === null )
                derr("cannot find VSYS/DG named '$targetLocation'");

            $targetStore = $findSubSystem->appStore;
        }

        if( $localLocation == 'shared' )
        {
            $reflocations = $object->getReferencesLocation();

            foreach( $object->getReferences() as $ref )
            {
                if( PH::getLocationString($ref) != $targetLocation )
                {
                    $skipped = TRUE;
                    //check if targetLocation is parent of reflocation
                    $locations = $findSubSystem->childDeviceGroups(TRUE);
                    foreach( $locations as $childloc )
                    {
                        if( PH::getLocationString($ref) == $childloc->name() )
                            $skipped = FALSE;
                    }

                    if( $skipped )
                    {
                        $string = "moving from SHARED to sub-level is NOT possible because of references on higher DG level";
                        PH::ACTIONstatus( $context, "SKIPPED", $string );
                        return;
                    }
                }
            }
        }

        if( $localLocation != 'shared' && $targetLocation != 'shared' )
        {
            if( $context->baseObject->isFirewall() )
            {
                $string = "moving between VSYS is not supported";
                PH::ACTIONstatus( $context, "SKIPPED", $string );
                return;
            }

            foreach( $object->getReferences() as $ref )
            {
                if( PH::getLocationString($ref) != $targetLocation )
                {
                    $skipped = TRUE;
                    //check if targetLocation is parent of reflocation
                    $locations = $findSubSystem->childDeviceGroups(TRUE);
                    foreach( $locations as $childloc )
                    {
                        if( PH::getLocationString($ref) == $childloc->name() )
                            $skipped = FALSE;
                    }

                    if( $skipped )
                    {
                        $string = "moving between 2 VSYS/DG is not possible because of references on higher DG level";
                        PH::ACTIONstatus( $context, "SKIPPED", $string );
                        return;
                    }
                }
            }
        }

        $conflictObject = $targetStore->find($object->name(), null);
        if( $conflictObject === null )
        {
            $string = "moved, no conflict";
            PH::ACTIONlog( $context, $string );

            if( $context->isAPI )
            {
                $oldXpath = $object->getXPath();
                $object->owner->remove($object);
                $targetStore->addApp($object);
                $object->API_sync();
                $context->connector->sendDeleteRequest($oldXpath);
            }
            else
            {
                $object->owner->remove($object);
                $targetStore->addApp($object);
            }
            return;
        }

        if( $context->arguments['mode'] == 'skipifconflict' )
        {
            $string = "there is an object with same name. Choose another mode to resolve this conflict";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        $string = "there is a conflict with an object of same name and type. Please use address-merger.php script with argument 'allowmergingwithupperlevel'";
        PH::ACTIONlog( $context, $string );
        #if( $conflictObject->isGroup() )
        #    PH::print_stdout( " - Group" );
        #else
            $string = $conflictObject->type() . "";
            PH::ACTIONlog( $context, $string );

        /*
        if( $conflictObject->isGroup() && !$object->isGroup() || !$conflictObject->isGroup() && $object->isGroup() )
        {
            PH::print_stdout( $context->padding . "   * SKIPPED because conflict has mismatching types" );
            return;
        }*/

        /*
        if( $conflictObject->isTmpAddr() )
        {
            PH::print_stdout( $context->padding . "   * SKIPPED because the conflicting object is TMP| value: ".$conflictObject->value()."" );
            //normally the $object must be moved and the conflicting TMP object must be replaced by this $object
            return;
        }
        */

        /*
        if( $object->equals($conflictObject) )
        {
            PH::print_stdout( "    * Removed because target has same content" );
            $object->replaceMeGlobally($conflictObject);

            if( $context->isAPI )
                $object->owner->API_remove($object);
            else
                $object->owner->remove($object);
            return;
        }*/


        if( $context->arguments['mode'] == 'removeifmatch' )
            return;

        $string ="    * Removed because target has same numerical value";
        PH::ACTIONlog( $context, $string );

        $object->replaceMeGlobally($conflictObject);
        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);


    },
    'args' => array('location' => array('type' => 'string', 'default' => '*nodefault*'),
        #'mode' => array('type' => 'string', 'default' => 'skipIfConflict', 'choices' => array('skipIfConflict', 'removeIfMatch'))
        'mode' => array('type' => 'string', 'default' => 'skipIfConflict', 'choices' => array('skipIfConflict'))
    ),
);

ApplicationCallContext::$supportedActions['delete'] = array(
    'name' => 'delete',
    'MainFunction' => function (ApplicationCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            $string = "this object is used by other objects and cannot be deleted (use delete-Force to try anyway)";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);
    },
);

ApplicationCallContext::$supportedActions['delete-Force'] = array(
    'name' => 'delete-Force',
    'MainFunction' => function (ApplicationCallContext $context) {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            $string = "this object seems to be used so deletion may fail.";
            PH::ACTIONstatus( $context, "WARNING", $string );
        }

        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);
    },
);