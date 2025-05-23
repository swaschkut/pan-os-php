<?php
/**
 * ISC License
 *
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

class SECURITYPROFILEUTIL extends UTIL
{
    public $securityProfileTypes = null;

    public function utilStart()
    {
        $this->utilInit();
        //unique for SECURITYPROFILEUTIL
        $this->securityProfileTypes();


        $this->utilActionFilter();


        $this->location_filter_object();


        $this->time_to_process_objects();


        $this->GlobalFinishAction();

        PH::print_stdout();
        PH::print_stdout( " **** PROCESSED $this->totalObjectsProcessed objects over {$this->totalObjectsOfSelectedStores} available ****" );
        PH::print_stdout();
        PH::print_stdout();

        $this->stats();

        $this->save_our_work(TRUE);

        $runtime = number_format((microtime(TRUE) - $this->runStartTime), 2, '.', '');
        PH::print_stdout( array( 'value' => $runtime, 'type' => "seconds" ), false,'runtime' );

        if( PH::$shadow_json )
        {
            PH::$JSON_OUT['log'] = PH::$JSON_OUTlog;
            //print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
        }
    }

    public function supportedArguments()
    {
        parent::supportedArguments();
        $supportedSP = array('any','url-filtering','virus','vulnerability','spyware','file-blocking','data-filtering','wildfire-analysis','custom-url-category',
            'dns-security','saas-security',
            'predefined-url','predefined-url-filtering',
            'predefined-virus','predefined-spyware',
            'predefined-file-blocking',
            'predefined-vulnerability',
            'predefined-wildfire-analysis'
        );
        $this->supportedArguments['securityprofiletype'] = array('niceName' => 'securityProfileType', 'shortHelp' => 'specify which type(s) of you rule want to edit, (default is "security". ie: securityprofiletype=any  securityprofiletype=url-filtering, custom-url-category', 'argDesc' => 'any|url-filtering|virus|vulnerability|spyware|file-blocking|data-filtering|wildfire-analysis|custom-url-category|dns-security|saas-security|predefined-url|predefined-url-filtering|');
    }

    public function location_filter_object()
    {
        $sub = null;

        foreach( $this->objectsLocation as $location )
        {
            $locationFound = FALSE;

            if( $this->configType == 'panos' )
            {
                #if( $location == 'shared' || $location == 'any' || $location == 'all' )
                if( $location == 'shared' || $location == 'any' )
                {
                    /*
                    //Todo: is there a need to display all predefined Profiles???
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('predefined-url', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->urlStore, 'rules' => $this->pan->urlStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('predefined-url-filtering', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->UrlFilteringPredefinedStore, 'rules' => $this->pan->UrlFilteringPredefinedStore->securityProfiles())
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('predefined-virus', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->AntiVirusPredefinedStore, 'rules' => $this->pan->AntiVirusPredefinedStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('predefined-vulnerability', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->VulnerabilityPredefinedStore, 'rules' => $this->pan->VulnerabilityPredefinedStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('predefined-file-blocking', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->FileBlockingPredefinedStore, 'rules' => $this->pan->FileBlockingPredefinedStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('predefined-spyware', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->AntiSpywarePredefinedStore, 'rules' => $this->pan->AntiSpywarePredefinedStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('predefined-wildfire-analysis', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->WildfirePredefinedStore, 'rules' => $this->pan->WildfirePredefinedStore->securityProfiles());
                    */

                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('url-filtering', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->URLProfileStore, 'rules' => $this->pan->URLProfileStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('virus', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->AntiVirusProfileStore, 'rules' => $this->pan->AntiVirusProfileStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('vulnerability', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->VulnerabilityProfileStore, 'rules' => $this->pan->VulnerabilityProfileStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('file-blocking', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->FileBlockingProfileStore, 'rules' => $this->pan->FileBlockingProfileStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('spyware', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->AntiSpywareProfileStore, 'rules' => $this->pan->AntiSpywareProfileStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('wildfire-analysis', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->WildfireProfileStore, 'rules' => $this->pan->WildfireProfileStore->securityProfiles());


                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('data-filtering', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->DataFilteringProfileStore, 'rules' => $this->pan->DataFilteringProfileStore->securityProfiles());

                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('custom-url-category', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->customURLProfileStore, 'rules' => $this->pan->customURLProfileStore->securityProfiles());

                    $locationFound = TRUE;
                }

                foreach( $this->pan->getVirtualSystems() as $sub )
                {
                    if( isset(PH::$args['loadpanoramapushedconfig']) )
                    {
                        #if( ($location == 'any' || $location == 'all' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                        if( ($location == 'any' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                        {
                            //Todo: Validation needed,cmpare to rule no pre/post rule but check if something else needed
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('url-filtering', $this->securityProfileTypes) !== FALSE )
                                $this->objectsToProcess[] = array('store' => $sub->URLProfileStore, 'rules' => $sub->URLProfileStore->securityProfiles());
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('virus', $this->securityProfileTypes) !== FALSE )
                                $this->objectsToProcess[] = array('store' => $sub->AntiVirusProfileStore, 'rules' => $sub->AntiVirusProfileStore->securityProfiles());
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('vulnerability', $this->securityProfileTypes) !== FALSE )
                                $this->objectsToProcess[] = array('store' => $sub->VulnerabilityProfileStore, 'rules' => $sub->VulnerabilityProfileStore->securityProfiles());
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('file-blocking', $this->securityProfileTypes) !== FALSE )
                                $this->objectsToProcess[] = array('store' => $sub->FileBlockingProfileStore, 'rules' => $sub->FileBlockingProfileStore->securityProfiles());
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('spyware', $this->securityProfileTypes) !== FALSE )
                                $this->objectsToProcess[] = array('store' => $sub->AntiSpywareProfileStore, 'rules' => $sub->AntiSpywareProfileStore->securityProfiles());
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('wildfire-analysis', $this->securityProfileTypes) !== FALSE )
                                $this->objectsToProcess[] = array('store' => $sub->WildfireProfileStore, 'rules' => $sub->WildfireProfileStore->securityProfiles());


                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('data-filtering', $this->securityProfileTypes) !== FALSE )
                                $this->objectsToProcess[] = array('store' => $sub->DataFilteringProfileStore, 'rules' => $sub->DataFilteringProfileStore->securityProfiles());


                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('custom-url-category', $this->securityProfileTypes) !== FALSE )
                                $this->objectsToProcess[] = array('store' => $sub->customURLProfileStore, 'rules' => $sub->customURLProfileStore->securityProfiles());

                            $locationFound = TRUE;
                        }
                    }
                    else
                    {
                        #if( ($location == 'any' || $location == 'all' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                        if( ($location == 'any' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                        {
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('url-filtering', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->URLProfileStore, 'rules' => $sub->URLProfileStore->securityProfiles());
                            }
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('virus', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->AntiVirusProfileStore, 'rules' => $sub->AntiVirusProfileStore->securityProfiles());
                            }


                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('vulnerability', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->VulnerabilityProfileStore, 'rules' => $sub->VulnerabilityProfileStore->securityProfiles());
                            }
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('file-blocking', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->FileBlockingProfileStore, 'rules' => $sub->FileBlockingProfileStore->securityProfiles());
                            }
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('spyware', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->AntiSpywareProfileStore, 'rules' => $sub->AntiSpywareProfileStore->securityProfiles());
                            }
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('wildfire-analysis', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->WildfireProfileStore, 'rules' => $sub->WildfireProfileStore->securityProfiles());
                            }
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('data-filtering', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->DataFilteringProfileStore, 'rules' => $sub->DataFilteringProfileStore->securityProfiles());
                            }


                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('custom-url-category', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->customURLProfileStore, 'rules' => $sub->customURLProfileStore->securityProfiles());
                            }
                            $locationFound = TRUE;
                        }
                    }

                    self::GlobalInitAction($sub);
                }
            }
            else
            {
                #if( $this->configType == 'panorama' && ($location == 'shared' || $location == 'any' || $location == 'all') )
                if( $this->configType == 'panorama' && ($location == 'shared' || $location == 'any' ) )
                {
                    /*
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('predefined-url', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->urlStore, 'rules' => $this->pan->urlStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('predefined-url-filtering', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->VulnerabilityPredefinedStore, 'rules' => $this->pan->VulnerabilityPredefinedStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('predefined-virus', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->AntiVirusPredefinedStore, 'rules' => $this->pan->AntiVirusPredefinedStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('predefined-vulnerability', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->VulnerabilityPredefinedStore, 'rules' => $this->pan->VulnerabilityPredefinedStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('predefined-spyware', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->AntiSpywarePredefinedStore, 'rules' => $this->pan->AntiSpywarePredefinedStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('predefined-file-blocking', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->FileBlockingPredefinedStore, 'rules' => $this->pan->FileBlockingPredefinedStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('predefined-wildfire-analysis', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->WildfirePredefinedStore, 'rules' => $this->pan->WildfirePredefinedStore->securityProfiles());
                    */

                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('url-filtering', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->URLProfileStore, 'rules' => $this->pan->URLProfileStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('virus', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->AntiVirusProfileStore, 'rules' => $this->pan->AntiVirusProfileStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('vulnerability', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->VulnerabilityProfileStore, 'rules' => $this->pan->VulnerabilityProfileStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('file-blocking', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->FileBlockingProfileStore, 'rules' => $this->pan->FileBlockingProfileStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('spyware', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->AntiSpywareProfileStore, 'rules' => $this->pan->AntiSpywareProfileStore->securityProfiles());
                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('wildfire-analysis', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->WildfireProfileStore, 'rules' => $this->pan->WildfireProfileStore->securityProfiles());


                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('data-filtering', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->DataFilteringProfileStore, 'rules' => $this->pan->DataFilteringProfileStore->securityProfiles());


                    if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('custom-url-category', $this->securityProfileTypes) !== FALSE )
                        $this->objectsToProcess[] = array('store' => $this->pan->customURLProfileStore, 'rules' => $this->pan->customURLProfileStore->securityProfiles());

                    $locationFound = TRUE;
                }

                if( $this->configType == 'panorama' )
                    $subGroups = $this->pan->getDeviceGroups();
                elseif( $this->configType == 'fawkes' )
                {
                    $subGroups = $this->pan->getContainers();
                    $subGroups2 = $this->pan->getDeviceClouds();

                    $subGroups = array_merge( $subGroups, $subGroups2 );

                    $subGroups2 = $this->pan->getDeviceOnPrems();
                    $subGroups = array_merge( $subGroups, $subGroups2 );

                    $subGroups2 = $this->pan->getSnippets();
                    $subGroups = array_merge( $subGroups, $subGroups2 );
                }


                foreach( $subGroups as $sub )
                {
                    #if( $location == 'any' || $location == 'all' || $location == $sub->name() )
                    if( $location == 'any' || $location == $sub->name() )
                    {
                        if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('url-filtering', $this->securityProfileTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->URLProfileStore, 'rules' => $sub->URLProfileStore->securityProfiles());
                        }
                        if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('data-filtering', $this->securityProfileTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->DataFilteringProfileStore, 'rules' => $sub->DataFilteringProfileStore->securityProfiles());
                        }

                        //Panorama
                        if( $this->configType == 'fawkes' )
                        {
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('virusandwildfire', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->VirusAndWildfireProfileStore, 'rules' => $sub->VirusAndWildfireProfileStore->securityProfiles());
                            }
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('dns-security', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->DNSSecurityProfileStore, 'rules' => $sub->DNSSecurityProfileStore->securityProfiles());
                            }
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('saas-security', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->SaasSecurityProfileStore, 'rules' => $sub->SaasSecurityProfileStore->securityProfiles());
                            }
                        }
                        else
                        {
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('virus', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->AntiVirusProfileStore, 'rules' => $sub->AntiVirusProfileStore->securityProfiles());
                            }
                            if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('wildfire-analysis', $this->securityProfileTypes) !== FALSE )
                            {
                                $this->objectsToProcess[] = array('store' => $sub->WildfireProfileStore, 'rules' => $sub->WildfireProfileStore->securityProfiles());
                            }
                        }






                        if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('vulnerability', $this->securityProfileTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->VulnerabilityProfileStore, 'rules' => $sub->VulnerabilityProfileStore->securityProfiles());
                        }
                        if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('file-blocking', $this->securityProfileTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->FileBlockingProfileStore, 'rules' => $sub->FileBlockingProfileStore->securityProfiles());
                        }
                        if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('spyware', $this->securityProfileTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->AntiSpywareProfileStore, 'rules' => $sub->AntiSpywareProfileStore->securityProfiles());
                        }



                        if( array_search('any', $this->securityProfileTypes) !== FALSE || array_search('custom-url-category', $this->securityProfileTypes) !== FALSE )
                        {
                            $this->objectsToProcess[] = array('store' => $sub->customURLProfileStore, 'rules' => $sub->customURLProfileStore->securityProfiles());
                        }
                        $locationFound = TRUE;
                    }

                    self::GlobalInitAction($sub);
                }
            }

            if( !$locationFound )
                self::locationNotFound($location, $this->configType, $this->pan);
        }
    }

    public function securityProfileTypes()
    {
        //
        // Determine rule types
        //
        #$supportedSecurityProfileTypes = array('all', 'any', 'url-filtering', 'virus', 'vulnerability', 'spyware', 'file-blocking', 'wildfire-analysis', 'custom-url-category', 'predefined-url');
        $supportedSecurityProfileTypes = array('any', 'url-filtering', 'virus', 'vulnerability', 'spyware', 'file-blocking', 'wildfire-analysis', 'custom-url-category', 'data-filtering',
            'predefined-url',
            'predefined-virus',
            'predefined-spyware',
            'predefined-vulnerability',
            'predefined-file-blocking',
            'predefined-url-filtering',
            'predefined-wildfire-analysis'
            );
        if( !isset(PH::$args['securityprofiletype']) )
        {
            PH::print_stdout( " - No 'securityProfileType' specified, using 'any' by default" );
            $this->securityProfileTypes = array('any');
        }
        else
        {
            $this->securityProfileTypes = explode(',', PH::$args['securityprofiletype']);
            foreach( $this->securityProfileTypes as &$rType )
            {
                $rType = strtolower($rType);
                if( array_search($rType, $supportedSecurityProfileTypes) === FALSE )
                {
                    $this->display_error_usage_exit("'securityProfileType' has unsupported value: '" . $rType . "'. Supported values are: " . PH::list_to_string($supportedSecurityProfileTypes));
                }
                if( $rType == 'all' )
                    $rType = 'any';
            }

            $this->securityProfileTypes = array_unique($this->securityProfileTypes);
        }
    }

    public function time_to_process_objects()
    {
        //
        // It's time to process Rules !!!!
        //

        // <editor-fold desc="Rule Processing" defaultstate="collapsed" >

        foreach( $this->objectsToProcess as &$rulesRecord )
        {
            $subObjectsProcessed = 0;

            $store = $rulesRecord['store'];
            $rules = &$rulesRecord['rules'];

            $this->totalObjectsOfSelectedStores += $store->count();

            PH::print_stdout();
            $string = "* processing SecurityProfileset '" . $store->toString() . " that holds " . count($rules) . "' SecurityProfiles";
            PH::print_stdout( $string );

            PH::$JSON_TMP = array();
            PH::$JSON_TMP['header'] = $string;

            foreach( $this->doActions as $doAction )
            {
                if( is_object($store->owner) )
                {
                    $doAction->subSystem = $store->owner;
                    PH::$JSON_TMP['sub']['name'] = $store->owner->name();
                    PH::$JSON_TMP['sub']['type'] = get_class( $store->owner );
                }

                else
                {
                    $doAction->subSystem = $store;
                    PH::$JSON_TMP['sub']['name'] = $store->name();
                    PH::$JSON_TMP['sub']['type'] = "shared";
                }

            }

            PH::$JSON_TMP['sub']['store'] = get_class( $store );




            foreach( $rules as $rule )
            {
                // If a filter query was input and it doesn't match this object then we simply skip it
                if( $this->objectFilterRQuery !== null )
                {
                    $queryResult = $this->objectFilterRQuery->matchSingleObject(array('object' => $rule, 'nestedQueries' => &$this->nestedQueries));
                    if( !$queryResult )
                        continue;
                }

                $this->totalObjectsProcessed++;
                $subObjectsProcessed++;

                // object will pass through every action now
                foreach( $this->doActions as $doAction )
                {
                    $doAction->padding = '      ';
                    $doAction->executeAction($rule);

                    PH::print_stdout();
                }
            }

            if( is_object($store->owner) )
            {
                $tmp_name = $store->owner->name();
            }
            elseif( is_object($store) )
            {
                $tmp_name = $store->name();

            }

            if( isset($store->owner->owner) && is_object($store->owner->owner) )
                $tmp_platform = get_class( $store->owner->owner );
            elseif( isset($store->owner) && is_object($store->owner) )
                $tmp_platform = get_class( $store->owner );
            else
                $tmp_platform = get_class( $store );

            PH::print_stdout();
            PH::print_stdout( "* objects processed in DG/Vsys '{$tmp_name}' : $subObjectsProcessed" );
            PH::print_stdout();

            PH::$JSON_TMP['sub']['summary']['processed'] = $subObjectsProcessed;
            PH::$JSON_TMP['sub']['summary']['available'] = $store->count();
            PH::print_stdout( PH::$JSON_TMP, false, $tmp_platform );
            PH::$JSON_TMP = array();
            #PH::print_stdout( "* objects processed in DG/Vsys '{$store->owner->name()}' : $subObjectsProcessed filtered over {$store->count()} available\n\n" );
        }
        PH::print_stdout();
        // </editor-fold>
    }
}