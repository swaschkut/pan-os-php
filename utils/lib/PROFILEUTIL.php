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

class PROFILEUTIL extends UTIL
{
    public $ProfileTypes = null;

    public function utilStart()
    {
        $this->utilInit();
        //unique for SECURITYPROFILEUTIL
        $this->ProfileTypes();


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


        if( PH::$shadow_json )
        {
            PH::$JSON_OUT['log'] = PH::$JSON_OUTlog;
            //print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
        }
    }

    /**
     * profiletype => store property on PANConf / PanoramaConf / VirtualSystem / DeviceGroup / Container ...
     */
    static public $profileTypeStores = array(
        'decryption' => 'DecryptionProfileStore',
        'hip-objects' => 'HipObjectsProfileStore',
        'hip-profiles' => 'HipProfilesProfileStore',
    );

    public function supportedArguments()
    {
        parent::supportedArguments();
        $this->supportedArguments['profiletype'] = array('niceName' => 'ProfileType', 'shortHelp' => 'specify which type(s) of profile to process (default is "any"). ie: profiletype=any  profiletype=decryption,hip-profiles', 'argDesc' => 'any|' . implode('|', array_keys(self::$profileTypeStores)));
    }

    /**
     * add all stores of $sub matching the requested profiletype(s) to objectsToProcess
     */
    private function addProfileStores( $sub )
    {
        $any = array_search('any', $this->ProfileTypes) !== FALSE;
        foreach( self::$profileTypeStores as $type => $storeProp )
        {
            if( !$any && array_search($type, $this->ProfileTypes) === FALSE )
                continue;
            if( !property_exists($sub, $storeProp) || $sub->$storeProp === null )
                continue;
            $this->objectsToProcess[] = array('store' => $sub->$storeProp, 'rules' => $sub->$storeProp->securityProfiles());
        }
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

                    $this->addProfileStores( $this->pan );

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

                            $this->addProfileStores( $sub );

                            $locationFound = TRUE;
                        }
                    }
                    else
                    {
                        #if( ($location == 'any' || $location == 'all' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                        if( ($location == 'any' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                        {

                            $this->addProfileStores( $sub );

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
                    $this->addProfileStores( $this->pan );

                    $locationFound = TRUE;
                }

                if( $this->configType == 'panorama' )
                    $subGroups = $this->pan->getDeviceGroups();
                elseif( $this->configType == 'fawkes' || $this->configType == 'buckbeak' )
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
                    if( $location == 'any' || $location == $sub->name() )
                    {
                        $this->addProfileStores( $sub );

                        $locationFound = TRUE;
                    }

                    self::GlobalInitAction($sub);
                }
            }

            if( !$locationFound )
                self::locationNotFound($location, $this->configType, $this->pan);
        }
    }

    public function ProfileTypes()
    {
        //
        // Determine rule types
        //
        $supportedProfileTypes = array_merge( array('any', 'all'), array_keys(self::$profileTypeStores) );
        
        if( !isset(PH::$args['profiletype']) )
        {
            PH::print_stdout( " - No 'ProfileType' specified, using 'any' by default" );
            $this->ProfileTypes = array('any');
        }
        else
        {
            $this->ProfileTypes = explode(',', PH::$args['profiletype']);
            foreach($this->ProfileTypes as &$rType )
            {
                $rType = strtolower($rType);
                if( array_search($rType, $supportedProfileTypes) === FALSE )
                {
                    $this->display_error_usage_exit("'ProfileType' has unsupported value: '" . $rType . "'. Supported values are: " . PH::list_to_string($supportedProfileTypes));
                }
                if( $rType == 'all' )
                    $rType = 'any';
            }

            $this->ProfileTypes = array_unique($this->ProfileTypes);
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
            $string = "* processing Profileset '" . $store->toString() . " that holds " . count($rules) . "' Profiles";
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