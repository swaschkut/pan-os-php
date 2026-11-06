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

require_once(dirname(__FILE__)."/MERGESAFETY.php");
require_once(dirname(__FILE__)."/MERGERENGINE.php");

class MERGER extends UTIL
{
    /** type=securityprofile-merger: profiletype argument => store property of a device group / vsys / shared */
    public static $securityProfileMergerStores = array(
        'virus' => 'AntiVirusProfileStore',
        'spyware' => 'AntiSpywareProfileStore',
        'vulnerability' => 'VulnerabilityProfileStore',
        'url-filtering' => 'URLProfileStore',
        'file-blocking' => 'FileBlockingProfileStore',
        'wildfire-analysis' => 'WildfireProfileStore',
        'data-filtering' => 'DataFilteringProfileStore',
    );
    /**
     * type=object-merger: objecttype argument => merger run for it (in this order for objecttype=any:
     * objects before groups, profiles before security profile groups)
     */
    public static $objectMergerTypes = array(
        'tag' => 'tag-merger',
        'address' => 'address-merger',
        'service' => 'service-merger',
        'edl' => 'edl-merger',
        'region' => 'region-merger',
        'application-custom' => 'appcustom-merger',
        'application-filter' => 'appfilter-merger',
        'addressgroup' => 'addressgroup-merger',
        'servicegroup' => 'servicegroup-merger',
        'application-group' => 'appgroup-merger',
        'custom-url-category' => 'custom-url-category-merger',
        'schedule' => 'schedule-merger',
        'log-profile' => 'logprofile-merger',
        'decryption-profile' => 'decryptionprofile-merger',
        'securityprofile' => 'securityprofile-merger',
        'securityprofilegroup' => 'securityprofilegroup-merger',
    );
    /** type=object-merger: merger runs that only exist inside the object merger => store property */
    public static $xmlObjectMergerStores = array(
        'schedule-merger' => 'scheduleStore',
        'logprofile-merger' => 'LogProfileStore',
        'decryptionprofile-merger' => 'DecryptionProfileStore',
        'edl-merger' => 'EDLStore',
        'appcustom-merger' => 'appStore',
        'appfilter-merger' => 'appStore',
        'appgroup-merger' => 'appStore',
        'region-merger' => 'addressStore',
    );
    /** type=object-merger: selected objecttype values */
    public $objectMergerSelected = array();

    /** type=securityprofile-merger: selected profile type and its store property */
    public $spProfileType = null;
    public $spStoreProp = null;
    /** type=securityprofile-merger: all profile types to process (profiletype=any or a list) */
    public $spProfileTypes = array();
    /** prefix of the exportCSV keys while several profile types are processed in one run */
    public $mergeIndexPrefix = '';

    use MergerEngine;

    public $utilType = null;
    public $location_array = array();
    public $pickFilter = null;
    public $excludeFilter = null;
    public $upperLevelSearch = FALSE;
    public $mergeCountLimit = FALSE;
    public $dupAlg = null;

    public $deletedObjects = array();
    public $skippedObjects = array();

    public $addMissingObjects = FALSE;
    public $action = "merge";
    public $mergermodeghost = TRUE;

    public $exportcsv = FALSE;
    public $exportcsvFile = null;
    public $exportcsvSkippedFile = null;

    public bool $allowMergingObjectWith_m32 = true;

    public function utilStart()
    {
        $this->usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " in=inputfile.xml [out=outputfile.xml] location=shared [DupAlgorithm=XYZ] [MergeCountLimit=100] ['pickFilter=(name regex /^H-/)'] ...";


        $this->add_supported_arguments();


        $this->prepareSupportedArgumentsArray();

        PH::processCliArgs();

        $this->arg_validation();

        $this->listfilters();

        if( isset(PH::$args['actions']) )
        {
            $this->action = PH::$args['actions'];

            if( $this->action !== 'merge' && $this->action !== 'display' && $this->action !== 'mergenoghost' )
                derr( 'argument actions only support value: merge / display / mergenoghost | actions=merge' );

            if( $this->action === 'mergenoghost' )
            {
                $this->action = "merge";
                $this->mergermodeghost = FALSE;
            }
        }
        else
            $this->action = "merge";

        if( isset(PH::$args['projectfolder']) )
        {
            $this->projectFolder = PH::$args['projectfolder'];
            if (!file_exists($this->projectFolder)) {
                mkdir($this->projectFolder, 0777, true);
            }
        }

        if( isset(PH::$args['outputformatset']) )
        {
            $this->outputformatset = TRUE;

            if( !is_bool(PH::$args['outputformatset']) )
            {
                $this->outputformatsetFile = PH::$args['outputformatset'];

                if( $this->projectFolder !== null )
                    $this->outputformatsetFile = $this->projectFolder."/".$this->outputformatsetFile;
            }
            else
                $this->outputformatsetFile = null;
        }

        if( isset(PH::$args['exportcsv']) )
        {
            $this->exportcsv = TRUE;
            $this->exportcsvFile = PH::$args['exportcsv'];
            $this->exportcsvSkippedFile = "skipped-".$this->exportcsvFile;

            if( $this->projectFolder !== null )
            {
                $this->exportcsvSkippedFile = $this->projectFolder."/skipped-".$this->exportcsvFile;
                $this->exportcsvFile = $this->projectFolder."/".$this->exportcsvFile;
            }

        }

        if( isset(PH::$args['outputformatset']) )
        {
            PH::print_stdout(" set 'origXmlDoc' variable");
            $this->outputformatset = TRUE;
            $this->origXmlDoc = new DOMDocument();

            if( !is_bool(PH::$args['outputformatset']) )
            {
                $this->outputformatsetFile = PH::$args['outputformatset'];

                if( $this->projectFolder !== null )
                {
                    if( strpos($this->outputformatsetFile, $this->projectFolder) === FALSE )
                        $this->outputformatsetFile = $this->projectFolder."/".$this->outputformatsetFile;
                }

            }
        }

        $this->help(PH::$args);
        $this->inDebugapiArgument();
        $this->inputValidation();
        $this->location_provided();

        $this->load_config();

        $this->location_filter();

        if( $this->action === "display" )
        {
            $this->apiMode = FALSE;
            $this->action = "merge";
        }

        if( $this->utilType == "object-merger" )
            $this->object_merging();
        else
            $this->runMerger();

        $this->merger_final_step();

    }

    /** location / filter / argument handling and the merge run for $this->utilType */
    function runMerger()
    {
        $this->location_array = $this->merger_location_array($this->utilType, $this->objectsLocation, $this->pan);


        $this->filterArgument( );


        $this->merger_arguments( );

        if( $this->utilType == "address-merger" )
            $this->address_merging();
        elseif( $this->utilType == "addressgroup-merger" )
            $this->addressgroup_merging();
        elseif( $this->utilType == "service-merger" )
            $this->service_merging();
        elseif( $this->utilType == "servicegroup-merger" )
            $this->servicegroup_merging();
        elseif( $this->utilType == "tag-merger" )
            $this->tag_merging();
        elseif( $this->utilType == "custom-url-category-merger" )
        {
            $this->custom_url_category_merging();
        }
        elseif( $this->utilType == "securityprofile-merger" )
        {
            if( count($this->spProfileTypes) > 1 )
            {
                foreach( $this->spProfileTypes as $type )
                {
                    PH::print_stdout( "\n\n######################## profiletype: {$type} ########################" );
                    $this->selectSecurityProfileMergerType( $type );
                    $this->mergeIndexPrefix = $type . ": ";
                    $this->location_array = $this->merger_location_array($this->utilType, $this->objectsLocation, $this->pan);
                    $this->securityprofile_merging();
                }
                $this->mergeIndexPrefix = '';
            }
            else
                $this->securityprofile_merging();
        }
        elseif( $this->utilType == "securityprofilegroup-merger" )
            $this->securityprofilegroup_merging();
        elseif( isset(self::$xmlObjectMergerStores[$this->utilType]) )
            $this->genericObjectMerging( $this->objectXmlMergeSpec( $this->utilType, self::$xmlObjectMergerStores[$this->utilType] ) );
    }

    /** type=object-merger: reads objecttype= (any or a comma separated list) */
    function objectMergerTypes()
    {
        if( !isset(PH::$args['objecttype']) )
            $this->display_error_usage_exit('argument objecttype= is required: any|' . implode('|', array_keys(self::$objectMergerTypes)));

        $selected = array();
        foreach( explode(',', strtolower(PH::$args['objecttype'])) as $type )
        {
            $type = trim($type);
            if( $type === 'any' )
                $selected = array_merge( $selected, array_keys(self::$objectMergerTypes) );
            elseif( isset(self::$objectMergerTypes[$type]) )
                $selected[] = $type;
            else
                $this->display_error_usage_exit('unsupported value for objecttype: ' . PH::$args['objecttype'] . ' - supported: any|' . implode('|', array_keys(self::$objectMergerTypes)));
        }

        // always in the order of $objectMergerTypes
        $ordered = array();
        foreach( array_keys(self::$objectMergerTypes) as $type )
            if( in_array($type, $selected, TRUE) )
                $ordered[] = $type;

        return $ordered;
    }

    /** puts the merger back into its start state before the next objecttype is processed */
    private function resetMergerRun( $utilType )
    {
        $this->utilType = $utilType;
        $this->spStoreProp = null;
        $this->spProfileType = null;
        $this->spProfileTypes = array();
        $this->pickFilter = null;
        $this->excludeFilter = null;
        $this->dupAlg = null;
        $this->mergeSafety = null;
        $this->addMissingObjects = FALSE;
    }

    /**
     * type=object-merger objecttype=...: runs the merger of every selected object type, one after the other,
     * on the same configuration; the result is saved once at the end
     */
    function object_merging()
    {
        $this->objectMergerSelected = $this->objectMergerTypes();

        // security profiles inside the object merger: all profile types unless profiletype= is given
        if( in_array('securityprofile', $this->objectMergerSelected, TRUE) && !isset(PH::$args['profiletype']) )
            PH::$args['profiletype'] = 'any';

        // check DupAlgorithm (and the other arguments) for every object type before anything is changed
        foreach( $this->objectMergerSelected as $type )
        {
            $this->resetMergerRun( self::$objectMergerTypes[$type] );
            $this->merger_arguments();
        }

        foreach( $this->objectMergerSelected as $type )
        {
            PH::print_stdout( "\n\n######################## objecttype: {$type} ########################" );
            $this->resetMergerRun( self::$objectMergerTypes[$type] );
            $this->mergeIndexPrefix = $type . ": ";

            if( $this->utilType == "securityprofile-merger" )
            {
                $this->securityProfileMergerType();
                foreach( $this->spProfileTypes as $profileType )
                {
                    PH::print_stdout( "\n\n######################## profiletype: {$profileType} ########################" );
                    $this->selectSecurityProfileMergerType( $profileType );
                    $this->mergeIndexPrefix = $type . "-" . $profileType . ": ";
                    $this->location_array = $this->merger_location_array($this->utilType, $this->objectsLocation, $this->pan);
                    $this->filterArgument( );
                    $this->merger_arguments( );
                    $this->securityprofile_merging();
                }
            }
            else
                $this->runMerger();
        }

        $this->mergeIndexPrefix = '';
        $this->utilType = "object-merger";
    }

    function merger_location_array($utilType, $objectsLocation, $pan)
    {
        $this->utilType = $utilType;

        if( $objectsLocation[0] == 'any' )
        {
            if( $pan->isPanorama() )
            {
                $alldevicegroup = $pan->deviceGroups;
            }
            elseif( $pan->isFawkes() || $pan->isBuckbeak() )
            {
                $subGroups = $pan->getContainers();
                $subGroups2 = $pan->getDeviceClouds();

                $alldevicegroup = array_merge( $subGroups, $subGroups2 );

                $subGroups2 = $this->pan->getDeviceOnPrems();
                $alldevicegroup = array_merge( $alldevicegroup, $subGroups2 );
            }
            elseif( $pan->isFirewall() )
                $alldevicegroup = $pan->virtualSystems;
            else
                $alldevicegroup = $pan->virtualSystems;

            $location_array = array();
            foreach( $alldevicegroup as $key => $tmp_location )
            {
                $objectsLocation = $tmp_location->name();
                $findLocation = $pan->findSubSystemByName($objectsLocation);
                if( $findLocation === null )
                    $this->locationNotFound( $objectsLocation );
                    #derr("cannot find DeviceGroup/VSYS named '{$objectsLocation}', check case or syntax");

                if( $this->utilType == "address-merger" || $this->utilType == "addressgroup-merger" )
                {
                    $store = $findLocation->addressStore;

                    if( $pan->isPanorama() && isset($findLocation->parentDeviceGroup) && $findLocation->parentDeviceGroup !== null )
                        $parentStore = $findLocation->parentDeviceGroup->addressStore;
                    elseif( ($pan->isFawkes() || $pan->isBuckbeak()) && isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                        $parentStore = $findLocation->parentContainer->addressStore;
                    elseif( (!$pan->isFawkes() && !$pan->isBuckbeak()) )
                        $parentStore = $findLocation->owner->addressStore;
                }
                elseif( $this->utilType == "service-merger" || $this->utilType == "servicegroup-merger" )
                {
                    $store = $findLocation->serviceStore;

                    if( $pan->isPanorama() && isset($findLocation->parentDeviceGroup) && $findLocation->parentDeviceGroup !== null )
                        $parentStore = $findLocation->parentDeviceGroup->serviceStore;
                    elseif( ($pan->isFawkes() || $pan->isBuckbeak()) && isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                        $parentStore = $findLocation->parentContainer->serviceStore;
                    elseif( (!$pan->isFawkes() && !$pan->isBuckbeak()) )
                        $parentStore = $findLocation->owner->serviceStore;
                }
                elseif( $this->utilType == "tag-merger" )
                {
                    $store = $findLocation->tagStore;

                    if( $pan->isPanorama() && isset($findLocation->parentDeviceGroup) && $findLocation->parentDeviceGroup !== null )
                        $parentStore = $findLocation->parentDeviceGroup->tagStore;
                    elseif( ($pan->isFawkes() || $pan->isBuckbeak()) && isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                        $parentStore = $findLocation->parentContainer->tagStore;
                    elseif( (!$pan->isFawkes() && !$pan->isBuckbeak()) )
                        $parentStore = $findLocation->owner->tagStore;
                }
                elseif( $this->utilType == "custom-url-category-merger" )
                {
                    $store = $findLocation->customURLProfileStore;

                    if( $pan->isPanorama() && isset($findLocation->parentDeviceGroup) && $findLocation->parentDeviceGroup !== null )
                        $parentStore = $findLocation->parentDeviceGroup->customURLProfileStore;
                    elseif( ($pan->isFawkes() || $pan->isBuckbeak()) && isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                        $parentStore = $findLocation->parentContainer->customURLProfileStore;
                    else
                        $parentStore = $findLocation->owner->customURLProfileStore;
                }
                elseif( $this->genericStoreProp() !== null )
                {
                    $storeProp = $this->genericStoreProp();
                    $store = $findLocation->$storeProp;

                    if( $pan->isPanorama() && isset($findLocation->parentDeviceGroup) && $findLocation->parentDeviceGroup !== null )
                        $parentStore = $findLocation->parentDeviceGroup->$storeProp;
                    elseif( ($pan->isFawkes() || $pan->isBuckbeak()) && isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                        $parentStore = $findLocation->parentContainer->$storeProp;
                    else
                        $parentStore = $findLocation->owner->$storeProp;
                }

                if( get_class( $findLocation->owner ) == "FawkesConf" || get_class( $findLocation->owner ) == "BuckbeakConf" )
                    $parentStore = null;
                

                $location_array[$key]['findLocation'] = $findLocation;
                $location_array[$key]['store'] = $store;
                $location_array[$key]['parentStore'] = $parentStore;
                if( $pan->isPanorama() )
                {
                    $childDeviceGroups = $findLocation->childDeviceGroups(TRUE);
                    $location_array[$key]['childDeviceGroups'] = $childDeviceGroups;
                }
                elseif( ($pan->isFawkes() || $pan->isBuckbeak()) )
                {
                    //child Container/CloudDevices
                    //Todo: swaschkut 20210414
                    $location_array[$key]['childDeviceGroups'] = array();
                }
                else
                    $location_array[$key]['childDeviceGroups'] = array();

            }

            $location_array = array_reverse($location_array);

            if( !$pan->isFawkes() && !$pan->isBuckbeak() )
            {
                $location_array[$key + 1]['findLocation'] = 'shared';
                if( $this->utilType == "address-merger" || $this->utilType == "addressgroup-merger" )
                    $location_array[$key + 1]['store'] = $pan->addressStore;
                elseif( $this->utilType == "service-merger" || $this->utilType == "servicegroup-merger" )
                    $location_array[$key + 1]['store'] = $pan->serviceStore;
                elseif( $this->utilType == "tag-merger" )
                    $location_array[$key + 1]['store'] = $pan->tagStore;
                elseif( $this->utilType == "custom-url-category-merger" )
                    $location_array[$key + 1]['store'] = $pan->customURLProfileStore;
                elseif( $this->genericStoreProp() !== null )
                {
                    $storeProp = $this->genericStoreProp();
                    $location_array[$key + 1]['store'] = $pan->$storeProp;
                }

                $location_array[$key + 1]['parentStore'] = null;
                $location_array[$key + 1]['childDeviceGroups'] = $alldevicegroup;
            }
        }
        else
        {
            if( !$pan->isFawkes() && !$pan->isBuckbeak() )
            {
                $objectsLocations = $objectsLocation;
                #print "location count: ".count($objectsLocations);
                foreach( $objectsLocations as $key => $objectsLocation )
                {
                    if( $objectsLocation == "shared" )
                    {
                        if( $this->utilType == "address-merger" || $this->utilType == "addressgroup-merger" )
                            $store = $pan->addressStore;
                        elseif( $this->utilType == "service-merger" || $this->utilType == "servicegroup-merger" )
                            $store = $pan->serviceStore;
                        elseif( $this->utilType == "tag-merger" )
                            $store = $pan->tagStore;
                        elseif( $this->utilType == "custom-url-category-merger" )
                            $store = $pan->customURLProfileStore;
                        elseif( $this->genericStoreProp() !== null )
                        {
                            $storeProp = $this->genericStoreProp();
                            $store = $pan->$storeProp;
                        }

                        $parentStore = null;
                        $location_array[$key]['findLocation'] = $objectsLocation;
                        $location_array[$key]['store'] = $store;
                        $location_array[$key]['parentStore'] = $parentStore;
                    }
                    else
                    {
                        $findLocation = $pan->findSubSystemByName($objectsLocation);
                        if( $findLocation === null )
                            $this->locationNotFound($objectsLocation);

                        if( $this->utilType == "address-merger" || $this->utilType == "addressgroup-merger" )
                        {
                            $store = $findLocation->addressStore;

                            if( $pan->isPanorama() && isset($findLocation->parentDeviceGroup) && $findLocation->parentDeviceGroup !== null )
                                $parentStore = $findLocation->parentDeviceGroup->addressStore;
                            elseif( ($pan->isFawkes() || $pan->isBuckbeak()) && isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                                $parentStore = $findLocation->parentContainer->addressStore;
                            else
                                $parentStore = $findLocation->owner->addressStore;
                        }
                        elseif( $this->utilType == "service-merger" || $this->utilType == "servicegroup-merger" )
                        {
                            $store = $findLocation->serviceStore;

                            if( $pan->isPanorama() && isset($findLocation->parentDeviceGroup) && $findLocation->parentDeviceGroup !== null )
                                $parentStore = $findLocation->parentDeviceGroup->serviceStore;
                            elseif( ($pan->isFawkes() || $pan->isBuckbeak()) && isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                                $parentStore = $findLocation->parentContainer->serviceStore;
                            else
                                $parentStore = $findLocation->owner->serviceStore;
                        }
                        elseif( $this->utilType == "tag-merger" )
                        {
                            $store = $findLocation->tagStore;

                            if( $pan->isPanorama() && isset($findLocation->parentDeviceGroup) && $findLocation->parentDeviceGroup !== null )
                                $parentStore = $findLocation->parentDeviceGroup->tagStore;
                            elseif( ($pan->isFawkes() || $pan->isBuckbeak()) && isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                                $parentStore = $findLocation->parentContainer->tagStore;
                            else
                                $parentStore = $findLocation->owner->tagStore;
                        }
                        elseif( $this->utilType == "custom-url-category-merger" )
                        {
                            $store = $findLocation->customURLProfileStore;

                            if( $pan->isPanorama() && isset($findLocation->parentDeviceGroup) && $findLocation->parentDeviceGroup !== null )
                                $parentStore = $findLocation->parentDeviceGroup->customURLProfileStore;
                            elseif( ($pan->isFawkes() || $pan->isBuckbeak()) && isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                                $parentStore = $findLocation->parentContainer->customURLProfileStore;
                            else
                                $parentStore = $findLocation->owner->customURLProfileStore;
                        }
                        elseif( $this->genericStoreProp() !== null )
                        {
                            $storeProp = $this->genericStoreProp();
                            $store = $findLocation->$storeProp;

                            if( $pan->isPanorama() && isset($findLocation->parentDeviceGroup) && $findLocation->parentDeviceGroup !== null )
                                $parentStore = $findLocation->parentDeviceGroup->$storeProp;
                            elseif( ($pan->isFawkes() || $pan->isBuckbeak()) && isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                                $parentStore = $findLocation->parentContainer->$storeProp;
                            else
                                $parentStore = $findLocation->owner->$storeProp;
                        }
                        if( get_class($findLocation->owner) == "FawkesConf" )
                            $parentStore = null;

                        $location_array[$key]['findLocation'] = $findLocation;
                        $location_array[$key]['store'] = $store;
                        $location_array[$key]['parentStore'] = $parentStore;
                    }
                }
            }

            if( $pan->isPanorama() )
            {

                foreach( $this->objectsLocation as $key => $objectsLocation )
                {
                    if( $objectsLocation == 'shared' )
                        $childDeviceGroups = $pan->deviceGroups;
                    else
                        $childDeviceGroups = $findLocation->childDeviceGroups(TRUE);
                    $location_array[$key]['childDeviceGroups'] = $childDeviceGroups;
                }

            }
            elseif( $pan->isFawkes() || $pan->isBuckbeak() )
            {
                //child Container/CloudDevices
                //Todo: swaschkut 20210414
                foreach( $this->objectsLocation as $key => $objectsLocation )
                    $location_array[$key]['childDeviceGroups'] = array();
            }
            else
            {
                foreach( $this->objectsLocation as $key => $objectsLocation )
                    $location_array[$key]['childDeviceGroups'] = array();
            }

        }

        return $location_array;
    }


    function filterArgument( )
    {
        if( $this->utilType == "address-merger" || $this->utilType == "addressgroup-merger" )
            $type = 'address';
        elseif( $this->utilType == "service-merger" || $this->utilType == "servicegroup-merger" )
            $type = 'service';
        elseif( $this->utilType == "tag-merger" )
            $type = 'tag';
        elseif( $this->utilType == "custom-url-category-merger" || $this->utilType == "securityprofile-merger" )
            $type = 'securityprofile';
        elseif( $this->utilType == "securityprofilegroup-merger" )
            $type = 'securityprofilegroup';
        elseif( $this->utilType == "schedule-merger" )
            $type = 'schedule';
        elseif( $this->utilType == "logprofile-merger" )
            $type = 'log-profile';
        elseif( $this->utilType == "decryptionprofile-merger" )
            $type = 'securityprofile';
        elseif( $this->utilType == "edl-merger" )
            $type = 'edl';
        elseif( $this->utilType == "region-merger" )
            $type = 'address';
        elseif( $this->utilType == "appcustom-merger" || $this->utilType == "appfilter-merger" || $this->utilType == "appgroup-merger" )
            $type = 'application';

        if( isset(PH::$args['pickfilter']) )
        {
            $this->pickFilter = new RQuery($type);
            $errMsg = '';
            if( $this->pickFilter->parseFromString(PH::$args['pickfilter'], $errMsg) === FALSE )
                derr("invalid pickFilter was input: " . $errMsg);
            PH::print_stdout( " - pickFilter was input: " );
            $this->pickFilter->display();
            PH::print_stdout();
        }

        if( isset(PH::$args['excludefilter']) )
        {
            $this->excludeFilter = new RQuery($type);
            $errMsg = '';
            if( $this->excludeFilter->parseFromString(PH::$args['excludefilter'], $errMsg) === FALSE )
                derr("invalid pickFilter was input: " . $errMsg);
            PH::print_stdout( " - excludeFilter was input: " );
            $this->excludeFilter->display();
            PH::print_stdout();
        }

        if( isset(PH::$args['allowmergingwithupperlevel']) )
            $this->upperLevelSearch = TRUE;
    }

    function findAncestor( $current, $object, $StoreType = "addressStore" )
    {
        while( TRUE )
        {
            $findAncestor = $current->find($object->name(), null, TRUE);
            if( $findAncestor !== null )
            {
                return $findAncestor;
                break;
            }
            
            if( isset($current->owner->parentDeviceGroup) && $current->owner->parentDeviceGroup !== null )
                $current = $current->owner->parentDeviceGroup->$StoreType;
            elseif( isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                $current = $current->owner->parentContainer->$StoreType;
            elseif( isset($current->owner->owner) && $current->owner->owner !== null && !$current->owner->owner->isFawkes() && !$current->owner->owner->isBuckbeak() )
                $current = $current->owner->owner->$StoreType;
            else
            {
                return null;
                break;
            }
        }
    }

    function findChildAncestor( $childDeviceGroups, $object, $StoreType= "addressStore" )
    {

        foreach( $childDeviceGroups as $deviceGroup )
        {
            $findAncestor = $deviceGroup->$StoreType->find($object->name(), null, FALSE);
            if( $findAncestor !== null )
                return $findAncestor;
        }

        return null;
    }

    function add_supported_arguments()
    {
        $this->supportedArguments[] = array('niceName' => 'in', 'shortHelp' => 'input file ie: in=config.xml', 'argDesc' => '[filename]');
        $this->supportedArguments[] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
        $this->supportedArguments[] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS', 'argDesc' => 'sys1|shared|dg1');

        $this->supportedArguments[] = array('niceName' => 'mergeCountLimit', 'shortHelp' => 'stop operations after X objects have been merged', 'argDesc' => '100');

        if( $this->utilType == "service-merger" )
        {
            $this->supportedArguments[] = array('niceName' => 'pickFilter',
                'shortHelp' => "specify a filter a pick which object will be kept while others will be replaced by this one.\n" .
                    "   ie: 2 services are found to be mergeable: 'H-1.1.1.1' and 'Server-ABC'. Then by using pickFilter=(name regex /^H-/) you would ensure that object H-1.1.1.1 would remain and Server-ABC be replaced by it.",
                'argDesc' => '(name regex /^g/)');
            $this->supportedArguments[] = array('niceName' => 'DupAlgorithm',
                'shortHelp' => "Specifies how to detect duplicates:\n" .
                    "  - SameDstSrcPorts: objects with same Dst and Src ports will be replaced by the one picked (default)\n" .
                    "  - SamePorts: objects with same Dst ports will be replaced by the one picked\n" .
                    "  - Identical: objects with same Dst and Src ports and same name will be replaced by the one picked\n" .
                    "  - WhereUsed: objects used exactly in the same location will be merged into 1 single object and all ports covered by these objects will be aggregated\n",
                'argDesc' => 'SameDstSrcPorts|SamePorts|Identical|WhereUsed');
        }
        else
            $this->supportedArguments[] = array('niceName' => 'pickFilter', 'shortHelp' => 'specify a filter a pick which object will be kept while others will be replaced by this one', 'argDesc' => '(name regex /^g/)');

        if( $this->utilType == "address-merger" )
        {
            $this->supportedArguments[] = array('niceName' => 'DupAlgorithm',
                'shortHelp' => "Specifies how to detect duplicates:\n" .
                    "  - SameAddress: objects with same Network-Value will be replaced by the one picked (default)\n" .
                    "  - Identical: objects with same network-value and same name will be replaced by the one picked\n" .
                    "  - WhereUsed: objects used exactly in the same location will be merged into 1 single object and all ports covered by these objects will be aggregated\n",
                'argDesc' => 'SameAddress|Identical|WhereUsed');
        }
        elseif( $this->utilType == "addressgroup-merger" )
        {
            $this->supportedArguments[] = array('niceName' => 'DupAlgorithm',
                'shortHelp' => "Specifies how to detect duplicates:\n" .
                    "  - SameMembers: groups holding same members replaced by the one picked first (default)\n" .
                    "  - SameIP4Mapping: groups resolving the same IP4 coverage will be replaced by the one picked first\n" .
                    "  - Identical: groups holding same members and same name will be replaced by the one picked\n" .
                    "  - WhereUsed: groups used exactly in the same location will be merged into 1 single groups with all members together\n",
                'argDesc' => 'SameMembers|SameIP4Mapping|Identical|WhereUsed');
        }
        elseif( $this->utilType == "servicegroup-merger" )
        {
            $this->supportedArguments[] = array('niceName' => 'DupAlgorithm',
                'shortHelp' => "Specifies how to detect duplicates:\n" .
                    "  - SameMembers: groups holding same members replaced by the one picked first (default)\n" .
                    "  - SamePortMapping: groups resolving the same port mapping coverage will be replaced by the one picked first\n" .
                    "  - Identical: groups holding same members and same name will be replaced by the one picked\n" .
                    "  - WhereUsed: groups used exactly in the same location will be merged into 1 single groups with all members together\n",
                'argDesc' => 'SameMembers|SamePortMapping|Identical|WhereUsed');
        }
        elseif( $this->utilType == "tag-merger" )
        {
            $this->supportedArguments[] = array('niceName' => 'DupAlgorithm',
                'shortHelp' => "Specifies how to detect duplicates:\n" .
                    "  - SameColor: objects with same TAG-color will be replaced by the one picked; tags without a color are not merged\n" .
                    "  - Identical: objects with same TAG-color and same name will be replaced by the one picked (default)\n" .
                    "  - WhereUsed: objects used exactly in the same location will be merged into 1 single object and all ports covered by these objects will be aggregated\n" .
                    "  - SameName: objects with same Name\n",
                'argDesc' => 'SameColor|Identical|WhereUsed|SameName');
        }
        elseif( $this->utilType == "securityprofilegroup-merger" )
        {
            $this->supportedArguments[] = array(
                'niceName' => 'DupAlgorithm',
                'shortHelp' => "Specifies how to detect duplicates:\n" .
                    "  - SameMembers: groups with the same profile name per profile type (default)\n" .
                    "  - SameValue: groups with the same profile content per profile type, profile names may differ\n" .
                    "  a group is only merged / moved if every profile name resolves to the same content where it is used\n",
                'argDesc' => 'SameMembers|SameValue');
        }
        elseif( $this->utilType == "securityprofile-merger" )
        {
            $this->supportedArguments[] = array(
                'niceName' => 'ProfileType',
                'shortHelp' => "security profile type(s) to merge (required); any = all types, or a comma separated list",
                'argDesc' => 'any|' . implode('|', array_keys(self::$securityProfileMergerStores)));
            $this->supportedArguments[] = array(
                'niceName' => 'DupAlgorithm',
                'shortHelp' => "Specifies how to detect duplicates:\n" .
                    "  - SameName: profiles with the same name (across the device-group hierarchy) and the same content (default)\n" .
                    "  - SameValue: profiles with the same content, also with different names\n" .
                    "  content = profile XML compared like type=diff, the profile name is ignored\n",
                'argDesc' => 'SameName|SameValue');
        }
        elseif( $this->utilType == "object-merger" )
        {
            $this->supportedArguments[] = array(
                'niceName' => 'ObjectType',
                'shortHelp' => "object type(s) to merge (required); any = all types in this order, or a comma separated list",
                'argDesc' => 'any|' . implode('|', array_keys(self::$objectMergerTypes)));
            $this->supportedArguments[] = array(
                'niceName' => 'ProfileType',
                'shortHelp' => "objecttype=securityprofile: security profile type(s), default any",
                'argDesc' => 'any|' . implode('|', array_keys(self::$securityProfileMergerStores)));
            $this->supportedArguments[] = array(
                'niceName' => 'DupAlgorithm',
                'shortHelp' => "Specifies how to detect duplicates; leave it out to use the default of each object type:\n" .
                    "  - address: SameAddress (default) | Identical | WhereUsed\n" .
                    "  - addressgroup: SameMembers (default) | SameIP4Mapping | Identical | WhereUsed\n" .
                    "  - service: SameDstSrcPorts (default) | SamePorts | Identical | WhereUsed\n" .
                    "  - servicegroup: SameMembers (default) | SamePortMapping | Identical | WhereUsed\n" .
                    "  - tag: Identical (default) | SameColor | WhereUsed | SameName\n" .
                    "  - custom-url-category: SameValue (default) | Identical | SameName\n" .
                    "  - schedule / log-profile / decryption-profile / edl / region / application-custom / application-filter / application-group / securityprofile: SameName (default) | SameValue\n" .
                    "  - securityprofilegroup: SameMembers (default) | SameValue\n" .
                    "  with several object types the value must be valid for all of them\n",
                'argDesc' => 'SameName|SameValue|...');
        }
        elseif( $this->utilType == "custom-url-category-merger" )
        {
            $this->supportedArguments[] = array(
                'niceName' => 'DupAlgorithm',
                'shortHelp' => "Specifies how to detect duplicates:\n" .
                    "  - SameValue: objects with same URL will be replaced by the one picked (default)\n" .
                    "  - Identical: objects with same URL list and same name will be replaced by the one picked\n" .
                    "  - SameName: objects with same Name\n",
                'argDesc' => 'SameValue|Identical|SameName');
        }

        $this->supportedArguments[] = array('niceName' => 'excludeFilter', 'shortHelp' => 'specify a filter to exclude objects from merging process entirely', 'argDesc' => '(name regex /^g/)');
        $this->supportedArguments[] = array('niceName' => 'allowMergingWithUpperLevel', 'shortHelp' => 'when this argument is specified, it instructs the script to also look for duplicates in upper level');
        $this->supportedArguments[] = array('niceName' => 'allowaddingmissingobjects', 'shortHelp' => 'when this argument is specified, it instructs the script to also add missing objects for duplicates in upper level');
        $this->supportedArguments[] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments[] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');

        $this->supportedArguments[] = array('niceName' => 'exportCSV', 'shortHelp' => 'when this argument is specified, it instructs the script to display the kept and removed objects per value');
    }

    function merger_arguments( )
    {
        $display_error = false;


        if( isset(PH::$args['mergecountlimit']) )
            $this->mergeCountLimit = PH::$args['mergecountlimit'];

        if( isset(PH::$args['dupalgorithm']) )
        {
            $this->dupAlg = strtolower(PH::$args['dupalgorithm']);
        }

        if( $this->utilType == "address-merger" )
        {
            if( $this->dupAlg != 'sameaddress' && $this->dupAlg != 'whereused' && $this->dupAlg != 'identical' )
                $display_error = true;

            $defaultDupAlg = 'sameaddress';
        }
        elseif( $this->utilType == "addressgroup-merger" )
        {
            if( $this->dupAlg != 'samemembers' && $this->dupAlg != 'sameip4mapping' && $this->dupAlg != 'identical' && $this->dupAlg != 'whereused' && $this->dupAlg != 'samename' )
                $display_error = true;

            if( isset(PH::$args['allowaddingmissingobjects']) )
                $this->addMissingObjects = TRUE;

            $defaultDupAlg = 'samemembers';
        }
        elseif( $this->utilType == "service-merger" )
        {
            if( $this->dupAlg != 'sameports' && $this->dupAlg != 'whereused' && $this->dupAlg != 'samedstsrcports' && $this->dupAlg != 'identical' )
                $display_error = true;

            $defaultDupAlg = 'samedstsrcports';
        }
        elseif( $this->utilType == "servicegroup-merger" )
        {
            if( $this->dupAlg != 'samemembers' && $this->dupAlg != 'sameportmapping' && $this->dupAlg != 'identical' && $this->dupAlg != 'whereused' )
                $display_error = true;

            if( isset(PH::$args['allowaddingmissingobjects']) )
                $this->addMissingObjects = TRUE;

            $defaultDupAlg = 'samemembers';
        }
        elseif( $this->utilType == "tag-merger" )
        {
            if( $this->dupAlg != 'samecolor' && $this->dupAlg != 'whereused' && $this->dupAlg != 'identical' && $this->dupAlg != 'samename' )
                $display_error = true;

            $defaultDupAlg = 'identical';
        }
        elseif( $this->utilType == "custom-url-category-merger" )
        {
            if( $this->dupAlg != 'samevalue' && $this->dupAlg != 'identical' && $this->dupAlg != 'samename' )
                $display_error = true;

            if( isset(PH::$args['allowaddingmissingobjects']) )
                $this->addMissingObjects = TRUE;

            $defaultDupAlg = 'samevalue';
        }
        elseif( $this->utilType == "securityprofile-merger" )
        {
            $this->securityProfileMergerType();
            if( $this->dupAlg != 'samename' && $this->dupAlg != 'samevalue' )
                $display_error = true;

            $defaultDupAlg = 'samename';
        }
        elseif( $this->utilType == "securityprofilegroup-merger" )
        {
            if( $this->dupAlg != 'samemembers' && $this->dupAlg != 'samevalue' )
                $display_error = true;

            $defaultDupAlg = 'samemembers';
        }
        elseif( isset(self::$xmlObjectMergerStores[$this->utilType]) )
        {
            if( $this->dupAlg != 'samename' && $this->dupAlg != 'samevalue' )
                $display_error = true;

            $defaultDupAlg = 'samename';
        }
        /*
        elseif( $this->utilType == "object-merger" )
        {
            if( $this->dupAlg != 'identical' )
                $display_error = true;

            $defaultDupAlg = 'identical';
        }
        */


        if( isset(PH::$args['dupalgorithm']) )
        {
            #$this->dupAlg = strtolower(PH::$args['dupalgorithm']);
            if( $display_error )
                $this->display_error_usage_exit('unsupported value for dupAlgorithm: ' . PH::$args['dupalgorithm']
                    . ( count($this->objectMergerSelected) > 0 ? ' (objecttype ' . array_search($this->utilType, self::$objectMergerTypes) . ') - with several object types leave DupAlgorithm out to use the default of each type' : '' ) );
        }
        else
            $this->dupAlg = $defaultDupAlg;

    }

    /** type=securityprofile-merger: reads and checks the profiletype argument */
    function securityProfileMergerType()
    {
        if( $this->spStoreProp !== null )
            return;

        if( $this->utilType == "securityprofilegroup-merger" )
        {
            $this->spStoreProp = 'securityProfileGroupStore';
            return;
        }

        if( !isset(PH::$args['profiletype']) )
            $this->display_error_usage_exit('argument profiletype= is required: any|' . implode('|', array_keys(self::$securityProfileMergerStores)));

        $types = array();
        foreach( explode(',', strtolower(PH::$args['profiletype'])) as $type )
        {
            $type = trim($type);
            if( $type === 'any' )
                $types = array_merge( $types, array_keys(self::$securityProfileMergerStores) );
            elseif( isset(self::$securityProfileMergerStores[$type]) )
                $types[] = $type;
            else
                $this->display_error_usage_exit('unsupported value for profiletype: ' . PH::$args['profiletype'] . ' - supported: any|' . implode('|', array_keys(self::$securityProfileMergerStores)));
        }
        $this->spProfileTypes = array_values( array_unique($types) );

        $this->selectSecurityProfileMergerType( $this->spProfileTypes[0] );
    }

    /** store property of the security profile / security profile group / object merger runs, null for the others */
    function genericStoreProp()
    {
        if( isset(self::$xmlObjectMergerStores[$this->utilType]) )
            return self::$xmlObjectMergerStores[$this->utilType];

        if( $this->utilType == "securityprofile-merger" || $this->utilType == "securityprofilegroup-merger" )
        {
            $this->securityProfileMergerType();
            return $this->spStoreProp;
        }

        return null;
    }

    function selectSecurityProfileMergerType( $type )
    {
        $this->spProfileType = $type;
        $this->spStoreProp = self::$securityProfileMergerStores[$type];
    }

    function securityprofilegroup_merging()
    {
        $this->genericGroupMerging( $this->securityProfileGroupMergeSpec() );
    }

    function securityprofile_merging()
    {
        $this->genericObjectMerging( $this->securityProfileMergeSpec( $this->spProfileType, $this->spStoreProp ) );
    }

    function locationSettings( $tmp_location, $type, &$store, &$findLocation, &$parentStore, &$childDeviceGroups)
    {
        $store = $tmp_location['store'];
        $findLocation = $tmp_location['findLocation'];
        $parentStore = $tmp_location['parentStore'];
        if( $this->upperLevelSearch )
            $childDeviceGroups = $tmp_location['childDeviceGroups'];
        else
            $childDeviceGroups = array();

        PH::print_stdout( "\n\n***********************************************\n" );
        PH::print_stdout( " - upper level search status : " . boolYesNo($this->upperLevelSearch) . "" );
        if( is_string($findLocation) )
            PH::print_stdout( " - location 'shared' found" );
        else
            PH::print_stdout( " - location '{$findLocation->name()}' found" );
        PH::print_stdout( " - found {$store->count()} ".$type." Objects" );
        PH::print_stdout( " - DupAlgorithm selected: {$this->dupAlg}" );
        PH::print_stdout( " - computing ".$type." values database ... " );
        sleep(1);
    }

    function addressgroup_merging()
    {
        $this->genericGroupMerging( $this->addressGroupMergeSpec() );
    }

    function address_merging()
    {
        $this->genericObjectMerging( $this->addressMergeSpec() );
    }

    function servicegroup_merging()
    {
        $this->genericGroupMerging( $this->serviceGroupMergeSpec() );
    }

    function service_merging()
    {
        $this->genericObjectMerging( $this->serviceMergeSpec() );
    }

    function tag_merging()
    {
        $this->genericObjectMerging( $this->tagMergeSpec() );
    }

    function custom_url_category_merging()
    {
        $this->genericObjectMerging( $this->customUrlCategoryMergeSpec() );
    }

    function merger_final_step()
    {
        $this->save_our_work( true );

        if( $this->exportcsv )
        {
            PH::print_stdout(" * script was called with argument 'exportCSV' - please wait for calculation");

            $tmp_string = "value,kept(create),removed";
            foreach( $this->deletedObjects as $obj_index => $object_name )
            {
                if( isset($object_name['kept']) )
                    $tmp_kept = $object_name['kept'];
                else
                    $tmp_kept = "";
                $tmp_string .= $obj_index . "," . $tmp_kept . "," . $object_name['removed']."\n";
            }


            if( $this->exportcsvFile !== null )
            {
                self::exportCSVToHtml();
                self::exportCSVToHtml( true );
            }

            else
                PH::print_stdout( $tmp_string );
        }
    }

    function exportCSVToHtml( $skipped = FALSE)
    {
        if( !$skipped )
            $headers = '<th>ID</th><th>kept (create)</th><th>removed</th><th>hash</th>';
        else
            $headers = '<th>ID</th><th>kept</th><th>not merged with</th><th>reason</th><th>hash</th>';


        $lines = '';
        $encloseFunction = function ($value, $nowrap = TRUE) {
            if( is_string($value) )
                $output = PH::panosphp_htmlspecialchars($value);
            elseif( is_array($value) )
            {
                $output = '';
                $first = TRUE;
                foreach( $value as $subValue )
                {
                    if( !$first )
                    {
                        $output .= '<br />';
                    }
                    else
                        $first = FALSE;

                    if( is_string($subValue) )
                        $output .= PH::panosphp_htmlspecialchars($subValue);
                    else
                        $output .= PH::panosphp_htmlspecialchars($subValue->name());
                }
            }
            else
            {
                derr('unsupported: '.$value);
            }


            if( $nowrap )
                return '<td style="white-space: nowrap">' . $output . '</td>';

            return '<td>' . $output . '</td>';
        };

        $obj_Array = array();
        if( !$skipped )
        {
            if( isset($this->deletedObjects) )
                $obj_Array = $this->deletedObjects;
        }
        else
        {
            if( isset($this->skippedObjects) )
                $obj_Array = $this->skippedObjects;
        }


        $count = 0;
        foreach( $obj_Array as $index => $line )
            {
                $count++;

                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $encloseFunction( (string)$count );

                if( isset( $line['kept'] ) )
                    $lines .= $encloseFunction( $line['kept'] );
                else
                    $lines .= $encloseFunction( "" );

                $removedArray = explode( "|", $line['removed'] );
                $lines .= $encloseFunction( $removedArray );

                if( isset( $line['reason'] ) && $skipped )
                {
                    $tmp_array = explode(PHP_EOL, $line['reason']);
                    $lines .= $encloseFunction( $tmp_array );
                }
                elseif( $skipped )
                    $lines .= $encloseFunction( "" );

                $tmp_array = explode( "./.", $index );
                $lines .= $encloseFunction( $tmp_array );
                #$lines .= $encloseFunction( (string)$index );

                $lines .= "</tr>\n";

            }

        require_once dirname(__FILE__) . '/ExportToHtmlHelper.php';
        $content = ExportToHtmlHelper::buildHtmlExport($headers, $lines);

        if( PH::$shadow_json )
            PH::$JSON_OUT['exportcsv'] = $content;

        if( !$skipped )
            $filename = $this->exportcsvFile;
        else
            $filename = $this->exportcsvSkippedFile;
        file_put_contents($filename, $content);
    }

    private function deletedObject( $index, $keptOBJ, $removedOBJ)
    {
        $index = $this->mergeIndexPrefix . $index;
        if( is_object( $keptOBJ ) )
        {
            if( $keptOBJ->owner->owner->name() === "" )
                $tmpDG = "shared";
            else
                $tmpDG = $keptOBJ->owner->owner->name();
            $this->deletedObjects[$index]['kept'] = "[".$tmpDG. "] - ".$keptOBJ->name();
        }
        else
        {
            $this->deletedObjects[$index]['kept'] = $keptOBJ;
        }


        if( $removedOBJ->owner->owner->name() === "" )
            $tmpDG = "shared";
        else
            $tmpDG = $removedOBJ->owner->owner->name();

        if( !isset( $this->deletedObjects[$index]['removed'] ) )
        {
            $tmpstring = "[".$tmpDG. "] - ".$removedOBJ->name();
            if( get_class( $removedOBJ ) === "Address" && $removedOBJ->isType_TMP() )
                $tmpstring .= " (tmp)";

            $this->deletedObjects[$index]['removed'] = $tmpstring;
        }
        else
        {
            $tmpstring = "[".$tmpDG. "] - ".$removedOBJ->name();
            if( get_class( $removedOBJ ) === "Address" && $removedOBJ->isType_TMP() )
                $tmpstring .= " (tmp)";

            if( strpos( $this->deletedObjects[$index]['removed'], $tmpstring ) === FALSE )
                $this->deletedObjects[$index]['removed'] .= "|" . $tmpstring;
        }
    }

    private function skippedObject( $index, $keptOBJ, $removedOBJ, $reason = "")
    {
        $index = $this->mergeIndexPrefix . $index;
        if( is_object( $keptOBJ ) )
        {
            if( $keptOBJ->owner->owner->name() === "" )
                $tmpDG = "shared";
            else
                $tmpDG = $keptOBJ->owner->owner->name();
            $this->skippedObjects[$index]['kept'] = "[".$tmpDG. "] - ".$keptOBJ->name();
            if( get_class( $removedOBJ ) === "Address" )
            {
                if( get_class( $keptOBJ ) === "Address" )
                {
                    /** @var $keptOBJ Address */
                    $this->skippedObjects[$index]['kept'] .= "{value:".$keptOBJ->value()."}";
                }
                else
                    $this->skippedObjects[$index]['kept'] .= "{value:GROUP}";
            }
            elseif( get_class( $removedOBJ ) === "Service" )
            {
                if( get_class( $keptOBJ ) === "Service" )
                {
                    /** @var $keptOBJ Service */
                    $this->skippedObjects[$index]['kept'] .= " {prot:".$keptOBJ->protocol()."}{dport:".$keptOBJ->getDestPort()."}";
                    if( !empty($keptOBJ->getSourcePort()) )
                        $this->skippedObjects[$index]['kept'] .= "{sport:".$keptOBJ->getSourcePort()."}";
                    if( !empty($keptOBJ->getTimeout()) )
                        $this->skippedObjects[$index]['kept'] .= "{timeout:".$keptOBJ->getTimeout()."}";
                }
                else
                    $this->skippedObjects[$index]['kept'] .= "{value:GROUP}";
            }
            $this->skippedObjects[$index]['reason'] = $reason;
        }
        else
        {
            $this->skippedObjects[$index]['kept'] = $keptOBJ;
            $this->skippedObjects[$index]['reason'] = $reason;
        }

        if( is_object( $removedOBJ ) )
        {
            if( !isset( $removedOBJ->owner->owner ) )
            {
                $this->skippedObjects[$index]['removed'] = "1?????";
                return null;
            }

            if( $removedOBJ->owner->owner->name() === "" )
                $tmpDG = "shared";
            else
                $tmpDG = $removedOBJ->owner->owner->name();

            if( !isset($this->skippedObjects[$index]['removed']) )
            {
                $tmpstring = "[" . $tmpDG . "] - " . $removedOBJ->name();
                if( get_class($removedOBJ) === "Address" && $removedOBJ->isType_TMP() )
                    $tmpstring .= " (tmp)";

                $this->skippedObjects[$index]['removed'] = $tmpstring;
                if( get_class($removedOBJ) === "Address" )
                {
                    /** @var $keptOBJ Address */
                    $this->skippedObjects[$index]['removed'] .= "{value:" . $removedOBJ->value() . "}";
                }
                else if( get_class($removedOBJ) === "Service" )
                {
                    /** @var $keptOBJ Service */
                    $this->skippedObjects[$index]['removed'] .= "{prot:" . $removedOBJ->protocol() . "}{dport:" . $removedOBJ->getDestPort() . "}";
                    if( !empty($removedOBJ->getSourcePort()) )
                        $this->skippedObjects[$index]['removed'] .= "{sport:" . $removedOBJ->getSourcePort() . "}";
                    if( !empty($removedOBJ->getTimeout()) )
                        $this->skippedObjects[$index]['removed'] .= "{timeout:".$removedOBJ->getTimeout()."}";
                }
            }
            else
            {
                $tmpstring = "[" . $tmpDG . "] - " . $removedOBJ->name();
                if( get_class($removedOBJ) === "Address" && $removedOBJ->isType_TMP() )
                    $tmpstring .= " (tmp)";

                if( strpos($this->skippedObjects[$index]['removed'], $tmpstring) === FALSE )
                {
                    $this->skippedObjects[$index]['removed'] .= "|" . $tmpstring;
                    if( get_class($removedOBJ) === "Address" )
                    {
                        /** @var $keptOBJ Address */
                        $this->skippedObjects[$index]['removed'] .= "{value:" . $removedOBJ->value() . "}";
                    }
                    elseif( get_class($removedOBJ) === "Service" )
                    {
                        /** @var $keptOBJ Service */
                        $this->skippedObjects[$index]['removed'] .= "{prot:" . $removedOBJ->protocol() . "}{dport:" . $removedOBJ->getDestPort() . "}";
                        if( !empty($removedOBJ->getSourcePort()) )
                            $this->skippedObjects[$index]['removed'] .= "{sport:" . $removedOBJ->getSourcePort() . "}";
                        if( !empty($removedOBJ->getTimeout()) )
                            $this->skippedObjects[$index]['removed'] .= "{timeout:".$removedOBJ->getTimeout()."}";
                    }
                }
            }
        }
        else
        {
            $this->skippedObjects[$index]['removed'] = "2?????";
        }
    }

    private function deletedObjectSetRemoved( $index, $tmpstring )
    {
        $index = $this->mergeIndexPrefix . $index;
        if( !isset( $this->deletedObjects[$index]['removed'] ) )
            $this->deletedObjects[$index]['removed'] = "";

        $this->deletedObjects[$index]['removed'] .= $tmpstring;
    }

    private function removeSingleEntries( &$hashMap, $other_hashMap, $upperHashMap, &$countObjects = 0)
    {
        foreach( $hashMap as $index => &$hash )
        {
            if( count($hash) == 1 && !isset($upperHashMap[$index]) && !isset($other_hashMap[$index]) && !isset(reset($hash)->ancestor) )
                unset($hashMap[$index]);
            else
                $countObjects += count($hash);
        }
        unset($hash);
    }
}