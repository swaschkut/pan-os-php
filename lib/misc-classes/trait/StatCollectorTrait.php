<?php

/**
 * ISC License
 *
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

trait StatCollectorTrait
{
    public function display_statistics( $debug = false, $actions = "display")
    {
        $stdoutarray = array();

        $stdoutarray['type'] = get_class($this);

        $header = "Statistics for " . get_class($this) . " '" . PH::boldText($this->name) . "' | '" . $this->toString() . "'";
        $stdoutarray['header'] = $header;

        if(get_class($this) !== "Container" && get_class($this) !== "DeviceGroup")
        {
            $stdoutarray['security rules'] = $this->securityRules->count();

            $stdoutarray['nat rules'] = $this->natRules->count();

            $stdoutarray['qos rules'] = $this->qosRules->count();

            $stdoutarray['pbf rules'] = $this->pbfRules->count();

            $stdoutarray['decryption rules'] = $this->decryptionRules->count();

            $stdoutarray['app-override rules'] = $this->appOverrideRules->count();

            $stdoutarray['capt-portal rules'] = $this->captivePortalRules->count();

            $stdoutarray['authentication rules'] = $this->authenticationRules->count();

            $stdoutarray['dos rules'] = $this->dosRules->count();

            $stdoutarray['tunnel-inspection rules']['pre'] = $this->tunnelInspectionRules->count();

            $stdoutarray['default-security rules']['pre'] = $this->defaultSecurityRules->count();

            $stdoutarray['network-packet-broker rules']['pre'] = $this->networkPacketBrokerRules->count();

            $stdoutarray['sdwan rules']['pre'] = $this->sdWanRules->count();

        }
        elseif( get_class($this) == "Container" || get_class($this) == "DeviceGroup" )
        {
            $stdoutarray['security rules'] = array();
            $stdoutarray['security rules']['pre'] = $this->securityRules->countPreRules();
            $stdoutarray['security rules']['post'] = $this->securityRules->countPostRules();

            $stdoutarray['nat rules'] = array();
            $stdoutarray['nat rules']['pre'] = $this->natRules->countPreRules();
            $stdoutarray['nat rules']['post'] = $this->natRules->countPostRules();

            $stdoutarray['qos rules'] = array();
            $stdoutarray['qos rules']['pre'] = $this->qosRules->countPreRules();
            $stdoutarray['qos rules']['post'] = $this->qosRules->countPostRules();

            $stdoutarray['pbf rules'] = array();
            $stdoutarray['pbf rules']['pre'] = $this->pbfRules->countPreRules();
            $stdoutarray['pbf rules']['post'] = $this->pbfRules->countPostRules();

            $stdoutarray['decrypt rules'] = array();
            $stdoutarray['decrypt rules']['pre'] = $this->decryptionRules->countPreRules();
            $stdoutarray['decrypt rules']['post'] = $this->decryptionRules->countPostRules();

            $stdoutarray['app-override rules'] = array();
            $stdoutarray['app-override rules']['pre'] = $this->appOverrideRules->countPreRules();
            $stdoutarray['app-override rules']['post'] = $this->appOverrideRules->countPostRules();

            $stdoutarray['captive-portal rules'] = array();
            $stdoutarray['captive-portal rules']['pre'] = $this->captivePortalRules->countPreRules();
            $stdoutarray['captive-portal rules']['post'] = $this->captivePortalRules->countPostRules();

            $stdoutarray['authentication rules'] = array();
            $stdoutarray['authentication rules']['pre'] = $this->authenticationRules->countPreRules();
            $stdoutarray['authentication rules']['post'] = $this->authenticationRules->countPostRules();

            $stdoutarray['dos rules'] = array();
            $stdoutarray['dos rules']['pre'] = $this->dosRules->countPreRules();
            $stdoutarray['dos rules']['post'] = $this->dosRules->countPostRules();

            $stdoutarray['tunnel-inspection rules'] = array();
            $stdoutarray['tunnel-inspection rules']['pre'] = $this->tunnelInspectionRules->countPreRules();
            $stdoutarray['tunnel-inspection rules']['post'] = $this->tunnelInspectionRules->countPostRules();

            $stdoutarray['default-security rules'] = array();
            $stdoutarray['default-security rules']['pre'] = $this->defaultSecurityRules->countPreRules();
            $stdoutarray['default-security rules']['post'] = $this->defaultSecurityRules->countPostRules();

            $stdoutarray['network-packet-broker rules'] = array();
            $stdoutarray['network-packet-broker rules']['pre'] = $this->networkPacketBrokerRules->countPreRules();
            $stdoutarray['network-packet-broker rules']['post'] = $this->networkPacketBrokerRules->countPostRules();

            $stdoutarray['sdwan rules'] = array();
            $stdoutarray['sdwan rules']['pre'] = $this->sdWanRules->countPreRules();
            $stdoutarray['sdwan rules']['post'] = $this->sdWanRules->countPostRules();
        }


        $stdoutarray['address objects'] = array();
        $stdoutarray['address objects']['total'] = $this->addressStore->count();
        $stdoutarray['address objects']['address'] = $this->addressStore->countAddresses();
        $stdoutarray['address objects']['group'] = $this->addressStore->countAddressGroups();
        $stdoutarray['address objects']['tmp'] = $this->addressStore->countTmpAddresses();
        $stdoutarray['address objects']['region'] = $this->addressStore->countRegionObjects();
        $stdoutarray['address objects']['unused'] = $this->addressStore->countUnused();

        $stdoutarray['service objects'] = array();
        $stdoutarray['service objects']['total'] = $this->serviceStore->count();
        $stdoutarray['service objects']['service'] = $this->serviceStore->countServices();
        $stdoutarray['service objects']['group'] = $this->serviceStore->countServiceGroups();
        $stdoutarray['service objects']['tmp'] = $this->serviceStore->countTmpServices();
        $stdoutarray['service objects']['unused'] = $this->serviceStore->countUnused();

        $stdoutarray['tag objects'] = array();
        $stdoutarray['tag objects']['total'] = $this->tagStore->count();
        $stdoutarray['tag objects']['unused'] = $this->tagStore->countUnused();

        $stdoutarray['securityProfileGroup objects'] = array();
        $stdoutarray['securityProfileGroup objects']['total'] = $this->securityProfileGroupStore->count();


        $stdoutarray['Anti-Spyware objects'] = array();
        $stdoutarray['Anti-Spyware objects']['total'] = $this->AntiSpywareProfileStore->count();
        $stdoutarray['Vulnerability objects'] = array();
        $stdoutarray['Vulnerability objects']['total'] = $this->VulnerabilityProfileStore->count();

        if( get_class($this) == "Container"
            || get_class($this) == "DeviceCloud"
            || get_class($this) == "DeviceOnPrem"
            || get_class($this) == "Snippet"
        )
        {
            $stdoutarray['WildfireAndAntivirus objects'] = array();
            $stdoutarray['WildfireAndAntivirus objects']['total'] = $this->VirusAndWildfireProfileStore->count();

            $stdoutarray['DNS-Security objects'] = array();
            $stdoutarray['DNS-Security objects']['total'] = $this->DNSSecurityProfileStore->count();
            $stdoutarray['Saas-Security objects'] = array();
            $stdoutarray['Saas-Security objects']['total'] = $this->SaasSecurityProfileStore->count();
        }

        if( get_class($this) == "DeviceGroup"
            || get_class($this) == "VirtualSystem"
        )
        {
            $stdoutarray['Antivirus objects'] = array();
            $stdoutarray['Antivirus objects']['total'] = $this->AntiVirusProfileStore->count();

            $stdoutarray['Wildfire objects'] = array();
            $stdoutarray['Wildfire objects']['total'] = $this->WildfireProfileStore->count();
        }





        $stdoutarray['URL objects'] = array();
        $stdoutarray['URL objects']['total'] = $this->URLProfileStore->count();
        $stdoutarray['custom URL objects'] = array();
        $stdoutarray['custom URL objects']['total'] = $this->customURLProfileStore->count();
        $stdoutarray['File-Blocking objects'] = array();
        $stdoutarray['File-Blocking objects']['total'] = $this->FileBlockingProfileStore->count();
        $stdoutarray['Data-Filtering objects'] = array();
        $stdoutarray['Data-Filtering objects']['total'] = $this->DataFilteringProfileStore->count();
        $stdoutarray['Decryption objects'] = array();
        $stdoutarray['Decryption objects']['total'] = $this->DecryptionProfileStore->count();


        $stdoutarray['HipObject objects'] = array();
        $stdoutarray['HipObject objects']['total'] = $this->HipObjectsProfileStore->count();

        $stdoutarray['HipProfile objects'] = array();
        $stdoutarray['HipProfile objects']['total'] = $this->HipProfilesProfileStore->count();


        $stdoutarray['GTP objects'] = array();
        $stdoutarray['GTP objects']['total'] = $this->GTPProfileStore->count();

        $stdoutarray['SCEP objects'] = array();
        $stdoutarray['SCEP objects']['total'] = $this->SCEPProfileStore->count();

        $stdoutarray['PacketBroker objects'] = array();
        $stdoutarray['PacketBroker objects']['total'] = $this->PacketBrokerProfileStore->count();

        $stdoutarray['SDWanErrorCorrection objects'] = array();
        $stdoutarray['SDWanErrorCorrection objects']['total'] = $this->SDWanErrorCorrectionProfileStore->count();

        $stdoutarray['SDWanPathQuality objects'] = array();
        $stdoutarray['SDWanPathQuality objects']['total'] = $this->SDWanPathQualityProfileStore->count();

        $stdoutarray['SDWanSaasQuality objects'] = array();
        $stdoutarray['SDWanSaasQuality objects']['total'] = $this->SDWanSaasQualityProfileStore->count();

        $stdoutarray['SDWanTrafficDistribution objects'] = array();
        $stdoutarray['SDWanTrafficDistribution objects']['total'] = $this->SDWanTrafficDistributionProfileStore->count();

        $stdoutarray['DataObjects objects'] = array();
        $stdoutarray['DataObjects objects']['total'] = $this->DataObjectsProfileStore->count();


        $stdoutarray['LogProfile objects'] = array();
        $stdoutarray['LogProfile objects']['total'] = $this->LogProfileStore->count();


        $stdoutarray['zones'] = $this->zoneStore->count();
        $stdoutarray['apps'] = $this->appStore->count();


        $this->sizeArray['type'] = get_class($this);
        $this->sizeArray['statstype'] = "objects";
        $this->sizeArray['header'] = $header;
        $this->sizeArray['kb Container'] = &DH::dom_get_config_size($this->xmlroot);
        $this->sizeArray['kb security rules'] = &DH::dom_get_config_size($this->securityRules->xmlroot);
        $this->sizeArray['kb nat rules'] = &DH::dom_get_config_size($this->natRules->xmlroot);
        $this->sizeArray['kb qos rules'] = &DH::dom_get_config_size($this->qosRules->xmlroot);
        $this->sizeArray['kb pbf rules'] = &DH::dom_get_config_size($this->pbfRules->xmlroot);
        $this->sizeArray['kb decrypt rules'] = &DH::dom_get_config_size($this->decryptionRules->xmlroot);
        $this->sizeArray['kb app-override rules'] = &DH::dom_get_config_size($this->appOverrideRules->xmlroot);
        $this->sizeArray['kb captive-portal rules'] = &DH::dom_get_config_size($this->captivePortalRules->xmlroot);
        $this->sizeArray['kb authentication rules'] = &DH::dom_get_config_size($this->authenticationRules->xmlroot);
        $this->sizeArray['kb dos rules'] = &DH::dom_get_config_size($this->dosRules->xmlroot);
        $this->sizeArray['kb tunnel-inspection rules'] = &DH::dom_get_config_size($this->tunnelInspectionRules->xmlroot);
        $this->sizeArray['kb default-security rules'] = &DH::dom_get_config_size($this->defaultSecurityRules->xmlroot);
        $this->sizeArray['kb network-packet-broker rules'] = &DH::dom_get_config_size($this->networkPacketBrokerRules->xmlroot);
        $this->sizeArray['kb sdwan rules'] = &DH::dom_get_config_size($this->sdWanRules->xmlroot);

        $tmp_adr = &DH::dom_get_config_size($this->addressStore->addressRoot);
        $tmp_adrgrp = &DH::dom_get_config_size($this->addressStore->addressGroupRoot);
        $tmp_region = &DH::dom_get_config_size($this->addressStore->regionRoot);
        $this->sizeArray['kb address objects '] = $tmp_adr + $tmp_adrgrp + $tmp_region;
        $tmp_srv = &DH::dom_get_config_size($this->serviceStore->serviceRoot);
        $tmp_srvgrp = &DH::dom_get_config_size($this->serviceStore->serviceGroupRoot);
        $this->sizeArray['kb address objects '] = $tmp_srv + $tmp_srvgrp;
        $this->sizeArray['kb tag objects'] = &DH::dom_get_config_size($this->tagStore->xmlroot);

        $this->sizeArray['kb securityProfileGroup objects'] = &DH::dom_get_config_size($this->securityProfileGroupStore->xmlroot);

        $this->sizeArray['kb Anti-Spyware objects'] = &DH::dom_get_config_size($this->AntiSpywareProfileStore->xmlroot);
        $this->sizeArray['kb Vulnerability objects'] = &DH::dom_get_config_size($this->VulnerabilityProfileStore->xmlroot);

        if( get_class($this) == "Container"
            || get_class($this) == "DeviceCloud"
            || get_class($this) == "DeviceOnPrem"
            || get_class($this) == "Snippet"
        )
        {
            $this->sizeArray['kb Wildfire and Antivirus objects'] = &DH::dom_get_config_size($this->VirusAndWildfireProfileStore->xmlroot);
        }


        if( get_class($this) == "DeviceGroup"
            || get_class($this) == "VirtualSystem"
        )
        {
            $this->sizeArray['kb Antivirus objects'] = &DH::dom_get_config_size($this->AntiVirusProfileStore->xmlroot);
            $this->sizeArray['kb Wildfire objects'] = &DH::dom_get_config_size($this->WildfireProfileStore->xmlroot);
        }


        $this->sizeArray['kb URL objects'] = &DH::dom_get_config_size($this->URLProfileStore->xmlroot);
        $this->sizeArray['kb custom URL objects'] = &DH::dom_get_config_size($this->customURLProfileStore->xmlroot);
        $this->sizeArray['kb File-Blocking objects'] = &DH::dom_get_config_size($this->FileBlockingProfileStore->xmlroot);

        $this->sizeArray['kb Decryption objects'] = &DH::dom_get_config_size($this->DecryptionProfileStore->xmlroot);
        $this->sizeArray['kb HipObject objects'] = &DH::dom_get_config_size($this->HipObjectsProfileStore->xmlroot);
        $this->sizeArray['kb HipProfile objects'] = &DH::dom_get_config_size($this->HipProfilesProfileStore->xmlroot);


        $this->sizeArray['kb GTP objects'] = &DH::dom_get_config_size($this->GTPProfileStore->xmlroot);
        $this->sizeArray['kb SCEP objects'] = &DH::dom_get_config_size($this->SCEPProfileStore->xmlroot);
        $this->sizeArray['kb PacketBroker objects'] = &DH::dom_get_config_size($this->PacketBrokerProfileStore->xmlroot);
        $this->sizeArray['kb SDWanErrorCorrection objects'] = &DH::dom_get_config_size($this->tagStore->xmlroot);
        $this->sizeArray['kb SDWanPathQuality objects'] = &DH::dom_get_config_size($this->SDWanPathQualityProfileStore->xmlroot);
        $this->sizeArray['kb SDWanSaasQuality objects'] = &DH::dom_get_config_size($this->SDWanSaasQualityProfileStore->xmlroot);
        $this->sizeArray['kb SDWanTrafficDistribution objects'] = &DH::dom_get_config_size($this->SDWanTrafficDistributionProfileStore->xmlroot);
        $this->sizeArray['kb DataObjects objects'] = &DH::dom_get_config_size($this->DataObjectsProfileStore->xmlroot);

        $this->sizeArray['kb LogProfile objects'] = &DH::dom_get_config_size($this->LogProfileStore->xmlroot);



        if( !PH::$shadow_json && $actions == "display"  )
            PH::print_stdout( $stdoutarray, true );

        if( !PH::$shadow_json && $actions == "display-size"  )
        {
            PH::stats_remove_zero_arrays($this->sizeArray);
            PH::print_stdout( $this->sizeArray, true );
        }

        if( $actions == "display-available" )
        {
            PH::stats_remove_zero_arrays($stdoutarray);
            if( !PH::$shadow_json )
                PH::print_stdout( $stdoutarray, true );
        }

        PH::$JSON_TMP[] = $stdoutarray;


        $this->display_bp_statistics( $debug, $actions );

    }

    public function get_bp_statistics()
    {
        if( get_class($this) == "BuckbeakConf" )
        {
            $container_all = $this->findContainer( "All");
            $sub = $container_all;
            $sub_ruleStore = $container_all->securityRules;
        }
        else
        {
            $sub = $this;
            $sub_ruleStore = $sub->securityRules;
        }


        $stdoutarray = array();


        if( get_class($this) == "BuckbeakConf" )
            $stdoutarray['type'] = "Container";
        else
            $stdoutarray['type'] = get_class( $sub );

        $stdoutarray['statstype'] = "adoption";

        $header = "BP/Visibility Statistics for ".get_class( $sub )." '" . PH::boldText($sub->name()) . "' | '" . $sub->toString() . "'";
        $stdoutarray['header'] = $header;

        $stdoutarray['security rules'] = $sub_ruleStore->count();

        $stdoutarray['security rules allow'] = count( $sub_ruleStore->rules( "(action is.allow)" ) );
        $stdoutarray['security rules allow enabled'] = count( $sub_ruleStore->rules( "(action is.allow) and (rule is.enabled)" ) );
        $stdoutarray['security rules allow disabled'] = count( $sub_ruleStore->rules( "(action is.allow) and (rule is.disabled)" ) );
        $stdoutarray['security rules enabled'] = count( $sub_ruleStore->rules( "(rule is.enabled)" ) );
        $stdoutarray['security rules deny'] = count( $sub_ruleStore->rules( "!(action is.allow)" ) );
        $stdoutarray['security rules deny enabled'] = count( $sub_ruleStore->rules( "!(action is.allow) and (rule is.enabled)" ) );
        $ruleForCalculation = $stdoutarray['security rules allow enabled'];

        $generalFilter = "(rule is.enabled) and ";
        $generalFilter_allow = "(rule is.enabled) and (action is.allow) and ";


        $stdoutarray['log at end'] = count( $sub_ruleStore->rules( $generalFilter."(log at.end)" ) );
        $stdoutarray['log at not start'] = count( $sub_ruleStore->rules( $generalFilter."!(log at.start)" ) );
        $stdoutarray['log prof set'] = count( $sub_ruleStore->rules( $generalFilter."(logprof is.set)" ) );
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "wf is.visibility" );
        $stdoutarray['wf visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "wf is.best-practice" );
        $stdoutarray['wf best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "wf is.adoption" );
        $stdoutarray['wf adoption'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter."!(from is.any) and (from all.has.from.query subquery1)", 'subquery1' => "zpp is.set" );
        $stdoutarray['zone protection'] = count( $sub_ruleStore->rules( $filter_array ) );

        $stdoutarray['app id'] = count( $sub_ruleStore->rules( $generalFilter_allow."!(app is.any)" ) );
        $stdoutarray['user id'] = count( $sub_ruleStore->rules( $generalFilter_allow."!(user is.any)" ) );

        $stdoutarray['service port'] = count( $sub_ruleStore->rules( $generalFilter_allow."!(service is.any)" ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "av is.visibility" );
        $stdoutarray['av visibility'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "av is.best-practice" );
        $stdoutarray['av best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "av is.adoption" );
        $stdoutarray['av adoption'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "as is.visibility" );
        $stdoutarray['as visibility'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "as.rules is.visibility" );
        $stdoutarray['as visibility rules'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "as.mica-engine is.visibility" );
        $stdoutarray['as visibility mica-engine'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "as is.best-practice" );
        $stdoutarray['as best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "as.rules is.best-practice" );
        $stdoutarray['as best-practice rules'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "as.mica-engine is.best-practice" );
        $stdoutarray['as best-practice mica-engine'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "as is.adoption" );
        $stdoutarray['as adoption'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "vp is.visibility" );
        $stdoutarray['vp visibility'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "vp.rules is.visibility" );
        $stdoutarray['vp visibility rules'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "vp.mica-engine is.visibility" );
        $stdoutarray['vp visibility mica-engine'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "vp is.best-practice" );
        $stdoutarray['vp best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "vp.rules is.best-practice" );
        $stdoutarray['vp best-practice rules'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "vp.mica-engine is.best-practice" );
        $stdoutarray['vp best-practice mica-engine'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "vp is.adoption" );
        $stdoutarray['vp adoption'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "fb is.visibility" );
        $stdoutarray['fb visibility'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "fb is.best-practice" );
        $stdoutarray['fb best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "fb is.adoption" );
        $stdoutarray['fb adoption'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "df is.visibility" );
        $stdoutarray['data visibility'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "df is.adoption" );
        $stdoutarray['data adoption'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "url.site-access is.visibility" );
        $stdoutarray['url-site-access visibility'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "url.site-access is.best-practice" );
        $stdoutarray['url-site-access best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "url.site-access is.adoption" );
        $stdoutarray['url-site-access adoption'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "url.user-credential-detection is.visibility" );
        $stdoutarray['url-credential visibility'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "url.user-credential-detection is.best-practice" );
        $stdoutarray['url-credential best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "url.user-credential-detection is.adoption" );
        $stdoutarray['url-credential adoption'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "dns-list is.visibility" );
        $stdoutarray['dns-list visibility'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "dns-list is.best-practice" );
        $stdoutarray['dns-list best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "dns-list is.adoption" );
        $stdoutarray['dns-list adoption'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "dns-security is.visibility" );
        $stdoutarray['dns-security visibility'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "dns-security is.best-practice" );
        $stdoutarray['dns-security best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "dns-security is.adoption" );
        $stdoutarray['dns-security adoption'] = count( $sub_ruleStore->rules( $filter_array ) );



        $this->bp_calculation( $stdoutarray );



        $percentageArray = $this->get_bp_percentageArray( $stdoutarray );

        $stdoutarray['percentage'] = $percentageArray;


        return $stdoutarray;
    }

    public function bp_calculation( &$stdoutarray ): void
    {
        $ruleForCalculation = $stdoutarray['security rules allow enabled'];

        //Logging
        $stdoutarray['log at end calc'] = $stdoutarray['log at end']."/".$stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['log at end percentage'] = floor(( $stdoutarray['log at end'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['log at end percentage'] = 0;

        $stdoutarray['log at not start calc'] = $stdoutarray['log at not start']."/".$stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['log at not start percentage'] = floor(( $stdoutarray['log at not start'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['log at not start percentage'] = 0;

        //Log Forwarding Profiles
        $stdoutarray['log prof set calc'] = $stdoutarray['log prof set']."/".$stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['log prof set percentage'] = floor(( $stdoutarray['log prof set'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['log prof set percentage'] = 0;

        //Wildfire Analysis Profiles
        $stdoutarray['wf visibility calc'] = $stdoutarray['wf visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['wf visibility percentage'] = floor(( $stdoutarray['wf visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['wf visibility percentage'] = 0;
        //--

        $stdoutarray['wf best-practice calc'] = $stdoutarray['wf best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['wf best-practice percentage'] = floor( ( $stdoutarray['wf best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['wf best-practice percentage'] = 0;
        //--

        $stdoutarray['wf adoption calc'] = $stdoutarray['wf adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['wf adoption percentage'] = floor(( $stdoutarray['wf adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['wf adoption percentage'] = 0;

        //Zone Protection
        $stdoutarray['zone protection calc'] = $stdoutarray['zone protection']."/".$stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['zone protection percentage'] = floor( ( $stdoutarray['zone protection'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['zone protection percentage'] = 0;

        // App-ID
        $stdoutarray['app id calc'] = $stdoutarray['app id']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['app id percentage'] = floor( ( $stdoutarray['app id'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['app id percentage'] = 0;

        //User-ID
        $stdoutarray['user id calc'] = $stdoutarray['user id']."/".$stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['user id percentage'] = floor( ( $stdoutarray['user id'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['user id percentage'] = 0;

        //Service/Port
        $stdoutarray['service port calc'] = $stdoutarray['service port']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['service port percentage'] = floor( ( $stdoutarray['service port'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['service port percentage'] = 0;

        //Antivirus Profiles
        $stdoutarray['av visibility calc'] = $stdoutarray['av visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['av visibility percentage'] = floor( ( $stdoutarray['av visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['av visibility percentage'] = 0;
        //--
        $stdoutarray['av best-practice calc'] = $stdoutarray['av best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['av best-practice percentage'] = floor( ( $stdoutarray['av best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['av best-practice percentage'] = 0;
        //--
        $stdoutarray['av adoption calc'] = $stdoutarray['av adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['av adoption percentage'] = floor( ( $stdoutarray['av adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['av adoption percentage'] = 0;


        //Anti-Spyware Profiles
        $stdoutarray['as visibility calc'] = $stdoutarray['as visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['as visibility percentage'] = floor( ( $stdoutarray['as visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['as visibility percentage'] = 0;
        //--
        $stdoutarray['as visibility rules calc'] = $stdoutarray['as visibility rules']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['as visibility rules percentage'] = floor( ( $stdoutarray['as visibility rules'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['as visibility rules percentage'] = 0;
        //--
        $stdoutarray['as visibility mica-engine calc'] = $stdoutarray['as visibility mica-engine']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['as visibility mica-engine percentage'] = floor( ( $stdoutarray['as visibility mica-engine'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['as visibility mica-engine percentage'] = 0;
        //--
        $stdoutarray['as best-practice calc'] = $stdoutarray['as best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['as best-practice percentage'] = floor( ( $stdoutarray['as best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['as best-practice percentage'] = 0;
        //--
        $stdoutarray['as best-practice rules calc'] = $stdoutarray['as best-practice rules']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['as best-practice rules percentage'] = floor( ( $stdoutarray['as best-practice rules'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['as best-practice rules percentage'] = 0;
        //--
        $stdoutarray['as best-practice mica-engine calc'] = $stdoutarray['as best-practice mica-engine']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['as best-practice mica-engine percentage'] = floor( ( $stdoutarray['as best-practice mica-engine'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['as best-practice mica-engine percentage'] = 0;
        //--
        $stdoutarray['as adoption calc'] = $stdoutarray['as adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['as adoption percentage'] = floor( ( $stdoutarray['as adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['as adoption percentage'] = 0;


        //Vulnerability Profiles
        $stdoutarray['vp visibility calc'] = $stdoutarray['vp visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['vp visibility percentage'] = floor( ( $stdoutarray['vp visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['vp visibility percentage'] = 0;
        //--
        $stdoutarray['vp visibility rules calc'] = $stdoutarray['vp visibility rules']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['vp visibility rules percentage'] = floor( ( $stdoutarray['vp visibility rules'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['vp visibility rules percentage'] = 0;
        //--

        $stdoutarray['vp visibility mica-engine calc'] = $stdoutarray['vp visibility mica-engine']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['vp visibility mica-engine percentage'] = floor( ( $stdoutarray['vp visibility mica-engine'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['vp visibility mica-engine percentage'] = 0;
        //--

        $stdoutarray['vp best-practice calc'] = $stdoutarray['vp best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['vp best-practice percentage'] = floor( ( $stdoutarray['vp best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['vp best-practice percentage'] = 0;
        //--

        $stdoutarray['vp best-practice rules calc'] = $stdoutarray['vp best-practice rules']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['vp best-practice rules percentage'] = floor( ( $stdoutarray['vp best-practice rules'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['vp best-practice rules percentage'] = 0;
        //--
        $stdoutarray['vp best-practice mica-engine calc'] = $stdoutarray['vp best-practice mica-engine']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['vp best-practice mica-engine percentage'] = floor( ( $stdoutarray['vp best-practice mica-engine'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['vp best-practice mica-engine percentage'] = 0;
        //--

        $stdoutarray['vp adoption calc'] = $stdoutarray['vp adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['vp adoption percentage'] = floor( ( $stdoutarray['vp adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['vp adoption percentage'] = 0;

        //File Blocking Profiles
        $stdoutarray['fb visibility calc'] = $stdoutarray['fb visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['fb visibility percentage'] = floor( ( $stdoutarray['fb visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['fb visibility percentage'] = 0;
        //--
        $stdoutarray['fb best-practice calc'] = $stdoutarray['fb best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['fb best-practice percentage'] = floor( ( $stdoutarray['fb best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['fb best-practice percentage'] = 0;
        //--
        $stdoutarray['fb adoption calc'] = $stdoutarray['fb adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['fb adoption percentage'] = floor( ( $stdoutarray['fb adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['fb adoption percentage'] = 0;

        //Data Filtering
        $stdoutarray['data visibility calc'] = $stdoutarray['data visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['data visibility percentage'] = floor( ( $stdoutarray['data visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['data visibility percentage'] = 0;
        $stdoutarray['data best-practice'] = "NOT available";
        //--
        //--
        $stdoutarray['data adoption calc'] = $stdoutarray['data adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['data adoption percentage'] = floor( ( $stdoutarray['data adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['data adoption percentage'] = 0;

        //URL Filtering Profiles
        $stdoutarray['url-site-access visibility calc'] = $stdoutarray['url-site-access visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-site-access visibility percentage'] = floor( ( $stdoutarray['url-site-access visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-site-access visibility percentage'] = 0;
        //--
        $stdoutarray['url-site-access best-practice calc'] = $stdoutarray['url-site-access best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-site-access best-practice percentage'] = floor( ( $stdoutarray['url-site-access best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-site-access best-practice percentage'] = 0;
        //--
        $stdoutarray['url-site-access adoption calc'] = $stdoutarray['url-site-access adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-site-access adoption percentage'] = floor( ( $stdoutarray['url-site-access adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-site-access adoption percentage'] = 0;

        //Credential Theft Prevention
        $stdoutarray['url-credential visibility calc'] = $stdoutarray['url-credential visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-credential visibility percentage'] = floor( ( $stdoutarray['url-credential visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-credential visibility percentage'] = 0;
        //--
        $stdoutarray['url-credential best-practice calc'] = $stdoutarray['url-credential best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-credential best-practice percentage'] = floor( ( $stdoutarray['url-credential best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-credential best-practice percentage'] = 0;
        //--
        $stdoutarray['url-credential adoption calc'] = $stdoutarray['url-credential adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-credential adoption percentage'] = floor( ( $stdoutarray['url-credential adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-credential adoption percentage'] = 0;

        //DNS List
        $stdoutarray['dns-list visibility calc'] = $stdoutarray['dns-list visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-list visibility percentage'] = floor( ( $stdoutarray['dns-list visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-list visibility percentage'] = 0;
        //--

        $stdoutarray['dns-list best-practice calc'] = $stdoutarray['dns-list best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-list best-practice percentage'] = floor( ( $stdoutarray['dns-list best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-list best-practice percentage'] = 0;
        //--
        $stdoutarray['dns-list adoption calc'] = $stdoutarray['dns-list adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-list adoption percentage'] = floor( ( $stdoutarray['dns-list adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-list adoption percentage'] = 0;

        //DNS Security
        $stdoutarray['dns-security visibility calc'] = $stdoutarray['dns-security visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-security visibility percentage'] = floor( ( $stdoutarray['dns-security visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-security visibility percentage'] = 0;
        //--

        $stdoutarray['dns-security best-practice calc'] = $stdoutarray['dns-security best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-security best-practice percentage'] = floor( ( $stdoutarray['dns-security best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-security best-practice percentage'] = 0;
        //--
        $stdoutarray['dns-security adoption calc'] = $stdoutarray['dns-security adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-security adoption percentage'] = floor( ( $stdoutarray['dns-security adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-security adoption percentage'] = 0;
    }


    public function get_bp_percentageArray( $stdoutarray ): array
    {

        $percentageArray = array();

        $percentageArray_adoption = array();
        $percentageArray_adoption['Logging']['value'] = $stdoutarray['log at end percentage'];
        $percentageArray_adoption['Logging']['group'] = 'Logging';
        $percentageArray_adoption['Log Forwarding Profiles']['value'] = $stdoutarray['log prof set percentage'];
        $percentageArray_adoption['Log Forwarding Profiles']['group'] = 'Logging';
        $percentageArray_adoption['Wildfire Analysis Profiles']['value'] = $stdoutarray['wf adoption percentage'];
        $percentageArray_adoption['Wildfire Analysis Profiles']['group'] = 'Wildfire';
        $percentageArray_adoption['Zone Protection']['value'] = $stdoutarray['zone protection percentage'];
        $percentageArray_adoption['Zone Protection']['group'] = 'Zone Protection';
        $percentageArray_adoption['App-ID']['value'] = $stdoutarray['app id percentage'];
        $percentageArray_adoption['App-ID']['group'] = 'Apps, Users, Ports';
        $percentageArray_adoption['User-ID']['value'] = $stdoutarray['user id percentage'];
        $percentageArray_adoption['User-ID']['group'] = 'Apps, Users, Ports';
        $percentageArray_adoption['Service/Port']['value'] = $stdoutarray['service port percentage'];
        $percentageArray_adoption['Service/Port']['group'] = 'Apps, Users, Ports';

        $percentageArray_adoption['Antivirus Profiles']['value'] = $stdoutarray['av adoption percentage'];
        $percentageArray_adoption['Antivirus Profiles']['group'] = 'Threat Prevention';
        $percentageArray_adoption['Anti-Spyware Profiles']['value'] = $stdoutarray['as adoption percentage'];
        $percentageArray_adoption['Anti-Spyware Profiles']['group'] = 'Threat Prevention';
        $percentageArray_adoption['Vulnerability Profiles']['value'] = $stdoutarray['vp adoption percentage'];
        $percentageArray_adoption['Vulnerability Profiles']['group'] = 'Threat Prevention';
        $percentageArray_adoption['File Blocking Profiles']['value'] = $stdoutarray['fb adoption percentage'];
        $percentageArray_adoption['File Blocking Profiles']['group'] = 'Data Loss Prevention';
        $percentageArray_adoption['Data Filtering']['value'] = $stdoutarray['data adoption percentage'];
        $percentageArray_adoption['Data Filtering']['group'] = 'Data Loss Prevention';
        $percentageArray_adoption['URL Filtering Profiles']['value'] = $stdoutarray['url-site-access adoption percentage'];
        $percentageArray_adoption['URL Filtering Profiles']['group'] = 'URL Filtering';
        $percentageArray_adoption['Credential Theft Prevention']['value'] = $stdoutarray['url-credential adoption percentage'];
        $percentageArray_adoption['Credential Theft Prevention']['group'] = 'URL Filtering';
        $percentageArray_adoption['DNS List']['value'] = $stdoutarray['dns-list adoption percentage'];
        $percentageArray_adoption['DNS List']['group'] = 'DNS Security';

        $percentageArray_adoption['DNS Security']['value'] = $stdoutarray['dns-security adoption percentage'];
        $percentageArray_adoption['DNS Security']['group'] = 'DNS Security';

        $percentageArray['adoption'] = $percentageArray_adoption;


        //-------------
        $percentageArray_visibility = array();
        $percentageArray_visibility['Logging']['value'] = $stdoutarray['log at end percentage'];
        $percentageArray_visibility['Logging']['group'] = 'Logging';
        $percentageArray_visibility['Log Forwarding Profiles']['value'] = $stdoutarray['log prof set percentage'];
        $percentageArray_visibility['Log Forwarding Profiles']['group'] = 'Logging';
        $percentageArray_visibility['Wildfire Analysis Profiles']['value'] = $stdoutarray['wf visibility percentage'];
        $percentageArray_visibility['Wildfire Analysis Profiles']['group'] = 'Wildfire';
        $percentageArray_visibility['Zone Protection']['value'] = $stdoutarray['zone protection percentage'];
        $percentageArray_visibility['Zone Protection']['group'] = 'Zone Protection';
        $percentageArray_visibility['App-ID']['value'] = $stdoutarray['app id percentage'];
        $percentageArray_visibility['App-ID']['group'] = 'Apps, Users, Ports';
        $percentageArray_visibility['User-ID']['value'] = $stdoutarray['user id percentage'];
        $percentageArray_visibility['User-ID']['group'] = 'Apps, Users, Ports';
        $percentageArray_visibility['Service/Port']['value'] = $stdoutarray['service port percentage'];
        $percentageArray_visibility['Service/Port']['group'] = 'Apps, Users, Ports';

        $percentageArray_visibility['Antivirus Profiles']['value'] = $stdoutarray['av visibility percentage'];
        $percentageArray_visibility['Antivirus Profiles']['group'] = 'Threat Prevention';
        $percentageArray_visibility['Anti-Spyware Profiles']['value'] = $stdoutarray['as visibility percentage'];
        $percentageArray_visibility['Anti-Spyware Profiles']['group'] = 'Threat Prevention';
        $percentageArray_visibility['Anti-Spyware Rules']['value'] = $stdoutarray['as visibility rules percentage'];
        $percentageArray_visibility['Anti-Spyware Rules']['group'] = 'Threat Prevention';
        $percentageArray_visibility['Anti-Spyware InLine ML']['value'] = $stdoutarray['as visibility mica-engine percentage'];
        $percentageArray_visibility['Anti-Spyware InLine ML']['group'] = 'Threat Prevention';

        $percentageArray_visibility['Vulnerability Profiles']['value'] = $stdoutarray['vp visibility percentage'];
        $percentageArray_visibility['Vulnerability Profiles']['group'] = 'Threat Prevention';
        $percentageArray_visibility['Vulnerability Rules']['value'] = $stdoutarray['vp visibility rules percentage'];
        $percentageArray_visibility['Vulnerability Rules']['group'] = 'Threat Prevention';
        $percentageArray_visibility['Vulnerability InLine ML']['value'] = $stdoutarray['vp visibility mica-engine percentage'];
        $percentageArray_visibility['Vulnerability InLine ML']['group'] = 'Threat Prevention';

        $percentageArray_visibility['File Blocking Profiles']['value'] = $stdoutarray['fb visibility percentage'];
        $percentageArray_visibility['File Blocking Profiles']['group'] = 'Data Loss Prevention';
        $percentageArray_visibility['Data Filtering']['value'] = $stdoutarray['data visibility percentage'];
        $percentageArray_visibility['Data Filtering']['group'] = 'Data Loss Prevention';
        $percentageArray_visibility['URL Filtering Profiles']['value'] = $stdoutarray['url-site-access visibility percentage'];
        $percentageArray_visibility['URL Filtering Profiles']['group'] = 'URL Filtering';
        $percentageArray_visibility['Credential Theft Prevention']['value'] = $stdoutarray['url-credential visibility percentage'];
        $percentageArray_visibility['Credential Theft Prevention']['group'] = 'URL Filtering';
        $percentageArray_visibility['DNS List']['value'] = $stdoutarray['dns-list visibility percentage'];
        $percentageArray_visibility['DNS List']['group'] = 'DNS Security';

        $percentageArray_visibility['DNS Security']['value'] = $stdoutarray['dns-security visibility percentage'];
        $percentageArray_visibility['DNS Security']['group'] = 'DNS Security';

        $percentageArray['visibility'] = $percentageArray_visibility;



        $percentageArray_best_practice = array();
        $percentageArray_best_practice['Logging']['value'] = $stdoutarray['log at not start percentage'];
        $percentageArray_best_practice['Logging']['group'] = 'Logging';
        #$percentageArray_best_practice['Log Forwarding Profiles']['value'] = $stdoutarray['log prof set percentage'];
        $percentageArray_best_practice['Wildfire Analysis Profiles']['value'] = $stdoutarray['wf best-practice percentage'];
        $percentageArray_best_practice['Wildfire Analysis Profiles']['group'] = 'Wildfire';

        #$percentageArray_best_practice['Zone Protection']['value'] = '---';
        #$percentageArray_best_practice['App-ID']['value'] = $stdoutarray['app id percentage'];
        #$percentageArray_best_practice['User-ID']['value'] = $stdoutarray['user id percentage'];
        #$percentageArray_best_practice['Service/Port']['value'] = $stdoutarray['service port percentage'];

        $percentageArray_best_practice['Antivirus Profiles']['value'] = $stdoutarray['av best-practice percentage'];
        $percentageArray_best_practice['Antivirus Profiles']['group'] = 'Threat Prevention';
        $percentageArray_best_practice['Anti-Spyware Profiles']['value'] = $stdoutarray['as best-practice percentage'];
        $percentageArray_best_practice['Anti-Spyware Profiles']['group'] = 'Threat Prevention';
        $percentageArray_best_practice['Anti-Spyware Rules']['value'] = $stdoutarray['as best-practice rules percentage'];
        $percentageArray_best_practice['Anti-Spyware Rules']['group'] = 'Threat Prevention';
        $percentageArray_best_practice['Anti-Spyware InLine ML']['value'] = $stdoutarray['as best-practice mica-engine percentage'];
        $percentageArray_best_practice['Anti-Spyware InLine ML']['group'] = 'Threat Prevention';
        $percentageArray_best_practice['Vulnerability Profiles']['value'] = $stdoutarray['vp best-practice percentage'];
        $percentageArray_best_practice['Vulnerability Profiles']['group'] = 'Threat Prevention';
        $percentageArray_best_practice['Vulnerability Rules']['value'] = $stdoutarray['vp best-practice rules percentage'];
        $percentageArray_best_practice['Vulnerability Rules']['group'] = 'Threat Prevention';
        $percentageArray_best_practice['Vulnerability InLine ML']['value'] = $stdoutarray['vp best-practice mica-engine percentage'];
        $percentageArray_best_practice['Vulnerability InLine ML']['group'] = 'Threat Prevention';

        $percentageArray_best_practice['File Blocking Profiles']['value'] = $stdoutarray['fb best-practice percentage'];
        $percentageArray_best_practice['File Blocking Profiles']['group'] = 'Data Loss Prevention';

        $percentageArray_best_practice['Data Filtering']['value'] = $stdoutarray['data adoption percentage'];
        $percentageArray_best_practice['Data Filtering']['group'] = 'Data Loss Prevention';

        $percentageArray_best_practice['URL Filtering Profiles']['value'] = $stdoutarray['url-site-access best-practice percentage'];
        $percentageArray_best_practice['URL Filtering Profiles']['group'] = 'URL Filtering';
        $percentageArray_best_practice['Credential Theft Prevention']['value'] = $stdoutarray['url-credential best-practice percentage'];
        $percentageArray_best_practice['Credential Theft Prevention']['group'] = 'URL Filtering';
        $percentageArray_best_practice['DNS List']['value'] = $stdoutarray['dns-list best-practice percentage'];
        $percentageArray_best_practice['DNS List']['group'] = 'DNS Security';

        $percentageArray_best_practice['DNS Security']['value'] = $stdoutarray['dns-security best-practice percentage'];
        $percentageArray_best_practice['DNS Security']['group'] = 'DNS Security';

        $percentageArray['best-practice'] = $percentageArray_best_practice;

        return $percentageArray;
    }

    public function display_bp_statistics( $debug = false, $actions = "display" ): void
    {
        $stdoutarray = $this->get_bp_statistics();
        PH::$JSON_TMP[] = $stdoutarray;


        $this->generate_table($stdoutarray, $debug, $actions);
    }

    public function generate_table( $stdoutarray, $debug = false, $actions = 'display' )
    {
        $header = $stdoutarray['header'];


        PH::validateIncludedInBPA( $stdoutarray );

        $percentageArray_adoption = $stdoutarray['percentage']['adoption'];
        $percentageArray_visibility = $stdoutarray['percentage']['visibility'];
        $percentageArray_best_practice = $stdoutarray['percentage']['best-practice'];

        if( !PH::$shadow_json && $actions == "display-bpa")
        {
            PH::print_stdout( $header );

            $string_check = "adoption";
            $this->print_table( $string_check, $percentageArray_adoption);


            $string_check = "visibility";
            $this->print_table( $string_check, $percentageArray_visibility);


            $string_check = "best-practice";
            $this->print_table( $string_check, $percentageArray_best_practice);

            PH::print_stdout( );
        }



        if( !PH::$shadow_json && $debug && $actions == "display-bpa" )
            PH::print_stdout( $stdoutarray, true );

        if( $actions == "display-available" )
        {
            PH::stats_remove_zero_arrays($stdoutarray);
            if( !PH::$shadow_json )
                PH::print_stdout( $stdoutarray, true );
        }

        if( $actions == "display-bpa" )
            PH::$JSON_TMP[] = $stdoutarray;
    }

    private function print_table( $string_check, $percentageArray )
    {
        PH::print_stdout($string_check);
        $tbl = new ConsoleTable();
        $tbl->setHeaders(
            array('Type', 'percentage', "%")
        );
        foreach( $percentageArray as $key => $value )
        {
            if( strpos($value['value'], "---") !== False )
            {
                $string = $value['value'];
            }
            else
            {
                $string = "";
                $test = floor( ($value['value']/10) * 2 );
                $string = str_pad($string, $test, "*", STR_PAD_LEFT);
            }
            $tbl->addRow(array($key, $value['value'], $string));
        }

        echo $tbl->getTable();
    }
}
