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

    public function display_mainDevice_statistics( &$stdoutarray, $statsArray, $sub, $subName, $header): void
    {
        $stdoutarray['header'] = $header;

        $stdoutarray['pre security rules'] = array();
        $stdoutarray['pre security rules'][$subName] = $sub->securityRules->countPreRules();
        $stdoutarray['pre security rules']['total_DGs'] = $statsArray['gpreSecRules'];

        $stdoutarray['post security rules'] = array();
        $stdoutarray['post security rules'][$subName] = $sub->securityRules->countPostRules();
        $stdoutarray['post security rules']['total_DGs'] = $statsArray['gpostSecRules'];


        $stdoutarray['pre nat rules'] = array();
        $stdoutarray['pre nat rules'][$subName] = $sub->natRules->countPreRules();
        $stdoutarray['pre nat rules']['total_DGs'] = $statsArray['gpreNatRules'];

        $stdoutarray['post nat rules'] = array();
        $stdoutarray['post nat rules'][$subName] = $sub->natRules->countPostRules();
        $stdoutarray['post nat rules']['total_DGs'] = $statsArray['gpostNatRules'];


        $stdoutarray['pre qos rules'] = array();
        $stdoutarray['pre qos rules'][$subName] = $sub->qosRules->countPreRules();
        $stdoutarray['pre qos rules']['total_DGs'] = $statsArray['gpreQoSRules'];

        $stdoutarray['post qos rules'] = array();
        $stdoutarray['post qos rules'][$subName] = $sub->qosRules->countPostRules();
        $stdoutarray['post qos rules']['total_DGs'] = $statsArray['gpostQoSRules'];


        $stdoutarray['pre pbf rules'] = array();
        $stdoutarray['pre pbf rules'][$subName] = $sub->pbfRules->countPreRules();
        $stdoutarray['pre pbf rules']['total_DGs'] = $statsArray['gprePbfRules'];

        $stdoutarray['post pbf rules'] = array();
        $stdoutarray['post pbf rules'][$subName] = $sub->pbfRules->countPostRules();
        $stdoutarray['post pbf rules']['total_DGs'] = $statsArray['gpostPbfRules'];


        $stdoutarray['pre decryption rules'] = array();
        $stdoutarray['pre decryption rules'][$subName] = $sub->decryptionRules->countPreRules();
        $stdoutarray['pre decryption rules']['total_DGs'] = $statsArray['gpreDecryptRules'];

        $stdoutarray['post decryption rules'] = array();
        $stdoutarray['post decryption rules'][$subName] = $sub->decryptionRules->countPostRules();
        $stdoutarray['post decryption rules']['total_DGs'] = $statsArray['gpostDecryptRules'];


        $stdoutarray['pre app-override rules'] = array();
        $stdoutarray['pre app-override rules'][$subName] = $sub->appOverrideRules->countPreRules();
        $stdoutarray['pre app-override rules']['total_DGs'] = $statsArray['gpreAppOverrideRules'];

        $stdoutarray['post app-override rules'] = array();
        $stdoutarray['post app-override rules'][$subName] = $sub->appOverrideRules->countPostRules();
        $stdoutarray['post app-override rules']['total_DGs'] = $statsArray['gpostAppOverrideRules'];


        $stdoutarray['pre capt-portal rules'] = array();
        $stdoutarray['pre capt-portal rules'][$subName] = $sub->captivePortalRules->countPreRules();
        $stdoutarray['pre capt-portal rules']['total_DGs'] = $statsArray['gpreCPRules'];

        $stdoutarray['post capt-portal rules'] = array();
        $stdoutarray['post capt-portal rules'][$subName] = $sub->captivePortalRules->countPostRules();
        $stdoutarray['post capt-portal rules']['total_DGs'] = $statsArray['gpostCPRules'];


        $stdoutarray['pre authentication rules'] = array();
        $stdoutarray['pre authentication rules'][$subName] = $sub->authenticationRules->countPreRules();
        $stdoutarray['pre authentication rules']['total_DGs'] = $statsArray['gpreAuthRules'];

        $stdoutarray['post authentication rules'] = array();
        $stdoutarray['post authentication rules'][$subName] = $sub->authenticationRules->countPostRules();
        $stdoutarray['post authentication rules']['total_DGs'] = $statsArray['gpostAuthRules'];


        $stdoutarray['pre dos rules'] = array();
        $stdoutarray['pre dos rules'][$subName] = $sub->dosRules->countPreRules();
        $stdoutarray['pre dos rules']['total_DGs'] = $statsArray['gpreDoSRules'];

        $stdoutarray['post dos rules'] = array();
        $stdoutarray['post dos rules'][$subName] = $sub->dosRules->countPostRules();
        $stdoutarray['post dos rules']['total_DGs'] = $statsArray['gpostDoSRules'];

        $stdoutarray['pre tunnel-inspection rules'] = array();
        $stdoutarray['pre tunnel-inspection rules'][$subName] = $sub->tunnelInspectionRules->countPreRules();
        $stdoutarray['pre tunnel-inspection rules']['total_DGs'] = $statsArray['gpreTunnelInspectionRules'];

        $stdoutarray['post tunnel-inspection rules'] = array();
        $stdoutarray['post tunnel-inspection rules'][$subName] = $sub->tunnelInspectionRules->countPostRules();
        $stdoutarray['post tunnel-inspection rules']['total_DGs'] = $statsArray['gpostTunnelInspectionRules'];

        #pre default-security not existent
        #$stdoutarray['pre default-security rules'] = array();
        #$stdoutarray['pre default-security rules'][$subName] = $sub->defaultSecurityRules->countPreRules();
        #$stdoutarray['pre default-security rules']['total_DGs'] = $statsArray['gpreDefaultSecurityRules'];

        $stdoutarray['post default-security rules'] = array();
        $stdoutarray['post default-security rules'][$subName] = $sub->defaultSecurityRules->countPostRules();
        $stdoutarray['post default-security rules']['total_DGs'] = $statsArray['gpostDefaultSecurityRules'];

        $stdoutarray['pre network-packet-broker rules'] = array();
        $stdoutarray['pre network-packet-broker rules'][$subName] = $sub->networkPacketBrokerRules->countPreRules();
        $stdoutarray['pre network-packet-broker rules']['total_DGs'] = $statsArray['gpreNetworkPacketBrokerRules'];

        $stdoutarray['post network-packet-broker rules'] = array();
        $stdoutarray['post network-packet-broker rules'][$subName] = $sub->networkPacketBrokerRules->countPostRules();
        $stdoutarray['post network-packet-broker rules']['total_DGs'] = $statsArray['gpostNetworkPacketBrokerRules'];

        $stdoutarray['pre sdwan rules'] = array();
        $stdoutarray['pre sdwan rules'][$subName] = $sub->sdWanRules->countPreRules();
        $stdoutarray['pre sdwan rules']['total_DGs'] = $statsArray['gpreSDWanRules'];

        $stdoutarray['post sdwan rules'] = array();
        $stdoutarray['post sdwan rules'][$subName] = $sub->sdWanRules->countPostRules();
        $stdoutarray['post sdwan rules']['total_DGs'] = $statsArray['gpostSDWanRules'];

        $stdoutarray['address objects'] = array();
        $stdoutarray['address objects'][$subName] = $sub->addressStore->countAddresses();
        $stdoutarray['address objects']['total_DGs'] = $statsArray['gnaddresss'];
        $stdoutarray['address objects']['unused'] = $statsArray['gnaddresssUnused'];

        $stdoutarray['addressgroup objects'] = array();
        $stdoutarray['addressgroup objects'][$subName] = $sub->addressStore->countAddressGroups();
        $stdoutarray['addressgroup objects']['total_DGs'] = $statsArray['gnaddressGs'];
        $stdoutarray['addressgroup objects']['unused'] = $statsArray['gnaddressGsUnused'];

        $stdoutarray['temporary address objects'] = array();
        $stdoutarray['temporary address objects'][$subName] = $sub->addressStore->countTmpAddresses();
        $stdoutarray['temporary address objects']['total_DGs'] = $statsArray['gnTmpAddresses'];

        $stdoutarray['region objects'] = array();
        $stdoutarray['region objects'][$subName] = $sub->addressStore->countRegionObjects();
        $stdoutarray['region objects']['total_DGs'] = $statsArray['gnRegionAddresses'];

        $stdoutarray['service objects'] = array();
        $stdoutarray['service objects'][$subName] = $sub->serviceStore->countServices();
        $stdoutarray['service objects']['total_DGs'] = $statsArray['gnservices'];
        $stdoutarray['service objects']['unused'] = $statsArray['gnservicesUnused'];

        $stdoutarray['servicegroup objects'] = array();
        $stdoutarray['servicegroup objects'][$subName] = $sub->serviceStore->countServiceGroups();
        $stdoutarray['servicegroup objects']['total_DGs'] = $statsArray['gnserviceGs'];
        $stdoutarray['servicegroup objects']['unused'] = $statsArray['gnserviceGsUnused'];

        $stdoutarray['temporary service objects'] = array();
        $stdoutarray['temporary service objects'][$subName] = $sub->serviceStore->countTmpServices();
        $stdoutarray['temporary service objects']['total_DGs'] = $statsArray['gnTmpServices'];


        $stdoutarray['tag objects'] = array();
        $stdoutarray['tag objects'][$subName] = $sub->tagStore->count();
        $stdoutarray['tag objects']['total_DGs'] = $statsArray['gTagCount'];
        $stdoutarray['tag objects']['unused'] = $statsArray['gTagUnusedCount'];

        $stdoutarray['securityProfileGroup objects'] = array();
        $stdoutarray['securityProfileGroup objects'][$subName] = $sub->securityProfileGroupStore->count();
        $stdoutarray['securityProfileGroup objects']['total_DGs'] = $statsArray['gnsecurityprofileGs'];


        $stdoutarray['Anti-Spyware objects'] = array();
        $stdoutarray['Anti-Spyware objects'][$subName] = $sub->AntiSpywareProfileStore->count();
        $stdoutarray['Anti-Spyware objects']['total_DGs'] = $statsArray['gnantispyware'];
        $stdoutarray['Vulnerability objects'] = array();
        $stdoutarray['Vulnerability objects'][$subName] = $sub->VulnerabilityProfileStore->count();
        $stdoutarray['Vulnerability objects']['total_DGs'] = $statsArray['gnvulnerability'];


        if( get_class($this) == "PanoramaConf" )
        {
            $stdoutarray['Antivirus objects'] = array();
            $stdoutarray['Antivirus objects'][$subName] = $sub->AntiVirusProfileStore->count();
            $stdoutarray['Antivirus objects']['total_DGs'] = $statsArray['gnantivirus'];
            $stdoutarray['Wildfire objects'] = array();
            $stdoutarray['Wildfire objects'][$subName] = $sub->WildfireProfileStore->count();
            $stdoutarray['Wildfire objects']['total_DGs'] = $statsArray['gnwildfire'];
        }


        if( get_class($this) == "BuckbeakConf" )
        {
            $stdoutarray['WildfireAndAnti-Virus objects'] = array();
            $stdoutarray['WildfireAndAnti-Virus objects'][$subName] = $sub->VirusAndWildfireProfileStore->count();
            $stdoutarray['WildfireAndAnti-Virus objects']['total_DGs'] = $statsArray['gnsecprofAVWF'];
        }



        $stdoutarray['URL objects'] = array();
        $stdoutarray['URL objects'][$subName] = $sub->URLProfileStore->count();
        $stdoutarray['URL objects']['total_DGs'] = $statsArray['gnurlprofil'];
        $stdoutarray['custom URL objects'] = array();
        $stdoutarray['custom URL objects'][$subName] = $sub->customURLProfileStore->count();
        $stdoutarray['custom URL objects']['total_DGs'] = $statsArray['gncustomurlprofil'];

        $stdoutarray['File-Blocking objects'] = array();
        $stdoutarray['File-Blocking objects'][$subName] = $sub->FileBlockingProfileStore->count();
        $stdoutarray['File-Blocking objects']['total_DGs'] = $statsArray['gnfileblocking'];
        $stdoutarray['Decryption objects'] = array();
        $stdoutarray['Decryption objects'][$subName] = $sub->DecryptionProfileStore->count();
        $stdoutarray['Decryption objects']['total_DGs'] = $statsArray['gndecryption'];

        $stdoutarray['HipObject objects'] = array();
        $stdoutarray['HipObject objects'][$subName] = $sub->HipObjectsProfileStore->count();
        $stdoutarray['HipObject objects']['total_DGs'] = $statsArray['gnhipobjects'];
        $stdoutarray['HipProfile objects'] = array();
        $stdoutarray['HipProfile objects'][$subName] = $sub->HipProfilesProfileStore->count();
        $stdoutarray['HipProfile objects']['total_DGs'] = $statsArray['gnhipprofiles'];

        $stdoutarray['GTP objects'] = array();
        $stdoutarray['GTP objects'][$subName] = $sub->GTPProfileStore->count();
        $stdoutarray['GTP objects']['total_DGs'] = $statsArray['gngtp'];
        $stdoutarray['SCEP objects'] = array();
        $stdoutarray['SCEP objects'][$subName] = $sub->SCEPProfileStore->count();
        $stdoutarray['SCEP objects']['total_DGs'] = $statsArray['gnscep'];
        $stdoutarray['PacketBroker objects'] = array();
        $stdoutarray['PacketBroker objects'][$subName] = $sub->PacketBrokerProfileStore->count();
        $stdoutarray['PacketBroker objects']['total_DGs'] = $statsArray['gnpacketbroker'];

        $stdoutarray['SDWanErrorCorrection objects'] = array();
        $stdoutarray['SDWanErrorCorrection objects'][$subName] = $sub->SDWanErrorCorrectionProfileStore->count();
        $stdoutarray['SDWanErrorCorrection objects']['total_DGs'] = $statsArray['gnsdwanerrorcorrection'];
        $stdoutarray['SDWanPathQuality objects'] = array();
        $stdoutarray['SDWanPathQuality objects'][$subName] = $sub->SDWanPathQualityProfileStore->count();
        $stdoutarray['SDWanPathQuality objects']['total_DGs'] = $statsArray['gnsdwanpathquality'];
        $stdoutarray['SDWanSaasQuality objects'] = array();
        $stdoutarray['SDWanSaasQuality objects'][$subName] = $sub->SDWanSaasQualityProfileStore->count();
        $stdoutarray['SDWanSaasQuality objects']['total_DGs'] = $statsArray['gnsdwansaasquality'];
        $stdoutarray['SDWanTrafficDistribution objects'] = array();
        $stdoutarray['SDWanTrafficDistribution objects'][$subName] = $sub->SDWanTrafficDistributionProfileStore->count();
        $stdoutarray['SDWanTrafficDistribution objects']['total_DGs'] = $statsArray['gnsdwantrafficdistribution'];

        $stdoutarray['DataObjects objects'][$subName] = $sub->DataObjectsProfileStore->count();
        $stdoutarray['DataObjects objects']['total_DGs'] = $statsArray['gndataobjects'];

        $stdoutarray['LogProfile objects'] = array();
        $stdoutarray['LogProfile objects'][$subName] = $sub->LogProfileStore->count();
        $stdoutarray['LogProfile objects']['total_DGs'] = $statsArray['gLogProfileCount'];

        $stdoutarray['zones'] = $sub->zoneStore->count();
        #$stdoutarray['apps'] = $sub->appStore->count();

        /*
        $stdoutarray['interfaces'] = array();
        $stdoutarray['interfaces']['total'] = $numInterfaces;
        $stdoutarray['interfaces']['ethernet'] = $sub->network->ethernetIfStore->count();

        $stdoutarray['sub-interfaces'] = array();
        $stdoutarray['sub-interfaces']['total'] = $numSubInterfaces;
        $stdoutarray['sub-interfaces']['ethernet'] = $sub->network->ethernetIfStore->countSubInterfaces();
        */


        #$stdoutarray['certificate objects'] = array();
        #$stdoutarray['certificate objects']['total_Templates'] = $gCertificatCount;

        #$stdoutarray['SSL_TLSServiceProfile objects'] = array();
        #$stdoutarray['SSL_TLSServiceProfile objects']['total_Templates'] = $gSSL_TLSServiceProfileCount;



        //todo:
        //missing part size calculation
    }

    public function get_mainDevice_statistics( &$statsArray ): void
    {

        if( get_class($this) == "PANConf" )
        {
            $statsArray['gpreSecRules'] = 0;
            $statsArray['gpreNatRules'] = 0;
            $statsArray['gpreDecryptRules'] = 0;
            $statsArray['gpreAppOverrideRules'] = 0;
            $statsArray['gpreCPRules'] = 0;
            $statsArray['gpreAuthRules'] = 0;
            $statsArray['gprePbfRules'] = 0;
            $statsArray['gpreQoSRules'] = 0;
            $statsArray['gpreDoSRules'] = 0;

            $statsArray['gpreTunnelInspectionRules'] = 0;
            $statsArray['gpreDefaultSecurityRules'] = 0;
            $statsArray['gpreNetworkPacketBrokerRules'] = 0;
            $statsArray['gpreSDWanRules'] = 0;
        }
        else
        {
            $statsArray['gpreSecRules'] = $this->securityRules->countPreRules();
            $statsArray['gpreNatRules'] = $this->natRules->countPreRules();
            $statsArray['gpreDecryptRules'] = $this->decryptionRules->countPreRules();
            $statsArray['gpreAppOverrideRules'] = $this->appOverrideRules->countPreRules();
            $statsArray['gpreCPRules'] = $this->captivePortalRules->countPreRules();
            $statsArray['gpreAuthRules'] = $this->authenticationRules->countPreRules();
            $statsArray['gprePbfRules'] = $this->pbfRules->countPreRules();
            $statsArray['gpreQoSRules'] = $this->qosRules->countPreRules();
            $statsArray['gpreDoSRules'] = $this->dosRules->countPreRules();

            $statsArray['gpreTunnelInspectionRules'] = $this->tunnelInspectionRules->countPreRules();
            $statsArray['gpreDefaultSecurityRules'] = 0;
            $statsArray['gpreNetworkPacketBrokerRules'] = $this->networkPacketBrokerRules->countPreRules();
            $statsArray['gpreSDWanRules'] = $this->sdWanRules->countPreRules();


            $statsArray['gpostSecRules'] = $this->securityRules->countPostRules();
            $statsArray['gpostNatRules'] = $this->natRules->countPostRules();
            $statsArray['gpostDecryptRules'] = $this->decryptionRules->countPostRules();
            $statsArray['gpostAppOverrideRules'] = $this->appOverrideRules->countPostRules();
            $statsArray['gpostCPRules'] = $this->captivePortalRules->countPostRules();
            $statsArray['gpostAuthRules'] = $this->authenticationRules->countPostRules();
            $statsArray['gpostPbfRules'] = $this->pbfRules->countPostRules();
            $statsArray['gpostQoSRules'] = $this->qosRules->countPostRules();
            $statsArray['gpostDoSRules'] = $this->dosRules->countPostRules();

            $statsArray['gpostTunnelInspectionRules'] = $this->tunnelInspectionRules->countPostRules();
            $statsArray['gpostDefaultSecurityRules'] = $this->defaultSecurityRules->countPostRules();
            $statsArray['gpostNetworkPacketBrokerRules'] = $this->networkPacketBrokerRules->countPostRules();
            $statsArray['gpostSDWanRules'] = $this->sdWanRules->countPostRules();
        }



        $this->get_combined_objectDevice_statistics($statsArray);




        $this->get_size_statistics($statsArray );
    }


    public function get_combined_subDevice_statistics(array &$statsArray, $cur, bool $onlyPre = false): void
    {
        // Map of Stat Key Suffix => Property Name
        $ruleMaps = [
            'SecRules'                  => 'securityRules',
            'NatRules'                  => 'natRules',
            'DecryptRules'              => 'decryptionRules',
            'AppOverrideRules'          => 'appOverrideRules',
            'CPRules'                   => 'captivePortalRules',
            'AuthRules'                 => 'authenticationRules',
            'PbfRules'                  => 'pbfRules',
            'QoSRules'                  => 'qosRules',
            'DoSRules'                  => 'dosRules',
            'TunnelInspectionRules'     => 'tunnelInspectionRules',
            'DefaultSecurityRules'      => 'defaultSecurityRules',
            'NetworkPacketBrokerRules' => 'networkPacketBrokerRules',
            'SDWanRules'                => 'sdWanRules',
        ];

        foreach ($ruleMaps as $suffix => $prop)
        {
            // Ensure property exists on the object
            if (!isset($cur->$prop)) {
                continue;
            }

            if( $onlyPre )
            {
                $statsArray['gpre' . $suffix] += $cur->$prop->count();
            }
            else
            {
                $statsArray['gpre' . $suffix] += $cur->$prop->countPreRules();

                $statsArray['gpost' . $suffix] += $cur->$prop->countPostRules();
            }
        }

        $this->get_combined_objectDevice_statistics($statsArray, $cur, true);
        $this->get_size_statistics($statsArray, $cur, true);
    }



    public function get_combined_objectDevice_statistics(array &$statsArray, $targetObj = null, bool $accumulate = false): void
    {
        $cur = $targetObj ?? $this;
        $className = get_class($cur);

        // --- 1. Define Standard Mappings (Key => [StoreProperty, MethodName]) ---
        $standardMaps = [
            // Service Store
            'gnservices'        => ['serviceStore', 'countServices'],
            'gnservicesUnused'  => ['serviceStore', 'countUnusedServices'],
            'gnserviceGs'       => ['serviceStore', 'countServiceGroups'],
            'gnserviceGsUnused' => ['serviceStore', 'countUnusedServiceGroups'],
            'gnTmpServices'     => ['serviceStore', 'countTmpServices'],

            // Address Store
            'gnaddresss'        => ['addressStore', 'countAddresses'],
            'gnaddresssUnused'  => ['addressStore', 'countUnusedAddresses'],
            'gnaddressGs'       => ['addressStore', 'countAddressGroups'],
            'gnaddressGsUnused' => ['addressStore', 'countUnusedAddressGroups'],
            'gnTmpAddresses'    => ['addressStore', 'countTmpAddresses'],
            'gnRegionAddresses' => ['addressStore', 'countRegionObjects'],

            // Tag Store
            'gTagCount'         => ['tagStore', 'count'],
            'gTagUnusedCount'   => ['tagStore', 'countUnused'],

            // Security Profile Group
            'gnsecurityprofileGs' => ['securityProfileGroupStore', 'count'],

            // Basic Profiles
            'gnantispyware'   => ['AntiSpywareProfileStore', 'count'],
            'gnvulnerability' => ['VulnerabilityProfileStore', 'count'],
            'gnurlprofil'     => ['URLProfileStore', 'count'],
            'gncustomurlprofil' => ['customURLProfileStore', 'count'],

            // File & Decryption
            'gnfileblocking' => ['FileBlockingProfileStore', 'count'],
            'gndecryption'   => ['DecryptionProfileStore', 'count'],

            // HIP (Using logic from Main function: Objects->Objects, Profiles->Profiles)
            'gnhipobjects'    => ['HipObjectsProfileStore', 'count'],
            'gnhipprofiles'   => ['HipProfilesProfileStore', 'count'],

            // Logs
            'gLogProfileCount' => ['LogProfileStore', 'count'],
        ];

        // --- 2. Process Standard Mappings ---
        foreach ($standardMaps as $statKey => $map)
        {
            $store = $map[0];
            $method = $map[1];

            // Safety check: ensure store exists
            if (isset($cur->$store))
            {
                $val = $cur->$store->$method();
                if ($accumulate)
                {
                    if (!isset($statsArray[$statKey]))
                        $statsArray[$statKey] = 0;
                    $statsArray[$statKey] += $val;
                } else {
                    $statsArray[$statKey] = $val;
                }
            }
        }

        // --- 3. Handle Special Calculations (Size & Conditionals) ---

        // Identify Class Type for Conditionals
        $isPanConf = ($className === 'PANConf');
        $isVirtualSystem = ($className === 'VirtualSystem');
        $isPanoramaConf = ($className === 'PanoramaConf');
        $isFawkesLike = in_array($className, ['FawkesConf', 'BuckbeakConf', 'DeviceCloud', 'Container', 'DeviceOnPrem']);

        // Conditional: Interfaces (Only applicable to PANConf)
        if($isPanConf)
        {
            $numInterfaces = $cur->network->ipsecTunnelStore->count() + $cur->network->ethernetIfStore->count();
            $numSubInterfaces = $cur->network->ethernetIfStore->countSubInterfaces();

            if ($accumulate) {
                $statsArray['numInterfaces'] += $numInterfaces;
                $statsArray['numSubInterfaces'] += $numSubInterfaces;
            } else {
                $statsArray['numInterfaces'] = $numInterfaces;
                $statsArray['numSubInterfaces'] = $numSubInterfaces;
            }
        }

        // Conditional: AV & Wildfire (PANConf, Panorama, VSYS)
        if ($isPanConf || $isPanoramaConf || $isVirtualSystem)
        {
            $avCount = $cur->AntiVirusProfileStore->count();
            $wfCount = $cur->WildfireProfileStore->count();

            if ($accumulate)
            {
                $statsArray['gnantivirus'] = ($statsArray['gnantivirus'] ?? 0) + $avCount;
                $statsArray['gnwildfire'] = ($statsArray['gnwildfire'] ?? 0) + $wfCount;
            }
            else
            {
                $statsArray['gnantivirus'] = $avCount;
                $statsArray['gnwildfire'] = $wfCount;
            }
        }

        // Conditional: NextGen/Cloud Profiles
        if ($isFawkesLike)
        {
            $avWfCount = $cur->VirusAndWildfireProfileStore->count();
            $dnsCount = $cur->DNSSecurityProfileStore->count();
            $saasCount = $cur->SaasSecurityProfileStore->count();

            if ($accumulate) {
                $statsArray['gnsecprofAVWF'] += $avWfCount;
                $statsArray['gnsecprofDNS'] += $dnsCount;
                $statsArray['gnsecprofSaas'] += $saasCount;
            } else {
                $statsArray['gnsecprofAVWF'] = $avWfCount;
                $statsArray['gnsecprofDNS'] = $dnsCount;
                $statsArray['gnsecprofSaas'] = $saasCount;
            }
        }

        // Conditional: Advanced Networking Profiles (Not PANConf, Not VSYS)
        if (!$isPanConf && !$isVirtualSystem) {
            $advancedMaps = [
                'gngtp' => ['GTPProfileStore', 'count'],
                'gnscep' => ['SCEPProfileStore', 'count'],
                'gnpacketbroker' => ['PacketBrokerProfileStore', 'count'],
                'gnsdwanerrorcorrection' => ['SDWanErrorCorrectionProfileStore', 'count'],
                'gnsdwanpathquality' => ['SDWanPathQualityProfileStore', 'count'],
                'gnsdwansaasquality' => ['SDWanSaasQualityProfileStore', 'count'],
                'gnsdwantrafficdistribution' => ['SDWanTrafficDistributionProfileStore', 'count'],
                'gndataobjects' => ['DataObjectsProfileStore', 'count']
            ];

            foreach ($advancedMaps as $statKey => $map)
            {
                $store = $map[0];
                $method = $map[1];
                if (isset($cur->$store))
                {
                    $val = $cur->$store->$method();
                    if ($accumulate)
                    {
                        if (!isset($statsArray[$statKey]))
                            $statsArray[$statKey] = 0;
                        $statsArray[$statKey] += $val;
                    }
                    else
                    {
                        $statsArray[$statKey] = $val;
                    }
                }
            }
        }

        // Conditional: Certificates & SSL (PANConf or VSYS)
        if ($isPanConf || $isVirtualSystem)
        {
            $certCount = $cur->certificateStore->count();
            $sslCount = $cur->SSL_TLSServiceProfileStore->count();

            if ($accumulate)
            {
                $statsArray['gCertificatCount'] += $certCount;
                $statsArray['gSSL_TLSServiceProfileCount'] += $sslCount;
            }
            else
            {
                $statsArray['gCertificatCount'] = $certCount;
                $statsArray['gSSL_TLSServiceProfileCount'] = $sslCount;
            }
        }
        else
        {
            // Explicitly set to 0 if not accumulating (Template behavior)
            if (!$accumulate) {
                $statsArray['gCertificatCount'] = 0;
                $statsArray['gSSL_TLSServiceProfileCount'] = 0;
            }
        }
    }


    public function get_size_statistics(&$statsArray, $targetObj = null, $accumulate = false): void
    {
        if($targetObj === null)
            $targetObj = $this;

        // List of rule properties to process generically
        $ruleTypes = [
            'securityRules',
            'natRules',
            'decryptionRules',
            'appOverrideRules',
            'captivePortalRules',
            'authenticationRules',
            'pbfRules',
            'qosRules',
            'dosRules',
            'tunnelInspectionRules',
            'defaultSecurityRules',
            'networkPacketBrokerRules',
            'sdWanRules'
        ];

        // 1. Process Rules
        foreach ($ruleTypes as $rule)
        {
            $key = 'size_' . $rule;
            $size = 0;

            if( get_class($targetObj) !== "PANConf" && isset($targetObj->$rule))
            {
                $size = DH::dom_get_config_size($targetObj->$rule->xmlroot);
            }

            // Apply Accumulation or Assignment
            if( $accumulate )
            {
                // Ensure key exists before adding to avoid notices
                if (!isset($statsArray[$key]))
                    $statsArray[$key] = 0;
                $statsArray[$key] += $size;
            }
            else
            {
                $statsArray[$key] = $size;
            }
        }

        // 2. Process Service Store
        $sRoot = isset($targetObj->serviceStore) ? DH::dom_get_config_size($targetObj->serviceStore->serviceRoot) : 0;
        $sgRoot = isset($targetObj->serviceStore) ? DH::dom_get_config_size($targetObj->serviceStore->serviceGroupRoot) : 0;

        $statsArray['size_srvRoot'] = $sRoot;
        $statsArray['size_srvgrpRoot'] = $sgRoot;

        $totalService = $sRoot + $sgRoot;

        if( $accumulate )
        {
            if (!isset($statsArray['size_serviceStore']))
                $statsArray['size_serviceStore'] = 0;
            $statsArray['size_serviceStore'] += $totalService;
        } else {
            $statsArray['size_serviceStore'] = $totalService;
        }

        // 3. Process Address Store
        $aRoot = isset($targetObj->addressStore) ? DH::dom_get_config_size($targetObj->addressStore->addressRoot) : 0;
        $agRoot = isset($targetObj->addressStore) ? DH::dom_get_config_size($targetObj->addressStore->addressGroupRoot) : 0;
        $rRoot = isset($targetObj->addressStore) ? DH::dom_get_config_size($targetObj->addressStore->regionRoot) : 0;

        $statsArray['size_adrRoot'] = $aRoot;
        $statsArray['size_adrgrpRoot'] = $agRoot;
        $statsArray['size_regionRoot'] = $rRoot;

        $totalAddress = $aRoot + $agRoot + $rRoot;

        if($accumulate)
        {
            if (!isset($statsArray['size_addressStore']))
                $statsArray['size_addressStore'] = 0;
            $statsArray['size_addressStore'] += $totalAddress;
        }
        else
        {
            $statsArray['size_addressStore'] = $totalAddress;
        }


        /////////////////////////////////////

        $storeTypes = [
            'tagStore',
            'customURLProfileStore'
        ];

        // 1. Process Rules
        foreach ($storeTypes as $store)
        {
            $key = 'size_' . $store;
            $size = 0;

            if( isset($targetObj->$store) )
            {
                $size = DH::dom_get_config_size($targetObj->$store->xmlroot);
            }

            // Apply Accumulation or Assignment
            if( $accumulate )
            {
                // Ensure key exists before adding to avoid notices
                if (!isset($statsArray[$key]))
                    $statsArray[$key] = 0;
                $statsArray[$key] += $size;
            }
            else
            {
                $statsArray[$key] = $size;
            }
        }
    }


    public function display_statistics( $debug = false, $actions = 'display', $statsArray = array(), $connector = null  ): void
    {
        self::display_statistics_NEW( $debug, $actions, $statsArray, $connector );
    }


    public $stats_ruleTypes = [
            'security rules'            => ['prop' => 'securityRules',           'stat' => 'gpreSecRules'],
            'nat rules'                 => ['prop' => 'natRules',                'stat' => 'gpreNatRules'],
            'qos rules'                 => ['prop' => 'qosRules',                'stat' => 'gpreQoSRules'],
            'pbf rules'                 => ['prop' => 'pbfRules',                'stat' => 'gprePbfRules'],
            'decryption rules'          => ['prop' => 'decryptionRules',         'stat' => 'gpreDecryptRules'],
            'app-override rules'        => ['prop' => 'appOverrideRules',        'stat' => 'gpreAppOverrideRules'],
            'capt-portal rules'         => ['prop' => 'captivePortalRules',      'stat' => 'gpreCPRules'],
            'authentication rules'      => ['prop' => 'authenticationRules',     'stat' => 'gpreAuthRules'],
            'dos rules'                 => ['prop' => 'dosRules',                'stat' => 'gpreDoSRules'],
            'tunnel-inspection rules'   => ['prop' => 'tunnelInspectionRules',   'stat' => 'gpreTunnelInspectionRules'],
            'default-security rules'    => ['prop' => 'defaultSecurityRules',    'stat' => 'gpreDefaultSecurityRules'],
            'network-packet-broker rules' => ['prop' => 'networkPacketBrokerRules', 'stat' => 'gpreNetworkPacketBrokerRules'],
            'sdwan rules'               => ['prop' => 'sdWanRules',               'stat' => 'gpreSDWanRules']
        ];
    public $stats_profileMaps = [
            'tag objects' => ['store' => 'tagStore', 'sum_total' => 'gTagCount', 'sum_unused' => 'gTagUnusedCount'],
            'securityProfileGroup objects' => ['store' => 'securityProfileGroupStore'],
            'Anti-Spyware objects' => ['store' => 'AntiSpywareProfileStore'],
            'Vulnerability objects' => ['store' => 'VulnerabilityProfileStore'],
            'URL objects' => ['store' => 'URLProfileStore'],
            'custom URL objects' => ['store' => 'customURLProfileStore'],
            'File-Blocking objects' => ['store' => 'FileBlockingProfileStore'],
            'Data-Filtering objects' => ['store' => 'DataFilteringProfileStore'],
            'Decryption objects' => ['store' => 'DecryptionProfileStore'],
            'HipObject objects' => ['store' => 'HipObjectsProfileStore'],
            'HipProfile objects' => ['store' => 'HipProfilesProfileStore'],
            'GTP objects' => ['store' => 'GTPProfileStore'],
            'SCEP objects' => ['store' => 'SCEPProfileStore'],
            'PacketBroker objects' => ['store' => 'PacketBrokerProfileStore'],
            'SDWanErrorCorrection objects' => ['store' => 'SDWanErrorCorrectionProfileStore'],
            'SDWanPathQuality objects' => ['store' => 'SDWanPathQualityProfileStore'],
            'SDWanSaasQuality objects' => ['store' => 'SDWanSaasQualityProfileStore'],
            'SDWanTrafficDistribution objects' => ['store' => 'SDWanTrafficDistributionProfileStore'],
            'DataObjects objects' => ['store' => 'DataObjectsProfileStore'],
            'LogProfile objects' => ['store' => 'LogProfileStore', 'sum_total' => 'gLogProfileCount'],
            'certificate objects' => ['store' => 'certificateStore', 'sum_total' => 'gCertificatCount'],
            'SSL_TLSServiceProfile objects' => ['store' => 'SSL_TLSServiceProfileStore', 'sum_total' => 'gSSL_TLSServiceProfileCount']
        ];

   public function display_statistics_NEW($debug = false, $actions = "display", $statsArray = array(), $connector = null, $location = false): void
    {
        $stdoutarray = array();

        $class = get_class($this);
        $isPANConf = ($class === "PANConf");
        $isPanoramaConf = ($class === "PanoramaConf");
        $isContainerOrDG = ($class === "Container" || $class === "DeviceGroup");

        // Conditional Profile Logic
        $isCloudOrSnippet = in_array($class, ["Container", "DeviceCloud", "DeviceOnPrem", "Snippet"]);


        // Check if we are in "Summary Mode" (data provided in $statsArray)
        $isSummaryMode = !empty($statsArray);


        if( $isPanoramaConf )
            $stdoutarray['type'] = "DeviceGroup";
        else
            $stdoutarray['type'] = $class;
        $stdoutarray['statstype'] = "objects";

        $headerName = $isPANConf ? $this->name : PH::boldText($this->name);
        if( $isPanoramaConf )
            $stdoutarray['header'] = "Statistics for DG '".PH::boldText("shared")."'";
        else
            $stdoutarray['header'] = "Statistics for {$class} '{$headerName}'" . (!$isPANConf ? " | '" . $this->toString() . "'" : "");

        // Handle Connector Info
        if ($isPANConf && $connector !== null)
        {
            $stdoutarray['model'] = ($connector->info_model == "PA-VM") ? $connector->info_vmlicense : $connector->info_model;
        }

        // --- 1. Rule Statistics ---
        foreach ($this->stats_ruleTypes as $label => $conf)
        {
            $prop = $conf['prop'];
            if (!isset($this->$prop))
                continue;

            if ($isSummaryMode && isset($statsArray[$conf['stat']]))
            {
                $stdoutarray[$label] = $statsArray[$conf['stat']];
            }
            elseif($isContainerOrDG || $isPanoramaConf)
            {
                $stdoutarray[$label] = [
                    'pre' => $this->$prop->countPreRules(),
                    'post' => $this->$prop->countPostRules()
                ];
            }
            elseif (!$isPANConf)
            {
                $stdoutarray[$label] = $this->$prop->count();
            }
        }

        // --- 2. Address & Service Store Statistics ---
        $stores = [
            'address objects' => [
                'store' => 'addressStore',
                'map' => [
                    'total' => 'count', 'address' => 'countAddresses', 'group' => 'countAddressGroups',
                    'tmp' => 'countTmpAddresses', 'region' => 'countRegionObjects', 'unused' => 'countUnused'
                ],
                'summary_map' => ['shared' => 'countAddresses', 'total VSYSs' => 'gnaddresss', 'unused' => 'gnaddresssUnused']
            ],
            'service objects' => [
                'store' => 'serviceStore',
                'map' => [
                    'total' => 'count', 'service' => 'countServices', 'group' => 'countServiceGroups',
                    'tmp' => 'countTmpServices', 'unused' => 'countUnused'
                ],
                'summary_map' => ['shared' => 'countServices', 'total VSYSs' => 'gnservices', 'unused' => 'gnservicesUnused']
            ]
        ];

        foreach ($stores as $label => $conf)
        {
            $store = $this->{$conf['store']};
            $stdoutarray[$label] = array();

            if ($isSummaryMode) {
                foreach ($conf['summary_map'] as $outKey => $source)
                {
                    $stdoutarray[$label][$outKey] = method_exists($store, $source) ? $store->$source() : ($statsArray[$source] ?? 0);
                }
            }
            else
            {
                foreach ($conf['map'] as $outKey => $method)
                {
                    $stdoutarray[$label][$outKey] = $store->$method();
                }
            }
        }


        if ($isCloudOrSnippet)
        {
            $this->stats_profileMaps['WildfireAndAntivirus objects'] = array('store' => 'VirusAndWildfireProfileStore');
            $this->stats_profileMaps['DNS-Security objects'] = array('store' => 'DNSSecurityProfileStore');
            $this->stats_profileMaps['Saas-Security objects'] = array('store' => 'SaasSecurityProfileStore');
        }
        if ($class === "DeviceGroup" || $class === "VirtualSystem")
        {
            $this->stats_profileMaps['Antivirus objects'] = array('store' => 'AntiVirusProfileStore');
            $this->stats_profileMaps['Wildfire objects'] = array('store' => 'WildfireProfileStore');
        }


        // --- 3. Profile & Other Object Statistics ---
        foreach($this->stats_profileMaps as $label => $conf)
        {
            $storeName = $conf['store'];
            if (!isset($this->$storeName)) continue;
            $store = $this->$storeName;

            if ($isSummaryMode && isset($conf['sum_total']))
            {
                $stdoutarray[$label] = ['shared' => $store->count(), 'total VSYSs' => $statsArray[$conf['sum_total']] ?? 0];
                if (isset($conf['sum_unused']))
                    $stdoutarray[$label]['unused'] = $statsArray[$conf['sum_unused']] ?? 0;
            } else {
                $stdoutarray[$label] = ['total' => $store->count()];
                if (method_exists($store, 'countUnused'))
                {
                    $stdoutarray[$label]['unused'] = $store->countUnused();
                }
            }
        }


        if (!$isSummaryMode)
        {
            $stdoutarray['zones'] = $this->zoneStore->count();
            $stdoutarray['apps'] = $this->appStore->count();
        }

        //size
        if( $location == "shared" )
            $this->display_size_NEW($stdoutarray, true );
        else
            $this->display_size_NEW($stdoutarray );


        // --- 5. Output Handling ---
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
            if( !PH::$shadow_json && !empty($stdoutarray) )
                PH::print_stdout( $stdoutarray, true );
        }

        if( $actions == "display" || $actions == "display-available" )
            PH::$JSON_TMP[] = $stdoutarray;

        if( $isContainerOrDG )
        {
            //in general print full Panorama / shared and here all specific DG
            if( !PH::$shadow_loaddghierarchy )
                $this->display_bp_statistics( $debug, $actions );
            else
                $this->display_bp_statistics( $debug, $actions, $location );
        }
        elseif( $class === "VirtualSystem" )
        {
            //in general print full Firewall /vsys1 and here all specific vsys
            if( $this->name() !== "vsys1" )
                $this->display_bp_statistics( $debug, $actions );
        }
    }


    public function display_size_NEW( & $stdoutarray, $PanoramaShared = false )
    {
        $class = get_class($this);

        // Conditional Profile Logic
        $isCloudOrSnippet = in_array($class, ["Container", "DeviceCloud", "DeviceOnPrem", "Snippet"]);


        // Check if we are in "Summary Mode" (data provided in $statsArray)
        $isSummaryMode = !empty($statsArray);

        // --- 4. Size Array Logic ---
        $this->sizeArray = array();
        if( $PanoramaShared )
            $this->sizeArray['type'] = "DeviceGroup";
        else
            $this->sizeArray['type'] = $class;



        $this->sizeArray['statstype'] = "objects";
        $this->sizeArray['header'] = $stdoutarray['header'];
        if( $PanoramaShared )
            $this->sizeArray['kb ' . $class] = &DH::dom_get_config_size($this->sharedroot);
        else
            $this->sizeArray['kb ' . $class] = &DH::dom_get_config_size($this->xmlroot);

        // Rule Sizes
        foreach ($this->stats_ruleTypes as $label => $conf) {
            $sizeKey = 'size_' . str_replace('Rules', '', $conf['prop']);
            if ($isSummaryMode && isset($statsArray[$sizeKey])) {
                $this->sizeArray['kb ' . $label] = $statsArray[$sizeKey];
            } else {
                $prop = $conf['prop'];
                if (isset($this->$prop)) {
                    $this->sizeArray['kb ' . $label] = &DH::dom_get_config_size($this->$prop->xmlroot);
                }
            }
        }

        // Store and Profile Sizes
        if ($isSummaryMode)
        {
            $this->sizeArray['kb address objects'] = $statsArray['size_addressStore'] ?? 0;
            $this->sizeArray['kb service objects'] = $statsArray['size_serviceStore'] ?? 0;
            $this->sizeArray['kb tag objects'] = $statsArray['size_tagStore'] ?? 0;
            $this->sizeArray['kb custom URL objects'] = $statsArray['size_customURLProfileStore'] ?? 0;
        }
        else
        {
            // Address Objects Size (Sum of addressRoot + groupRoot + regionRoot)
            $tmp_adr = &DH::dom_get_config_size($this->addressStore->addressRoot);
            $tmp_adrgrp = &DH::dom_get_config_size($this->addressStore->addressGroupRoot);
            $tmp_region = &DH::dom_get_config_size($this->addressStore->regionRoot);
            $sumAddressObjects = $tmp_adr + $tmp_adrgrp + $tmp_region;
            $this->sizeArray['kb address objects '] = $sumAddressObjects;

            // Service Objects Size (Sum of serviceRoot + groupRoot)
            $tmp_srv = &DH::dom_get_config_size($this->serviceStore->serviceRoot);
            $tmp_srvgrp = &DH::dom_get_config_size($this->serviceStore->serviceGroupRoot);
            $sumServiceObjects = $tmp_srv + $tmp_srvgrp;
            $this->sizeArray['kb service objects '] = $sumServiceObjects;

            // General Profile Sizes loop
            foreach ($this->stats_profileMaps as $label => $conf)
            {
                $storeName = $conf['store'];
                if (isset($this->$storeName))
                {
                    $this->sizeArray['kb ' . $label] = &DH::dom_get_config_size($this->$storeName->xmlroot);
                }
            }

            // Specific Conditionals for size
            if ($isCloudOrSnippet)
            {
                $this->sizeArray['kb Wildfire and Antivirus objects'] = &DH::dom_get_config_size($this->VirusAndWildfireProfileStore->xmlroot);
            }
            if ($class === "DeviceGroup" || $class === "VirtualSystem")
            {
                $this->sizeArray['kb Antivirus objects'] = &DH::dom_get_config_size($this->AntiVirusProfileStore->xmlroot);
                $this->sizeArray['kb Wildfire objects'] = &DH::dom_get_config_size($this->WildfireProfileStore->xmlroot);
            }
        }
    }

    public function get_bp_statistics(): array
    {
        //Todo: add missing stuff
        //AV actions
        //AV mica-engine

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
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "wf.rules is.visibility" );
        $stdoutarray['wf visibility rules'] = count( $sub_ruleStore->rules( $filter_array ) );
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "wf.mica-engine is.visibility" );
        $stdoutarray['wf visibility mica-engine'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "wf is.best-practice" );
        $stdoutarray['wf best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "wf.rules is.best-practice" );
        $stdoutarray['wf best-practice rules'] = count( $sub_ruleStore->rules( $filter_array ) );
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "wf.mica-engine is.best-practice" );
        $stdoutarray['wf best-practice mica-engine'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "wf is.adoption" );
        $stdoutarray['wf adoption'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter."!(from is.any) and (from all.has.from.query subquery1)", 'subquery1' => "zpp is.set" );
        $stdoutarray['zone protection'] = count( $sub_ruleStore->rules( $filter_array ) );

        $stdoutarray['app id'] = count( $sub_ruleStore->rules( $generalFilter_allow."!(app is.any)" ) );
        $stdoutarray['user id'] = count( $sub_ruleStore->rules( $generalFilter_allow."!(user is.any)" ) );

        $stdoutarray['service port'] = count( $sub_ruleStore->rules( $generalFilter_allow."!(service is.any)" ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "av is.visibility" );
        $stdoutarray['av visibility'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "av.actions is.visibility" );
        $stdoutarray['av visibility actions'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "av.mica-engine is.visibility" );
        $stdoutarray['av visibility mica-engine'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "av is.best-practice" );
        $stdoutarray['av best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "av.actions is.best-practice" );
        $stdoutarray['av best-practice actions'] = count( $sub_ruleStore->rules( $filter_array ) );

        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "av.mica-engine is.best-practice" );
        $stdoutarray['av best-practice mica-engine'] = count( $sub_ruleStore->rules( $filter_array ) );

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
        $dummy_stdoutarray = array();
        //$ruleForCalculation = $stdoutarray['security rules allow enabled'];
        $ruleForCalculation = 'security rules allow enabled';

        $workingArray = array();
        $workingArray[] = array( 'log at end', 'security rules enabled' );
        $workingArray[] = array( 'log at not start', 'security rules enabled' );
        $workingArray[] = array( 'log prof set', 'security rules enabled');

        $workingArray[] = array( 'wf visibility', $ruleForCalculation);
        $workingArray[] = array( 'wf visibility rules', $ruleForCalculation);
        $workingArray[] = array( 'wf visibility mica-engine', $ruleForCalculation);
        $workingArray[] = array( 'wf best-practice', $ruleForCalculation);
        $workingArray[] = array( 'wf best-practice rules', $ruleForCalculation);
        $workingArray[] = array( 'wf best-practice mica-engine', $ruleForCalculation);
        $workingArray[] = array( 'wf adoption', $ruleForCalculation);

        $workingArray[] = array( 'zone protection', 'security rules enabled');
        $workingArray[] = array( 'app id', $ruleForCalculation);
        $workingArray[] = array( 'user id', 'security rules enabled');
        $workingArray[] = array( 'service port', $ruleForCalculation);

        $workingArray[] = array( 'av visibility', $ruleForCalculation);
        $workingArray[] = array( 'av visibility actions', $ruleForCalculation);
        $workingArray[] = array( 'av visibility mica-engine', $ruleForCalculation);
        $workingArray[] = array( 'av best-practice', $ruleForCalculation);
        $workingArray[] = array( 'av best-practice actions', $ruleForCalculation);
        $workingArray[] = array( 'av best-practice mica-engine', $ruleForCalculation);
        $workingArray[] = array( 'av adoption', $ruleForCalculation);

        $workingArray[] = array( 'as visibility', $ruleForCalculation);
        $workingArray[] = array( 'as visibility rules', $ruleForCalculation);
        $workingArray[] = array( 'as visibility mica-engine', $ruleForCalculation);
        $workingArray[] = array( 'as best-practice', $ruleForCalculation);
        $workingArray[] = array( 'as best-practice rules', $ruleForCalculation);
        $workingArray[] = array( 'as best-practice mica-engine', $ruleForCalculation);
        $workingArray[] = array( 'as adoption', $ruleForCalculation);

        $workingArray[] = array( 'vp visibility', $ruleForCalculation);
        $workingArray[] = array( 'vp visibility rules', $ruleForCalculation);
        $workingArray[] = array( 'vp visibility mica-engine', $ruleForCalculation);
        $workingArray[] = array( 'vp best-practice', $ruleForCalculation);
        $workingArray[] = array( 'vp best-practice rules', $ruleForCalculation);
        $workingArray[] = array( 'vp best-practice mica-engine', $ruleForCalculation);
        $workingArray[] = array( 'vp adoption', $ruleForCalculation);

        $workingArray[] = array( 'fb visibility', $ruleForCalculation);
        $workingArray[] = array( 'fb best-practice', $ruleForCalculation);
        $workingArray[] = array( 'fb adoption', $ruleForCalculation);

        $workingArray[] = array( 'data visibility', $ruleForCalculation);
        $workingArray[] = array( 'data best-practice', $ruleForCalculation);
        $workingArray[] = array( 'data adoption', $ruleForCalculation);

        $workingArray[] = array( 'url-site-access visibility', $ruleForCalculation);
        $workingArray[] = array( 'url-site-access best-practice', $ruleForCalculation);
        $workingArray[] = array( 'url-site-access adoption', $ruleForCalculation);

        $workingArray[] = array( 'url-credential visibility', $ruleForCalculation);
        $workingArray[] = array( 'url-credential best-practice', $ruleForCalculation);
        $workingArray[] = array( 'url-credential adoption', $ruleForCalculation);

        $workingArray[] = array( 'dns-list visibility', $ruleForCalculation);
        $workingArray[] = array( 'dns-list best-practice', $ruleForCalculation);
        $workingArray[] = array( 'dns-list adoption', $ruleForCalculation);

        $workingArray[] = array( 'dns-security visibility', $ruleForCalculation);
        $workingArray[] = array( 'dns-security best-practice', $ruleForCalculation);
        $workingArray[] = array( 'dns-security adoption', $ruleForCalculation);

        foreach( $workingArray as $entry )
        {
            if($entry[0] == 'data best-practice')
            {
                $stdoutarray['data best-practice'] = "NOT available";
                continue;
            }

            $stdoutarray[$entry[0].' calc'] = $stdoutarray[$entry[0]]."/".$stdoutarray[$entry[1]];
            if( $stdoutarray[$entry[1]] !== 0 )
                $stdoutarray[$entry[0].' percentage'] = floor(( $stdoutarray[$entry[0]] / $stdoutarray[$entry[1]] ) * 100 );
            else
                $stdoutarray[$entry[0].' percentage'] = 0;
        }
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
        $percentageArray_visibility['Wildfire Analysis Rules']['value'] = $stdoutarray['wf visibility rules percentage'];
        $percentageArray_visibility['Wildfire Analysis Rules']['group'] = 'Wildfire';
        $percentageArray_visibility['Wildfire Analysis InLine ML']['value'] = $stdoutarray['wf visibility mica-engine percentage'];
        $percentageArray_visibility['Wildfire Analysis InLine ML']['group'] = 'Wildfire';

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
        $percentageArray_visibility['Antivirus Actions']['value'] = $stdoutarray['av visibility actions percentage'];
        $percentageArray_visibility['Antivirus Actions']['group'] = 'Threat Prevention';
        $percentageArray_visibility['Antivirus InLine ML']['value'] = $stdoutarray['as visibility mica-engine percentage'];
        $percentageArray_visibility['Antivirus InLine ML']['group'] = 'Threat Prevention';

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
        $percentageArray_best_practice['Wildfire Analysis Rules']['value'] = $stdoutarray['wf best-practice rules percentage'];
        $percentageArray_best_practice['Wildfire Analysis Rules']['group'] = 'Wildfire';
        $percentageArray_best_practice['Wildfire Analysis InLine ML']['value'] = $stdoutarray['wf best-practice mica-engine percentage'];
        $percentageArray_best_practice['Wildfire Analysis InLine ML']['group'] = 'Wildfire';

        #$percentageArray_best_practice['Zone Protection']['value'] = '---';
        #$percentageArray_best_practice['App-ID']['value'] = $stdoutarray['app id percentage'];
        #$percentageArray_best_practice['User-ID']['value'] = $stdoutarray['user id percentage'];
        #$percentageArray_best_practice['Service/Port']['value'] = $stdoutarray['service port percentage'];

        $percentageArray_best_practice['Antivirus Profiles']['value'] = $stdoutarray['av best-practice percentage'];
        $percentageArray_best_practice['Antivirus Profiles']['group'] = 'Threat Prevention';
        $percentageArray_best_practice['Antivirus Actions']['value'] = $stdoutarray['av best-practice actions percentage'];
        $percentageArray_best_practice['Antivirus Actions']['group'] = 'Threat Prevention';
        $percentageArray_best_practice['Antivirus InLine ML']['value'] = $stdoutarray['as best-practice mica-engine percentage'];
        $percentageArray_best_practice['Antivirus InLine ML']['group'] = 'Threat Prevention';

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

        #$percentageArray_best_practice['Data Filtering']['value'] = $stdoutarray['data adoption percentage'];
        #$percentageArray_best_practice['Data Filtering']['group'] = 'Data Loss Prevention';

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

        //Todo:
        //if SCM remove virus / wildfire
        //if Panorama remvoe virus-and-wildfire

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
