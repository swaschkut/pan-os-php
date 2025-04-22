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

class SecurityProfileGroup
{
    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;

    /** @var SecurityProfileGroupStore|null */
    public $owner = null;

    /*
     * FAWKES
     *    <dns-security>    <spyware>   <vulnerability> <url-filtering> <file-blocking> <saas-security> <virus-and-wildfire-analysis>
     */
    private $secprof_array = array('virus', 'spyware', 'vulnerability', 'file-blocking', 'wildfire-analysis', 'url-filtering', 'data-filtering');
    private $secprof_fawkes_array = array('virus-and-wildfire-analysis', 'spyware', 'vulnerability', 'file-blocking', 'dns-security', 'url-filtering', 'saas-security', 'data-filtering');

    /*
     * FAWKES
     * define new ProfileStore:
     * ->VirusWildfireProfileStore; DnsSecurityProfileStore; SaasSecurityProfileStore
     */
    private $secprof_store = array( 'AntiVirusProfileStore', 'AntiSpywareProfileStore', 'VulnerabilityProfileStore', 'FileBlockingProfileStore', 'WildfireProfileStore', 'URLProfileStore', 'DataFilteringProfileStore' );
    private $secprof_fawkes_store = array( 'VirusAndWildfireProfileStore', 'AntiSpywareProfileStore', 'VulnerabilityProfileStore', 'FileBlockingProfileStore', 'DNSSecurityProfileStore', 'URLProfileStore', 'SaasSecurityProfileStore', 'DataFilteringProfileStore' );


    public $secprofiles = array();
    public $secprofProfiles_obj = array();

    /** @var string|null */
    public $comments;

    public $hash = null;

    /**
     * @param string $name
     * @param SecurityProfileGroupStore|null $owner
     * @param bool $fromXmlTemplate
     */
    public function __construct($name, $owner, $fromXmlTemplate = FALSE)
    {
        $this->name = $name;


        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElement('entry', $doc);

            if( $owner->xmlroot === null )
                $owner->createXmlRoot();

            $rootDoc = $owner->xmlroot->ownerDocument;

            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot, $owner);

            $this->setName($name);
        }

        //Panorama
        if( get_class( $owner->owner ) == "Container" || get_class( $owner->owner ) == "DeviceCloud" || get_class( $owner->owner ) == "FawkesConf" || get_class( $owner->owner ) == "DeviceOnPrem" || get_class( $owner->owner ) == "Snippet" )
            $used_secprof_array = $this->secprof_fawkes_array;
        else
            $used_secprof_array = $this->secprof_array;

        foreach( $used_secprof_array as $secprof )
        {
            $this->secprofiles[$secprof] = null;
        }

        $this->owner = $owner;

    }

    /**
     * @param string $newName
     * @return bool
     */
    public function setName($newName)
    {
        $ret = $this->setRefName($newName);

        if( $this->xmlroot === null )
            return $ret;

        $this->xmlroot->setAttribute('name', $newName);

        return $ret;
    }

    /**
     * @param string $newName
     */
    public function API_setName($newName)
    {
        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $this->setName($newName);

        if( $c->isAPI() )
            $c->sendRenameRequest($xpath, $newName);
    }


    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getSecurityProfileGroupStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }



    public function load_from_domxml(DOMElement $xml, $owner)
    {
        $this->xmlroot = $xml;
        $this->owner = $owner;

        $str = '';

        if( get_class( $owner->owner ) == "Container" || get_class( $owner->owner ) == "DeviceCloud" || get_class( $owner->owner ) == "FawkesConf" || get_class( $owner->owner ) == "DeviceOnPrem" || get_class( $owner->owner ) == "Snippet" )
            $used_secprof_array = $this->secprof_fawkes_array;
        else
            $used_secprof_array = $this->secprof_array;


        $counter = count( $used_secprof_array );
        $i = 1;
        foreach( $used_secprof_array as $key => $secprof_type )
        {
            $tmp_type = DH::findFirstElement($secprof_type, $xml);
            if( $tmp_type != FALSE )
            {
                $tmp_type = DH::findFirstElement('member', $tmp_type);
                if( $tmp_type != null )
                {
                    //Panorama
                    if( get_class( $owner->owner ) == "Container" || get_class( $owner->owner ) == "DeviceCloud" || get_class( $owner->owner ) == "FawkesConf" || get_class( $owner->owner ) == "DeviceOnPrem" || get_class( $owner->owner ) == "Snippet" )
                        $used_secprof_store = $this->secprof_fawkes_store;
                    else
                        $used_secprof_store = $this->secprof_store;

                    $tmp_store_name = $used_secprof_store[$key];
                    $profile = $this->owner->owner->$tmp_store_name->find( $tmp_type->nodeValue );
                    if( $profile != false )
                    {
                        #PH::print_stdout( "SecurityProfileGroup: ".$this->name()." - proftype: ".$secprof_type." - PROFILE: ".$tmp_type->nodeValue." used");
                        $this->secprofProfiles_obj[ $secprof_type ] = $profile;
                        $profile->addReference( $this );
                    }
                    else
                    {
                        if( get_class( $this->owner->owner ) == "DeviceGroup" || get_class( $this->owner->owner ) == "VirtualSystem" )
                            $sub = $this->owner->owner->owner;
                        elseif( get_class( $this->owner->owner ) == "PANConfig" || get_class( $this->owner->owner ) == "PanoramaConf" )
                            $sub = $this->owner->owner;

                        if( $tmp_store_name == 'AntiVirusProfileStore')
                            $profile = $sub->AntiVirusPredefinedStore->find( $tmp_type->nodeValue );
                        elseif( $tmp_store_name == 'AntiSpywareProfileStore')
                            $profile = $sub->AntiSpywarePredefinedStore->find( $tmp_type->nodeValue );
                        elseif( $tmp_store_name == 'VulnerabilityProfileStore')
                            $profile = $sub->VulnerabilityPredefinedStore->find( $tmp_type->nodeValue );
                        elseif( $tmp_store_name == 'FileBlockingProfileStore' )
                            $profile = $sub->FileBlockingPredefinedStore->find( $tmp_type->nodeValue );
                        elseif( $tmp_store_name == 'WildfireProfileStore' )
                            $profile = $sub->WildfirePredefinedStore->find( $tmp_type->nodeValue );
                        elseif( $tmp_store_name == 'URLProfileStore' )
                            $profile = $sub->UrlFilteringPredefinedStore->find( $tmp_type->nodeValue );

                        if( $profile != null )
                        {
                            $this->secprofProfiles_obj[$secprof_type] = $profile;

                            $profile->addReference( $this );
                        }
                        else
                        {
                            //Todo: not a profile - default profile
                            #PH::print_stdout( "SecurityProfileGroup: ".$this->name()." - proftype: ".$secprof_type." - PROFILE: ".$tmp_type->nodeValue." not found");
                            $this->secprofiles[$secprof_type] = $tmp_type->nodeValue;
                        }
                    }

                    $str .= $secprof_type.':'.$tmp_type->nodeValue;
                    if( $i < $counter )
                    {
                        $str .= ',';
                        $i++;
                    }
                }
            }
        }

        $this->hash = md5( $str );

    }

    public function securityProfiles()
    {
        return $this->secprofProfiles_obj;
    }

    /**
     * @return string
     */
    public function getComments()
    {
        $ret = $this->comments;

        return $ret;
    }

    /**
     * * @param string $newComment
     * * @param bool $rewriteXml
     * @return bool
     */
    public function addComments($newComment, $rewriteXml = TRUE)
    {
        $oldComment = $this->comments;
        $newComment = $oldComment . $newComment;


        if( $this->xmlroot === null )
            return FALSE;

        if( $rewriteXml )
        {
            $commentsRoot = DH::findFirstElement('comments', $this->xmlroot);
            if( $commentsRoot === FALSE )
            {
                $child = new DOMElement('comments');
                $this->xmlroot->appendChild($child);
                $commentsRoot = DH::findFirstElement('comments', $this->xmlroot);
            }

            DH::setDomNodeText($commentsRoot, $newComment);
        }


        return TRUE;
    }

    /**
     * @param string $newComment
     * @return bool
     */
    public function API_addComments($newComment)
    {
        if( !$this->addComments($newComment) )
            return FALSE;

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $commentsRoot = DH::findFirstElement('comments', $this->xmlroot);

        if( $c->isAPI() )
            $c->sendEditRequest($xpath . "/comments", DH::dom_to_xml($commentsRoot, -1, FALSE));

        return TRUE;
    }

    /**
     * @return bool
     */
    public function deleteComments()
    {
        if( $this->xmlroot === null )
            return FALSE;

        $commentsRoot = DH::findFirstElement('comments', $this->xmlroot);
        $valueRoot = DH::findFirstElement('color', $this->xmlroot);
        if( $commentsRoot !== FALSE )
            $this->xmlroot->removeChild($commentsRoot);

        if( $valueRoot === FALSE )
            $this->xmlroot->nodeValue = "";

        return TRUE;
    }

    /**
     * @return bool
     */
    public function API_deleteComments()
    {
        if( !$this->deleteComments() )
            return FALSE;

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        if( $c->isAPI() )
            $c->sendEditRequest($xpath, DH::dom_to_xml($this->xmlroot, -1, FALSE));

        return TRUE;
    }

    public function removeSecurityProfile()
    {
        $this->secprofiles = array();

        $this->rewriteXML();

        return TRUE;
    }

    public function API_removeSecurityProfile()
    {
        $ret = $this->removeSecurityProfile();

        if( $ret )
        {
            $xpath = $this->getXPath();
            $con = findConnectorOrDie($this);

            if( $con->isAPI() )
                $con->sendDeleteRequest($xpath);
        }

        return $ret;
    }

    public function setSecProf_AV($newAVprof)
    {
        if( $newAVprof == null )
        {
            unset($this->secprofiles['virus']);
            unset($this->secprofProfiles_obj['virus']);
        }
        else
        {
            $newAVproftxt = $newAVprof;
            $newAVprof = $this->owner->owner->AntiVirusProfileStore->find( $newAVproftxt );
            if( $newAVprof !== null )
                $this->secprofProfiles_obj['virus'] = $newAVprof;
            else
                $this->secprofiles['virus'] = $newAVproftxt;
        }


        $this->rewriteXML();

        return TRUE;
    }

    public function setSecProf_Vuln($newAVprof)
    {
        if( $newAVprof == null )
        {
            unset($this->secprofiles['vulnerability']);
            unset($this->secprofProfiles_obj['vulnerability']);
        }
        else
        {
            $newAVproftxt = $newAVprof;
            $newAVprof = $this->owner->owner->VulnerabilityProfileStore->find( $newAVproftxt );
            if( $newAVprof !== null )
                $this->secprofProfiles_obj['vulnerability'] = $newAVprof;
            else
                $this->secprofiles['vulnerability'] = $newAVproftxt;
        }


        $this->rewriteXML();

        return TRUE;
    }

    public function setSecProf_URL($newAVprof)
    {
        if( $newAVprof == null )
        {
            unset($this->secprofiles['url-filtering']);
            unset($this->secprofProfiles_obj['url-filtering']);
        }
        else
        {
            $newAVproftxt = $newAVprof;
            $newAVprof = $this->owner->owner->URLProfileStore->find( $newAVproftxt );
            if( $newAVprof !== null )
                $this->secprofProfiles_obj['url-filtering'] = $newAVprof;
            else
                $this->secprofiles['url-filtering'] = $newAVproftxt;
        }


        $this->rewriteXML();

        return TRUE;
    }

    public function setSecProf_DataFilt($newAVprof)
    {
        if( $newAVprof == null )
        {
            unset($this->secprofiles['data-filtering']);
            unset($this->secprofProfiles_obj['data-filtering']);
        }
        else
        {
            $newAVproftxt = $newAVprof;
            #$newAVprof = $this->owner->owner->DataProfileStore->find( $newAVproftxt );
            $newAVprof = null;
            if( $newAVprof !== null )
                $this->secprofProfiles_obj['data-filtering'] = $newAVprof;
            else
                $this->secprofiles['data-filtering'] = $newAVproftxt;
        }


        $this->rewriteXML();

        return TRUE;
    }

    public function setSecProf_FileBlock($newAVprof)
    {
        if( $newAVprof == null )
        {
            unset($this->secprofiles['file-blocking']);
            unset($this->secprofProfiles_obj['file-blocking']);
        }
        else
        {
            $newAVproftxt = $newAVprof;
            $newAVprof = $this->owner->owner->FileBlockingProfileStore->find( $newAVproftxt );
            if( $newAVprof !== null )
                $this->secprofProfiles_obj['file-blocking'] = $newAVprof;
            else
                $this->secprofiles['file-blocking'] = $newAVproftxt;
        }


        $this->rewriteXML();

        return TRUE;
    }

    public function setSecProf_Spyware($newAVprof)
    {
        if( $newAVprof == null )
        {
            unset($this->secprofiles['spyware']);
            unset($this->secprofProfiles_obj['spyware']);
        }
        else
        {
            $newAVproftxt = $newAVprof;
            $newAVprof = $this->owner->owner->AntiSpywareProfileStore->find( $newAVproftxt );
            if( $newAVprof !== null )
                $this->secprofProfiles_obj['spyware'] = $newAVprof;
            else
                $this->secprofiles['spyware'] = $newAVproftxt;
        }


        $this->rewriteXML();

        return TRUE;
    }

    public function setSecProf_Wildfire($newAVprof)
    {
       
        if( $newAVprof == null )
        {
            unset($this->secprofiles['wildfire-analysis']);
            unset($this->secprofProfiles_obj['wildfire-analysis']);
        }
        else
        {
            $newAVproftxt = $newAVprof;
            $newAVprof = $this->owner->owner->WildfireProfileStore->find( $newAVproftxt );
            if( $newAVprof !== null )
                $this->secprofProfiles_obj['wildfire-analysis'] = $newAVprof;
            else
                $this->secprofiles['wildfire-analysis'] = $newAVproftxt;
        }


        $this->rewriteXML();

        return TRUE;
    }

    public function countDisabledRefRule()
    {
        $counter = 0;
        foreach( $this->refrules as $refrule )
        {
            /** @var Rule $refrule */
            if( $refrule->isDisabled() )
                $counter++;
        }
        return $counter;
    }

    public function is_best_practice()
    {
        //Todo: continue extending check for URL/FB/WF aso.
        $bp_av_set = false;
        $bp_as_set = false;
        $bp_vp_set = false;
        $bp_url_set = false;
        $bp_fb_set = false;
        $bp_wf_set = false;
        if(isset($this->secprofProfiles_obj['virus']))
        {
            /** @var AntiVirusProfile $profile */
            /*if( is_string($this->secprofiles['virus']) )
                $profile = $this->owner->owner->AntiVirusProfileStore->find($this->secprofiles['virus']);
            else*/
                $profile = $this->secprofProfiles_obj['virus'];
            if( is_object($profile) )
            {
                if ($profile->is_best_practice())
                    $bp_av_set = TRUE;
                else
                    return FALSE;
            }
            else
            {
                mwarning( "BP SPG check not possible - SecurityProfile AV ".$this->secprofiles['virus']." not found", null, false );
                return FALSE;
            }

        }

        if(isset($this->secprofProfiles_obj['spyware']))
        {
            /** @var AntiSpywareProfile $profile */
            /*if( is_string($this->secprofiles['spyware']) )
                $profile = $this->owner->owner->AntiSpywareProfileStore->find($this->secprofiles['spyware']);
            else*/
                $profile = $this->secprofProfiles_obj['spyware'];
            if( is_object($profile) )
            {
                if ($profile->is_best_practice())
                    $bp_as_set = TRUE;
                else
                    return FALSE;
            }
            else
            {
                mwarning( "BP SPG check not possible - profile AS ".$this->secprofiles['spyware']." not found", null, false );
                return FALSE;
            }

        }

        if(isset($this->secprofProfiles_obj['vulnerability']))
        {
            /** @var VulnerabilityProfile $profile */
            /*if( is_string($this->secprofiles['vulnerability']) )
                $profile = $this->owner->owner->VulnerabilityProfileStore->find($this->secprofiles['vulnerability']);
            else*/
                $profile = $this->secprofProfiles_obj['vulnerability'];
            if( is_object($profile) )
            {
                if ($profile->is_best_practice())
                    $bp_vp_set = TRUE;
                else
                    return FALSE;
            }
            else
            {
                mwarning( "BP SPG check not possible - profile VP ".$this->secprofiles['vulnerability']." not found", null, false );
                return FALSE;
            }

        }

        if(isset($this->secprofProfiles_obj['url-filtering']))
        {
            /** @var URLProfile $profile */
            $profile = $this->secprofProfiles_obj['url-filtering'];
            if( is_object($profile) )
            {
                if ($profile->is_best_practice())
                    $bp_url_set = TRUE;
                else
                    return FALSE;
            }
            else
            {
                mwarning( "BP SPG check not possible - profile URL ".$this->secprofiles['url-filtering']." not found", null, false );
                return FALSE;
            }

        }
        if(isset($this->secprofProfiles_obj['file-blocking']))
        {
            /** @var FileBlockingProfile $profile */
            $profile = $this->secprofProfiles_obj['file-blocking'];
            if( is_object($profile) )
            {
                if ($profile->is_best_practice() )
                    $bp_fb_set = TRUE;
                else
                    return FALSE;
            }
            else
            {
                mwarning( "BP SPG check not possible - profile VP ".$this->secprofiles['file-blocking']." not found", null, false );
                return FALSE;
            }

        }
        if(isset($this->secprofProfiles_obj['wildfire-analysis']))
        {
            /** @var WildfireProfile $profile */
            $profile = $this->secprofProfiles_obj['wildfire-analysis'];
            if( is_object($profile) )
            {
                if ($profile->is_best_practice())
                    $bp_wf_set = TRUE;
                else
                    return FALSE;
            }
            else
            {
                mwarning( "BP SPG check not possible - profile VP ".$this->secprofiles['wildfire-analysis']." not found", null, false );
                return FALSE;
            }
        }

        if( $bp_av_set && $bp_as_set && $bp_vp_set && $bp_url_set && $bp_fb_set && $bp_wf_set )
            return TRUE;
        else
            return FALSE;
    }

    public function is_visibility()
    {
        //Todo: continue implementing more checks URL/WF/FB aso.
        $bp_av_set = false;
        $bp_as_set = false;
        $bp_vp_set = false;
        $bp_url_set = false;
        $bp_fb_set = false;
        $bp_wf_set = false;
        if(isset($this->secprofProfiles_obj['virus']))
        {
            /** @var AntiVirusProfile $profile */
            /*
            if( is_string($this->secprofiles['virus']) )
                $profile = $this->owner->owner->AntiVirusProfileStore->find($this->secprofiles['virus']);
            else
                */
            $profile = $this->secprofProfiles_obj['virus'];
            if( is_object($profile) )
            {
                if ($profile->is_visibility())
                    $bp_av_set = TRUE;
                else
                    return FALSE;
            }
            else
            {
                mwarning( "Visibility SPG check not possible - SecurityProfile AV ".$this->secprofiles['virus']." not found", null, false );
                return FALSE;
            }

        }

        if(isset($this->secprofProfiles_obj['spyware']))
        {
            /** @var AntiSpywareProfile $profile */
            /*if( is_string($this->secprofiles['spyware']) )
                $profile = $this->owner->owner->AntiSpywareProfileStore->find($this->secprofiles['spyware']);
            else*/
            $profile = $this->secprofProfiles_obj['spyware'];
            if( is_object($profile) )
            {
                if ($profile->is_visibility())
                    $bp_as_set = TRUE;
                else
                    return FALSE;
            }
            else
            {
                mwarning( "Visibility SPG check not possible - profile AS ".$this->secprofiles['spyware']." not found", null, false );
                return FALSE;
            }

        }

        if(isset($this->secprofProfiles_obj['vulnerability']))
        {
            /** @var VulnerabilityProfile $profile */
            /*if( is_string($this->secprofiles['vulnerability']) )
                $profile = $this->owner->owner->VulnerabilityProfileStore->find($this->secprofiles['vulnerability']);
            else*/
                $profile = $this->secprofProfiles_obj['vulnerability'];
            if( is_object($profile) )
            {
                if ($profile->is_visibility())
                    $bp_vp_set = TRUE;
                else
                    return FALSE;
            }
            else
            {
                mwarning( "Visibility SPG check not possible - profile VP ".$this->secprofiles['vulnerability']." not found", null, false );
                return FALSE;
            }

        }

        if(isset($this->secprofProfiles_obj['url-filtering']))
        {
            /** @var URLProfile $profile */
            $profile = $this->secprofProfiles_obj['url-filtering'];
            if( is_object($profile) )
            {
                if ($profile->is_visibility())
                    $bp_url_set = TRUE;
                else
                    return FALSE;
            }
            else
            {
                mwarning( "Visibility SPG check not possible - profile URL ".$this->secprofiles['url-filtering']." not found", null, false );
                return FALSE;
            }

        }
        if(isset($this->secprofProfiles_obj['file-blocking']))
        {
            /** @var FileBlockingProfile $profile */
            $profile = $this->secprofProfiles_obj['file-blocking'];
            if( is_object($profile) )
            {
                if ($profile->is_visibility())
                    $bp_fb_set = TRUE;
                else
                    return FALSE;
            }
            else
            {
                mwarning( "Visibility SPG check not possible - profile VP ".$this->secprofiles['file-blocking']." not found", null, false );
                return FALSE;
            }

        }
        if(isset($this->secprofProfiles_obj['wildfire-analysis']))
        {
            /** @var WildfireProfile $profile */
            $profile = $this->secprofProfiles_obj['wildfire-analysis'];
            if( is_object($profile) )
            {
                if ($profile->is_visibility())
                    $bp_wf_set = TRUE;
                else
                    return FALSE;
            }
            else
            {
                mwarning( "Visibility SPG check not possible - profile VP ".$this->secprofiles['wildfire-analysis']." not found", null, false );
                return FALSE;
            }
        }

        if( $bp_av_set && $bp_as_set && $bp_vp_set && $bp_url_set && $bp_fb_set && $bp_wf_set )
            return TRUE;
        else
            return FALSE;
    }

    public function is_adoption()
    {
        //Todo: continue implementing more checks URL/WF/FB aso.
        $bp_av_set = false;
        $bp_as_set = false;
        $bp_vp_set = false;
        $bp_url_set = false;
        $bp_fb_set = false;
        $bp_wf_set = false;
        if(isset($this->secprofProfiles_obj['virus']))
        {
            /** @var AntiVirusProfile $profile */
            /*
            if( is_string($this->secprofiles['virus']) )
                $profile = $this->owner->owner->AntiVirusProfileStore->find($this->secprofiles['virus']);
            else
                */
            $profile = $this->secprofProfiles_obj['virus'];
            if( is_object($profile) )
            {
                if ($profile->is_adoption())
                    $bp_av_set = TRUE;
                else
                    return FALSE;
            }
            else
            {
                mwarning( "Visibility SPG check not possible - SecurityProfile AV ".$this->secprofiles['virus']." not found", null, false );
                return FALSE;
            }

        }

        if(isset($this->secprofProfiles_obj['spyware']))
        {
            /** @var AntiSpywareProfile $profile */
            /*if( is_string($this->secprofiles['spyware']) )
                $profile = $this->owner->owner->AntiSpywareProfileStore->find($this->secprofiles['spyware']);
            else*/
            $profile = $this->secprofProfiles_obj['spyware'];
            if( is_object($profile) )
            {
                if ($profile->is_adoption())
                    $bp_as_set = TRUE;
                else
                    return FALSE;
            }
            else
            {
                mwarning( "Visibility SPG check not possible - profile AS ".$this->secprofiles['spyware']." not found", null, false );
                return FALSE;
            }

        }

        if(isset($this->secprofProfiles_obj['vulnerability']))
        {
            /** @var VulnerabilityProfile $profile */
            /*if( is_string($this->secprofiles['vulnerability']) )
                $profile = $this->owner->owner->VulnerabilityProfileStore->find($this->secprofiles['vulnerability']);
            else*/
            $profile = $this->secprofProfiles_obj['vulnerability'];
            if( is_object($profile) )
            {
                if ($profile->is_adoption())
                    $bp_vp_set = TRUE;
                else
                    return FALSE;
            }
            else
            {
                mwarning( "Visibility SPG check not possible - profile VP ".$this->secprofiles['vulnerability']." not found", null, false );
                return FALSE;
            }

        }

        if(isset($this->secprofProfiles_obj['url-filtering']))
        {
            /** @var URLProfile $profile */
            $profile = $this->secprofProfiles_obj['url-filtering'];
            if( is_object($profile) )
            {
                if ($profile->is_adoption())
                    $bp_url_set = TRUE;
                else
                    return FALSE;
            }
            else
            {
                mwarning( "Visibility SPG check not possible - profile URL ".$this->secprofiles['url-filtering']." not found", null, false );
                return FALSE;
            }

        }
        if(isset($this->secprofProfiles_obj['file-blocking']))
        {
            /** @var FileBlockingProfile $profile */
            $profile = $this->secprofProfiles_obj['file-blocking'];
            if( is_object($profile) )
            {
                if ($profile->is_adoption())
                    $bp_fb_set = TRUE;
                else
                    return FALSE;
            }
            else
            {
                mwarning( "Visibility SPG check not possible - profile VP ".$this->secprofiles['file-blocking']." not found", null, false );
                return FALSE;
            }

        }
        if(isset($this->secprofProfiles_obj['wildfire-analysis']))
        {
            /** @var WildfireProfile $profile */
            $profile = $this->secprofProfiles_obj['wildfire-analysis'];
            if( is_object($profile) )
            {
                if ($profile->is_adoption())
                    $bp_wf_set = TRUE;
                else
                    return FALSE;
            }
            else
            {
                mwarning( "Visibility SPG check not possible - profile VP ".$this->secprofiles['wildfire-analysis']." not found", null, false );
                return FALSE;
            }
        }

        if( $bp_av_set && $bp_as_set && $bp_vp_set && $bp_url_set && $bp_fb_set && $bp_wf_set )
            return TRUE;
        else
            return FALSE;
    }

    /*
    public function rewriteSecProfXML()
    {

        if( $this->secprofroot !== null )
            DH::clearDomNodeChilds($this->secprofroot);
        if( $this->secproftype == 'group' )
        {
            if( $this->secprofroot === null || $this->secprofroot === FALSE )
                $this->secprofroot = DH::createElement($this->xmlroot, 'profile-setting');
            else
                $this->xmlroot->appendChild($this->secprofroot);

            $tmp = $this->secprofroot->ownerDocument->createElement('group');
            $tmp = $this->secprofroot->appendChild($tmp);
            $tmp = $tmp->appendChild($this->secprofroot->ownerDocument->createElement('member'));
            $tmp->appendChild($this->secprofroot->ownerDocument->createTextNode($this->secprofgroup));
        }
        else if( $this->secproftype == 'profile' )
        {
            if( $this->secprofroot === null || $this->secprofroot === FALSE )
                $this->secprofroot = DH::createElement($this->xmlroot, 'profile-setting');
            else
                $this->xmlroot->appendChild($this->secprofroot);

            $tmp = $this->secprofroot->ownerDocument->createElement('profiles');
            $tmp = $this->secprofroot->appendChild($tmp);

            foreach( $this->secprofProfiles as $index => $value )
            {
                $type = $tmp->appendChild($this->secprofroot->ownerDocument->createElement($index));
                $ntmp = $type->appendChild($this->secprofroot->ownerDocument->createElement('member'));
                $ntmp->appendChild($this->secprofroot->ownerDocument->createTextNode($value));
            }
        }
    }
    */

    public function rewriteXML()
    {
        if( $this->xmlroot !== null )
            DH::clearDomNodeChilds($this->xmlroot);

        foreach( $this->secprofProfiles_obj as $key => $secprof)
        {
            if( $secprof != null )
            {
                $tmp = $this->owner->xmlroot->ownerDocument->createElement($key);
                $tmp1 = $this->xmlroot->appendChild( $tmp );

                $tmp = $this->owner->xmlroot->ownerDocument->createElement('member');
                $tmp1 = $tmp1->appendChild( $tmp );

                if( is_object( $secprof ) )
                {
                    $tmp = $this->owner->xmlroot->ownerDocument->createTextNode( $secprof->name() );
                }
                else
                {
                    $tmp = $this->owner->xmlroot->ownerDocument->createTextNode( $secprof );
                }

                $tmp1->appendChild( $tmp );
            }
        }
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

}

