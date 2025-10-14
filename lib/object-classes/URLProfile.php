<?php


/**
 * @property $_ip4Map IP4Map cached ip start and end value for fast optimization
 */
class URLProfile extends SecurityProfile2
{
    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;
    use ObjectWithDescription;

    /** @var string|null */
    protected $value;

    public $_all;
    public $_all_credential;

    /** @var SecurityProfileStore|null */
    public $owner;

    public $secprof_type;

    public $allow = array();
    public $allow_credential = array();

    public $alert = array();
    public $alert_credential = array();

    public $block = array();
    public $block_credential = array();

    public $continue = array();
    public $continue_credential = array();

    public $override = array();
    public $override_credential = array();

    public $predefined = array();

    public $credential_mode = null;
    public $credential_log = null;

    public $tmp_url_prof_array = array('allow', 'alert', 'block', 'continue', 'override');

    /**
     * you should not need this one for normal use
     * @param string $name
     * @param SecurityProfileStore $owner
     * @param bool $fromXmlTemplate
     */
    function __construct($name, $owner, $fromXmlTemplate = FALSE)
    {
        $this->owner = $owner;

        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElementOrDie('entry', $doc);

            $rootDoc = $this->owner->securityProfileRoot->ownerDocument;
            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot);

            $this->name = $name;
            $this->xmlroot->setAttribute('name', $name);
        }

        $this->name = $name;
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

        if( $c->isAPI())
            $c->sendRenameRequest($xpath, $newName);
    }

    /**
     * @param DOMElement $xml
     * @return bool TRUE if loaded ok, FALSE if not
     * @ignore
     */
    public function load_from_domxml(DOMElement $xml, $withOwner = true )
    {
        $this->secprof_type = "url-filtering";

        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("URL SecurityProfile name not found\n");

        #PH::print_stdout( "\nsecprofURL TMP: object named '".$this->name."' found");

        if( $withOwner )
        {
            if(  get_class($this->owner->owner) == "PanoramaConf" || get_class($this->owner->owner) == "PANConf" || get_class($this->owner->owner) == "FawkesConf" )
                $predefined_url_store = $this->owner->owner->urlStore;
            else
                $predefined_url_store = $this->owner->owner->owner->urlStore;
            $predefined_urls = $predefined_url_store->securityProfiles();

            foreach( $predefined_urls as $predefined_url )
            {
                $this->allow[$predefined_url->name()] = $predefined_url->name();
                $this->allow_credential[$predefined_url->name()] = $predefined_url->name();
            }

            $this->predefined = $this->allow;
        }
        else
        {
            $this->allow = array();
            $this->predefined = $this->allow;
        }



        foreach( $this->tmp_url_prof_array as $url_type )
        {
            $tmp_url_action = DH::findFirstElement($url_type, $xml);
            if( $tmp_url_action !== FALSE )
            {
                foreach( $tmp_url_action->childNodes as $tmp_entry )
                {
                    if( $tmp_entry->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $url_category = $tmp_entry->textContent;
                    $this->_all[ $url_category ] = $url_type;

                    if( $url_type == 'allow' )
                        $this->allow[ $url_category ] = $url_category;
                    elseif( $url_type !== 'allow' )
                    {
                        if( $url_type == 'alert' )
                            $this->alert[ $url_category ] = $url_category;
                        elseif( $url_type == 'block' )
                            $this->block[ $url_category ] = $url_category;
                        elseif( $url_type == 'continue' )
                            $this->continue[ $url_category ] = $url_category;
                        elseif( $url_type == 'override' )
                            $this->override[ $url_category ] = $url_category;

                        unset($this->allow[ $url_category ]);
                    }

                    // add references
                    if( isset( $this->predefined[$url_category] ) )
                    {
                        $tmp_obj = $predefined_url_store->find($url_category);
                        if( $tmp_obj !== null )
                            $tmp_obj->addReference($this);
                    }
                    else
                    {
                        # add references to custom url category
                        $tmp_obj = $this->owner->owner->customURLProfileStore->find( $url_category );
                        if( $tmp_obj !== null )
                            $tmp_obj->addReference($this);
                    }
                }
            }
        }

        $tmp_credential_enforcement = DH::findFirstElement("credential-enforcement", $xml);
        if( $tmp_credential_enforcement != null )
        {
            foreach( $this->tmp_url_prof_array as $url_type )
            {
                $tmp_url_action = DH::findFirstElement($url_type, $tmp_credential_enforcement);
                if( $tmp_url_action !== FALSE )
                {
                    foreach( $tmp_url_action->childNodes as $tmp_entry )
                    {
                        if( $tmp_entry->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $url_category = $tmp_entry->textContent;
                        $this->_all_credential[ $url_category ] = $url_type;

                        if( $url_type == 'allow' )
                            $this->allow_credential[ $url_category ] = $url_category;
                        elseif( $url_type !== 'allow' )
                        {
                            if( $url_type == 'alert' )
                                $this->alert_credential[ $url_category ] = $url_category;
                            elseif( $url_type == 'block' )
                                $this->block_credential[ $url_category ] = $url_category;
                            elseif( $url_type == 'continue' )
                                $this->continue_credential[ $url_category ] = $url_category;
                            elseif( $url_type == 'override' )
                                $this->override_credential[ $url_category ] = $url_category;

                            unset($this->allow_credential[ $url_category ]);
                        }
                    }
                }
            }

            $tmp_credential_mode = DH::findFirstElement("mode", $tmp_credential_enforcement);
            if( $tmp_credential_mode != null )
            {
                $mode_node = DH::firstChildElement($tmp_credential_mode);
                $this->credential_mode = $mode_node->nodeName;
            }

            $tmp_credential_log_severity = DH::findFirstElement("log-severity", $tmp_credential_enforcement);
            if( $tmp_credential_log_severity != null )
                $this->credential_log = $tmp_credential_log_severity->textContent;
        }

        return TRUE;
    }


    public function display()
    {
        PH::print_stdout(  "     * " . get_class($this) . " '" . $this->name() . "'    " );
        PH::$JSON_TMP['sub']['object'][$this->name()]['name'] = $this->name();
        PH::$JSON_TMP['sub']['object'][$this->name()]['type'] = get_class($this);

        //Todo: continue for PH::print_stdout( ); out
        foreach( $this->tmp_url_prof_array as $url_type )
        {
            PH::print_stdout(  "       " . PH::boldText(strtoupper($url_type)) );
            sort($this->$url_type);
            foreach( $this->$url_type as $member )
            {
                PH::print_stdout(  "         - " . $member );
                PH::$JSON_TMP['sub']['object'][$this->name()][strtoupper($url_type)][] = $member;
            }

            $url_type_credential = $url_type."_credential";
            PH::print_stdout(  "       " . PH::boldText(strtoupper($url_type_credential)) );
            foreach( $this->$url_type_credential as $member )
            {
                PH::print_stdout(  "         - " . $member );
                PH::$JSON_TMP['sub']['object'][$this->name()][strtoupper($url_type_credential)][] = $member;
            }
        }
        PH::print_stdout( ) ;
        if( $this->credential_mode !== null )
            PH::print_stdout(  "       - mode: " . $this->credential_mode );
        if( $this->credential_log !== null )
            PH::print_stdout(  "       - log-severity: " . $this->credential_log );
    }

    public function getAllow()
    {
        return $this->allow;
    }

    public function getAlert()
    {
        return $this->alert;
    }

    public function getBlock()
    {
        return $this->block;
    }

    public function getContinue()
    {
        return $this->continue;
    }

    public function getOverride()
    {
        return $this->override;
    }

    public function setAction($action, $category, $type="site-access")
    {
        #print "ACTION: $action\n";
        #print "CATEGORY: $category\n";
        if( $category == "all" )
        {
            //Todo:
            //1) update memory
            //2) update XML
            //3) update API
        }
        elseif( strpos($category, "all-") !== FALSE )
        {
            $tmp_action = explode("all-", $category);

            #print_r($tmp_action);
            if( $tmp_action[1] == "allow" )
            {
                $typeFilter = $tmp_action[1];
                if( $type == "site-access" )
                {
                    foreach( $this->allow as $member )
                    {
                        $this->deleteMember( $member, $typeFilter );
                        $this->addMember( $member, $action);
                    }
                }
                else
                {
                    foreach( $this->allow_credential as $member )
                    {
                        $this->deleteMember( $member, $typeFilter );
                        $this->addMember( $member, $action);
                    }
                }
            }
            elseif( $tmp_action[0] == "alert" )
            {
                $typeFilter = $tmp_action[0];
                if( $type == "site-access" )
                {
                    foreach ($this->alert as $member)
                    {
                        $this->deleteMember($member, $typeFilter);
                        $this->addMember($member, $action);
                    }
                }
                else
                {
                    foreach ($this->alert_credential as $member)
                    {
                        $this->deleteMember($member, $typeFilter);
                        $this->addMember($member, $action);
                    }
                }
            }
        }
        else
        {
            print "do something\n";
            //check if input is possible category;
            $curr_action = $this->getAction($category);

            print "curAction: ".$curr_action."\n";

            $this->deleteMember( $category, $curr_action );

            $this->addMember( $category, $action);

        }

    }

    public function getAction( $category )
    {
        if( isset( $this->alert[$category] ) )
            return "alert";

        if( isset( $this->block[$category] ) )
            return "block";

        if( isset( $this->continue[$category] ) )
            return "continue";

        if( isset( $this->override[$category] ) )
            return "override";

        return "allow";
    }



//ALL above are wrong and from addressstroe
//TOdo:

    /**
     * Add a member to this group, it must be passed as an object
     * @param string $newMember Object to be added
     * @param bool $rewriteXml
     * @return bool
     */
    public function addMember($newMember, $type, $rewriteXml = TRUE)
    {
        if( !in_array( $type, $this->tmp_url_prof_array ) )
            return false;

        if( !in_array($newMember, $this->$type, TRUE) )
        {
            $this->$type[] = $newMember;
            $this->_all[$newMember] = $type;
            if( $rewriteXml && $this->owner !== null )
            {
                $tmp = DH::findFirstElementOrCreate("credential-enforcement", $this->xmlroot);
                $array = array( $this->xmlroot, $tmp );
                #$array = array( $this->xmlroot );
                foreach( $array as $xmlNode )
                {
                    $tmp = DH::findFirstElementOrCreate($type, $xmlNode);
                    DH::createElement($tmp, 'member', $newMember);
                }
            }

            return TRUE;
        }

        return FALSE;
    }

    /**
     * Add a member to this group, it must be passed as an object
     * @param string $newMember Object to be added
     * @param bool $rewriteXml
     * @return bool
     */
    public function deleteMember($newMember, $type, $rewriteXml = TRUE)
    {
        if( !in_array( $type, $this->tmp_url_prof_array ) )
            return false;

        if( in_array($newMember, $this->$type, TRUE) )
        {
            $key = array_search($newMember, $this->$type);
            unset($this->$type[$key]);
            unset($this->_all[$key]);

            if( $rewriteXml && $this->owner !== null )
            {
                $tmp = DH::findFirstElementOrCreate("credential-enforcement", $this->xmlroot);
                $array = array( $this->xmlroot, $tmp );
                #$array = array( $this->xmlroot );
                foreach( $array as $xmlNode )
                {
                    $actionXMLnode = DH::findFirstElementOrCreate($type, $xmlNode);
                    foreach( $actionXMLnode->childNodes as $membernode )
                    {
                        /** @var DOMElement $membernode */
                        if( $membernode->nodeType != 1 ) continue;

                        if( $membernode->textContent == $newMember )
                            $actionXMLnode->removeChild( $membernode );
                    }

                    if( count( $this->$type ) === 0 || $type === "allow")
                        $xmlNode->removeChild( $actionXMLnode );
                }
            }

            return TRUE;
        }

        return FALSE;
    }

    /**
     * @return string ie: 'ip-netmask' 'ip-range'
     */
    public function type()
    {
        return self::$SecurityProfileTypes[$this->type];
    }

    public function isSecurityProfile()
    {
        return TRUE;
    }

    public function isTmpSecProf()
    {
        if( $this->type == self::TypeTmp )
            return TRUE;

        return FALSE;
    }

    public function isType_Virus()
    {
        return $this->type == self::TypeVirus;
    }

    public function isType_Spyware()
    {
        return $this->type == self::TypeSpyware;
    }

    public function isType_Vulnerability()
    {
        return $this->type == self::TypeVulnerability;
    }

    public function isType_TMP()
    {
        return $this->type == self::TypeTmp;
    }

    public function isType_File_blocking()
    {
        return $this->type == self::TypeFile_blocking;
    }

    public function isType_Wildfire_analysis()
    {
        return $this->type == self::TypeWildfire_analysis;
    }

    public function isType_Url_filtering()
    {
        return $this->type == self::TypeUrl_filtering;
    }


    public function removeReference($object)
    {
        $this->super_removeReference($object);

        // adding extra cleaning
        if( $this->isTmpSecProf() && $this->countReferences() == 0 && $this->owner !== null )
        {
            //todo fix as remove has protected
            #$this->owner->remove($this);
        }

    }

    /**
     * @param customURLProfile $old
     * @param customURLProfile|null $new
     * @return bool
     */
    public function replaceReferencedObject($old, $new)
    {
        if( $old === null )
            derr("\$old cannot be null");

        if( isset( $this->_all[$old->name()] ) )
        {
            $old_type = $this->_all[$old->name()];

            if( $new === null || $new->name() == $old->name() )
                return False;

            #if( $new !== null && !$this->has( $new->name() ) )
            if( $new !== null && !isset( $this->_all[$new->name()] ) )
            {
                $this->deleteMember($old->name(), $old_type);
                $this->addMember( $new->name(), $old_type );
                $new->addReference($this);
            }
            else
            {
                $this->deleteMember($old->name(), $old_type);
                if( isset($this->_all[$new->name()]) )
                    $this->deleteMember($new->name(), $this->_all[$new->name()]);
                $this->addMember( $new->name(), $old_type );
            }
            $old->removeReference($this);

            #if( $new === null || $new->name() != $old->name() )
            #    $this->rewriteXML();

            return TRUE;
        }

        return FALSE;
    }

    public function API_replaceReferencedObject($old, $new)
    {
        $ret = $this->replaceReferencedObject($old, $new);

        if( $ret )
        {
            $this->API_sync();
        }

        return $ret;
    }


    public function url_siteaccess_bp_visibility_JSON( $checkType, $secprof_type )
    {
        $checkArray = array();

        if( $checkType !== "bp" && $checkType !== "visibility" )
            derr( "only 'bp' or 'visibility' argument allowed" );

        ###############################
        $details = PH::getBPjsonFile( );

        $array_type = "site_access";

        if( isset($details[$secprof_type][$array_type]) )
        {
            if( $checkType == "bp" )
            {
                if( isset($details[$secprof_type][$array_type]['bp']))
                    $checkArray = $details[$secprof_type][$array_type]['bp'];
                else
                    derr( "this JSON bp/visibility JSON file does not have 'bp' -> '".$array_type."' defined correctly for: '".$secprof_type."'", null, FALSE );
            }
            elseif( $checkType == "visibility")
            {
                if( isset($details[$secprof_type][$array_type]['visibility']))
                    $checkArray = $details[$secprof_type][$array_type]['visibility'];
                else
                    derr( "this JSON bp/visibility JSON file does not have 'visibility' -> '".$array_type."' defined correctly for: '".$secprof_type."'", null, FALSE );
            }
        }

        return $checkArray;
    }

    public function url_usercredentialsubmission_bp_visibility_JSON( $checkType, $secprof_type )
    {
        $checkArray = array();

        if( $checkType !== "bp" && $checkType !== "visibility" )
            derr( "only 'bp' or 'visibility' argument allowed" );

        ###############################
        $details = PH::getBPjsonFile( );

        $array_type = "user_credential_submission";

        if( isset($details[$secprof_type][$array_type]) )
        {
            if( $checkType == "bp" )
            {
                if( isset($details[$secprof_type][$array_type]['bp']))
                    $checkArray = $details[$secprof_type][$array_type]['bp'];
                else
                    derr( "this JSON bp/visibility JSON file does not have 'bp' -> '".$array_type."' defined correctly for: '".$secprof_type."'", null, FALSE );
            }
            elseif( $checkType == "visibility")
            {
                if( isset($details[$secprof_type][$array_type]['visibility']))
                    $checkArray = $details[$secprof_type][$array_type]['visibility'];
                else
                    derr( "this JSON bp/visibility JSON file does not have 'visibility' -> '".$array_type."' defined correctly for: '".$secprof_type."'", null, FALSE );
            }
        }

        return $checkArray;
    }

    public function check_siteaccess_bp_json( $check_array )
    {
        foreach( $check_array as $check )
        {
            $action = $check["action"];
            $urlList = $check["type"];

            foreach( $urlList as $url )
            {
                if( !in_array( $url, $this->$action ) )
                    return false;
            }
        }

        return TRUE;
    }

    public function check_siteaccess_visibility_json( $check_array )
    {
        $finding = $check_array;
        if( strpos( $check_array, "!") !== FALSE )
        {
            $finding = str_replace("!", "", $check_array);

            $sanitized_action = $this->$finding;
            foreach( $sanitized_action as $key => $url_category)
            {
                $custom_url_category_obj = $this->owner->owner->customURLProfileStore->find($url_category);
                if( $custom_url_category_obj !== NULL )
                    unset( $sanitized_action[$key] );
            }

            if( !empty($sanitized_action) )
                return False;
        }

        return TRUE;
    }

    public function check_usercredentialsubmission_bp_json( $check_array )
    {
        if( is_array( $check_array['category'] ) )
        {
            foreach( $check_array['category'] as $check )
            {
                $action = $check["action"]."_credential";
                $urlList = $check["type"];

                foreach( $urlList as $url )
                {
                    if( !isset($this->$action[$url]) )
                    {
                        #print $url." NOT in array\n";
                        return false;
                    }

                    #if( !in_array( $url, $this->$action ) )
                    #    return false;
                }
            }
        }
        else
        {
            if( strpos( $check_array['category'], "!") !== FALSE )
            {
                $finding = str_replace("!", "", $check_array['category']);

                $sanitized_action = $this->$finding;
                foreach( $sanitized_action as $key => $url_category)
                {
                    $custom_url_category_obj = $this->owner->owner->customURLProfileStore->find($url_category);
                    if( $custom_url_category_obj !== NULL )
                        unset( $sanitized_action[$key] );
                }

                if( !empty($sanitized_action) )
                    return False;
            }
        }



        return TRUE;
    }

    public function check_usercredentialsubmission_visibility_json( $check_array )
    {
        $finding = $check_array['category'];
        if( strpos( $check_array['category'], "!") !== FALSE )
        {
            $finding = str_replace("!", "", $check_array['category']);

            $sanitized_action = $this->$finding;
            foreach( $sanitized_action as $key => $url_category)
            {
                $custom_url_category_obj = $this->owner->owner->customURLProfileStore->find($url_category);
                if( $custom_url_category_obj !== NULL )
                    unset( $sanitized_action[$key] );
            }

            if( !empty($sanitized_action) )
                return False;
        }

        return TRUE;
    }

    public function check_usercredentialsubmission_bp_tab_json( $check_array )
    {
        if( $this->credential_mode == null)
        {
            #PH::print_stdout("no credential mode");
            return False;
        }

        if( $this->credential_log == null)
        {
            #PH::print_stdout("no credential log");
            return False;
        }


        if( $check_array['tab']['mode'] !== $this->credential_mode )
        {
            #PH::print_stdout("wrong credential mode");
            return False;
        }

        #if( isset($check_array['tab']['log-severity']) && $check_array['tab']['log-severity'] !== $this->credential_log )
        #{
        #    PH::print_stdout("wrong log-severity");
        #    return False;
        #}

        return TRUE;
    }

    public function check_usercredentialsubmission_visibility_tab_json( $check_array )
    {
        if( $this->credential_mode == null)
            return False;

        $finding = $check_array['tab']['mode'];
        if( strpos( $check_array['tab']['mode'], "!") !== FALSE )
        {
            $finding = str_replace("!", "", $check_array['tab']['mode']);
            if( $finding === $this->credential_mode )
                return False;
        }

        return TRUE;
    }

    public function url_siteaccess_best_practice()
    {
        $check_array = $this->url_siteaccess_bp_visibility_JSON( "bp", "url" );
        $bestpractise = $this->check_siteaccess_bp_json( $check_array );

        if ($bestpractise == FALSE)
            return FALSE;
        else
            return TRUE;
    }

    public function url_siteaccess_visibility()
    {
        $check_array = $this->url_siteaccess_bp_visibility_JSON( "visibility", "url" );
        $bestpractise = $this->check_siteaccess_visibility_json( $check_array );

        if ($bestpractise == FALSE)
            return FALSE;
        else
            return TRUE;
    }


    public function url_usercredentialsubmission_best_practice()
    {
        $check_array = $this->url_usercredentialsubmission_bp_visibility_JSON( "bp", "url" );
        $bestpractise = $this->check_usercredentialsubmission_bp_json( $check_array );

        if ($bestpractise == FALSE)
            return FALSE;
        else
            return TRUE;
    }

    public function url_usercredentialsubmission_best_practice_tab()
    {
        $check_array = $this->url_usercredentialsubmission_bp_visibility_JSON( "bp", "url" );
        $bestpractise = $this->check_usercredentialsubmission_bp_tab_json( $check_array );

        if ($bestpractise == FALSE)
            return FALSE;
        else
            return TRUE;
    }

    public function url_usercredentialsubmission_visibility()
    {
        $check_array = $this->url_usercredentialsubmission_bp_visibility_JSON( "visibility", "url" );
        $bestpractise = $this->check_usercredentialsubmission_visibility_json( $check_array );

        if ($bestpractise == FALSE)
            return FALSE;
        else
            return TRUE;
    }

    public function url_usercredentialsubmission_visibility_tab()
    {
        $check_array = $this->url_usercredentialsubmission_bp_visibility_JSON( "visibility", "url" );
        $bestpractise = $this->check_usercredentialsubmission_visibility_tab_json( $check_array );

        if ($bestpractise == FALSE)
            return FALSE;
        else
            return TRUE;
    }

    public function is_best_practice()
    {
        if( $this->url_siteaccess_best_practice()
            && $this->url_usercredentialsubmission_best_practice()
            && $this->url_usercredentialsubmission_best_practice_tab()
        )
            return TRUE;
        else
            return FALSE;
    }

    public function is_visibility()
    {
        if( $this->url_siteaccess_visibility()
            && $this->url_usercredentialsubmission_visibility()
            && $this->url_usercredentialsubmission_visibility_tab()
        )
            return TRUE;
        else
            return FALSE;
    }

    public function is_adoption()
    {
        if( $this->site_access_is_adoption() && $this->credential_is_adoption() )
            return true;
        else
            return false;
    }

    public function site_access_is_best_practice()
    {
        if( $this->url_siteaccess_best_practice() )
            return TRUE;
        else
            return FALSE;
    }

    public function site_access_is_visibility()
    {
        if( $this->url_siteaccess_visibility() )
            return TRUE;
        else
            return FALSE;
    }

    public function site_access_is_adoption()
    {
        return TRUE;
    }

    public function credential_is_best_practice()
    {
        if( $this->url_usercredentialsubmission_best_practice()
            && $this->url_usercredentialsubmission_best_practice_tab()
        )
            return TRUE;
        else
            return FALSE;
    }

    public function credential_is_visibility()
    {
        if( $this->url_usercredentialsubmission_visibility()
            && $this->url_usercredentialsubmission_visibility_tab()
        )
            return TRUE;
        else
            return FALSE;
    }

    public function credential_is_adoption()
    {
        if( $this->credential_mode !== null && $this->credential_mode !== "disabled")
            return TRUE;
        return False;
    }

    static $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

}

