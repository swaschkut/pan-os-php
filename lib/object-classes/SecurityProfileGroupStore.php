<?php

/**
 * Class SecurityProfileGroup
 * @property SecurityProfileGroup[] $o
 * @property VirtualSystem|DeviceGroup|PanoramaConf|PANConf|Container|DeviceCloud $owner
 * @method SecurityProfileGroup[] getAll()
 */
class SecurityProfileGroupStore extends ObjStore
{

    /** @var VirtualSystem|DeviceGroup|PanoramaConf|PANConf|Container|DeviceCloud|DeviceOnPrem|null */
    public $owner;
    public $name = 'temporaryname';

    /** @var null|SecurityProfileGroupStore */
    public $parentCentralStore = null;

    public static $childn = 'SecurityProfileGroup';

    public $secprof_array = array('virus', 'spyware', 'vulnerability', 'file-blocking', 'wildfire-analysis', 'url-filtering', 'data-filtering');
    public $secprof_store = array( 'AntiVirusProfileStore', 'AntiSpywareProfileStore', 'VulnerabilityProfileStore', 'FileBlockingProfileStore', 'WildfireProfileStore', 'URLProfileStore', 'DataFilteringProfileStore' );

    // SCM (Fawkes / Buckbeak): the profile types of a security profile group / rule profile-setting
    private $secprof_fawkes_array = array('virus-and-wildfire-analysis', 'spyware', 'vulnerability', 'file-blocking', 'dns-security', 'url-filtering', 'saas-security', 'data-filtering');
    private $secprof_fawkes_store = array( 'VirusAndWildfireProfileStore', 'AntiSpywareProfileStore', 'VulnerabilityProfileStore', 'FileBlockingProfileStore', 'DNSSecurityProfileStore', 'URLProfileStore', 'SaasSecurityProfileStore', 'DataFilteringProfileStore' );
    

    /** @var DOMElement */
    public $securityProfileRoot;

    /** @var DOMElement */
    public $securityProfileGroupRoot;

    public function __construct($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;
        $this->o = array();

        // SCM locations use the SCM profile types (rules look them up through secprof_array / secprof_store)
        if( is_object($owner) && in_array( get_class($owner), array( 'FawkesConf', 'BuckbeakConf', 'Container', 'DeviceCloud', 'DeviceOnPrem', 'Snippet' ), TRUE ) )
        {
            $this->secprof_array = $this->secprof_fawkes_array;
            $this->secprof_store = $this->secprof_fawkes_store;
        }

        $this->setParentCentralStore( 'securityProfileGroupStore' );
    }

    public function all($withFilter = null)
    {
        $query = null;

        if( $withFilter !== null && $withFilter !== '' )
        {
            $queryContext = array();

            if( is_array($withFilter) )
            {
                $filter = &$withFilter['query'];
                $queryContext['nestedQueries'] = &$withFilter;
            }
            else
                $filter = &$withFilter;

            $errMesg = '';
            $query = new RQuery('securityprofilegroup');
            if( $query->parseFromString($filter, $errMsg) === FALSE )
                derr("error while parsing query: {$errMesg}");

            $res = array();

            foreach( $this->o as $securityProfileGroup )
            {
                $queryContext['object'] = $securityProfileGroup;
                if( $query->matchSingleObject($queryContext) )
                    $res[] = $securityProfileGroup;
            }

            return $res;
        }

        $res = $this->o;

        return $res;
    }

    public function count()
    {
        return count($this->o);
    }

    public function load_securityprofile_groups_from_domxml($xml)
    {
        $this->securityProfileGroupRoot = $xml;
        $this->xmlroot = $this->securityProfileGroupRoot;


        foreach( $this->securityProfileGroupRoot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $name = DH::findAttribute('name', $node);
            $tmp_secgroup = new SecurityProfileGroup( $name, $this, true );
            $tmp_secgroup->load_from_domxml( $node, $this);

            $this->o[] = $tmp_secgroup;
            $this->nameIndex[$name] = $tmp_secgroup;


            $this->addSecurityProfileGroup( $tmp_secgroup );
            #$this->xmlroot->appendChild($tmp_secgroup->xmlroot);
        }
    }

    /**
     * Returns name of this rule
     * @return string
     */
    public function name()
    {
        return $this->name;
    }


    /**
     * profile group with these profiles (hash of calculateHash())
     * @param string $hash
     * @param bool $nested also the stores of the parent device-groups / containers and shared (nearest first)
     * @param array|null $profilesObj profile objects of the rule (securityProfiles_obj()): a group of a parent store is
     *        only taken if its profiles are the same objects - a profile overridden below (same name) is not the same
     * @return SecurityProfileGroup|null
     */
    public function findByHash( $hash, $nested = FALSE, $profilesObj = null )
    {
        foreach( $this->all() as $securityProfileGroup )
        {
            if( $hash == $securityProfileGroup->hash )
                return $securityProfileGroup;
        }

        if( !$nested )
            return null;

        $seen = array( spl_object_id($this) => TRUE );
        for( $store = $this->parentCentralStore; $store !== null && !isset($seen[spl_object_id($store)]); $store = $store->parentCentralStore )
        {
            $seen[spl_object_id($store)] = TRUE;
            foreach( $store->all() as $securityProfileGroup )
                if( $hash == $securityProfileGroup->hash
                    && ( $profilesObj === null || self::sameProfileObjects($securityProfileGroup, $profilesObj) ) )
                    return $securityProfileGroup;
        }

        return null;
    }

    /** the profiles of the group are the profile objects of the rule (names compared where one side is not an object) */
    static private function sameProfileObjects( SecurityProfileGroup $group, array $profilesObj )
    {
        foreach( $profilesObj as $type => $obj )
        {
            $gobj = isset($group->secprofProfiles_obj[$type]) ? $group->secprofProfiles_obj[$type] : null;
            if( is_object($obj) && is_object($gobj) )
            {
                if( $obj !== $gobj )
                    return FALSE;
            }
            else
            {
                $n1 = is_object($obj) ? $obj->name() : (string)$obj;
                $n2 = is_object($gobj) ? $gobj->name() : (string)$gobj;
                if( $n1 !== $n2 )
                    return FALSE;
            }
        }
        return TRUE;
    }

    public function calculateHash( $secprofArray )
    {
        $str = '';
        $counter = count( $this->secprof_array );
        $i = 1;
        foreach( $this->secprof_array as $secprof )
        {
            if( isset( $secprofArray[$secprof] ) )
            {
                if( is_object( $secprofArray[$secprof] ) )
                    $str .= $secprof.':'.$secprofArray[$secprof]->name();
                else
                    $str .= $secprof.':'.$secprofArray[$secprof];
            }


            if( $i < $counter )
            {
                if( isset( $secprofArray[$secprof] ) )
                    $str .= ',';

                $i++;
            }
        }

        return md5( $str );
    }

    public function createSecurityProfileGroup_based_Profile( $secProf_array, $secProfOBJ_array = array() )
    {
        $name = $this->findAvailableSecurityProfileGroupName( "secProfGroup"  );

        $tmp_secProfGroup = new SecurityProfileGroup( $name, $this, true );

        $this->o[] = $tmp_secProfGroup;
        $this->nameIndex[$name] = $tmp_secProfGroup;

        $string = "<entry name=\"".$name."\">\n";

        foreach( $secProf_array as $key => $secProf )
        {
            $string .= "<".$key.">\n";
            if( is_object($secProf) )
                $string .= "<member>".$secProf->name()."</member>\n";
            else
                $string .= "<member>".$secProf."</member>\n";
            $string .= "</".$key.">\n";

            if( is_object($secProf) )
            {
                if( isset( $secProfOBJ_array[$secProf->name()] ) )
                    $secProfOBJ_array[$secProf->name()]->addReference( $tmp_secProfGroup );
            }
            else
            {
                if( isset( $secProfOBJ_array[$secProf] ) )
                    $secProfOBJ_array[$secProf]->addReference( $tmp_secProfGroup );
            }
        }

        $string .= "</entry>\n";


        $newSecProfGroupRoot = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $string);

        $tmp_secProfGroup->load_from_domxml( $newSecProfGroupRoot, $this );


        $this->xmlroot->appendChild($tmp_secProfGroup->xmlroot);
        #$this->addSecurityProfileGroup( $tmp_secProfGroup );


        return $tmp_secProfGroup;

    }

    public function removeAllSecurityProfileGroups()
    {
        $this->removeAll();
        $this->rewriteXML();
    }

    /**
     * add a SecurityProfileGroup to this store. Use at your own risk.
     * @param SecurityProfileGroupStore $Obj
     * @param bool
     * @return bool
     */
    public function addSecurityProfileGroup(SecurityProfileGroup $Obj, $rewriteXML = TRUE)
    {
        $ret = $this->add($Obj);
        if( $ret && $rewriteXML )
        {
            if( $this->xmlroot === null )
            {
                $xml = $this->findCreateXmlRoot();

                $this->xmlroot = DH::findFirstElementOrCreate('profile-group', $xml);
            }

            $this->xmlroot->appendChild($Obj->xmlroot);
        }
        return $ret;
    }

    /**
     * @param string $base
     * @param string $suffix
     * @param integer|string $startCount
     * @return string
     */
    public function findAvailableSecurityProfileGroupName($base, $suffix = '', $startCount = 0)
    {
        $maxl = 31;
        $basel = strlen($base);
        $suffixl = strlen($suffix);
        $inc = $startCount;
        $basePlusSuffixL = $basel + $suffixl;

        while( TRUE )
        {
            $incl = strlen(strval($inc));

            if( $basePlusSuffixL + $incl > $maxl )
            {
                $newname = substr($base, 0, $basel - $suffixl - $incl) . $suffix . $inc;
            }
            else
                $newname = $base . $suffix . $inc;

            if( $this->find($newname, null, FALSE) === null )
                return $newname;

            if( $startCount == '' )
                $startCount = 0;
            $inc++;
        }
    }


    /**
     * return securityprofilegroups in this store
     * @return SecurityProfileGroup[]
     */
    public function securityProfileGroups()
    {
        return $this->o;
    }

    function createSecurityProfileGroup($name, $ref = null)
    {
        if( $this->find($name, null, FALSE) !== null )
            derr('SecurityProfileGroup named "' . $name . '" already exists, cannot create');

        if( $this->xmlroot === null )
        {
            $xml = $this->findCreateXmlRoot();

            $this->xmlroot = DH::findFirstElementOrCreate('profile-group', $xml);
        }

        $newSecurityProfileGroup = new SecurityProfileGroup($name, $this);
        $newSecurityProfileGroup->owner = null;

        $this->o[] = $newSecurityProfileGroup;

        $newSecurityProfileRoot = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, SecurityProfileGroup::$templatexml);
        $newSecurityProfileRoot->setAttribute('name', $name);
        $newSecurityProfileGroup->load_from_domxml($newSecurityProfileRoot, $this);

        if( $ref !== null )
            $newSecurityProfileGroup->addReference($ref);

        $this->addSecurityProfileGroup($newSecurityProfileGroup);

        return $newSecurityProfileGroup;
    }

    function findOrCreate($name, $ref = null, $nested = TRUE)
    {
        $f = $this->find($name, $ref, $nested);

        if( $f !== null )
            return $f;

        return $this->createSecurityProfileGroup($name, $ref);
    }

    function API_createSecurityProfileGroup($name, $ref = null)
    {
        $newSecurityProfileGroup = $this->createSecurityProfileGroup($name, $ref);

        $xpath = $this->getXPath();
        $con = findConnectorOrDie($this);
        $element = $newSecurityProfileGroup->getXmlText_inline();

        if( $con->isAPI() )
            $con->sendSetRequest($xpath, $element);

        return $newSecurityProfileGroup;
    }


    /**
     * @param SecurityProfileGroupStore $tag
     *
     * @return bool  True if Zone was found and removed. False if not found.
     */
    /**
     * Groups visible from this location: own groups first, then those of the parent locations
     * (a name is listed once, the lowest copy wins).
     * @return SecurityProfileGroup[]
     */
    public function nestedPointOfView()
    {
        $current = $this;
        $objects = array();

        while( TRUE )
        {
            foreach( $current->o as $o )
                if( !isset($objects[$o->name()]) )
                    $objects[$o->name()] = $o;

            if( isset($current->owner->parentDeviceGroup) && $current->owner->parentDeviceGroup !== null )
                $current = $current->owner->parentDeviceGroup->securityProfileGroupStore;
            elseif( isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                $current = $current->owner->parentContainer->securityProfileGroupStore;
            elseif( isset($current->owner->owner) && $current->owner->owner !== null && !$current->owner->owner->isFawkes() && !$current->owner->owner->isBuckbeak() )
                $current = $current->owner->owner->securityProfileGroupStore;
            else
                break;
        }

        return $objects;
    }

    public function removeSecurityProfileGroup(SecurityProfileGroup $tag)
    {
        $ret = $this->remove($tag);

        if( $ret && $this->xmlroot !== null )
        {
            $this->xmlroot->removeChild($tag->xmlroot);
        }

        return $ret;
    }

    /**
     * @param SecurityProfileGroupStore $securityProfileGroup
     * @return bool
     */
    public function API_removeSecurityProfileGroup(SecurityProfileGroup $securityProfileGroup)
    {
        $xpath = null;

        $xpath = $securityProfileGroup->getXPath();

        $ret = $this->removeSecurityProfileGroup($securityProfileGroup);

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            if( $con->isAPI() )
                $con->sendDeleteRequest($xpath);
        }

        return $ret;
    }

    public function &getXPath()
    {
        $str = '';

        if( $this->owner->isDeviceGroup() || $this->owner->isVirtualSystem() || $this->owner->isContainer() || $this->owner->isDeviceCloud() )
            $str = $this->owner->getXPath();
        elseif( $this->owner->isPanorama() )
            $str = '/config/shared';
        elseif( $this->owner->isFirewall() )
        {
            $str = '/config';
        }
        else
            derr('unsupported');

        $str = $str . '/profile-group';

        return $str;
    }


    private function &getBaseXPath()
    {
        if( $this->owner->isPanorama() || $this->owner->isFirewall() )
        {
            $str = "/config/shared";
            if( $this->owner->isFirewall() )
                $str = "/config";
            $str = $str . '/profile-group';
        }
        else
            $str = $this->owner->getXPath();


        return $str;
    }

    public function &getSecurityProfileGroupStoreXPath()
    {
        #$path = $this->getBaseXPath() . '/profile-group';
        $path = $this->getBaseXPath();
        return $path;
    }

    public function rewriteXML()
    {
        if( count($this->o) > 0 )
        {
            if( $this->xmlroot === null )
                return;

            $this->xmlroot->parentNode->removeChild($this->xmlroot);
            $this->xmlroot = null;
        }

        if( $this->xmlroot === null )
        {
            if( count($this->o) > 0 )
            {
                $xml = $this->findCreateXmlRoot();

                $this->xmlroot = DH::findFirstElementOrCreate('profile-group', $xml);
            }

        }

        DH::clearDomNodeChilds($this->xmlroot);
        foreach( $this->o as $o )
        {
            #PH::print_stdout(  "OBJ: ".$o->name() );
            $this->xmlroot->appendChild($o->xmlroot);
        }
    }



    public function createXmlRoot()
    {
        if( $this->xmlroot === null )
        {
            $xml = $this->findCreateXmlRoot();

            $xml = DH::findFirstElementOrCreate('profile-group', $xml);
            $this->xmlroot = $xml;
        }
    }
}

