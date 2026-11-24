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

/**
 * Class IKEGateway
 * @property IKEGatewayStore $owner
 */
class IKEGateway
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferenceableObject;
    use NetworkObjectEdit;

    public $owner;

    /** @var null|string[]|DOMElement */
    public $typeRoot = null;

    public $type = 'notfound';

    public $preSharedKey = '';

    public $proposal = '';

    public $version = '';

    public $natTraversal = '';
    public $fragmentation = '';

    public $localAddress = FALSE;
    public $localInterface = FALSE;
    public $peerAddress = FALSE;

    public $localID = FALSE;
    public $peerID = FALSE;

    public $localIDtype = FALSE;
    public $peerIDtype = FALSE;

    public $disabled = "no";

    public $exchangemode = "auto";

    /**
     * IKEGateway constructor.
     * @param string $name
     * @param IKEGatewayStore $owner
     */
    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
    }

    /**
     * @param DOMElement $xml
     */
    public function load_from_domxml($xml)
    {
        $tmp_interface = null;

        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("IKE gateway name not found\n");

        #print "imported gateway with name: ". $this->name."\n";

        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 )
                continue;

            if( $node->nodeName == 'authentication' )
            {
                $tmp_psk = DH::findFirstElement('pre-shared-key', $node);
                if( $tmp_psk != null )
                {
                    $tmp_key = DH::findFirstElement('key', $tmp_psk);
                    if( $tmp_key != null )
                        $this->preSharedKey = $tmp_key->textContent;
                }

            }

            if( $node->nodeName == 'local-address' )
            {
                $tmp_interface_string = DH::findFirstElement('interface', $node);
                if( $tmp_interface_string != null )
                {
                    $this->localInterface = $tmp_interface_string->textContent;

                    // template stack: the interface comes from one of its templates
                    $tmp_interface = $this->owner->owner->network->findInterfaceInTemplateScopeOrCreateTmp($this->localInterface);
                    $tmp_interface->addReference($this);
                }

                $localAddressNode = DH::findFirstElement('ip', $node);
                if( $localAddressNode != null )
                {
                    $this->localAddress = $localAddressNode->textContent;
                    $this->validateIPorObject($this->localAddress, $type = 'local-address');
                }

            }

            if( $node->nodeName == 'peer-address' )
            {
                $peerAddressNode = DH::findFirstElement('ip', $node);
                if( $peerAddressNode != null )
                {
                    $this->peerAddress = $peerAddressNode->textContent;
                    $this->validateIPorObject($this->peerAddress, $type = 'peer-address');
                }
            }


            if( $node->nodeName == 'protocol' )
            {
                $this->version = DH::findFirstElement('version', $node);
                if( $this->version != null )
                    $this->version = $this->version->textContent;

                // the IKE crypto profile: ikev1 / ikev2 each can name one; the version decides which one is used
                // (ikev2-preferred or no version: ikev2, else ikev1) - every one named is referenced
                $proposals = array();
                foreach( array( 'ikev2', 'ikev1' ) as $v )
                {
                    $tmp_v = DH::findFirstElement($v, $node);
                    $proposalNode = $tmp_v !== FALSE ? DH::findFirstElement('ike-crypto-profile', $tmp_v) : FALSE;
                    if( $proposalNode !== FALSE && $proposalNode !== null && $proposalNode->textContent !== '' )
                        $proposals[$v] = $proposalNode->textContent;
                }
                if( count($proposals) > 0 )
                    $this->proposal = isset($proposals[$this->version]) ? $proposals[$this->version] : reset($proposals);
                // template stack: the profile can come from one of its templates; SCM: from a parent folder / snippet
                $inTemplateScope = PH::templateScopeOwner( $this->owner->owner ) !== null;
                foreach( array_unique($proposals) as $proposal )
                {
                    $tmp_ike_profile = PH::findInNetworkScope( $this->owner->owner, 'ikeCryptoProfileStore', $proposal, 'findIKECryptoProfil' );
                    if( $tmp_ike_profile != NULL )
                        $tmp_ike_profile->addReference($this);
                    elseif( $inTemplateScope && !in_array( $proposal, array( 'default', 'Suite-B-GCM-128', 'Suite-B-GCM-256' ), TRUE ) )
                        mwarning( "Template '" . $this->owner->owner->owner->name() . "' IKE-gateway: '" . $this->name() . "' IKE-crypto-profile '" . $proposal . "' not found", null, false );
                }

                $tmp_ikevX = DH::findFirstElement( $this->version !== null && $this->version !== '' && $this->version !== 'ikev2-preferred' ? $this->version : 'ikev2', $node );
                if( $tmp_ikevX === FALSE || $tmp_ikevX === null )
                    $tmp_ikevX = DH::findFirstElement( 'ikev1', $node );
                if( $tmp_ikevX != null )
                {
                    $exchangemodeNode = DH::findFirstElement('exchange-mode', $tmp_ikevX);
                    if( $exchangemodeNode != null )
                        $this->exchangemode = $exchangemodeNode->textContent;
                    //<exchange-mode>main</exchange-mode>

                    $tmpDPD = DH::findFirstElement('dpd', $tmp_ikevX);
                    if( $tmpDPD != null )
                    {
                        $dpd_enabled = DH::findFirstElement('enable', $tmpDPD);
                        if( $dpd_enabled != null )
                            $dpd_enabled = $dpd_enabled->textContent;

                        $dpd_interval = DH::findFirstElement('interval', $tmpDPD);
                        if( $dpd_interval != null )
                            $dpd_interval = $dpd_interval->textContent;

                        $dpd_retry = DH::findFirstElement('retry', $tmpDPD);
                        if( $dpd_retry != null )
                            $dpd_retry = $dpd_retry->textContent;
                    }


                    //todo: dpd
                    /*
                      <protocol>
                        <ikev1>
                          <dpd>
                            <enable>yes</enable>
                            <interval>15</interval>
                            <retry>15</retry>
                          </dpd>
                        </ikev1>
                        <ikev2>
                          <dpd>
                            <enable>yes</enable>
                          </dpd>
                        </ikev2>
                      </protocol>
                     */
                }


                if( $this->proposal == null )
                    $this->proposal = "default";
                if( $this->exchangemode == null )
                    $this->exchangemode = "auto";
            }

            if( $node->nodeName == 'protocol-common' )
            {
                $tmp_natT = DH::findFirstElement('nat-traversal', $node);
                if( $tmp_natT != null )
                    $this->natTraversal = DH::findFirstElement('enable', $tmp_natT)->textContent;

                $tmp_frag = DH::findFirstElement('fragmentation', $node);
                if( $tmp_frag != null )
                    $this->fragmentation = DH::findFirstElement('enable', $tmp_frag)->textContent;
            }

            if( $node->nodeName == 'local-id' )
            {
                $this->localID = DH::findFirstElement('id', $node)->textContent;
                $this->localIDtype = DH::findFirstElement('type', $node)->textContent;
            }

            if( $node->nodeName == 'peer-id' )
            {
                $this->peerID = DH::findFirstElement('id', $node)->textContent;
                $this->peerIDtype = DH::findFirstElement('type', $node)->textContent;
            }


            if( $node->nodeName == 'disabled' )
                $this->disabled = $node->textContent;
        }
    }


    function validateIPorObject($nexthopIP, $type = 'local-address')
    {
        $pan_object = $this->owner->owner;
        if( isset( $pan_object->owner ) )
        {
            #if( get_class($pan_object->owner) == "Template" )
            if( get_class($pan_object->owner) == "Template" || get_class($pan_object->owner) == "TemplateStack" )
            {
                $template_object = $pan_object->owner;
                $panorama_object = $template_object->owner;
                $shared_object = $panorama_object->addressStore->find($nexthopIP);
                if( $shared_object != null )
                {
                    $shared_object->addReference($this);

                    if( $type == "local-address" )
                    {
                        #$this->_destination = $shared_object->value();
                        #$this->_destinationObject = $shared_object;
                    }
                    elseif( $type == "peer-address" )
                    {
                        #$this->_nexthopIP = $shared_object->value();
                        #$this->_nexthopIPObject = $shared_object;
                    }
                }
            }
        }
        else
        {
            $all_vsys = $pan_object->getVirtualSystems();

            foreach( $all_vsys as $vsys )
            {
                $ngfw_object = $vsys->addressStore->find($nexthopIP);
                if( $ngfw_object != null && !$ngfw_object->isTmpAddr() )
                {
                    $ngfw_object->addReference($this);

                    if( $type == "local-address" )
                    {
                        #$this->_destination = $ngfw_object->value();
                        #$this->_destinationObject = $ngfw_object;
                    }
                    elseif( $type == "peer-address" )
                    {
                        #$this->_nexthopIP = $ngfw_object->value();
                        #$this->_nexthopIPObject = $ngfw_object;
                    }
                }
            }

            if( count($all_vsys) == 0 )
            {
                #if( $type == "local-address" )
                #    $this->_destination = $nexthopIP;
                #elseif( $type == "peer-address" )
                #    $this->_nexthopIP = $nexthopIP;
            }
        }
    }

    /**
     * return true if change was successful false if not (duplicate rulename?)
     * @param string $name new name for the rule
     * @return bool
     */
    public function setName($name)
    {
        if( $this->name == $name )
            return TRUE;

        if( preg_match('[^\d]', $name) )
        {
            //NO digit allowed at the beginning of a name
            derr('no digit allowed at the beginning of a IKE gateway name');
        }

        if( preg_match('/[^0-9a-zA-Z_\-]/', $name) )
        {
            //NO blank allowed in gateway name
            //NO other characters are allowed as seen here
            $name = preg_replace('/[^0-9a-zA-Z_\-]/', "", $name);
            #print " *** new gateway name: ".$name." \n";
            #mwarning( 'Name will be replaced with: '.$name."\n" );
        }


        /* TODO: 20180331 finalize needed
        if( isset($this->owner) && $this->owner !== null )
        {
            if( $this->owner->isRuleNameAvailable($name) )
            {
                $oldname = $this->name;
                $this->name = $name;
                $this->owner->ruleWasRenamed($this,$oldname);
            }
            else
                return false;
        }
*/
        if( $this->name != "**temporarynamechangeme**" )
            $this->setRefName($name);

        $this->name = $name;

        $this->xmlroot->setAttribute('name', $name);

        return TRUE;

    }

    public function setproposal($proposal)
    {
        if( $this->proposal == $proposal )
            return TRUE;

        $this->proposal = $proposal;

        $tmp_gateway = DH::findFirstElementOrCreate('protocol', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate($this->version, $tmp_gateway);
        $tmp_gateway = DH::findFirstElementOrCreate('ike-crypto-profile', $tmp_gateway);
        DH::setDomNodeText($tmp_gateway, $proposal);

        return TRUE;
    }

    //Todo: swaschkut 20201001 update this
    public function setExchangeMode($mode)
    {
        if( $this->exchangemode == $mode )
            return TRUE;

        $this->exchangemode = $mode;

        //find correct xpath
        /*
        $tmp_gateway = DH::findFirstElementOrCreate('protocol', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate($this->version, $tmp_gateway);
        $tmp_gateway = DH::findFirstElementOrCreate('ike-crypto-profile', $tmp_gateway);
        DH::setDomNodeText($tmp_gateway, $mode);
        */
        return TRUE;
    }

    public function setinterface($interface, $type = "ethernet")
    {
        if( $this->localInterface == $interface )
            return TRUE;

        $this->localInterface = $interface;

        $tmp_gateway = DH::findFirstElementOrCreate('local-address', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate('interface', $tmp_gateway);
        DH::setDomNodeText($tmp_gateway, $interface);


        $tmp_interface = $this->owner->owner->network->findInterface($interface);
        if( !is_object($tmp_interface) )
        {
            if( $type == "ethernet" )
            {
                if( strpos($interface, ".") === FALSE )
                {
                    $tmp_interface = $this->owner->owner->network->ethernetIfStore->newEthernetIf($interface, 'layer3');

                    #$this->owner->owner->importedInterfaces->addInterface( $tmp_interface );
                }
                else
                {
                    //subinterface
                    $tmp_subinterface = explode(".", $interface);

                    $int_name = $tmp_subinterface[0];
                    $vlan_name = $tmp_subinterface[1];

                    $tmp_int_main = $this->owner->owner->network->findInterface($int_name);
                    if( !is_object($tmp_int_main) )
                    {
                        PH::print_stdout(  " - create interface: " . $int_name );
                        $tmp_int_main = $this->owner->owner->network->ethernetIfStore->newEthernetIf($int_name, 'layer3');
                        #$v->importedInterfaces->addInterface( $tmp_int_main );
                    }

                    $tmp_interface = $this->owner->owner->network->findInterface($interface);
                    if( !is_object($tmp_interface) )
                    {
                        #print "   - add subinterface: " . $int[5] . "\n";
                        $tmp_interface = $tmp_int_main->addSubInterface($vlan_name, $interface);
                        #$v->importedInterfaces->addInterface($tmp_sub);
                    }
                }
            }
            elseif( $type == "loopback" )
            {
                $tmp_interface = $this->owner->owner->network->loopbackIfStore->newLoopbackIf( $interface );
            }

        }
        $tmp_interface->addReference($this);

        #if( $interface == "loopback.21" )
            #derr( "STOP" );
        return TRUE;
    }

    public function setpeerAddress($peeraddress)
    {
        if( $this->peerAddress == $peeraddress )
            return TRUE;

        $this->peerAddress = $peeraddress;

        $tmp_gateway = DH::findFirstElementOrCreate('peer-address', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate('ip', $tmp_gateway);
        DH::setDomNodeText($tmp_gateway, $peeraddress);

        return TRUE;
    }

    public function setPreSharedKey($presharedkey)
    {
        if( $this->preSharedKey == $presharedkey )
            return TRUE;

        $this->preSharedKey = $presharedkey;

        $tmp_gateway = DH::findFirstElementOrCreate('authentication', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate('pre-shared-key', $tmp_gateway);
        $tmp_gateway = DH::findFirstElementOrCreate('key', $tmp_gateway);
        DH::setDomNodeText($tmp_gateway, $presharedkey);

        return TRUE;
    }

    /**
     * @param $newType string
     * @return bool true if successful
     */
    public function API_setPreSharedKey($presharedkey)
    {
        if( !$this->setPreSharedKey($presharedkey) )
            return FALSE;

        $c = findConnectorOrDie($this);

        #$xpath = $this->getXPath();
        $tmp_gateway = DH::findFirstElementOrCreate('authentication', $this->xmlroot);
        $xpath = DH::findFirstElementOrCreate('pre-shared-key', $tmp_gateway);
        $xpath = $xpath->getNodePath();

        $element = "<key>".PH::panosphp_htmlspecialchars($presharedkey) . "</key>";

        $c->sendSetRequest($xpath, $element);

        $this->setPreSharedKey($presharedkey);

        return TRUE;
    }
    //TODO: create set functions for:
    //set nat-traversal
    //set dpd


    // ---- changes of the actions (ike-gateway …-set): XML, object and references together; an invalid value: Exception

    const IKE_VERSIONS = array( 'ikev1', 'ikev2', 'ikev2-preferred' );
    const ID_TYPES = array( 'ipaddr', 'fqdn', 'ufqdn', 'keyid', 'dn' );
    /** IKE crypto profiles PAN-OS has without configuration */
    const PREDEFINED_IKE_CRYPTO_PROFILES = array( 'default', 'Suite-B-GCM-128', 'Suite-B-GCM-256' );

    /** the profile of the version used: ikev1 - the IKEv1 one, else the IKEv2 one (then the other one) */
    private function editProposal(): void
    {
        $v1 = $this->editTextOf( array( 'protocol', 'ikev1', 'ike-crypto-profile' ) );
        $v2 = $this->editTextOf( array( 'protocol', 'ikev2', 'ike-crypto-profile' ) );
        $p = $this->version === 'ikev1' ? ( $v1 !== '' ? $v1 : $v2 ) : ( $v2 !== '' ? $v2 : $v1 );
        $this->proposal = $p !== '' ? $p : 'default';
    }

    public function editVersion( string $version ): void
    {
        $version = strtolower( trim( $version ) );
        if( !in_array( $version, self::IKE_VERSIONS, TRUE ) )
            throw new Exception( "version: one of " . implode( ', ', self::IKE_VERSIONS ) );
        $this->editText( array( 'protocol', 'version' ), $version );
        $this->version = $version;
        $this->editProposal();
    }

    /** the IKE crypto profile for IKEv1 or IKEv2 - it must exist in the location / its scope (or be predefined) */
    public function editIkeCryptoProfile( string $profile, string $ikeVersion ): void
    {
        $ikeVersion = strtolower( trim( $ikeVersion ) );
        if( !in_array( $ikeVersion, array( 'ikev1', 'ikev2' ), TRUE ) )
            throw new Exception( "ike-version: ikev1 or ikev2" );
        $profile = self::editName( $profile, 'IKE crypto profile' );
        $new = $this->editLookup( 'ikeCryptoProfileStore', $profile, 'findIKECryptoProfil' );
        if( $new === null && !in_array( $profile, self::PREDEFINED_IKE_CRYPTO_PROFILES, TRUE ) )
            throw new Exception( "IKE crypto profile '" . $profile . "' not found in the location of the gateway or above it" );
        $other = $ikeVersion === 'ikev1' ? 'ikev2' : 'ikev1';
        $oldName = $this->editTextOf( array( 'protocol', $ikeVersion, 'ike-crypto-profile' ) );
        $old = $oldName !== '' && $oldName !== $this->editTextOf( array( 'protocol', $other, 'ike-crypto-profile' ) )
            ? $this->editLookup( 'ikeCryptoProfileStore', $oldName, 'findIKECryptoProfil' ) : null;
        $this->editText( array( 'protocol', $ikeVersion, 'ike-crypto-profile' ), $profile );
        $this->editSwapReference( $old, $new );
        $this->editProposal();
    }

    /** ip (an address or address object), fqdn, or dynamic (no value) */
    public function editPeerAddress( string $type, string $value = '' ): void
    {
        $type = strtolower( trim( $type ) );
        $value = trim( $value );
        if( !in_array( $type, array( 'ip', 'fqdn', 'dynamic' ), TRUE ) )
            throw new Exception( "peer address type: ip, fqdn or dynamic" );
        if( $type !== 'dynamic' && ( $value === '' || strlen( $value ) > 255 || preg_match( '/[\s<>]/', $value ) ) )
            throw new Exception( "peer address: a value for " . $type );
        $this->editChoice( array( 'peer-address' ), $type, $type === 'dynamic' ? null : $value );
        $this->peerAddress = $type === 'dynamic' ? 'dynamic' : $value;
    }

    /** the local interface; FALSE: no interface of this name in the location / its scope (set all the same - e.g. an SCM variable) */
    public function editLocalInterface( string $interface ): bool
    {
        $interface = self::editName( $interface, 'interface' );
        $old = is_string( $this->localInterface ) && $this->localInterface !== '' ? $this->editLookup( null, $this->localInterface, 'findInterface' ) : null;
        $new = $this->editLookup( null, $interface, 'findInterface' );
        $this->editText( array( 'local-address', 'interface' ), $interface );
        $this->localInterface = $interface;
        $this->editSwapReference( $old, $new );
        return $new !== null;
    }

    /** the local IP (an address of the interface or an address object); '' removes it */
    public function editLocalIp( string $ip ): void
    {
        $ip = trim( $ip );
        if( $ip === '' )
        {
            $this->editRemove( array( 'local-address', 'ip' ) );
            $this->localAddress = FALSE;
            return;
        }
        if( strlen( $ip ) > 255 || preg_match( '/[\s<>]/', $ip ) )
            throw new Exception( "local IP: an IP address (with mask) or an address object" );
        $this->editText( array( 'local-address', 'ip' ), $ip );
        $this->localAddress = $ip;
    }

    /** local / peer identification: type and id; type '' removes it */
    public function editIdentification( string $which, string $type, string $id = '' ): void
    {
        if( !in_array( $which, array( 'local', 'peer' ), TRUE ) )
            throw new Exception( "local or peer" );
        $type = strtolower( trim( $type ) );
        $id = trim( $id );
        if( $type === '' )
        {
            $this->editRemove( array( $which . '-id' ) );
            $this->{$which . 'ID'} = FALSE;
            $this->{$which . 'IDtype'} = FALSE;
            return;
        }
        if( !in_array( $type, self::ID_TYPES, TRUE ) )
            throw new Exception( $which . " id type: one of " . implode( ', ', self::ID_TYPES ) );
        if( $id === '' || strlen( $id ) > 1024 || preg_match( '/[\x00-\x1F<>]/', $id ) )
            throw new Exception( $which . " id: a value" );
        $this->editText( array( $which . '-id', 'type' ), $type );
        $this->editText( array( $which . '-id', 'id' ), $id );
        $this->{$which . 'ID'} = $id;
        $this->{$which . 'IDtype'} = $type;
    }

    /** protocol-common: nat-traversal, fragmentation (…/enable) or passive-mode */
    public function editProtocolCommon( string $setting, bool $enable ): void
    {
        $yn = self::editYesNo( $enable );
        if( $setting === 'passive-mode' )
            $this->editText( array( 'protocol-common', 'passive-mode' ), $yn );
        elseif( $setting === 'nat-traversal' || $setting === 'fragmentation' )
        {
            $this->editText( array( 'protocol-common', $setting, 'enable' ), $yn );
            if( $setting === 'nat-traversal' )
                $this->natTraversal = $yn;
            else
                $this->fragmentation = $yn;
        }
        else
            throw new Exception( "nat-traversal, fragmentation or passive-mode" );
    }

    /** dead peer detection of IKEv1 / IKEv2 */
    public function editDpd( string $ikeVersion, bool $enable ): void
    {
        $ikeVersion = strtolower( trim( $ikeVersion ) );
        if( !in_array( $ikeVersion, array( 'ikev1', 'ikev2' ), TRUE ) )
            throw new Exception( "ike-version: ikev1 or ikev2" );
        $this->editText( array( 'protocol', $ikeVersion, 'dpd', 'enable' ), self::editYesNo( $enable ) );
    }

    /** IKEv1 exchange mode */
    public function editExchangeMode( string $mode ): void
    {
        $mode = strtolower( trim( $mode ) );
        if( !in_array( $mode, array( 'auto', 'main', 'aggressive' ), TRUE ) )
            throw new Exception( "exchange mode: auto, main or aggressive" );
        $this->editText( array( 'protocol', 'ikev1', 'exchange-mode' ), $mode );
        $this->exchangemode = $mode;
    }

    public function editDisabled( bool $disabled ): void
    {
        $this->editText( array( 'disabled' ), self::editYesNo( $disabled ) );
        $this->disabled = self::editYesNo( $disabled );
    }

    public function isIKEGatewayType()
    {
        return TRUE;
    }

    public function referencedObjectRenamed($h, $old, $replaceType = 'name')
    {
        if( is_object($h) )
        {
            if( get_class( $h ) == "Address"  )
            {
                //Text replace
                $qualifiedNodeName = '//*[text()="'.$old.'"]';
                $xpathResult = DH::findXPath( $qualifiedNodeName, $this->xmlroot);
                foreach( $xpathResult as $node )
                {
                    if( $replaceType == "name" )
                        $node->textContent = $h->name();
                    elseif( $replaceType == "value" )
                        $node->textContent = $h->value();
                }


                //attribute replace
                $nameattribute = $old;
                $qualifiedNodeName = "entry";
                $nodeList = $this->xmlroot->getElementsByTagName($qualifiedNodeName);
                $nodeArray = iterator_to_array($nodeList);

                $templateEntryArray = array();
                foreach( $nodeArray as $item )
                {
                    if ($nameattribute !== null)
                    {
                        $XMLnameAttribute = DH::findAttribute("name", $item);
                        if ($XMLnameAttribute === FALSE)
                            continue;

                        if ($XMLnameAttribute !== $nameattribute)
                            continue;
                    }
                    if( $replaceType == "name" )
                        $item->setAttribute('name', $h->name());
                    elseif( $replaceType == "value" )
                        $item->setAttribute('name', $h->value());
                }
            }

            return;
        }

        mwarning("object is not part of this Tunnel Interface : {$h->toString()}");
    }


    public function replaceReferencedObject($old, $new)
    {
        $this->referencedObjectRenamed($new, $old->name());
        return true;
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

    public function rewriteInterface_XML()
    {
        $tmp_gateway = DH::findFirstElementOrCreate('local-address', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate('interface', $tmp_gateway);
        DH::setDomNodeText($tmp_gateway, $this->localInterface);
        #DH::createOrResetElement( $this->xmlroot, 'interface', $this->_interface->name());
    }

    //"-AQ==A4vEGnxsZCP7poqzjhJD4Gc+tbE=DS4xndFfZiigUHPCm4ASFQ==" => "DEMO"
    //"-AQ==2WmDHripnP+MAuaB9DKJ5dPWlmQ=wgoOihqVrKK2NmxerTkFKg==" => 'temp'
    static public $templatexml = '<entry name="**temporarynamechangeme**">
    <authentication>
        <pre-shared-key>
            <key>-AQ==A4vEGnxsZCP7poqzjhJD4Gc+tbE=DS4xndFfZiigUHPCm4ASFQ==</key>
        </pre-shared-key>
    </authentication>
    <protocol>
        <ikev1><dpd><enable>yes</enable><interval>5</interval><retry>5</retry></dpd><ike-crypto-profile>default</ike-crypto-profile><exchange-mode>auto</exchange-mode></ikev1>
        <ikev2><dpd><enable>yes</enable><interval>5</interval></dpd><ike-crypto-profile>default</ike-crypto-profile></ikev2>
        <version>ikev1</version>
      </protocol>
    <protocol-common><nat-traversal><enable>no</enable></nat-traversal><fragmentation><enable>no</enable></fragmentation></protocol-common>
    <local-address><interface></interface></local-address>
    <peer-address><ip></ip></peer-address>
    <disabled>no</disabled>
</entry>';

    static public $templatexml_ikev2 = '<entry name="**temporarynamechangeme**">
    <authentication>
        <pre-shared-key>
            <key>-AQ==A4vEGnxsZCP7poqzjhJD4Gc+tbE=DS4xndFfZiigUHPCm4ASFQ==</key>
        </pre-shared-key>
    </authentication>
    <protocol>
        <ikev1><dpd><enable>yes</enable><interval>5</interval><retry>5</retry></dpd><ike-crypto-profile>default</ike-crypto-profile><exchange-mode>auto</exchange-mode></ikev1>
        <ikev2><dpd><enable>yes</enable><interval>5</interval></dpd><ike-crypto-profile>default</ike-crypto-profile></ikev2>
        <version>ikev2</version>
      </protocol>
    <protocol-common><nat-traversal><enable>no</enable></nat-traversal><fragmentation><enable>no</enable></fragmentation></protocol-common>
    <local-address><interface></interface></local-address>
    <peer-address><ip></ip></peer-address>
    <disabled>no</disabled>
</entry>';

}