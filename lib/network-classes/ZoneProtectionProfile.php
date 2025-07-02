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
 * Class ZoneProtectionProfile
 * @property ZoneProtectionProfileStore $owner
 */
class ZoneProtectionProfile
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferenceableObject;

    public $owner;

    /** @var null|string[]|DOMElement */
    public $typeRoot = null;

    public $type = 'notfound';



    /**
     * ZoneProtectionProfile constructor.
     * @param string $name
     * @param IPSecCryptoProfileStore $owner
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
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("tunnel name not found\n");


        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 )
                continue;

            //Todo: swaschkut 20250702 continue here
            #DH::DEBUGprintDOMDocument($node);
            /*
<entry name="Recommended_Zone_Protection">
 <flood>
  <tcp-syn>
   <red>
    <alarm-rate>10000</alarm-rate>
    <activate-rate>10000</activate-rate>
    <maximal-rate>40000</maximal-rate>
   </red>
   <enable>no</enable>
  </tcp-syn>
  <icmp>
   <red>
    <alarm-rate>10000</alarm-rate>
    <activate-rate>10000</activate-rate>
    <maximal-rate>40000</maximal-rate>
   </red>
   <enable>no</enable>
  </icmp>
  <icmpv6>
   <red>
    <alarm-rate>10000</alarm-rate>
    <activate-rate>10000</activate-rate>
    <maximal-rate>40000</maximal-rate>
   </red>
   <enable>no</enable>
  </icmpv6>
  <other-ip>
   <red>
    <alarm-rate>10000</alarm-rate>
    <activate-rate>10000</activate-rate>
    <maximal-rate>40000</maximal-rate>
   </red>
   <enable>no</enable>
  </other-ip>
  <udp>
   <red>
    <alarm-rate>10000</alarm-rate>
    <activate-rate>10000</activate-rate>
    <maximal-rate>40000</maximal-rate>
   </red>
   <enable>no</enable>
  </udp>
 </flood>
 <scan>
  <entry name="8001">
   <action>
    <alert/>
   </action>
   <interval>2</interval>
   <threshold>100</threshold>
  </entry>
  <entry name="8002">
   <action>
    <alert/>
   </action>
   <interval>10</interval>
   <threshold>100</threshold>
  </entry>
  <entry name="8003">
   <action>
    <alert/>
   </action>
   <interval>2</interval>
   <threshold>100</threshold>
  </entry>
 </scan>
 <discard-ip-spoof>yes</discard-ip-spoof>
 <discard-malformed-option>yes</discard-malformed-option>
 <remove-tcp-timestamp>yes</remove-tcp-timestamp>
 <strip-tcp-fast-open-and-data>no</strip-tcp-fast-open-and-data>
 <strip-mptcp-option>global</strip-mptcp-option>
</entry>
<entry name="Alert_Only_Zone_Protection">
 <flood>
  <tcp-syn>
   <enable>no</enable>
  </tcp-syn>
  <udp>
   <enable>no</enable>
  </udp>
  <icmp>
   <enable>no</enable>
  </icmp>
  <icmpv6>
   <enable>no</enable>
  </icmpv6>
  <other-ip>
   <enable>no</enable>
  </other-ip>
 </flood>
 <scan>
  <entry name="8001">
   <action>
    <alert/>
   </action>
   <interval>2</interval>
   <threshold>100</threshold>
  </entry>
  <entry name="8002">
   <action>
    <alert/>
   </action>
   <interval>10</interval>
   <threshold>100</threshold>
  </entry>
  <entry name="8003">
   <action>
    <alert/>
   </action>
   <interval>2</interval>
   <threshold>100</threshold>
  </entry>
 </scan>
</entry>

                     */
        }
    }

    /**
     * return true if change was successful false if not (duplicate IPsecCryptoProfil name?)
     * @param string $name new name for the IPsecCryptoProfil
     * @return bool
     */
    public function setName($name)
    {
        if( $this->name == $name )
            return TRUE;

        if( preg_match('/[^0-9a-zA-Z_\-\s]/', $name) )
        {
            $name = preg_replace('/[^0-9a-zA-Z_\-\s]/', "", $name);
            PH::print_stdout(  "new name: " . $name );
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


    public function isZoneProtectionProfileType()
    {
        return TRUE;
    }

    public function cloneZoneProtectionProfile($newName)
    {
        $newProfile = $this->owner->newZoneProtectionProfile($newName);



        return $newProfile;
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**">
<esp>
 ..... add missing stuff
</entry>';

    /*
        static public $templatexml = '<entry name="**temporarynamechangeme**">
    <esp>
      <authentication>
      </authentication>
      <encryption>
      </encryption>
    </esp>
    <lifetime>
    </lifetime>
    <dh-group></dh-group>
    </entry>';
    */
}