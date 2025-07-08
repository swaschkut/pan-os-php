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

    public $flood = array();
    public $scan = array();

    public $discard_ip_spoof = false;
    public $discard_malformed_option = false;
    public $remove_tcp_timestamp = false;
    public $strip_tcp_fast_open_and_data = false;
    public $strip_mptcp_option = false;

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
        $debug = false;

        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("zone-protection-profile name not found\n");

        //Todo: swaschkut 20250702 continue here
        $flood_Node = DH::findFirstElement('flood', $xml);
        if( $flood_Node !== FALSE )
        {
            //tcp-syn
            //icmp
            //icmpv6
            //other-ip
            //udp
            foreach( $flood_Node->childNodes as $flood_entry_Node )
            {
                if ($flood_entry_Node->nodeType != 1)
                    continue;

                $node_name = $flood_entry_Node->nodeName;
                $red_node = DH::findFirstElement('red', $flood_entry_Node);
                if( $red_node !== FALSE )
                {
                    $alarm_rate_node = DH::findFirstElement('alarm-rate', $red_node);
                    if( $alarm_rate_node !== FALSE )
                        $this->flood[$node_name]['red']['alarm-rate'] = $alarm_rate_node->textContent;
                    $activate_rate_node = DH::findFirstElement('activate-rate', $red_node);
                    if( $activate_rate_node !== FALSE )
                        $this->flood[$node_name]['red']['activate-rate'] = $activate_rate_node->textContent;
                    $maximal_rate_node = DH::findFirstElement('maximal-rate', $red_node);
                    if( $maximal_rate_node !== FALSE )
                        $this->flood[$node_name]['red']['maximal-rate'] = $maximal_rate_node->textContent;
                }

                $enable_node = DH::findFirstElement('enable', $flood_entry_Node);
                if( $enable_node !== FALSE )
                    $this->flood[$node_name]['enable'] = $enable_node->textContent;
                /*
                 <tcp-syn>
                   <red>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>10000</activate-rate>
                    <maximal-rate>40000</maximal-rate>
                   </red>
                   <enable>no</enable>
                  </tcp-syn>
                 */
            }
        }


        $scan_Node = DH::findFirstElement('scan', $xml);
        if( $scan_Node !== FALSE )
        {
            foreach( $scan_Node->childNodes as $scan_entry_Node )
            {
                if( $scan_entry_Node->nodeType != 1 )
                    continue;

                if( $debug )
                    DH::DEBUGprintDOMDocument($scan_entry_Node);

                $entry_name = DH::findAttribute('name', $scan_entry_Node);
                if( $entry_name === FALSE )
                    derr("zone-protection-profile scan name not found\n");

                $action_Node = DH::findFirstElement('action', $scan_entry_Node);
                if( $action_Node !== FALSE )
                {
                    $severity = DH::firstChildElement($action_Node);
                    $this->scan[$entry_name]['action'] = $severity->nodeName;
                }

                $interval_Node = DH::findFirstElement('interval', $scan_entry_Node);
                if( $interval_Node !== FALSE )
                    $this->scan[$entry_name]['interval'] = $interval_Node->textContent;
                $threshold_Node = DH::findFirstElement('threshold', $scan_entry_Node);
                if( $threshold_Node !== FALSE )
                    $this->scan[$entry_name]['threshold'] = $threshold_Node->textContent;
                /*
                 <entry name="8003">
                   <action>
                    <alert/>
                   </action>
                   <interval>2</interval>
                   <threshold>100</threshold>
                  </entry>
                 */
            }

        }


        /*
            <discard-ip-spoof>yes</discard-ip-spoof>
            <discard-malformed-option>yes</discard-malformed-option>
            <remove-tcp-timestamp>yes</remove-tcp-timestamp>
            <strip-tcp-fast-open-and-data>no</strip-tcp-fast-open-and-data>
            <strip-mptcp-option>global</strip-mptcp-option>
        */
        $discard_ip_spoof_Node = DH::findFirstElement('discard-ip-spoof', $xml);
        if( $discard_ip_spoof_Node !== FALSE )
            $this->discard_ip_spoof = $discard_ip_spoof_Node->textContent;
        $discard_malformed_option_Node = DH::findFirstElement('discard-malformed-option', $xml);
        if( $discard_malformed_option_Node !== FALSE )
            $this->discard_malformed_option = $discard_malformed_option_Node->textContent;
        $remove_tcp_timestamp_Node = DH::findFirstElement('remove-tcp-timestamp', $xml);
        if( $remove_tcp_timestamp_Node !== FALSE )
            $this->remove_tcp_timestamp = $remove_tcp_timestamp_Node->textContent;
        $strip_tcp_fast_open_Node = DH::findFirstElement('strip-tcp-fast-open-and-data', $xml);
        if( $strip_tcp_fast_open_Node !== FALSE )
            $this->strip_tcp_fast_open_and_data = $strip_tcp_fast_open_Node->textContent;
        $strip_mptcp_option_Node = DH::findFirstElement('strip-mptcp-option', $xml);
        if( $strip_mptcp_option_Node !== FALSE )
            $this->strip_mptcp_option = $strip_mptcp_option_Node->textContent;
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