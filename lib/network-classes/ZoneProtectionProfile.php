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

                    if( $action_Node->hasChildNodes() )
                    {
                        //<track-by>source</track-by>
                        //<duration>3600</duration>
                        $track_by_Node = DH::findFirstElement('track-by', $severity);
                        $duration_Node = DH::findFirstElement('duration', $severity);

                        if( $track_by_Node !== FALSE )
                            $this->scan[$entry_name]['track-by'] = $track_by_Node->textContent;
                        if( $duration_Node !== FALSE )
                            $this->scan[$entry_name]['duration'] = $duration_Node->textContent;
                    }
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
                /*
                <entry name="8003">
                  <action>
                    <block-ip>
                      <track-by>source</track-by>
                      <duration>3600</duration>
                    </block-ip>
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
        //Todo: missing - swaschkut 20250714
        /*
         <discard-ip-frag>yes</discard-ip-frag>
         <strict-ip-check>yes</strict-ip-check>
         <discard-strict-source-routing>yes</discard-strict-source-routing>
         <discard-security>yes</discard-security>
         <discard-loose-source-routing>yes</discard-loose-source-routing>
         <discard-stream-id>yes</discard-stream-id>
         <discard-timestamp>yes</discard-timestamp>
         <discard-unknown-option>yes</discard-unknown-option>
         <discard-record-route>yes</discard-record-route>
         <discard-tcp-split-handshake>yes</discard-tcp-split-handshake>
         <discard-overlapping-tcp-segment-mismatch>yes</discard-overlapping-tcp-segment-mismatch>
         <discard-icmp-ping-zero-id>yes</discard-icmp-ping-zero-id>
         <discard-icmp-frag>yes</discard-icmp-frag>
         <discard-icmp-large-packet>yes</discard-icmp-large-packet>
         <suppress-icmp-timeexceeded>yes</suppress-icmp-timeexceeded>
         <suppress-icmp-needfrag>yes</suppress-icmp-needfrag>
         <discard-icmp-error>yes</discard-icmp-error>
         */


        /*
        <net-inspection>
            <rule/>
         </net-inspection>
         -------------------------
         <ipv6>
            <filter-ext-hdr>
               <hop-by-hop-hdr>yes</hop-by-hop-hdr>
               <routing-hdr>yes</routing-hdr>
               <dest-option-hdr>yes</dest-option-hdr>
            </filter-ext-hdr>
            <ignore-inv-pkt>
               <dest-unreach>yes</dest-unreach>
               <pkt-too-big>yes</pkt-too-big>
               <time-exceeded>yes</time-exceeded>
               <param-problem>yes</param-problem>
               <redirect>yes</redirect>
            </ignore-inv-pkt>
            <ipv4-compatible-address>yes</ipv4-compatible-address>
            <anycast-source>yes</anycast-source>
            <needless-fragment-hdr>yes</needless-fragment-hdr>
            <icmpv6-too-big-small-mtu-discard>yes</icmpv6-too-big-small-mtu-discard>
            <options-invalid-ipv6-discard>yes</options-invalid-ipv6-discard>
            <reserved-field-set-discard>yes</reserved-field-set-discard>
            <routing-header-3>yes</routing-header-3>
            <routing-header-253>yes</routing-header-253>
            <routing-header-254>yes</routing-header-254>
         </ipv6>

            */

        /*
            <entry name="recommended">
              <flood>
                <tcp-syn>
                  <red>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>10000</activate-rate>
                    <maximal-rate>40000</maximal-rate>
                  </red>
                  <enable>yes</enable>
                </tcp-syn>
                <udp>
                  <red>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>10000</activate-rate>
                    <maximal-rate>40000</maximal-rate>
                  </red>
                  <enable>yes</enable>
                </udp>
                <icmp>
                  <red>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>10000</activate-rate>
                    <maximal-rate>40000</maximal-rate>
                  </red>
                  <enable>yes</enable>
                </icmp>
                <icmpv6>
                  <red>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>10000</activate-rate>
                    <maximal-rate>40000</maximal-rate>
                  </red>
                  <enable>yes</enable>
                </icmpv6>
                <other-ip>
                  <red>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>10000</activate-rate>
                    <maximal-rate>40000</maximal-rate>
                  </red>
                  <enable>yes</enable>
                </other-ip>
              </flood>
              <net-inspection>
                <rule/>
              </net-inspection>
              <ipv6>
                <ignore-inv-pkt>
                  <dest-unreach>yes</dest-unreach>
                  <pkt-too-big>yes</pkt-too-big>
                  <time-exceeded>yes</time-exceeded>
                  <param-problem>yes</param-problem>
                  <redirect>yes</redirect>
                </ignore-inv-pkt>
              </ipv6>
              <scan>
                <entry name="8001">
                  <action>
                    <block-ip>
                      <track-by>source</track-by>
                      <duration>3600</duration>
                    </block-ip>
                  </action>
                  <interval>2</interval>
                  <threshold>100</threshold>
                </entry>
                <entry name="8002">
                  <action>
                    <block-ip>
                      <track-by>source</track-by>
                      <duration>3600</duration>
                    </block-ip>
                  </action>
                  <interval>10</interval>
                  <threshold>100</threshold>
                </entry>
                <entry name="8003">
                  <action>
                    <block-ip>
                      <track-by>source</track-by>
                      <duration>3600</duration>
                    </block-ip>
                  </action>
                  <interval>2</interval>
                  <threshold>100</threshold>
                </entry>
                <entry name="8006">
                  <action>
                    <block-ip>
                      <track-by>source</track-by>
                      <duration>3600</duration>
                    </block-ip>
                  </action>
                  <interval>2</interval>
                  <threshold>4</threshold>
                </entry>
              </scan>
              <discard-ip-spoof>yes</discard-ip-spoof>
              <discard-strict-source-routing>yes</discard-strict-source-routing>
              <discard-security>yes</discard-security>
              <discard-loose-source-routing>yes</discard-loose-source-routing>
              <discard-stream-id>yes</discard-stream-id>
              <discard-timestamp>yes</discard-timestamp>
              <discard-unknown-option>yes</discard-unknown-option>
              <discard-record-route>yes</discard-record-route>
              <discard-malformed-option>yes</discard-malformed-option>
              <discard-icmp-ping-zero-id>yes</discard-icmp-ping-zero-id>
              <discard-icmp-frag>yes</discard-icmp-frag>
              <suppress-icmp-timeexceeded>no</suppress-icmp-timeexceeded>
              <suppress-icmp-needfrag>yes</suppress-icmp-needfrag>
              <discard-icmp-error>yes</discard-icmp-error>
            </entry>
         */
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