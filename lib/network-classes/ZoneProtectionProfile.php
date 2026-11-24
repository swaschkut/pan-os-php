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
    use NetworkObjectEdit;

    public $owner;

    /** @var null|string[]|DOMElement */
    public $typeRoot = null;

    public $type = 'notfound';

    public $flood = array();
    public $scan = array();

    /*
    public $discard_ip_spoof = false;
    public $discard_malformed_option = false;
    public $remove_tcp_timestamp = false;
    public $strip_tcp_fast_open_and_data = false;
    public $strip_mptcp_option = false;
*/
    public ?string $discard_ip_spoof = null;
    public ?string $discard_malformed_option = null;
    public ?string $remove_tcp_timestamp = null;
    public ?string $strip_tcp_fast_open_and_data = null;
    public ?string $strip_mptcp_option = null;

    public ?string $discard_ip_frag = null;
    public ?string $strict_ip_check = null;
    public ?string $discard_strict_source_routing = null;
    public ?string $discard_security = null;
    public ?string $discard_loose_source_routing = null;
    public ?string $discard_stream_id = null;
    public ?string $discard_timestamp = null;
    public ?string $discard_unknown_option = null;
    public ?string $discard_record_route = null;
    public ?string $discard_tcp_split_handshake = null;
    public ?string $discard_overlapping_tcp_segment_mismatch = null;
    public ?string $discard_icmp_ping_zero_id = null;
    public ?string $discard_icmp_frag = null;
    public ?string $discard_icmp_large_packet = null;
    public ?string $suppress_icmp_timeexceeded = null;
    public ?string $suppress_icmp_needfrag = null;
    public ?string $discard_icmp_error = null;

    // --- Missing TCP Drop Properties ---
    public ?string $discard_tcp_syn_with_data = null;
    public ?string $discard_tcp_synack_with_data = null;
    public ?string $tcp_reject_non_syn = null;
    public ?string $asymmetric_path = null;

// --- Missing IPv6 Drop Properties ---
    public ?string $ipv6_routing_header_0 = null;
    public ?string $ipv6_routing_header_1 = null;
    public ?string $ipv6_routing_header_3 = null;
    public ?string $ipv6_routing_header_4_252 = null;
    public ?string $ipv6_routing_header_253 = null;
    public ?string $ipv6_routing_header_254 = null;
    public ?string $ipv6_routing_header_255 = null;
    public ?string $ipv6_ipv4_compatible_address = null;
    public ?string $ipv6_options_invalid_discard = null;
    public ?string $ipv6_reserved_field_discard = null;
    public ?string $ipv6_anycast_source = null;
    public ?string $ipv6_needless_fragment_hdr = null;
    public ?string $ipv6_icmp_too_big_discard = null;

// --- Missing IPv6 Filter Ext Hdr Properties ---
    public ?string $ipv6_hop_by_hop_hdr = null;
    public ?string $ipv6_routing_hdr = null;
    public ?string $ipv6_dest_option_hdr = null;

// --- Missing ICMPv6 Drop Properties ---
    public ?string $icmpv6_dest_unreach = null;
    public ?string $icmpv6_pkt_too_big = null;
    public ?string $icmpv6_time_exceeded = null;
    public ?string $icmpv6_param_problem = null;
    public ?string $icmpv6_redirect = null;


    public $xmlMap = array();


    public $disabled_scans = array();

    public $scan_alert = array();


    public $scan_white_list = array();


    /**
     * ZoneProtectionProfile constructor.
     * @param string $name
     * @param ZoneProtectionProfileStore $owner
     */
    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;

        $this->disabled_scans['8001'] = 'yes';
        $this->disabled_scans['8002'] = 'yes';
        $this->disabled_scans['8003'] = 'yes';

        if( $this->owner->owner->version >= 111 )
            $this->disabled_scans['8006'] = 'yes';


        $this->scan_alert['8001']['interval'] = 2;
        $this->scan_alert['8001']['threshold'] = 100;

        $this->scan_alert['8002']['interval'] = 10;
        $this->scan_alert['8002']['threshold'] = 100;

        $this->scan_alert['8003']['interval'] = 2;
        $this->scan_alert['8003']['threshold'] = 100;

        $this->scan_alert['8006']['interval'] = 2;
        $this->scan_alert['8006']['threshold'] = 4;

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

                if( isset($this->disabled_scans[$entry_name]) )
                    unset($this->disabled_scans[$entry_name]);


                $action_Node = DH::findFirstElement('action', $scan_entry_Node);
                if( $action_Node !== FALSE )
                {
                    $severity = DH::firstChildElement($action_Node);
                    if( $severity !== FALSE )
                    {
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


        $this->xmlMap = [
            // --- IP DROP ---
            ['tag' => 'discard-ip-spoof', 'prop' => 'discard_ip_spoof', 'parents' => [], 'section' => 'IP Drop'],
            ['tag' => 'strict-ip-check', 'prop' => 'strict_ip_check', 'parents' => [], 'section' => 'IP Drop'],
            ['tag' => 'discard-ip-frag', 'prop' => 'discard_ip_frag', 'parents' => [], 'section' => 'IP Drop'],
            ['tag' => 'discard-strict-source-routing', 'prop' => 'discard_strict_source_routing', 'parents' => [], 'section' => 'IP Drop'],
            ['tag' => 'discard-loose-source-routing', 'prop' => 'discard_loose_source_routing', 'parents' => [], 'section' => 'IP Drop'],
            ['tag' => 'discard-timestamp', 'prop' => 'discard_timestamp', 'parents' => [], 'section' => 'IP Drop'],
            ['tag' => 'discard-record-route', 'prop' => 'discard_record_route', 'parents' => [], 'section' => 'IP Drop'],
            ['tag' => 'discard-security', 'prop' => 'discard_security', 'parents' => [], 'section' => 'IP Drop'],
            ['tag' => 'discard-stream-id', 'prop' => 'discard_stream_id', 'parents' => [], 'section' => 'IP Drop'],
            ['tag' => 'discard-unknown-option', 'prop' => 'discard_unknown_option', 'parents' => [], 'section' => 'IP Drop'],
            ['tag' => 'discard-malformed-option', 'prop' => 'discard_malformed_option', 'parents' => [], 'section' => 'IP Drop'],

            // --- TCP DROP ---
            ['tag' => 'discard-overlapping-tcp-segment-mismatch', 'prop' => 'discard_overlapping_tcp_segment_mismatch', 'parents' => [], 'section' => 'TCP Drop'],
            ['tag' => 'discard-tcp-split-handshake', 'prop' => 'discard_tcp_split_handshake', 'parents' => [], 'section' => 'TCP Drop'],
            ['tag' => 'discard-tcp-syn-with-data', 'prop' => 'discard_tcp_syn_with_data', 'parents' => [], 'section' => 'TCP Drop'],
            ['tag' => 'discard-tcp-synack-with-data', 'prop' => 'discard_tcp_synack_with_data', 'parents' => [], 'section' => 'TCP Drop'],
            ['tag' => 'tcp-reject-non-syn', 'prop' => 'tcp_reject_non_syn', 'parents' => [], 'section' => 'TCP Drop'],
            ['tag' => 'asymmetric-path', 'prop' => 'asymmetric_path', 'parents' => [], 'section' => 'TCP Drop'],
            ['tag' => 'remove-tcp-timestamp', 'prop' => 'remove_tcp_timestamp', 'parents' => [], 'section' => 'TCP Drop'],
            ['tag' => 'strip-tcp-fast-open-and-data', 'prop' => 'strip_tcp_fast_open_and_data', 'parents' => [], 'section' => 'TCP Drop'],
            ['tag' => 'strip-mptcp-option', 'prop' => 'strip_mptcp_option', 'parents' => [], 'section' => 'TCP Drop'],

            // --- ICMP DROP ---
            ['tag' => 'discard-icmp-ping-zero-id', 'prop' => 'discard_icmp_ping_zero_id', 'parents' => [], 'section' => 'ICMP Drop'],
            ['tag' => 'discard-icmp-frag', 'prop' => 'discard_icmp_frag', 'parents' => [], 'section' => 'ICMP Drop'],
            ['tag' => 'discard-icmp-large-packet', 'prop' => 'discard_icmp_large_packet', 'parents' => [], 'section' => 'ICMP Drop'],
            ['tag' => 'discard-icmp-error', 'prop' => 'discard_icmp_error', 'parents' => [], 'section' => 'ICMP Drop'],
            ['tag' => 'suppress-icmp-timeexceeded', 'prop' => 'suppress_icmp_timeexceeded', 'parents' => [], 'section' => 'ICMP Drop'],
            ['tag' => 'suppress-icmp-needfrag', 'prop' => 'suppress_icmp_needfrag', 'parents' => [], 'section' => 'ICMP Drop'],

            // --- IPV6 DROP ---
            ['tag' => 'routing-header-0', 'prop' => 'ipv6_routing_header_0', 'parents' => ['ipv6'], 'section' => 'IPv6 Drop'],
            ['tag' => 'routing-header-1', 'prop' => 'ipv6_routing_header_1', 'parents' => ['ipv6'], 'section' => 'IPv6 Drop'],
            ['tag' => 'routing-header-3', 'prop' => 'ipv6_routing_header_3', 'parents' => ['ipv6'], 'section' => 'IPv6 Drop'],
            ['tag' => 'routing-header-4-252', 'prop' => 'ipv6_routing_header_4_252', 'parents' => ['ipv6'], 'section' => 'IPv6 Drop'],
            ['tag' => 'routing-header-253', 'prop' => 'ipv6_routing_header_253', 'parents' => ['ipv6'], 'section' => 'IPv6 Drop'],
            ['tag' => 'routing-header-254', 'prop' => 'ipv6_routing_header_254', 'parents' => ['ipv6'], 'section' => 'IPv6 Drop'],
            ['tag' => 'routing-header-255', 'prop' => 'ipv6_routing_header_255', 'parents' => ['ipv6'], 'section' => 'IPv6 Drop'],
            ['tag' => 'ipv4-compatible-address', 'prop' => 'ipv6_ipv4_compatible_address', 'parents' => ['ipv6'], 'section' => 'IPv6 Drop'],
            ['tag' => 'options-invalid-ipv6-discard', 'prop' => 'ipv6_options_invalid_discard', 'parents' => ['ipv6'], 'section' => 'IPv6 Drop'],
            ['tag' => 'reserved-field-set-discard', 'prop' => 'ipv6_reserved_field_discard', 'parents' => ['ipv6'], 'section' => 'IPv6 Drop'],
            ['tag' => 'anycast-source', 'prop' => 'ipv6_anycast_source', 'parents' => ['ipv6'], 'section' => 'IPv6 Drop'],
            ['tag' => 'needless-fragment-hdr', 'prop' => 'ipv6_needless_fragment_hdr', 'parents' => ['ipv6'], 'section' => 'IPv6 Drop'],
            ['tag' => 'icmpv6-too-big-small-mtu-discard', 'prop' => 'ipv6_icmp_too_big_discard', 'parents' => ['ipv6'], 'section' => 'IPv6 Drop'],

            // --- IPV6 FILTER HDR ---
            ['tag' => 'hop-by-hop-hdr', 'prop' => 'ipv6_hop_by_hop_hdr', 'parents' => ['ipv6', 'filter-ext-hdr'], 'section' => 'IPv6 filter HDR'],
            ['tag' => 'routing-hdr', 'prop' => 'ipv6_routing_hdr', 'parents' => ['ipv6', 'filter-ext-hdr'], 'section' => 'IPv6 filter HDR'],
            ['tag' => 'dest-option-hdr', 'prop' => 'ipv6_dest_option_hdr', 'parents' => ['ipv6', 'filter-ext-hdr'], 'section' => 'IPv6 filter HDR'],

            // --- ICMPV6 ---
            ['tag' => 'dest-unreach', 'prop' => 'icmpv6_dest_unreach', 'parents' => ['ipv6', 'ignore-inv-pkt'], 'section' => 'ICMPv6'],
            ['tag' => 'pkt-too-big', 'prop' => 'icmpv6_pkt_too_big', 'parents' => ['ipv6', 'ignore-inv-pkt'], 'section' => 'ICMPv6'],
            ['tag' => 'time-exceeded', 'prop' => 'icmpv6_time_exceeded', 'parents' => ['ipv6', 'ignore-inv-pkt'], 'section' => 'ICMPv6'],
            ['tag' => 'param-problem', 'prop' => 'icmpv6_param_problem', 'parents' => ['ipv6', 'ignore-inv-pkt'], 'section' => 'ICMPv6'],
            ['tag' => 'redirect', 'prop' => 'icmpv6_redirect', 'parents' => ['ipv6', 'ignore-inv-pkt'], 'section' => 'ICMPv6'],
        ];
// Cache parent paths as strings (e.g., "ipv6/filter-ext-hdr") to avoid repeat lookups
        $cachedContexts = [];

        foreach ($this->xmlMap as $item)
        {
            $context = $xml; // Default search space is the main XML root
            $parents = $item['parents'];

            if (!empty($parents)) {
                $pathKey = implode('/', $parents); // Creates a unique key like "ipv6/filter-ext-hdr"

                if (!isset($cachedContexts[$pathKey])) {
                    // Drill down level by level dynamically
                    $currentContext = $xml;
                    foreach ($parents as $parentTag) {
                        $currentContext = DH::findFirstElement($parentTag, $currentContext);
                        if ($currentContext === false) {
                            break; // One of the parent wrappers is missing entirely
                        }
                    }
                    $cachedContexts[$pathKey] = $currentContext;
                }

                // If the path successfully resolved, update our search context
                if ($cachedContexts[$pathKey] !== false) {
                    $context = $cachedContexts[$pathKey];
                } else {
                    continue; // Path is broken in this XML config, skip searching for the leaf child
                }
            }

            // Safely look up the exact child tag within its true parent block
            $node = DH::findFirstElement($item['tag'], $context);
            if ($node !== false) {
                $this->{$item['prop']} = $node->textContent;
            }
        }



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

        /*
           <scan-white-list>
            <entry name="exclude_src">
              <ipv4>public_ipv4_dslmobil</ipv4>
            </entry>
            <entry name="exclude_src_ip">
              <ipv4>192.168.1.1</ipv4>
            </entry>
            <entry name="exclude_IPv6">
              <ipv6>public_ipv6_dslmobil</ipv6>
            </entry>
          </scan-white-list>
         */

        $scan_white_list_Node = DH::findFirstElement('scan-white-list', $xml);
        if( $scan_white_list_Node !== FALSE )
        {
            foreach ($scan_white_list_Node->childNodes as $scan_white_list_entry_Node)
            {
                if ($scan_white_list_entry_Node->nodeType != 1)
                    continue;

                if ($debug)
                    DH::DEBUGprintDOMDocument($scan_white_list_entry_Node);

                $tmp_array = array();

                $scan_whitelist_name = DH::findAttribute('name', $scan_white_list_entry_Node);
                $tmp_array['name'] = $scan_whitelist_name;

                $scan_whitelist_ipv4 = DH::findFirstElement('ipv4', $scan_white_list_entry_Node);
                $scan_whitelist_ipv6 = DH::findFirstElement('ipv6', $scan_white_list_entry_Node);
                if( $scan_whitelist_ipv4 !== FALSE )
                {
                    $tmp_ip = $scan_whitelist_ipv4->textContent;
                    $tmp_array['ipv4'] = $tmp_ip;

                    //not working yet
                    #$this->findorCreateAddressObject( $tmp_ip );
                }

                if( $scan_whitelist_ipv6 !== FALSE )
                {
                    $tmp_ip = $scan_whitelist_ipv6->textContent;
                    $tmp_array['ipv6'] = $tmp_ip;

                    #$this->findorCreateAddressObject( $tmp_ip );
                }



                $this->scan_white_list[$scan_whitelist_name] = $tmp_array;
            }
        }

    }

    public function findorCreateAddressObject( $ip )
    {
        if( strpos($ip, "/") === FALSE )
        {
            print "class: ".get_class($this->owner->owner)."\n";
            //firewall
            if( get_class($this->owner->owner) == "PANConf" )
            {
                print "PANconf found\n";
                print "count vsys: ".count($this->owner->owner->getVirtualSystems())."\n";

                $vsys_array = $this->owner->owner->getVirtualSystems();
                if( count($vsys_array) == 0 )
                    $vsys_array[] = $this->owner->owner->findVirtualSystem("vsys1" );

                foreach( $vsys_array as $vsys )
                {
                    $object = $vsys->addressStore->findOrCreate($ip);

                    print "object: ". $object->value() ."\n";
                    if( is_object($object) )
                    {
                        print "add reference\n";
                        $object->addReference($this);
                    }

                    else
                        derr("objectname: " . $ip . " not found. Can not be added to ZPP.\n", $this);

                    return $object->value();
                }
            }
            else
            {

            }
        }
        return $ip;
    }

    /**
     * return true if change was successful false if not (duplicate ZoneProtectionProfile name?)
     * @param string $name new name for the ZoneProtectionProfile
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


    // ---- changes of the actions (zone-protection-profile …-set): XML and object together; an invalid value: Exception

    const FLOOD_TYPES = array( 'tcp-syn', 'udp', 'icmp', 'icmpv6', 'other-ip' );
    /** reconnaissance protection: name => threat id of the scan entry */
    const SCANS = array( 'tcp-port-scan' => '8001', 'host-sweep' => '8002', 'udp-port-scan' => '8003' );

    public function editDescription( string $description ): void
    {
        $description = trim( $description );
        if( strlen( $description ) > 255 || preg_match( '/[\x00-\x08\x0B-\x1F]/', $description ) )
            throw new Exception( "description: up to 255 characters" );
        if( $description === '' )
            $this->editRemove( array( 'description' ) );
        else
            $this->editText( array( 'description' ), $description );
    }

    /**
     * flood protection of a type: on / off and its rates (connections per second; '' keeps a rate);
     * tcp-syn: action red or syn-cookies
     */
    public function editFlood( string $type, bool $enable, string $alarm = '', string $activate = '', string $maximal = '', string $synAction = '' ): void
    {
        $type = strtolower( trim( $type ) );
        if( !in_array( $type, self::FLOOD_TYPES, TRUE ) )
            throw new Exception( "flood type: one of " . implode( ', ', self::FLOOD_TYPES ) );
        $synAction = strtolower( trim( $synAction ) );
        if( $synAction !== '' && ( $type !== 'tcp-syn' || !in_array( $synAction, array( 'red', 'syn-cookies' ), TRUE ) ) )
            throw new Exception( "action: red or syn-cookies, only for tcp-syn" );
        $rates = array( 'alarm-rate' => array( $alarm, 0 ), 'activate-rate' => array( $activate, 1 ), 'maximal-rate' => array( $maximal, 1 ) );
        foreach( $rates as $k => $r )
            if( trim( $r[0] ) !== '' && ( !preg_match( '/^[0-9]{1,7}$/', trim( $r[0] ) ) || (int)$r[0] < $r[1] || (int)$r[0] > 2000000 ) )
                throw new Exception( $k . ": " . $r[1] . "-2000000" );
        $this->editText( array( 'flood', $type, 'enable' ), self::editYesNo( $enable ) );
        $this->flood[$type]['enable'] = self::editYesNo( $enable );
        // the rates are below red (or syn-cookies for tcp-syn)
        $mode = 'red';
        if( $type === 'tcp-syn' )
        {
            $cur = $this->editFind( array( 'flood', 'tcp-syn', 'syn-cookies' ) ) !== FALSE ? 'syn-cookies' : 'red';
            $mode = $synAction !== '' ? $synAction : $cur;
            $other = $mode === 'red' ? 'syn-cookies' : 'red';
            $old = $this->editFind( array( 'flood', 'tcp-syn', $other ) );
            if( $old !== FALSE )
            {
                // the rates go with the action
                $new = $this->editNode( array( 'flood', 'tcp-syn', $mode ) );
                foreach( iterator_to_array( $old->childNodes ) as $c )
                    if( $c instanceof DOMElement && DH::findFirstElement( $c->nodeName, $new ) === FALSE )
                        $new->appendChild( $c );
                $old->parentNode->removeChild( $old );
            }
        }
        foreach( $rates as $k => $r )
            if( trim( $r[0] ) !== '' )
            {
                $this->editText( array( 'flood', $type, $mode, $k ), (string)(int)$r[0] );
                $this->flood[$type][$mode][$k] = (string)(int)$r[0];
            }
    }

    /** reconnaissance protection of a scan: action allow / alert / block / block-ip (track by, duration), interval, threshold */
    public function editScan( string $scan, string $action, string $interval = '', string $threshold = '', string $trackBy = '', string $duration = '' ): void
    {
        $scan = strtolower( trim( $scan ) );
        if( !isset( self::SCANS[$scan] ) )
            throw new Exception( "scan: one of " . implode( ', ', array_keys( self::SCANS ) ) );
        $action = strtolower( trim( $action ) );
        if( !in_array( $action, array( 'allow', 'alert', 'block', 'block-ip' ), TRUE ) )
            throw new Exception( "action: allow, alert, block or block-ip" );
        foreach( array( 'interval' => $interval, 'threshold' => $threshold ) as $k => $v )
            if( trim( $v ) !== '' && ( !preg_match( '/^[0-9]{1,5}$/', trim( $v ) ) || (int)$v < 2 || (int)$v > 65535 ) )
                throw new Exception( $k . ": 2-65535" );
        if( $action === 'block-ip' )
        {
            if( !in_array( strtolower( trim( $trackBy ) ), array( 'source', 'source-and-destination' ), TRUE ) )
                throw new Exception( "block-ip: track by source or source-and-destination" );
            if( !preg_match( '/^[0-9]{1,7}$/', trim( $duration ) ) || (int)$duration < 1 || (int)$duration > 3600 )
                throw new Exception( "block-ip: duration 1-3600 seconds" );
        }
        $id = self::SCANS[$scan];
        $scanNode = $this->editNode( array( 'scan' ) );
        $entry = DH::findFirstElementByNameAttr( 'entry', $id, $scanNode );
        if( $entry === null || $entry === FALSE )
        {
            $entry = $scanNode->ownerDocument->createElement( 'entry' );
            $entry->setAttribute( 'name', $id );
            $scanNode->appendChild( $entry );
        }
        $actionNode = DH::findFirstElementOrCreate( 'action', $entry );
        foreach( iterator_to_array( $actionNode->childNodes ) as $c )
            $actionNode->removeChild( $c );
        $a = $actionNode->ownerDocument->createElement( $action );
        $actionNode->appendChild( $a );
        $this->scan[$id] = array( 'action' => $action );
        if( $action === 'block-ip' )
        {
            DH::createElement( $a, 'track-by', strtolower( trim( $trackBy ) ) );
            DH::createElement( $a, 'duration', (string)(int)$duration );
            $this->scan[$id]['track-by'] = strtolower( trim( $trackBy ) );
            $this->scan[$id]['duration'] = (string)(int)$duration;
        }
        foreach( array( 'interval' => $interval, 'threshold' => $threshold ) as $k => $v )
            if( trim( $v ) !== '' )
                DH::setDomNodeText( DH::findFirstElementOrCreate( $k, $entry ), (string)(int)$v );
        foreach( array( 'interval', 'threshold' ) as $k )
        {
            $n = DH::findFirstElement( $k, $entry );
            if( $n !== FALSE )
                $this->scan[$id][$k] = trim( $n->textContent );
        }
        unset( $this->disabled_scans[$id] );
    }

    /** a packet based protection (the settings of xmlMap: discard-ip-spoof, strict-ip-check, ipv6 routing-header-0, …) */
    public function editPacket( string $option, string $value ): void
    {
        $option = strtolower( trim( $option ) );
        $value = strtolower( trim( $value ) );
        $item = null;
        foreach( $this->xmlMap as $i )
            if( $i['tag'] === $option )
                $item = $i;
        if( $item === null )
            throw new Exception( "option: one of " . implode( ', ', array_column( $this->xmlMap, 'tag' ) ) );
        $allowed = $option === 'tcp-reject-non-syn' ? array( 'global', 'yes', 'no' ) : ( $option === 'asymmetric-path' ? array( 'global', 'drop', 'bypass' ) : array( 'yes', 'no' ) );
        if( !in_array( $value, $allowed, TRUE ) )
            throw new Exception( $option . ": " . implode( ', ', $allowed ) );
        $this->editText( array_merge( $item['parents'], array( $option ) ), $value );
        $this->{$item['prop']} = $value;
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

    public function is_visibility(): bool
    {
        foreach($this->scan as $scan)
        {
            if( !isset($scan['action']) || $scan['action'] == "allow" )
                return false;
        }
        if( empty($this->disabled_scans) )
            return true;


        return false;
    }

    public function scan_set_add_alert( $key, $array )
    {
        $xmlString = '    <entry name="dummy">
      <action>
        <alert/>
      </action>
      <interval>2</interval>
      <threshold>4</threshold>
    </entry>';

        $tmp_decoder = DH::findFirstElement('scan', $this->xmlroot);
        if( $tmp_decoder === False)
            $tmp_decoder = DH::findFirstElementorCreate('scan', $this->xmlroot);


        $tmp_name = DH::findFirstElementByNameAttr( 'entry', $key, $tmp_decoder);
        if( $tmp_name === False || $tmp_name === null )
        {
            $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $xmlString);
            $xmlElement->setAttribute('name', $key);

            $tmp_interval = DH::findFirstElementOrCreate( 'interval', $xmlElement );
            $tmp_interval->textContent = $array['interval'];

            $tmp_threshold = DH::findFirstElementOrCreate( 'threshold', $xmlElement );
            $tmp_threshold->textContent = $array['threshold'];

            $tmp_decoder->appendChild($xmlElement);

            //update memory
            unset( $this->disabled_scans[$key] );

            $this->scan[$key]['interval'] = $array['interval'];
            $this->scan[$key]['threshold'] = $array['threshold'];
        }
        else
        {
            $tmp_action = DH::findFirstElementOrCreate( 'action', $tmp_name );
            $tmp_action_allow = DH::findFirstElementOrCreate( 'allow', $tmp_action );
            $tmp_action->removeChild( $tmp_action_allow );
            $tmp_action_alert = DH::findFirstElementOrCreate( 'alert', $tmp_action );

            $this->scan[$key]['action'] = 'alert';
        }
    }

    public function scan_whitelist_add( $objname, $value_name, $ip_type )
    {
        $tmp_whitelist = DH::findFirstElementOrCreate( 'scan-white-list', $this->xmlroot );

        $tmp_entry = DH::findFirstElementByNameAttrOrCreate( 'entry', $objname, $tmp_whitelist, $this->xmlroot->ownerDocument );

        $tmp_ip_type_node = DH::findFirstElementOrCreate( $ip_type, $tmp_entry, $value_name );

        $tmp_array = array();
        $tmp_array['name'] = $objname;
        $tmp_array[$ip_type] = $value_name;

        $this->scan_white_list[$objname] = $tmp_array;
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

    /**
     * Base XML of the iron-skillet zone protection profiles
     * (iron-skillet templates/panorama/snippets/zone_protection_profile.xml):
     * 'Recommended_Zone_Protection' and 'Alert_Only_Zone_Protection'.
     *
     * Built from the values below, so that every value is written once:
     * - iron-skillet 10.0 to 11.0: scan entries 8001, 8002, 8003
     * - iron-skillet 11.1 and later: also scan entry 8006
     *
     * @param string $version iron-skillet PAN-OS version folder, e.g. "11.1"
     * @return string
     */
    public static function ironSkilletXml( $version )
    {
        // versions: PH::IRONSKILLET_VERSIONS / IRONSKILLET_SNIPPETS (newer PAN-OS: snippet of the newest version below)
        if( ( $version = PH::ironSkilletVersion( $version, 'zone protection profiles' ) ) === null )
            return null;

        // scan entry => array( interval, threshold ), action alert
        $scan = array(
            '8001' => array( 2, 100 ),
            '8002' => array( 10, 100 ),
            '8003' => array( 2, 100 ),
        );
        if( version_compare( $version, '11.1', '>=' ) )
            $scan['8006'] = array( 2, 4 );

        $scanXml = '';
        foreach( $scan as $name => $values )
            $scanXml .= '<entry name="' . $name . '"><action><alert/></action>'
                . '<interval>' . $values[0] . '</interval><threshold>' . $values[1] . '</threshold></entry>';

        // flood: every type disabled; Recommended has RED thresholds for when it is enabled
        $recommendedFlood = '';
        foreach( array( 'tcp-syn', 'icmp', 'icmpv6', 'other-ip', 'udp' ) as $type )
            $recommendedFlood .= '<' . $type . '><red><alarm-rate>10000</alarm-rate><activate-rate>10000</activate-rate>'
                . '<maximal-rate>40000</maximal-rate></red><enable>no</enable></' . $type . '>';

        $alertOnlyFlood = '';
        foreach( array( 'tcp-syn', 'udp', 'icmp', 'icmpv6', 'other-ip' ) as $type )
            $alertOnlyFlood .= '<' . $type . '><enable>no</enable></' . $type . '>';

        return '<root>'
            . '<entry name="Recommended_Zone_Protection">'
            . '<flood>' . $recommendedFlood . '</flood>'
            . '<scan>' . $scanXml . '</scan>'
            . '<discard-ip-spoof>yes</discard-ip-spoof>'
            . '<discard-malformed-option>yes</discard-malformed-option>'
            . '<remove-tcp-timestamp>yes</remove-tcp-timestamp>'
            . '<strip-tcp-fast-open-and-data>no</strip-tcp-fast-open-and-data>'
            . '<strip-mptcp-option>global</strip-mptcp-option>'
            . '</entry>'
            . '<entry name="Alert_Only_Zone_Protection">'
            . '<flood>' . $alertOnlyFlood . '</flood>'
            . '<scan>' . $scanXml . '</scan>'
            . '</entry>'
            . '</root>';
    }
}