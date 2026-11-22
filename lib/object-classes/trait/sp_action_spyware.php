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

trait sp_action_spyware
{
    public function load_from_domxml_spyware_rules(DOMElement $xml  ): void
    {
        $tmp_rule = DH::findFirstElement('rules', $xml);
        if( $tmp_rule !== FALSE )
        {
            foreach( $tmp_rule->childNodes as $tmp_entry1 )
            {
                if( $tmp_entry1->nodeType != XML_ELEMENT_NODE )
                    continue;

                $rule_name = DH::findAttribute('name', $tmp_entry1);
                if( $rule_name === FALSE )
                    derr("VB severity name not found\n");

                $threadPolicy_obj = new ThreatPolicySpyware( $rule_name, $this );
                $threadPolicy_obj->spywarepolicy_load_from_domxml( $tmp_entry1 );
                $this->rules_obj[] = $threadPolicy_obj;
                $threadPolicy_obj->addReference( $this );

                if( $this->owner !== null && $this->owner->owner !== null )
                    $this->owner->owner->ThreatPolicyStore->add($threadPolicy_obj);
            }
        }
    }

    public function load_from_domxml_spyware_inlineml(DOMElement $xml ): void
    {
        $tmp_rule = DH::findFirstElement('mica-engine-spyware-enabled', $xml);
        if( $tmp_rule !== FALSE && !$tmp_rule->hasChildNodes() )
        {
            $xml->removeChild($tmp_rule);
            $tmp_rule = DH::findFirstElement('mica-engine-spyware-enabled', $xml);
        }
        if( $tmp_rule !== FALSE )
        {
            $this->additional['mica-engine-spyware-enabled'] = array();
            $tmp_mica_Unknown_TCP_found = false;
            $tmp_mica_Unknown_UDP_found = false;
            foreach( $tmp_rule->childNodes as $tmp_entry1 )
            {
                if ($tmp_entry1->nodeType != XML_ELEMENT_NODE)
                    continue;

                $name = DH::findAttribute("name", $tmp_entry1);
                if( $name == "Unknown-TCP Command and Control detector" )
                    $tmp_mica_Unknown_TCP_found = TRUE;
                elseif( $name == "Unknown-UDP Command and Control detector" )
                    $tmp_mica_Unknown_UDP_found = TRUE;

                $tmp_inline_policy_action = DH::findFirstElement("inline-policy-action", $tmp_entry1);
                if( $tmp_inline_policy_action !== FALSE )
                    $this->additional['mica-engine-spyware-enabled'][$name]['inline-policy-action'] = $tmp_inline_policy_action->textContent;
                else
                {
                    $tmp_inline_policy_action = DH::findFirstElementOrCreate("inline-policy-action", $tmp_entry1);
                    $tmp_inline_policy_action->textContent = "disable";
                    $this->additional['mica-engine-spyware-enabled'][$name]['inline-policy-action'] = "disable";
                }

                // local deep learning: read only, as the firewall writes it (no element: not set - PANW documents no
                // default, the 12.1 GUI has no setting). Written only by the set-actions when the BP JSON lists it.
                $tmp_local_deep_learning = DH::findFirstElement("local-deep-learning", $tmp_entry1);
                if( $tmp_local_deep_learning !== FALSE )
                    $this->additional['mica-engine-spyware-enabled'][$name]['local-deep-learning'] = $tmp_local_deep_learning->textContent;
            }

            $Unkown_TCP_xmlstring = '<entry name="Unknown-TCP Command and Control detector">
  <inline-policy-action>alert</inline-policy-action>
</entry>';
            // Unknown-TCP has no local deep learning ($localDeepLearningMinVersion): same XML in every version
            $Unkown_TCP_xmlstring_112 = $Unkown_TCP_xmlstring;

            $Unkown_UDP_xmlstring = '<entry name="Unknown-UDP Command and Control detector">
  <inline-policy-action>alert</inline-policy-action>
</entry>';
            // Unknown-UDP has no local deep learning ($localDeepLearningMinVersion): same XML in every version
            $Unkown_UDP_xmlstring_112 = $Unkown_UDP_xmlstring;
            if( !$tmp_mica_Unknown_TCP_found && $this->bpFeatureSupported( 'spyware-mica' ))
            {
                if( $this->bpFeatureSupported( 'spyware-local-deep-learning' ) )
                    $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $Unkown_TCP_xmlstring_112);
                else
                    $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $Unkown_TCP_xmlstring);
                $tmp_rule->appendChild($xmlElement);

                $this->additional['mica-engine-spyware-enabled']['Unknown-TCP Command and Control detector']['inline-policy-action'] = "alert";
            }
            if( !$tmp_mica_Unknown_UDP_found && $this->bpFeatureSupported( 'spyware-mica' ) )
            {
                if( $this->bpFeatureSupported( 'spyware-local-deep-learning' ) )
                    $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $Unkown_UDP_xmlstring_112);
                else
                    $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $Unkown_UDP_xmlstring);
                $tmp_rule->appendChild($xmlElement);

                $this->additional['mica-engine-spyware-enabled']['Unknown-UDP Command and Control detector']['inline-policy-action'] = "alert";
            }
        }
        else
        {
            $xmlstring_102 = '<mica-engine-spyware-enabled>
  <entry name="HTTP Command and Control detector">
    <inline-policy-action>alert</inline-policy-action>
  </entry>
  <entry name="HTTP2 Command and Control detector">
    <inline-policy-action>alert</inline-policy-action>
  </entry>
  <entry name="SSL Command and Control detector">
    <inline-policy-action>alert</inline-policy-action>
  </entry>
  <entry name="Unknown-TCP Command and Control detector">
    <inline-policy-action>alert</inline-policy-action>
  </entry>
  <entry name="Unknown-UDP Command and Control detector">
    <inline-policy-action>alert</inline-policy-action>
  </entry>
</mica-engine-spyware-enabled>';


            // as the firewall writes a new profile: every detector 'alert', no local-deep-learning element
            if( $this->owner !== null && $this->bpFeatureSupported( 'spyware-mica' ) )
            {
                $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $xmlstring_102);
                $xml->appendChild($xmlElement);
            }

            if( $this->owner !== null && $this->bpFeatureSupported( 'spyware-mica' ) )
            {
                // same values as the XML written above (no local-deep-learning)
                foreach( array( 'HTTP', 'HTTP2', 'SSL', 'Unknown-TCP', 'Unknown-UDP' ) as $detector )
                    $this->additional['mica-engine-spyware-enabled'][$detector.' Command and Control detector']['inline-policy-action'] = "alert";
            }
        }

        //<cloud-inline-analysis>yes</cloud-inline-analysis>
        $tmp_rule = DH::findFirstElement('cloud-inline-analysis', $xml);
        if( $tmp_rule !== FALSE )
        {
            if( $tmp_rule->textContent == "yes")
                $this->cloud_inline_analysis_enabled = true;
        }
        else
        {
            if( $this->owner !== null && $this->bpFeatureSupported( 'spyware-mica' ) )
            {
                $tmp_rule = DH::findFirstElementOrCreate('cloud-inline-analysis', $xml);
                $tmp_rule->textContent = "no";

                $this->cloud_inline_analysis_enabled = false;
            }
        }
    }

    public function load_from_domxml_spyware_threat_exception(DOMElement $xml ): void
    {
        $tmp_threat_exception = DH::findFirstElement('threat-exception', $xml);
        if( $tmp_threat_exception !== FALSE )
        {
            $tmp_array[$this->secprof_type][$this->name]['threat-exception'] = array();
            foreach( $tmp_threat_exception->childNodes as $tmp_entry1 )
            {
                if( $tmp_entry1->nodeType != XML_ELEMENT_NODE )
                    continue;

                $tmp_name = DH::findAttribute('name', $tmp_entry1);
                if( $tmp_name === FALSE )
                    derr("VB severity name not found\n");

                $this->threatException[$tmp_name]['name'] = $tmp_name;


                if( get_class($this->owner->owner) == "DeviceGroup" )
                    $threatStore = $this->owner->owner->owner->threatStore;
                else
                    $threatStore = $this->owner->owner->threatStore;

                $threat_obj = $threatStore->find($tmp_name);
                if($threat_obj !== null)
                    $threat_obj->addReference($this);


                $action = DH::findFirstElement('action', $tmp_entry1);
                if( $action !== FALSE )
                {
                    if( $action->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_action = DH::firstChildElement($action);
                    if( $tmp_action !== FALSE )
                    {
                        $tmp_array[$this->secprof_type][$this->name]['threat-exception'][$tmp_name]['action'] = $tmp_action->nodeName;
                        $this->threatException[$tmp_name]['action'] = $tmp_action->nodeName;
                        if($threat_obj !== null)
                            $this->threatException[$tmp_name]['default-action'] = $threat_obj->defaultAction();
                    }
                }

                $exemptIP = DH::findFirstElement('exempt-ip', $tmp_entry1);
                $this->threatException[$tmp_name]['exempt-ip'] = array();
                if( $exemptIP !== FALSE )
                {
                    foreach( $exemptIP->childNodes as $tmp_entry2 )
                    {
                        if ($tmp_entry2->nodeType != XML_ELEMENT_NODE)
                            continue;

                        $this->threatException[$tmp_name]['exempt-ip'][] = DH::findAttribute("name", $tmp_entry2);
                    }
                }
            }
        }
    }

    public function load_from_domxml_spyware_botnet(DOMElement $xml ): void
    {
        $tmp_rule = DH::findFirstElementorCreate('botnet-domains', $xml);
        if( $tmp_rule !== FALSE )
        {
            $this->additional['botnet-domain'] = array();
            /*
                 <sinkhole>
                    <ipv4-address>sinkhole.paloaltonetworks.com</ipv4-address>
                    <ipv6-address>2600:5200::1</ipv6-address>
                 </sinkhole>
             */
            $tmp_sinkhole = DH::findFirstElement('sinkhole', $tmp_rule);
            if( $tmp_sinkhole !== FALSE )
            {
                $this->additional['botnet-domain']['sinkhole'] = array();
                $tmp_sinkhole_ipv4 = DH::findFirstElement('ipv4-address', $tmp_sinkhole);
                if( $tmp_sinkhole_ipv4 !== FALSE )
                    $this->additional['botnet-domain']['sinkhole']['ipv4-address'] = $tmp_sinkhole_ipv4->textContent;
                else
                {
                    $tmp_sinkhole_ipv4 = DH::findFirstElementOrCreate('ipv4-address', $tmp_sinkhole);
                    $tmp_sinkhole_ipv4->textContent = "pan-sinkhole-default-ip";
                    $this->additional['botnet-domain']['sinkhole']['ipv4-address'] = $tmp_sinkhole_ipv4->textContent;
                }
                $tmp_sinkhole_ipv6 = DH::findFirstElement('ipv6-address', $tmp_sinkhole);
                if( $tmp_sinkhole_ipv6 !== FALSE )
                    $this->additional['botnet-domain']['sinkhole']['ipv6-address'] = $tmp_sinkhole_ipv6->textContent;
                else
                {
                    $tmp_sinkhole_ipv6 = DH::findFirstElementOrCreate('ipv6-address', $tmp_sinkhole);
                    $tmp_sinkhole_ipv6->textContent = "2600:5200::1";
                    $this->additional['botnet-domain']['sinkhole']['ipv6-address'] = $tmp_sinkhole_ipv6->textContent;
                }
            }
            else
            {
                $tmp_sinkhole = DH::findFirstElementOrCreate('sinkhole', $tmp_rule);
                $this->additional['botnet-domain']['sinkhole'] = array();
                $tmp_sinkhole_ipv4 = DH::findFirstElementOrCreate('ipv4-address', $tmp_sinkhole);
                if( $tmp_sinkhole_ipv4 !== FALSE )
                {
                    $tmp_sinkhole_ipv4->textContent = "pan-sinkhole-default-ip";
                    $this->additional['botnet-domain']['sinkhole']['ipv4-address'] = $tmp_sinkhole_ipv4->textContent;
                }

                $tmp_sinkhole_ipv6 = DH::findFirstElementOrCreate('ipv6-address', $tmp_sinkhole);
                if( $tmp_sinkhole_ipv6 !== FALSE )
                {
                    $tmp_sinkhole_ipv6->textContent = "2600:5200::1";
                    $this->additional['botnet-domain']['sinkhole']['ipv6-address'] = $tmp_sinkhole_ipv6->textContent;
                }

            }

            $tmp_lists = DH::findFirstElement('lists', $tmp_rule);
            if( $tmp_lists == FALSE or !$tmp_lists->hasChildNodes() )
            {
                $tmp_lists = DH::findFirstElementOrCreate('lists', $tmp_rule);
                $tmp_xmlstring = '<entry name="default-paloalto-dns">
   <action>
      <alert/>
   </action>
   <packet-capture>disable</packet-capture>
</entry>';
                $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $tmp_xmlstring);
                $tmp_lists->appendChild($xmlElement);
                $tmp_lists = DH::findFirstElement('lists', $tmp_rule);
            }
            if( $tmp_lists !== FALSE )
            {
                $this->additional['botnet-domain']['lists'] = array();
                foreach( $tmp_lists->childNodes as $tmp_entry1 )
                {
                    if( $tmp_entry1->nodeType != XML_ELEMENT_NODE )
                        continue;

                    /*
                     <lists>
                        <entry name="default-paloalto-dns">
                           <action>
                              <alert/>
                           </action>
                           <packet-capture>disable</packet-capture>
                        </entry>
                     */

                    $name = DH::findAttribute("name", $tmp_entry1);

                    $dnsPolicy_obj = new DNSPolicy( $name, $this );
                    $dnsPolicy_obj->load_from_domxml( $tmp_entry1 );
                    $this->lists_obj[$name] = $dnsPolicy_obj;
                    $dnsPolicy_obj->addReference( $this );

                    $this->owner->owner->DNSPolicyStore->add($dnsPolicy_obj);

                    $this->additional['botnet-domain']['lists'][$name] = $dnsPolicy_obj;
                }
            }

            $tmp_dns_security_categories = DH::findFirstElement('dns-security-categories', $tmp_rule);
            if( $tmp_dns_security_categories === FALSE )
            {
                $xmlstring = '<dns-security-categories>
<entry name="pan-dns-sec-adtracking">
  <log-level>default</log-level>
  <action>default</action>
  <packet-capture>disable</packet-capture>
</entry>
<entry name="pan-dns-sec-cc">
  <log-level>default</log-level>
  <action>default</action>
  <packet-capture>disable</packet-capture>
</entry>
<entry name="pan-dns-sec-ddns">
  <log-level>default</log-level>
  <action>default</action>
  <packet-capture>disable</packet-capture>
</entry>
<entry name="pan-dns-sec-grayware">
  <log-level>default</log-level>
  <action>default</action>
  <packet-capture>disable</packet-capture>
</entry>
<entry name="pan-dns-sec-malware">
  <log-level>default</log-level>
  <action>default</action>
  <packet-capture>disable</packet-capture>
</entry>
<entry name="pan-dns-sec-parked">
  <log-level>default</log-level>
  <action>default</action>
  <packet-capture>disable</packet-capture>
</entry>
<entry name="pan-dns-sec-phishing">
  <log-level>default</log-level>
  <action>default</action>
  <packet-capture>disable</packet-capture>
</entry>
<entry name="pan-dns-sec-proxy">
  <log-level>default</log-level>
  <action>default</action>
  <packet-capture>disable</packet-capture>
</entry>
<entry name="pan-dns-sec-recent">
  <log-level>default</log-level>
  <action>default</action>
  <packet-capture>disable</packet-capture>
</entry>
</dns-security-categories>';

                // PAN-OS default categories, from the version the checks use (SecurityProfile2::$bpFeatureMinVersion)
                if( $this->bpFeatureSupported( 'spyware-dns' ) )
                {
                    $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $xmlstring);
                    $tmp_rule->appendChild($xmlElement);

                    $tmp_dns_security_categories = DH::findFirstElement('dns-security-categories', $tmp_rule);
                }
            }

            if( $tmp_dns_security_categories !== FALSE )
            {
                $this->additional['botnet-domain']['dns-security-categories'] = array();
                foreach( $tmp_dns_security_categories->childNodes as $tmp_entry1 )
                {
                    if ($tmp_entry1->nodeType != XML_ELEMENT_NODE)
                        continue;

                    /*
                    <dns-security-categories>
                        <entry name="pan-dns-sec-adtracking">
                           <log-level>default</log-level>
                           <action>default</action>
                           <packet-capture>disable</packet-capture>
                        </entry>
                    */

                    $name = DH::findAttribute("name", $tmp_entry1);

                    $dnsPolicy_obj = new DNSPolicy( $name, $this );
                    $dnsPolicy_obj->load_from_domxml( $tmp_entry1 );
                    $this->dns_rules_obj[$name] = $dnsPolicy_obj;
                    $dnsPolicy_obj->addReference( $this );

                    $this->owner->owner->DNSPolicyStore->add($dnsPolicy_obj);

                    $this->additional['botnet-domain']['dns-security-categories'][$name] = $dnsPolicy_obj;
                }

                foreach( $this->owner->owner->DNSPolicyStore->tmp_dns_prof_array as $dns_category )
                {
                    //add missing DNS security categories
                    if( !isset($this->additional['botnet-domain']['dns-security-categories'][$dns_category]) )
                    {
                        $tmp_xml_string = '<entry name="'.$dns_category.'">
                           <log-level>default</log-level>
                           <action>default</action>
                           <packet-capture>disable</packet-capture>
                        </entry>';

                        $dnsPolicy_obj = new DNSPolicy( $dns_category, $this );
                        $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $tmp_xml_string);
                        $tmp_dns_security_categories->appendChild($xmlElement);

                        $dnsPolicy_obj->load_from_domxml( $xmlElement );
                        $this->dns_rules_obj[$dns_category] = $dnsPolicy_obj;
                        $dnsPolicy_obj->addReference( $this );

                        $this->owner->owner->DNSPolicyStore->add($dnsPolicy_obj);

                        $this->additional['botnet-domain']['dns-security-categories'][$dns_category] = $dnsPolicy_obj;
                    }
                }
            }

            $tmp_advanced_dns_security_categories = DH::findFirstElement('advanced-dns-security-categories', $tmp_rule);
            if( $tmp_advanced_dns_security_categories === FALSE )
            {
                $xmlstring = '<advanced-dns-security-categories>
<entry name="pan-adns-sec-dnsmisconfig">
  <log-level>default</log-level>
  <action>default</action>
</entry>
<entry name="pan-adns-sec-hijacking">
  <log-level>default</log-level>
  <action>default</action>
</entry>
</advanced-dns-security-categories>';

                // PAN-OS default categories, from the version the checks use (SCM: always - SecurityProfile2::inlineVersion())
                if( $this->bpFeatureSupported( 'spyware-advanced-dns' ) )
                {
                    $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $xmlstring);
                    $tmp_rule->appendChild($xmlElement);

                    $tmp_advanced_dns_security_categories = DH::findFirstElement('advanced-dns-security-categories', $tmp_rule);
                }
            }

            if( $tmp_advanced_dns_security_categories !== FALSE )
            {
                $this->additional['botnet-domain']['advanced-dns-security-categories'] = array();
                foreach( $tmp_advanced_dns_security_categories->childNodes as $tmp_entry1 )
                {
                    if ($tmp_entry1->nodeType != XML_ELEMENT_NODE)
                        continue;

                    /*
                    <advanced-dns-security-categories>
                        <entry name="pan-adns-sec-dnsmisconfig">
                          <log-level>medium</log-level>
                          <action>block</action>
                        </entry>
                        <entry name="pan-adns-sec-hijacking">
                          <log-level>medium</log-level>
                          <action>block</action>
                        </entry>
                      </advanced-dns-security-categories>
                    */

                    $name = DH::findAttribute("name", $tmp_entry1);

                    $dnsPolicy_obj = new DNSPolicy( $name, $this, TRUE );
                    $dnsPolicy_obj->load_from_domxml( $tmp_entry1 );
                    $this->dns_rules_obj[] = $dnsPolicy_obj;
                    $dnsPolicy_obj->addReference( $this );

                    $this->owner->owner->DNSPolicyStore->add($dnsPolicy_obj);

                    $this->additional['botnet-domain']['advanced-dns-security-categories'][$name] = $dnsPolicy_obj;
                }


                foreach( $this->owner->owner->DNSPolicyStore->tmp_adns_prof_array as $dns_category )
                {
                    //add missing DNS security categories
                    if( !isset($this->additional['botnet-domain']['advanced-dns-security-categories'][$dns_category]) )
                    {
                        $tmp_xml_string = '<entry name="'.$dns_category.'">
                           <log-level>default</log-level>
                           <action>default</action>
                        </entry>';

                        $dnsPolicy_obj = new DNSPolicy( $dns_category, $this );
                        $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $tmp_xml_string);
                        $tmp_advanced_dns_security_categories->appendChild($xmlElement);

                        $dnsPolicy_obj->load_from_domxml( $xmlElement );
                        $this->dns_rules_obj[$dns_category] = $dnsPolicy_obj;
                        $dnsPolicy_obj->addReference( $this );

                        $this->owner->owner->DNSPolicyStore->add($dnsPolicy_obj);

                        $this->additional['botnet-domain']['advanced-dns-security-categories'][$dns_category] = $dnsPolicy_obj;
                    }
                }

            }

            $tmp_whitelists = DH::findFirstElement('whitelist', $tmp_rule);
            if( $tmp_whitelists !== FALSE )
            {
                $this->additional['botnet-domain']['whitelist'] = array();
                foreach ($tmp_whitelists->childNodes as $tmp_entry1)
                {
                    if ($tmp_entry1->nodeType != XML_ELEMENT_NODE)
                        continue;

                    $name = DH::findAttribute("name", $tmp_entry1);
                    $tmp_whitelists_description = DH::findFirstElement('description', $tmp_entry1);
                    $this->additional['botnet-domain']['whitelist'][$name]['name'] = $name;
                    if( $tmp_whitelists_description !== FALSE )
                        $this->additional['botnet-domain']['whitelist'][$name]['description'] = $tmp_whitelists_description->textContent;
                }
            }
        }
    }


    public function display_as_rules()
    {
        if( !empty( $this->rules_obj ) )
        {
            PH::print_stdout("        - Signature Policies:");
            foreach ($this->rules_obj as $rulename => $rule)
                $rule->display();
        }
    }

    public function display_as_threatException()
    {
        if( !empty( $this->threatException ) )
        {
            PH::print_stdout("        - Signature Exceptions:" );

            foreach( $this->threatException as $threatname => $threat )
            {
                PH::$JSON_TMP['sub']['object'][$this->name()]['threat-exception'][$threatname]['name'] = $threat['name'];

                $string = "             '" . $threat['name'] . "'";
                if( isset( $threat['action'] ) )
                {
                    $string .= "  - action : '".$threat['action']."'";
                    PH::$JSON_TMP['sub']['object'][$this->name()]['threat-exception'][$threatname]['action'] = $threat['action'];
                }
                if( isset( $threat['default-action'] ) )
                {
                    $string .= "  - default-action : '".$threat['default-action']."'";
                    PH::$JSON_TMP['sub']['object'][$this->name()]['threat-exception'][$threatname]['default-action'] = $threat['default-action'];
                }
                if( isset( $threat['exempt-ip'] ) )
                {
                    $string .= "  - exempt-ip: ".implode( ",", $threat['exempt-ip'] );
                    PH::$JSON_TMP['sub']['object'][$this->name()]['threat-exception'][$threatname]['exempt-ip'] = $threat['exempt-ip'];
                }
                PH::print_stdout(  $string );
            }
        }
    }
    public function display_as_additional()
    {
        if( !empty( $this->additional ) )
        {
            if( !empty( $this->additional['botnet-domain'] ) )
            {
                PH::print_stdout("        ----------------------------------------");
                PH::print_stdout("        - DNS Policies:" );

                foreach( $this->additional['botnet-domain'] as $type => $threat )
                {
                    PH::print_stdout("          * ".$type.":" );
                    if( $type == "lists" )
                    {
                        #print_r($this->additional['botnet-domain'][$type]);
                        foreach( $this->additional['botnet-domain']['lists'] as $name => $value )
                        {
                            $padding = "    ";
                            $value->display( $padding);
                        }
                    }
                    elseif( $type == "sinkhole" )
                    {
                        foreach( $this->additional['botnet-domain'][$type] as $name => $value )
                        {
                            PH::print_stdout("            - ".$name.": ".$value );
                        }
                    }
                    elseif( $type == "dns-security-categories" )
                    {
                        foreach( $this->additional['botnet-domain'][$type] as $name => $value )
                        {
                            $padding = "    ";
                            $value->display( $padding);
                        }
                    }
                    elseif( $type == "whitelist" )
                    {
                        foreach( $this->additional['botnet-domain'][$type] as $name => $value )
                        {
                            $string = "            - '".$value['name']."'";
                            if(isset($value['description']))
                                $string .= "| description:'".$value['description']."'";
                            PH::print_stdout( $string );
                        }
                    }
                    elseif( $type == "advanced-dns-security-categories" )
                    {
                        foreach( $this->additional['botnet-domain'][$type] as $name => $value )
                        {
                            $padding = "    ";
                            $value->display( $padding);
                        }
                    }
                }
            }

            if( !empty( $this->additional['mica-engine-spyware-enabled'] ) )
            {
                PH::print_stdout("        ----------------------------------------");
                $enabled = "[no]";
                if( $this->cloud_inline_analysis_enabled )
                    $enabled = "[yes]";
                PH::print_stdout("        - mica-engine-spyware-enabled: ". $enabled);

                foreach ($this->additional['mica-engine-spyware-enabled'] as $name => $threat)
                {
                    $string = "          * " . $name . " - inline-policy-action :" . $this->additional['mica-engine-spyware-enabled'][$name]['inline-policy-action'];
                    if( isset($this->additional['mica-engine-spyware-enabled'][$name]['local-deep-learning']) )
                        $string .= " - local-deep-learning :" . $this->additional['mica-engine-spyware-enabled'][$name]['local-deep-learning'];
                    PH::print_stdout( $string );
                }
            }
        }
        #PH::print_stdout();
    }

    public function spyware_lists_bp_visibility_JSON( $checkType, $secprof_type, $av_action_type = null )
    {
        $checkArray = array();

        if( $checkType !== "bp" && $checkType !== "visibility" )
            derr( "only 'bp' or 'visibility' argument allowed" );

        ###############################
        $details = PH::getBPjsonFile( );

        $array_type = "lists";

        if( isset($details[$secprof_type][$array_type]) )
        {
            if( $checkType == "bp" )
            {
                if( isset($details[$secprof_type][$array_type]['bp']))
                    $checkArray = $details[$secprof_type][$array_type]['bp'];
                else
                    mwarning( "this JSON bp/visibility JSON file customised 'bp' -> '".$array_type."' for: '".$secprof_type, null, FALSE );
            }
            elseif( $checkType == "visibility")
            {
                if( isset($details[$secprof_type][$array_type]['visibility']))
                    $checkArray = $details[$secprof_type][$array_type]['visibility'];
                else
                    mwarning( "this JSON bp/visibility JSON file customised 'visibility' -> '".$array_type."' for: '".$secprof_type, null, FALSE );
            }
        }

        return $checkArray;
    }

    /**
     * FALSE for an anti-spyware profile of an SCM / Prisma Access configuration: there the DNS part (DNS lists,
     * DNS security categories) is a dns-security profile, the anti-spyware profile has none - its DNS checks are N/A
     */
    public function spyware_dnsPartApplies(): bool
    {
        return !( $this instanceof AntiSpywareProfile && $this->isCloudManaged() );
    }

    public function spyware_dnslist_best_practice(): ?bool
    {
        if( !$this->spyware_dnsPartApplies() )
            return null;     // SCM anti-spyware profile: its DNS part is a dns-security profile
        if( $this->secprof_type != 'spyware' && $this->secprof_type != 'dns-security' )
            return null;

        // spyware -> lists -> bp not listed: not checked -> N/A
        if( empty( PH::getBPjsonFile()['spyware']['lists']['bp']['action'] ) )
            return null;

        $bp_set = false;
        if( isset($this->additional['botnet-domain']['lists']) )
        {
            foreach ($this->additional['botnet-domain']['lists'] as $name => $value)
            {
                /** @var DNSPolicy $value */
                $ret = $value->spyware_lists_bestpractice();
                if( $ret === FALSE )
                    return false;
                if( $ret !== null )     // null: this list is not in the BP JSON
                    $bp_set = true;
            }
        }
        return $bp_set;
    }

    public function spyware_dnslist_visibility(): ?bool
    {
        if( !$this->spyware_dnsPartApplies() )
            return null;     // SCM anti-spyware profile: its DNS part is a dns-security profile
        if( $this->secprof_type != 'spyware' && $this->secprof_type != 'dns-security' )
            return null;

        // spyware -> lists -> visibility not listed: not checked -> N/A
        if( empty( PH::getBPjsonFile()['spyware']['lists']['visibility']['action'] ) )
            return null;

        $bp_set = false;
        if( isset($this->additional['botnet-domain']['lists']) )
        {
            foreach ($this->additional['botnet-domain']['lists'] as $name => $value)
            {
                if( $value->name() !== "default-paloalto-dns" )
                    continue;
                /** @var DNSPolicy $value */
                $ret = $value->spyware_lists_visibility();
                if( $ret === FALSE )
                    return false;
                if( $ret !== null )     // null: this list is not in the visibility JSON
                    $bp_set = true;
            }
        }
        return $bp_set;
    }

    public function spyware_dnslist_adoption(): ?bool
    {
        if( !$this->spyware_dnsPartApplies() )
            return null;     // SCM anti-spyware profile: its DNS part is a dns-security profile
        // anti-spyware (PAN-OS) or dns-security profile (SCM): both hold the DNS lists
        if( $this->secprof_type != 'spyware' && $this->secprof_type != 'dns-security' )
            return null;

        return TRUE;
    }
    /**
     * PAN-OS reads a profile's rules top-down; the first rule that matches a threat's severity and category
     * decides its action. Rules naming a threat apply to that threat only and are skipped.
     */
    public function spyware_rules_first_match( $severity, $category )
    {
        foreach( $this->rules_obj as $rule )
            if( !$rule->namesParticularThreats() && $rule->matchesThreat( $severity, null, $category ) )
                return $rule;
        return null;     // no rule matches: PAN-OS takes no action and logs nothing
    }

    /**
     * Rules of the profile against the BP / visibility JSON (spyware -> rule -> bp|visibility):
     *  - severity not listed (key missing or empty): not checked -> null (N/A)
     *  - 'any' listed: a rule for every threat (severity and category any, no particular threat) must pass,
     *    or every single severity is covered by rules with category any
     *  - another severity listed: for every category the first matching rule (PAN-OS order) must pass
     * bp: the visibility check must pass as well (when it is asked for); categories in category-exclude are skipped.
     */
    private function spyware_rules_check( string $type ): ?bool
    {
        $details = PH::getBPjsonFile();
        $check_array = $details['spyware']['rule'][$type] ?? array();
        $severities = ThreatPolicy::checkedSeverities( $check_array );
        if( count($severities) == 0 )
            return null;
        if( empty( $this->rules_obj ) )
            return FALSE;       // asked for, but the profile has no rule: no action, no log

        $exclude = ( $type == "bp" ) ? ( $check_array['category-exclude'] ?? array() ) : array();
        $categories = ThreatPolicy::categoriesOf( $this->rules_obj );
        // the rule is checked for the severity in question (a rule for 'low' must not pass a check for 'any'
        // only because the JSON lists no 'low')
        $passes = function( $rule, $severity ) use ( $type, $check_array ) {
            $check = $check_array;
            $check['severity'] = array( $severity );
            $ret = ( $type == "bp" ) ? $rule->check_bp_json( $check ) : $rule->check_visibility_json( $check );
            return $ret !== FALSE;
        };

        foreach( $severities as $severity )
        {
            if( $severity == "any" )
            {
                $found = FALSE;
                foreach( $this->rules_obj as $rule )
                    if( $rule->matchesEveryThreat() && $passes( $rule, "any" ) )
                    {
                        $found = TRUE;
                        break;
                    }
                // or: every single severity covered with category any (first matching rule, PAN-OS order)
                if( !$found )
                {
                    $found = TRUE;
                    foreach( array( "critical", "high", "medium", "low", "informational" ) as $single )
                    {
                        $rule = $this->spyware_rules_first_match( $single, ThreatPolicy::OTHER_CATEGORY );
                        if( $rule === null || ( $rule->category() ?? "any" ) !== "any" || !$passes( $rule, $single ) )
                            $found = FALSE;
                    }
                }
                if( !$found )
                    return FALSE;
                continue;
            }
            foreach( $categories as $category )
            {
                if( in_array( $category, $exclude, TRUE ) )
                    continue;   // the BP file leaves these categories out of best practice
                $rule = $this->spyware_rules_first_match( $severity, $category );
                if( $rule === null || !$passes( $rule, $severity ) )
                    return FALSE;
            }
        }
        return TRUE;
    }

    /** null: not asked for by the BP JSON (N/A) */
    public function spyware_rules_best_practice(): ?bool
    {
        if( $this->spyware_rules_visibility() === FALSE )
            return FALSE;
        return $this->spyware_rules_check( "bp" );
    }

    /** null: not asked for by the visibility JSON (N/A) */
    public function spyware_rules_visibility(): ?bool
    {
        return $this->spyware_rules_check( "visibility" );
    }


    //todo: 20241107 swaschkut - bring in BP
    public function spyware_exception_best_practice(): void
    {
        if (!empty($this->threatException)) {
            foreach ($this->threatException as $threatname => $threat)
            {
                //which check??
            }
        }
        derr( "BP AS exception check not impemented" );
    }

    public function spyware_dns_security_best_practice(): ?bool
    {
        if( !$this->spyware_dnsPartApplies() )
            return null;     // SCM anti-spyware profile: its DNS part is a dns-security profile
        if( $this->bpFeatureSupported( 'spyware-dns' ) )
        {
            // spyware -> dns -> bp not listed: not checked -> N/A
            if( empty( PH::getBPjsonFile()['spyware']['dns']['bp']['action'] ) )
                return null;

            $bp_set = false;
            if( isset($this->additional['botnet-domain']['dns-security-categories']) )
            {
                foreach ($this->additional['botnet-domain']['dns-security-categories'] as $name => $value)
                {
                    /** @var DNSPolicy $value */
                    $ret = $value->spyware_dns_security_rule_bestpractice();
                    if( $ret === FALSE )
                        return false;
                    if( $ret !== null )     // null: this category is not in the JSON
                        $bp_set = true;
                }
            }
            return $bp_set;
        }
        return null;
    }

    public function spyware_dns_security_visibility(): ?bool
    {
        if( !$this->spyware_dnsPartApplies() )
            return null;     // SCM anti-spyware profile: its DNS part is a dns-security profile
        if( $this->bpFeatureSupported( 'spyware-dns' ) )
        {
            // spyware -> dns -> visibility not listed: not checked -> N/A
            if( empty( PH::getBPjsonFile()['spyware']['dns']['visibility']['action'] ) )
                return null;

            $bp_set = false;
            if( isset($this->additional['botnet-domain']['dns-security-categories']) )
            {
                foreach ($this->additional['botnet-domain']['dns-security-categories'] as $name => $value)
                {
                    /** @var DNSPolicy $value */
                    $ret = $value->spyware_dns_security_rule_visibility();
                    if( $ret === FALSE )
                        return false;
                    if( $ret !== null )     // null: this category is not in the JSON
                        $bp_set = true;
                }
            }
            return $bp_set;
        }
        return null;
    }

    public function spyware_advanced_dns_security_best_practice(): ?bool
    {
        if( !$this->spyware_dnsPartApplies() )
            return null;     // SCM anti-spyware profile: its DNS part is a dns-security profile
        if( $this->bpFeatureSupported( 'spyware-advanced-dns' ) )
        {
            // spyware -> advanced-dns -> bp not listed: not checked -> N/A
            if( empty( PH::getBPjsonFile()['spyware']['advanced-dns']['bp']['action'] ) )
                return null;

            $bp_set = false;
            if( isset($this->additional['botnet-domain']['advanced-dns-security-categories']) )
            {
                foreach ($this->additional['botnet-domain']['advanced-dns-security-categories'] as $name => $value)
                {
                    /** @var DNSPolicy $value */
                    $ret = $value->spyware_advanced_dns_security_rule_bestpractice();
                    if( $ret === FALSE )
                        return false;
                    if( $ret !== null )     // null: this category is not in the JSON
                        $bp_set = true;
                }
            }
            return $bp_set;
        }
        return null;    // PAN-OS without advanced DNS security: not checked
    }

    public function spyware_advanced_dns_security_visibility(): ?bool
    {
        if( !$this->spyware_dnsPartApplies() )
            return null;     // SCM anti-spyware profile: its DNS part is a dns-security profile
        if( $this->bpFeatureSupported( 'spyware-advanced-dns' ) )
        {
            // spyware -> advanced-dns -> visibility not listed: not checked -> N/A
            if( empty( PH::getBPjsonFile()['spyware']['advanced-dns']['visibility']['action'] ) )
                return null;

            $bp_set = false;
            if( isset($this->additional['botnet-domain']['advanced-dns-security-categories']) )
            {
                foreach ($this->additional['botnet-domain']['advanced-dns-security-categories'] as $name => $value)
                {
                    /** @var DNSPolicy $value */
                    $ret = $value->spyware_advanced_dns_security_rule_visibility();
                    if( $ret === FALSE )
                        return false;
                    if( $ret !== null )     // null: this category is not in the JSON
                        $bp_set = true;
                }
            }

            return $bp_set;
        }
        return null;    // PAN-OS without advanced DNS security: not checked
    }

    public function spyware_dns_security_adoption(): ?bool
    {
        if( !$this->spyware_dnsPartApplies() )
            return null;     // SCM anti-spyware profile: its DNS part is a dns-security profile
        if( $this->bpFeatureSupported( 'spyware-dns' ) )
        {
            return TRUE;
        }
        return null;
    }

    public function is_best_practice(): ?bool
    {
        if( $this->owner->owner->isPanorama()
            || $this->owner->owner->isDeviceGroup()
            || $this->owner->owner->isFirewall()
            || $this->owner->owner->isVirtualSystem() )
        {
            // each part returns null where the PAN-OS version has no such setting (SecurityProfile2::$bpFeatureMinVersion)
            return PH::bpCombine( array( $this->spyware_rules_best_practice(), $this->cloud_inline_analysis_best_practice($this->owner->bp_json_file), $this->spyware_dnslist_best_practice(), $this->spyware_dns_security_best_practice(), $this->spyware_advanced_dns_security_best_practice() ) );
        }
        else
        {
            // SCM: the DNS part of PAN-OS anti-spyware is a dns-security profile (DNSSecurityProfile checks it) -
            // an anti-spyware profile is checked without it; each part returns null where the PAN-OS version has
            // no such setting (SecurityProfile2::$bpFeatureMinVersion)
            if( $this instanceof AntiSpywareProfile )
                return PH::bpCombine( array( $this->spyware_rules_best_practice(), $this->cloud_inline_analysis_best_practice($this->owner->bp_json_file) ) );
            return PH::bpCombine( array( $this->spyware_rules_best_practice(), $this->cloud_inline_analysis_best_practice($this->owner->bp_json_file), $this->spyware_dns_security_best_practice(), $this->spyware_advanced_dns_security_best_practice() ) );
        }

    }

    public function is_visibility(): ?bool
    {
        if( $this->owner->owner->isPanorama()
            || $this->owner->owner->isDeviceGroup()
            || $this->owner->owner->isFirewall()
            || $this->owner->owner->isVirtualSystem() )
        {
            // each part returns null where the PAN-OS version has no such setting (SecurityProfile2::$bpFeatureMinVersion)
            return PH::bpCombine( array( $this->spyware_rules_visibility(), $this->cloud_inline_analysis_visibility($this->owner->bp_json_file), $this->spyware_dnslist_visibility(), $this->spyware_dns_security_visibility(), $this->spyware_advanced_dns_security_visibility() ) );
        }
        else
        {
            //Todo: validation for SCM needed - what version
            // SCM: the DNS part of PAN-OS anti-spyware is a dns-security profile (DNSSecurityProfile checks it)
            if( $this instanceof AntiSpywareProfile )
                return PH::bpCombine( array( $this->spyware_rules_visibility(), $this->cloud_inline_analysis_visibility($this->owner->bp_json_file) ) );
            return PH::bpCombine( array( $this->spyware_rules_visibility(), $this->cloud_inline_analysis_visibility($this->owner->bp_json_file), $this->spyware_dnslist_visibility(), $this->spyware_dns_security_visibility(), $this->spyware_advanced_dns_security_visibility() ) );
        }
    }

    public function is_adoption(): bool
    {
        #if at least one spyware rule is set -> adoption, if not false
        if( count($this->rules_obj) > 0 )
            return true;
        else
            return false;
    }

    /**
     * best-practice-set of the AS inline cloud analysis (mica-engine-spyware-enabled).
     * The action comes from the BP JSON spyware -> cloud-inline -> bp (entry with type 'any', as the checks);
     * a negated condition ('!allow') keeps a compliant value, else 'reset-both'. Nothing listed in the BP JSON or a
     * PAN-OS version without inline ML: no change.
     */
    public function inlineML_BestPracticeSet(): void
    {
        $this->spyware_inlineML_setFromJSON( 'bp', 'reset-both' );
    }

    private function spyware_inlineML_setFromJSON( string $section, string $fallback ): void
    {
        $validate = $this->inlineML_jsonAction( $section, 'spyware' );
        if( $validate === null )
            return;

        $container = DH::findFirstElement( 'mica-engine-spyware-enabled', $this->xmlroot );
        if( $container === False )
        {
            $value = self::inlineML_newValue( $validate, $fallback );
            $detectors = array( 'HTTP Command and Control detector', 'HTTP2 Command and Control detector', 'SSL Command and Control detector',
                'Unknown-TCP Command and Control detector', 'Unknown-UDP Command and Control detector' );
            $xmlString = '<mica-engine-spyware-enabled>';
            foreach( $detectors as $detector )
                $xmlString .= '<entry name="'.$detector.'"><inline-policy-action>'.$value.'</inline-policy-action></entry>';
            $xmlString .= '</mica-engine-spyware-enabled>';
            $xmlElement = DH::importXmlStringOrDie( $this->xmlroot->ownerDocument, $xmlString );
            $this->xmlroot->appendChild( $xmlElement );
            foreach( $detectors as $detector )
                $this->additional['mica-engine-spyware-enabled'][$detector]['inline-policy-action'] = $value;
        }
        else
            $this->inlineML_setEntriesFromJSON( $section, 'spyware', 'mica-engine-spyware-enabled', 'inline-policy-action', $fallback );

        // local-deep-learning of the detectors the BP JSON lists (from PAN-OS 11.2)
        $this->inlineML_localDeepLearningSetFromJSON( $section );

        $tmp_enable = DH::findFirstElementOrCreate( 'cloud-inline-analysis', $this->xmlroot );
        $tmp_enable->textContent = "yes";
        $this->cloud_inline_analysis_enabled = true;

        if( $this->secprof_type == 'spyware' )
            $this->bpSetVerify( $section, 'AS inline ML', $section == 'bp' ? $this->cloud_inline_analysis_best_practice() : $this->cloud_inline_analysis_visibility() );
    }

    /**
     * best-practice-set of the AS rules: action / packet-capture as the BP JSON spyware -> rule -> bp lists them,
     * for the severities it lists (categories in category-exclude left out) - see threatRules_setFromJSON().
     */
    public function rules_BestPracticeSet(): void
    {
        // the best-practice check asks for the visibility check first: visibility, then best practice
        $this->threatRules_setFromJSON( 'visibility', 'spyware', 'ThreatPolicySpyware', array( null ),
            function( $severity, $host, $category ) { return $this->spyware_rules_first_match( $severity, $category ); },
            function() { return $this->spyware_rules_visibility(); } );
        $this->threatRules_setFromJSON( 'bp', 'spyware', 'ThreatPolicySpyware', array( null ),
            function( $severity, $host, $category ) { return $this->spyware_rules_first_match( $severity, $category ); },
            function() { return $this->spyware_rules_best_practice(); } );
    }

    /**
     * best-practice-set of the DNS security categories (and advanced DNS security categories): action,
     * packet-capture and log-level of every category as the BP JSON spyware -> dns / advanced-dns -> bp lists them.
     * Without a DNS license: allow, disable, none.
     */
    public function dns_BestPracticeSet( $hasDNSlicense = true ): void
    {
        $this->dns_setFromJSON( 'bp', $hasDNSlicense );
    }

    private function dns_setFromJSON( string $section, $hasDNSlicense ): void
    {
        $fallbacks = array( 'action' => 'default', 'packet-capture' => 'disable', 'log-level' => 'default' );
        foreach( $this->dns_rules_obj as $rule )
        {
            /** @var DNSPolicy $rule */
            if( !$this->bpFeatureSupported( $rule->advanced ? 'spyware-advanced-dns' : 'spyware-dns' ) )
                continue;

            if( !$hasDNSlicense )
            {
                // no DNS security license: the categories do not apply
                $this->dnsPolicy_setValue( $rule, 'action', 'allow' );
                if( !$rule->advanced )
                    $this->dnsPolicy_setValue( $rule, 'packet-capture', 'disable' );
                $this->dnsPolicy_setValue( $rule, 'log-level', 'none' );
                continue;
            }

            $entries = PH::getBPjsonFile()['spyware'][$rule->advanced ? 'advanced-dns' : 'dns'][$section]['action'] ?? array();
            $this->dnsPolicy_setFromJSONEntries( $rule, $entries, $fallbacks );
        }

        if( $hasDNSlicense )
        {
            if( $section == 'bp' )
                $this->bpSetVerify( $section, 'DNS security', PH::bpCombine( array( $this->spyware_dns_security_best_practice(), $this->spyware_advanced_dns_security_best_practice() ) ) );
            else
                $this->bpSetVerify( $section, 'DNS security', PH::bpCombine( array( $this->spyware_dns_security_visibility(), $this->spyware_advanced_dns_security_visibility() ) ) );
        }
    }

    /**
     * best-practice-set of the DNS lists (botnet-domains -> lists): action and packet-capture of every list as the
     * BP JSON spyware -> lists -> bp lists them; lists the JSON does not name (custom EDLs) are not changed.
     * Without a DNS license: the lists the JSON names get allow, disable - custom EDLs stay.
     */
    public function botnet_BestPracticeSet( $hasDNSlicense = true ): void
    {
        $this->botnet_setFromJSON( 'bp', $hasDNSlicense );
    }

    private function botnet_setFromJSON( string $section, $hasDNSlicense ): void
    {
        if( empty( $this->additional['botnet-domain']['lists'] ) )
            return;

        $entries = PH::getBPjsonFile()['spyware']['lists'][$section]['action'] ?? array();
        $fallbacks = array( 'action' => 'alert', 'packet-capture' => 'disable' );
        // the lists the BP JSON names (the Palo Alto Networks list 'default-paloalto-dns'); all others are custom EDLs
        $listed = function( $rule ) use ( $entries )
        {
            if( empty( $entries ) )
                return $rule->name() == 'default-paloalto-dns';
            foreach( (array)$entries as $candidate )
                if( in_array( $rule->name(), (array)( $candidate['type'] ?? array() ), TRUE ) )
                    return TRUE;
            return FALSE;
        };
        foreach( $this->additional['botnet-domain']['lists'] as $name => $rule )
        {
            /** @var DNSPolicy $rule */
            if( !is_object( $rule ) || $rule->xmlroot === null )
                continue;

            if( !$hasDNSlicense )
            {
                // no DNS security license: only the Palo Alto Networks list does not apply. A custom EDL needs no
                // license - its action (block, sinkhole, alert) is never changed here.
                if( $section == 'bp' )
                {
                    if( $listed( $rule ) )
                    {
                        $this->dnsPolicy_setValue( $rule, 'action', 'allow', TRUE );
                        $this->dnsPolicy_setValue( $rule, 'packet-capture', 'disable' );
                    }
                }
                elseif( $rule->action() == 'allow' )
                    $this->dnsPolicy_setValue( $rule, 'packet-capture', 'disable' );
                continue;
            }
            $this->dnsPolicy_setFromJSONEntries( $rule, $entries, $fallbacks, TRUE );

            // alert-only-set: a list the BP JSON does not name (custom EDL) must not stay on 'allow' either -
            // 'allow' becomes 'alert' (logs, does not block; packet-capture is kept), as before the rework
            if( $section == 'visibility' && !empty( $entries ) && $rule->action() == 'allow' && !$listed( $rule ) )
                $this->dnsPolicy_setValue( $rule, 'action', 'alert', TRUE );
        }

        if( $hasDNSlicense )
            $this->bpSetVerify( $section, 'DNS lists', $section == 'bp' ? $this->spyware_dnslist_best_practice() : $this->spyware_dnslist_visibility() );
    }


    /**
     * alert-only-set of the AS inline cloud analysis (mica-engine-spyware-enabled).
     * The action comes from the BP JSON spyware -> cloud-inline -> visibility (entry with type 'any', as the checks);
     * a negated condition ('!allow') keeps a compliant value, else 'alert'. Nothing listed in the BP JSON or a
     * PAN-OS version without inline ML: no change.
     * Inline analysis still off: it is enabled and a compliant value is kept as well - a blocking action the BP JSON
     * accepts stays as the customer set it (same rule for AS, VP and WF).
     * local-deep-learning of the detectors the BP JSON lists is set as well (from PAN-OS 11.2).
     */
    public function inlineML_AlertOnlySet(): void
    {
        $this->spyware_inlineML_setFromJSON( 'visibility', 'alert' );
    }

    /**
     * alert-only-set of the AS rules: the rules check of the BP JSON spyware -> rule -> visibility must pass
     * afterwards (SecurityProfile2::threatRules_setFromJSON(): first matching rule per severity / category).
     */
    public function rules_AlertOnlySet(): void
    {
        $this->threatRules_setFromJSON( 'visibility', 'spyware', 'ThreatPolicySpyware', array( null ),
            function( $severity, $host, $category ) { return $this->spyware_rules_first_match( $severity, $category ); },
            function() { return $this->spyware_rules_visibility(); } );
    }

    /**
     * alert-only-set of the DNS security categories (and advanced DNS security categories): action, packet-capture
     * and log-level of every category as the BP JSON spyware -> dns / advanced-dns -> visibility lists them
     * (dnsPolicy_setFromJSONEntries(); '!none' -> 'default'). Without a DNS license: allow, disable, none.
     */
    public function dns_AlertOnlySet( $hasDNSlicense = true): void
    {
        $this->dns_setFromJSON( 'visibility', $hasDNSlicense );
    }

    /**
     * alert-only-set of the DNS lists (botnet-domains -> lists): action and packet-capture of every list as the
     * BP JSON spyware -> lists -> visibility lists them ('!allow' -> 'alert'). Lists the JSON does not name
     * (custom EDLs): 'allow' -> 'alert', everything else kept. Without a DNS license: a list on 'allow' gets
     * packet-capture disable, nothing else changes.
     */
    public function botnet_AlertOnlySet( $hasDNSlicense = true): void
    {
        $this->botnet_setFromJSON( 'visibility', $hasDNSlicense );
    }

    public function AlertOnlySet(): void
    {
        $this->inlineML_AlertOnlySet();

        $this->rules_AlertOnlySet();

        $this->dns_AlertOnlySet();

        $this->botnet_AlertOnlySet();
    }

    public function BestPracticeSet(): void
    {
        $this->inlineML_BestPracticeSet();

        $this->rules_BestPracticeSet();

        $this->dns_BestPracticeSet();

        $this->botnet_BestPracticeSet();
    }

}