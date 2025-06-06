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


//TODO swaschkut 20220720
// - implement app-tag
// - implement exclude

/*
  <application-filter>
    <entry name="test">
      <disable-override>no</disable-override>
      <tagging>
        <tag>
          <member>[DLP App Exclusion]</member>
        </tag>
      </tagging>
      <exclude>
        <member>google-analytics</member>
      </exclude>
    </entry>
  </application-filter>
 */
/*
        <entry id="225" name="google-analytics" ori_country="USA" ori_language="English">
...
          <tag minver="9.1.0">
            <member>[DLP App Exclusion]</member>
            <member>[Web App]</member>
          </tag>


      <app-tag minver="9.1.0">
        <entry name="Enterprise VoIP">
          <version>8195</version>
          <display>[Enterprise VoIP]</display>
          <comment>This tag identifies the most common VoIP applications used in an enterprise environment. This will also include protocols like SIP, RTP, etc. for which we do not have App-IDs yet.</comment>
          <description>This tag identifies the most common VoIP applications used in an enterprise environment. This will also include protocols like SIP, RTP, etc. for which we do not have App-IDs yet.</description>
        </entry>
 */
class AppFilter extends App
{
    use XmlConvertible;

    public $category;
    public $subcategory;
    public $technology;
    public $tagging;
    public $risk;

    public $exclude;

    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getAppFilterStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }

    
    public function load_from_domxml( $appx )
    {

        //TODO: check if multiple selections are needed
        //only first FILTER is checked
        //what about second/third??
        //- if use array how to get the information via the app filter
        $this->app_filter_details = array();

        $array = array( 'category', 'subcategory', 'technology', 'tagging', 'risk' );

        foreach( $array as $entry )
        {
            $tmp = DH::findFirstElement($entry, $appx);
            if( $entry == "tagging" && $tmp !== FALSE )
                $tmp = DH::findFirstElement("tag", $tmp);

            if( $tmp !== FALSE )
            {
                $this->app_filter_details[$entry] = array();
                foreach( $tmp->childNodes as $tmp1 )
                {
                    if( $tmp1->nodeType != XML_ELEMENT_NODE ) continue;

                    if( $entry == "tagging" )
                    {
                        $text = str_replace( "[", "", $tmp1->textContent);
                        $text = str_replace( "]", "", $text);
                        $this->apptag[$text] = $text;
                    }
                    else
                    {
                        $text = $tmp1->textContent;
                        $this->$entry = $tmp1->textContent;
                    }


                    $this->app_filter_details[$entry][$text] = $text;
                }
            }
        }


        #$arry = array( 'evasive', 'excessive-bandwidth-use', 'used-by-malware', 'transfers-files', 'has-known-vulnerabilities', 'tunnels-other-apps', 'prone-to-misuse', 'pervasive'  );

        $tmp = DH::findFirstElement('evasive', $appx);
        if( $tmp !== FALSE )
        {
            if( $tmp->textContent == 'yes' )
                $this->_characteristics['evasive'] = TRUE;
        }
        $tmp = DH::findFirstElement('excessive-bandwidth-use', $appx);
        if( $tmp !== FALSE )
        {
            if( $tmp->textContent == 'yes' )
                $this->_characteristics['excessive-bandwidth'] = TRUE;
        }
        $tmp = DH::findFirstElement('used-by-malware', $appx);
        if( $tmp !== FALSE )
        {
            if( $tmp->textContent == 'yes' )
                $this->_characteristics['used-by-malware'] = TRUE;
        }
        $tmp = DH::findFirstElement('transfers-files', $appx);
        if( $tmp !== FALSE )
        {
            if( $tmp->textContent == 'yes' )
                $this->_characteristics['transfers-files'] = TRUE;
        }
        $tmp = DH::findFirstElement('has-known-vulnerabilities', $appx);
        if( $tmp !== FALSE )
        {
            if( $tmp->textContent == 'yes' )
                $this->_characteristics['vulnerabilities'] = TRUE;
        }
        $tmp = DH::findFirstElement('tunnels-other-apps', $appx);
        if( $tmp !== FALSE )
        {
            if( $tmp->textContent == 'yes' )
                $this->_characteristics['tunnels-other-apps'] = TRUE;
        }
        $tmp = DH::findFirstElement('prone-to-misuse', $appx);
        if( $tmp !== FALSE )
        {
            if( $tmp->textContent == 'yes' )
                $this->_characteristics['prone-to-misuse'] = TRUE;
        }

        $tmp = DH::findFirstElement('pervasive', $appx);
        if( $tmp !== FALSE )
        {
            if( $tmp->textContent == 'yes' )
                $this->_characteristics['widely-used'] = TRUE;
        }

        //////////
        $tmp = DH::findFirstElement('exclude', $appx);
        if( $tmp !== FALSE )
        {
            foreach( $tmp->childNodes as $tmp1 )
            {
                if ($tmp1->nodeType != XML_ELEMENT_NODE)
                    continue;

                $this->exclude[$tmp1->textContent] = $tmp1->textContent;
            }
        }
    }
}