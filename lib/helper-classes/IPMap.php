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

class IPMap
{
    protected $_map = array();

    public $unresolved = array();

    public function getMapArray()
    {
        return $this->_map;
    }

    public function &getMapArrayPointer()
    {
        return $this->_map;
    }

    /**
     * @param $text
     * @return IP4Map|IP6Map
     */
    static public function mapFromText($text)
    {
        if( get_called_class() == "IP4Map" )
            $map = new IP4Map();
        elseif( get_called_class() == "IP6Map" )
            $map = new IP6Map();

        $map->_map[] = cidr::stringToStartEnd($text);
        return $map;
    }

    public function equals(IP4Map|IP6Map $other)
    {
        $ref1 = &$this->_map;
        $ref2 = &$other->_map;

        if( count($ref1) != count($ref2) )
            return FALSE;

        $key1 = array_keys($ref1);
        $key2 = array_keys($ref2);


        for( $i = 0; $i < count($key1); $i++ )
        {
            if( $ref1[$key1[$i]]['start'] != $ref2[$key2[$i]]['start'] )
                return FALSE;
            if( $ref1[$key1[$i]]['end'] != $ref2[$key2[$i]]['end'] )
                return FALSE;
        }

        return TRUE;
    }



    public function &mapDiff(IP4Map|IP6Map $other)
    {
        $thisCopy = clone $this;
        $otherCopy = clone $other;

        $diff = array();

        $thisCopy->substract($otherCopy);
        $diff['plus'] = &$thisCopy->_map;

        $otherCopy->substract($this);
        $diff['minus'] = &$otherCopy->_map;

        return $diff;
    }

    /**
     * @param IP4Map $other
     * @return int 1 if full match, 0 if not match, 2 if partial match
     */
    public function includesOtherMap(IP4Map|IP6Map $other)
    {
        if( $other->count() == 0 )
            return 0;

        if( $this->count() == 0 )
            return 0;

        $otherCopy = clone $other;

        $affectedRowsOther = $otherCopy->substract($this);

        if( $otherCopy->count() == 0 )
            return 1;

        if( $affectedRowsOther == 0 )
            return 0;

        return 2;
    }

    /**
     * @param IP4Map $other
     * @return int 1 if full match, 0 if not match, 2 if partial match
     */
    public function includedInOtherMap(IP4Map|IP6Map $other)
    {
        if( $other->count() == 0 )
            return 0;

        if( $this->count() == 0 )
            return 0;

        $thisCopy = clone $this;

        $affectedRowsThis = $thisCopy->substract($other);

        if( $thisCopy->count() == 0 )
            return 1;

        if( $affectedRowsThis == 0 )
            return 0;

        return 2;
    }

    /**
     * @param string $separator
     * @return string
     */
    public function &dumpToString($separator = ',')
    {

        $ret = array();

        foreach( $this->_map as &$entry )
        {
            if( strpos( $entry['network'], "-" ) !== false )
                $ex = explode('-', $entry['network']);
            else
                $ex = explode('/', $entry['network']);

            if( filter_var($ex[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE )
            {
                if( $entry['start'] == $entry['end'] )
                    $ret[] = long2ip($entry['start']);
                else
                    $ret[] = long2ip($entry['start']) . '-' . long2ip($entry['end']);
            }
            else
            {
                if( $entry['start'] == $entry['end'] )
                    $ret[] = cidr::inet_itop($entry['start']);
                else
                    $ret[] = cidr::inet_itop($entry['start']) . '-' . cidr::inet_itop($entry['end']);
            }
        }

        $ret = PH::list_to_string($ret, $separator);

        return $ret;
    }


    public function addMap(IPMap $other, $skipRecalculation = FALSE)
    {
        foreach( $other->_map as $mapEntry )
            $this->_map[] = $mapEntry;

        foreach( $other->unresolved as $oName => $object )
        {
            $this->unresolved[$oName] = $object;
        }

        if( !$skipRecalculation )
        {
            $this->sortAndRecalculate();
        }
    }

    /**
     * Usually called after addMap(..., false) for speed enhancements
     */
    public function sortAndRecalculate()
    {
        $newMapping = sortArrayByStartValue($this->_map);

        //PH::print_stdout(  "\nafter sorting" );
        //foreach($this->_map as $map)
        //    PH::print_stdout(  long2ip($map['start']).'-'.long2ip($map['end']) );

        $mapKeys = array_keys($newMapping);
        $mapCount = count($newMapping);
        for( $i = 0; $i < $mapCount; $i++ )
        {
            $current = &$newMapping[$mapKeys[$i]];
            //PH::print_stdout(  "\nhandling row ".long2ip($current['start']).'-'.long2ip($current['end']) );
            for( $j = $i + 1; $j < $mapCount; $j++ )
            {
                //$i++;
                $compare = &$newMapping[$mapKeys[$j]];

                //PH::print_stdout(  "   vs ".long2ip($compare['start']).'-'.long2ip($compare['end']) );

                if( $compare['start'] > $current['end'] + 1 )
                    break;

                if( $current['end'] < $compare['end'] )
                    $current['end'] = $compare['end'];

                //PH::print_stdout(  "     upgraded to ".long2ip($current['start']).'-'.long2ip($current['end']) );
                unset($newMapping[$mapKeys[$j]]);

                $i++;
            }
        }

        $this->_map = &$newMapping;
    }

    public function count()
    {
        return count($this->_map);
    }

    public function getFirstMapEntry()
    {
        if( count($this->_map) == 0 )
            return null;

        return reset($this->_map);
    }

}
