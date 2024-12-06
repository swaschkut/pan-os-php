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

class IP6Map extends IPMap
{

    public function substract(IP6Map $substractedMap)
    {
        $affectedRows = 0;

        foreach( $substractedMap->_map as &$subMap )
        {
            $affectedRows += $this->substractSingleIP6Entry($subMap);

            if( count($this->_map) == 0 )
                break;
        }

        return $affectedRows;
    }

    public function intersection(IP6Map $otherMap)
    {
        $invertedMap = IP6Map::mapFromText('::/0');
        $invertedMap->substract($otherMap);

        $result = clone $otherMap;
        $result->substract($invertedMap);

        return $result;
    }

    public function substractSingleIP6Entry(&$subEntry)
    {
        $affectedRows = 0;

        $arrayCopy = $this->_map;
        $this->_map = array();

        foreach( $arrayCopy as &$entry )
        {
            if( $subEntry['start'] > $entry['end'] )
            {
                $this->_map[] = &$entry;
                continue;
            }
            elseif( $subEntry['end'] < $entry['start'] )
            {
                $this->_map[] = &$entry;
                continue;
            }
            else if( $subEntry['start'] <= $entry['start'] && $subEntry['end'] >= $entry['end'] )
            {

            }
            elseif( $subEntry['start'] > $entry['start'] )
            {
                if( $subEntry['end'] >= $entry['end'] )
                {
                    $entry['end'] = $subEntry['start'] - 1;
                    $this->_map[] = &$entry;
                }
                else
                {
                    $oldEnd = $entry['end'];
                    $entry['end'] = $subEntry['start'] - 1;
                    $this->_map[] = &$entry;
                    $this->_map[] = array('start' => $subEntry['end'] + 1, 'end' => $oldEnd);
                }
            }
            else
            {
                $entry['start'] = $subEntry['end'] + 1;
                $this->_map[] = &$entry;
            }
            $affectedRows++;
        }

        return $affectedRows;
    }
}
