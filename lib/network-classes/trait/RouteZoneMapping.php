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
 * IP -> zone records of VirtualRouter / LogicalRouter::getIPtoZoneRouteMapping(), exact for IPv6.
 *
 * Record: array( 'network' => text, 'start' => int (IPv4) | decimal string (IPv6), 'end' => ..., 'zone', 'origin', 'priority' )
 * IPv6 values are 128 bit integers as decimal strings - '$end - $start' as array key was a float, truncated to int.
 */
trait RouteZoneMapping
{
    /**
     * split records into IPv4 / IPv6 and sort each list narrowest first (end - start), then by start - the order of the
     * former ksort() on (end - start) / start for IPv4; records with the same size and start keep their order
     * @return array( 'ipv4' => records, 'ipv6' => records )
     */
    protected static function sortZoneRecords( array $records )
    {
        $out = array( 'ipv4' => array(), 'ipv6' => array() );
        foreach( $records as $r )
            $out[ self::isIPv6Record($r) ? 'ipv6' : 'ipv4' ][] = $r;
        foreach( $out as $fam => $list )
        {
            // usort is stable since PHP 8.0
            usort( $list, function( $a, $b ) {
                $c = cidr::ipCmp( cidr::ipSub($a['end'], $a['start']), cidr::ipSub($b['end'], $b['start']) );
                return $c != 0 ? $c : cidr::ipCmp( $a['start'], $b['start'] );
            } );
            $out[$fam] = $list;
        }
        return $out;
    }

    protected static function isIPv6Record( array $r )
    {
        return isset($r['network']) && strpos( $r['network'], ':' ) !== FALSE;
    }

    /** 'start-end' text of a range */
    protected static function zoneRangeText( $start, $end, $isIPv6 )
    {
        return $isIPv6 ? cidr::inet_itop($start) . '-' . cidr::inet_itop($end) : long2ip($start) . '-' . long2ip($end);
    }

    /**
     * records of a next-vr route: its destination intersected with the records of the next router of the same address
     * family, narrowest first (the part of the destination already matched by a narrower record is not matched again)
     * @param string $destination route destination (IPv4 or IPv6 network)
     * @param array $nextRouterMapping result of getIPtoZoneRouteMapping() of the next router
     * @return array records
     */
    protected static function nextVrZoneRecords( $destination, array $nextRouterMapping )
    {
        $isIPv6 = strpos( $destination, ':' ) !== FALSE;
        $remains = $isIPv6 ? IP6Map::mapFromText( $destination ) : IP4Map::mapFromText( $destination );
        $records = array();
        $other = $nextRouterMapping[$isIPv6 ? 'ipv6' : 'ipv4'] ?? array();
        foreach( $other as $rec )
        {
            $recText = self::zoneRangeText( $rec['start'], $rec['end'], $isIPv6 );
            $intersection = $remains->intersection( $isIPv6 ? IP6Map::mapFromText($recText) : IP4Map::mapFromText($recText) );
            if( $isIPv6 )
                $remains->substractSingleIP6Entry( $rec );
            else
                $remains->substractSingleIP4Entry( $rec );
            foreach( $intersection->getMapArray() as $e )
                $records[] = array( 'network' => self::zoneRangeText( $e['start'], $e['end'], $isIPv6 ),
                    'start' => $e['start'], 'end' => $e['end'], 'zone' => $rec['zone'], 'origin' => 'static', 'priority' => 2 );
            if( $remains->count() == 0 )
                break;
        }
        return $records;
    }
}
