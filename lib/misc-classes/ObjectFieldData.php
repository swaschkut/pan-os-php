<?php
/**
 * ISC License
 *
 * Copyright (c) 2026, Sven Waschkut - pan-os-php@waschkut.net
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
 * The fields of an object for a window (shadow-json of 'display': 'fields') - values and what they can be, from the
 * same classes the field actions use (EDL, Schedule, LogProfile, Region, SecurityProfileGroup, SecurityProfileFields): nothing of it is kept twice
 * in the config viewer.
 */
class ObjectFieldData
{
    /** null: no field data for this class */
    static public function of( $object ): ?array
    {
        if( $object instanceof EDL )
        {
            $n = $object->typeNode();
            $rec = array( 'interval' => '', 'at' => '', 'day' => '' );
            $r = $n === null ? FALSE : DH::findFirstElement( 'recurring', $n );
            $i = $r === FALSE ? FALSE : DH::firstChildElement( $r );
            if( $i !== FALSE )
            {
                $rec['interval'] = $i->nodeName;
                foreach( array( 'at' => 'at', 'day-of-week' => 'day', 'day-of-month' => 'day' ) as $tag => $k )
                {
                    $e = DH::findFirstElement( $tag, $i );
                    if( $e !== FALSE )
                        $rec[$k] = $e->textContent;
                }
            }
            return array( 'kind' => 'edl', 'type' => $n === null ? '' : $n->nodeName, 'types' => EDL::EDL_TYPES,
                'source' => $object->typeValue( 'url' ), 'recurring' => $rec, 'intervals' => EDL::EDL_RECURRING, 'weekdays' => EDL::EDL_WEEKDAYS,
                'description' => $object->edlDescription(), 'certificate-profile' => $object->typeValue( 'certificate-profile' ),
                'exceptions' => $object->exceptions(), 'expand-domain' => $object->typeValue( 'expand-domain' ) === 'yes' );
        }
        if( $object instanceof Schedule )
        {
            $ranges = $object->ranges();
            return array( 'kind' => 'schedule', 'type' => count( $ranges ) ? $ranges[0]['type'] : '', 'types' => array( 'daily', 'weekly', 'non-recurring' ),
                'days' => Schedule::SCHEDULE_DAYS, 'ranges' => $ranges );
        }
        if( $object instanceof LogProfile )
        {
            $e = $object->xmlroot === null ? FALSE : DH::findFirstElement( 'enhanced-application-logging', $object->xmlroot );
            return array( 'kind' => 'log-profile', 'description' => (string)$object->description(),
                'enhanced-application-logging' => $e !== FALSE && $e->textContent === 'yes',
                'logTypes' => array_values( array_unique( array_merge( $object->type_available ?? array(), array( 'gtp', 'sctp' ) ) ) ),
                'sendKinds' => array_keys( LogProfile::MATCH_SEND ), 'matchList' => $object->matchList() );
        }
        if( $object instanceof App && ( $d = ApplicationFields::describe( $object ) ) !== null )
            return array( 'kind' => 'application' ) + $d;
        if( $object instanceof SecurityProfileGroup && $object->owner !== null )
        {
            // the profile slots: the type the actions take (securityProfile-Set:<type>,<name>), the candidates kind
            // of the viewer (ObjectCandidates profile-<type>, null: none), the profile set ('' = none)
            $types = array( 'wildfire-analysis' => 'wildfire', 'virus-and-wildfire-analysis' => 'virus-and-wildfire' );
            $slots = array();
            foreach( array_keys( $object->slotStores() ) as $slot )
            {
                $t = $types[$slot] ?? $slot;
                $slots[] = array( 'slot' => $slot, 'type' => $t, 'pick' => isset( SecurityRule::SECPROF_TYPES[$t] ) ? 'profile-' . $t : null,
                    'value' => $object->slotProfileName( $slot ) );
            }
            return array( 'kind' => 'securityprofilegroup', 'slots' => $slots );
        }
        if( $object instanceof Region )
            return array( 'kind' => 'region', 'predefined' => $object->isPredefined(), 'country' => $object->description(),
                'latitude' => $object->latitude(), 'longitude' => $object->longitude(), 'addresses' => $object->members() );
        if( isset( $object->secprof_type ) && is_object( $object ) && property_exists( $object, 'xmlroot' ) )
        {
            $d = SecurityProfileFields::describe( $object );
            if( $d !== null )
                return array( 'kind' => 'securityprofile' ) + $d;
        }
        return null;
    }
}
