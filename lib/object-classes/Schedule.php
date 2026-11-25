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

class Schedule
{
    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;

    /** @var ScheduleStore|null */
    public $owner = null;

    /** set by the mergers (type=object-merger) */
    public $ancestor;
    public $childancestor;

    protected $recurring_type = null;
    //possible recurring setting daily/weekly/non-recurring

    //daily/non-recurring could have multiple <member> XML tags
    //weekly could have different day entried
    protected $recurring_array = array();

//Todo:
//newSchedule => ScheduleStore
//- set schedule type
//- add member

    /**
     * @param string $name
     * @param ScheduleStore|null $owner
     * @param bool $fromXmlTemplate
     */
    public function __construct($name, $owner, $fromXmlTemplate = FALSE)
    {
        $this->name = $name;


        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElementOrDie('entry', $doc);

            $rootDoc = $owner->xmlroot->ownerDocument;

            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot);

            $this->setName($name);
        }

        $this->owner = $owner;
    }

    /**
     * @param string $newName
     * @return bool
     */
    public function setName($newName)
    {
        $ret = $this->setRefName($newName);

        if( $this->xmlroot === null )
            return $ret;

        $this->xmlroot->setAttribute('name', $newName);

        return $ret;
    }

    /**
     * @param string $newName
     */
    public function API_setName($newName)
    {
        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $this->setName($newName);

        if( $c->isAPI() )
            $c->sendRenameRequest($xpath, $newName);
    }


    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getScheduleStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }


    public function isTmp()
    {
        if( $this->xmlroot === null )
            return TRUE;
        return FALSE;
    }


    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("schedule name not found\n", $xml);


        if( strlen($this->name) < 1 )
            derr("schedule name '" . $this->name . "' is not valid.", $xml);

        $tmp = DH::findFirstElement('schedule-type', $xml);

        if( $tmp !== false )
        {
            foreach( $tmp->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE )
                    continue;

                if( $node->nodeName == "recurring" )
                {
                    foreach( $node->childNodes as $node2 )
                    {
                        if( $node2->nodeType != XML_ELEMENT_NODE )
                            continue;


                        if( $node2->nodeName == "daily" )
                        {
                            $this->recurring_type = "daily";

                            foreach( $node2->childNodes as $childNode )
                            {
                                if( $childNode->nodeType != XML_ELEMENT_NODE )
                                    continue;

                                $startEnd = explode("-", $childNode->textContent);
                                $tmp = array();
                                $tmp['start'] = $startEnd[0];
                                $tmp['end'] = $startEnd[1];

                                $this->recurring_array['daily'][] = $tmp;
                            }
                        }
                        elseif( $node2->nodeName == "weekly" )
                        {
                            $this->recurring_type = "weekly";

                            foreach( $node2->childNodes as $childNode )
                            {
                                if( $childNode->nodeType != XML_ELEMENT_NODE )
                                    continue;

                                foreach( $childNode->childNodes as $member )
                                {
                                    if( $member->nodeType != XML_ELEMENT_NODE )
                                        continue;

                                    $startEnd = explode("-", $member->textContent);
                                    $tmp = array();
                                    $tmp['start'] = $startEnd[0];
                                    $tmp['end'] = $startEnd[1];

                                    $this->recurring_array['weekly'][$childNode->nodeName][] = $tmp;
                                }

                            }
                        }
                        else
                            mwarning("recurringType: " . $node2->nodeName . " not supported");
                    }
                }
                elseif( $node->nodeName == "non-recurring" )
                {
                    $this->recurring_type = "non-recurring";

                    foreach( $node->childNodes as $childNode )
                    {
                        if( $childNode->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $startEnd = explode("-", $childNode->textContent);
                        $tmp = array();
                        $tmp['start'] = $startEnd[0];
                        $tmp['end'] = $startEnd[1];

                        $this->recurring_array['non-recurring'][] = $tmp;
                    }
                }
                else
                {
                    mwarning("recurringType: " . $node->nodeName . " not supported");
                }
            }
        }
    }

    /**
     * @param string $newValue
     * @param bool $rewriteXml
     * @return bool
     * @throws Exception
     */
    public function setRecurringDaily($newValue, $rewriteXml = TRUE)
    {
        if( !is_string($newValue) )
            derr('value can be text only');

        //validation needed
        #if( $newValue == $this->value )
        #    return FALSE;

        $startEnd = explode("-", $newValue);
        $tmp = array();
        $tmp['start'] = $startEnd[0];
        $tmp['end'] = $startEnd[1];

        $this->recurring_array['daily'][] = $tmp;

        if( $rewriteXml )
        {
            $valueRoot = DH::findFirstElementOrCreate("schedule-type", $this->xmlroot);
            $valueRoot = DH::findFirstElementOrCreate("recurring", $valueRoot);
            $valueRoot = DH::findFirstElementOrCreate("daily", $valueRoot);

            DH::clearDomNodeChilds($valueRoot);

            foreach( $this->recurring_array['daily'] as $entry )
            {
                DH::createElement($valueRoot, 'member', $entry['start']."-".$entry['end']);
            }
        }

        return TRUE;
    }

    /**
     * @param string $newValue
     * @param bool $rewriteXml
     * @return bool
     * @throws Exception
     */
    public function setRecurringWeekly( $day, $newValue, $rewriteXml = TRUE)
    {
        if( !is_string($newValue) )
            derr('value can be text only');

        //validation needed
        #if( $newValue == $this->value )
        #    return FALSE;

        $startEnd = explode("-", $newValue);
        $tmp = array();
        $tmp['start'] = $startEnd[0];
        $tmp['end'] = $startEnd[1];

        $this->recurring_array['weekly'][$day][] = $tmp;

        if( $rewriteXml )
        {
            $valueRoot = DH::findFirstElementOrCreate("schedule-type", $this->xmlroot);
            $valueRoot = DH::findFirstElementOrCreate("recurring", $valueRoot);
            $valueRoot = DH::findFirstElementOrCreate("weekly", $valueRoot);
            $valueRoot = DH::findFirstElementOrCreate($day, $valueRoot);

            DH::clearDomNodeChilds($valueRoot);

            foreach( $this->recurring_array['weekly'][$day] as $entry )
            {
                DH::createElement($valueRoot, 'member', $entry['start']."-".$entry['end']);
            }
        }

        return TRUE;
    }


    /**
     * @param string $newValue
     * @param bool $rewriteXml
     * @return bool
     * @throws Exception
     */
    public function setNonRecurring($newValue, $rewriteXml = TRUE)
    {
        if( !is_string($newValue) )
            derr('value can be text only');

        //validation needed
        #if( $newValue == $this->value )
        #    return FALSE;

        $startEnd = explode("-", $newValue);
        $tmp = array();
        $tmp['start'] = $startEnd[0];
        $tmp['end'] = $startEnd[1];

        $this->recurring_array['non-recurring'][] = $tmp;

        if( $rewriteXml )
        {
            $valueRoot = DH::findFirstElementOrCreate("schedule-type", $this->xmlroot);
            $valueRoot = DH::findFirstElementOrCreate("non-recurring", $valueRoot);

            DH::clearDomNodeChilds($valueRoot);
            
            foreach( $this->recurring_array['non-recurring'] as $entry )
            {
                DH::createElement($valueRoot, 'member', $entry['start']."-".$entry['end']);
            }
        }

        return TRUE;
    }


    static public $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

    public function isSchedule()
    {
        return TRUE;
    }

    // ------------------------------------------------------------------------------------------------- edit (offline)

    const SCHEDULE_DAYS = array( 'sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday' );

    /**
     * a time range of the schedule type, normalised: daily / weekly 'HH:MM-HH:MM' (also 'HHMM-HHMM'),
     * non-recurring 'YYYY/MM/DD@HH:MM-YYYY/MM/DD@HH:MM' (also 'YYYYMMDD@HHMM-YYYYMMDD@HHMM'); the aliases
     * $$colon$$ / $$forwardslash$$ are replaced before
     */
    static public function normaliseRange( string $type, string $range ): string
    {
        $range = trim( PH::textAliases( $range ) );
        if( $type === 'non-recurring' )
        {
            if( preg_match( '#^(\d{4})/?(\d{2})/?(\d{2})@(\d{2}):?(\d{2})-(\d{4})/?(\d{2})/?(\d{2})@(\d{2}):?(\d{2})$#', $range, $m ) )
            {
                $a = sprintf( '%s/%s/%s@%s:%s', $m[1], $m[2], $m[3], $m[4], $m[5] );
                $b = sprintf( '%s/%s/%s@%s:%s', $m[6], $m[7], $m[8], $m[9], $m[10] );
                $ta = DateTime::createFromFormat( '!Y/m/d@H:i', $a );
                $tb = DateTime::createFromFormat( '!Y/m/d@H:i', $b );
                if( $ta !== FALSE && $tb !== FALSE && $ta->format( 'Y/m/d@H:i' ) === $a && $tb->format( 'Y/m/d@H:i' ) === $b )
                {
                    if( $ta >= $tb )
                        throw new Exception( "range '" . $range . "': the start must be before the end" );
                    return $a . '-' . $b;
                }
            }
            throw new Exception( "range '" . $range . "': YYYY/MM/DD@HH:MM-YYYY/MM/DD@HH:MM (or YYYYMMDD@HHMM-YYYYMMDD@HHMM)" );
        }
        if( preg_match( '/^([01][0-9]|2[0-3]):?([0-5][0-9])-([01][0-9]|2[0-3]):?([0-5][0-9])$/', $range, $m ) )
        {
            if( $m[1] . $m[2] === $m[3] . $m[4] )
                throw new Exception( "range '" . $range . "': start and end are the same" );
            return $m[1] . ':' . $m[2] . '-' . $m[3] . ':' . $m[4];
        }
        throw new Exception( "range '" . $range . "': HH:MM-HH:MM (or HHMM-HHMM)" );
    }

    /** every range of the schedule: list of 'type', 'day' (weekly), 'range' */
    public function ranges(): array
    {
        $out = array();
        foreach( $this->recurring_array['daily'] ?? array() as $e )
            $out[] = array( 'type' => 'daily', 'day' => null, 'range' => $e['start'] . '-' . $e['end'] );
        foreach( $this->recurring_array['weekly'] ?? array() as $day => $list )
            foreach( $list as $e )
                $out[] = array( 'type' => 'weekly', 'day' => $day, 'range' => $e['start'] . '-' . $e['end'] );
        foreach( $this->recurring_array['non-recurring'] ?? array() as $e )
            $out[] = array( 'type' => 'non-recurring', 'day' => null, 'range' => $e['start'] . '-' . $e['end'] );
        return $out;
    }

    private function checkEditable(): void
    {
        if( $this->isTmp() )
            throw new Exception( 'a tmp object can not be changed' );
    }

    static private function checkType( string $type, string $day ): string
    {
        if( !in_array( $type, array( 'daily', 'weekly', 'non-recurring' ), TRUE ) )
            throw new Exception( "type '" . $type . "': daily, weekly or non-recurring" );
        $day = strtolower( $day );
        if( $type === 'weekly' && !in_array( $day, self::SCHEDULE_DAYS, TRUE ) )
            throw new Exception( "day '" . $day . "': " . implode( ', ', self::SCHEDULE_DAYS ) );
        return $type === 'weekly' ? $day : '';
    }

    /** the XML from the list of ranges (one type), then read again */
    private function writeRanges( string $type, array $ranges ): void
    {
        $st = DH::findFirstElementOrCreate( 'schedule-type', $this->xmlroot );
        DH::clearDomNodeChilds( $st );
        if( $type === 'non-recurring' )
        {
            $n = DH::createElement( $st, 'non-recurring' );
            foreach( $ranges as $r )
                DH::createElement( $n, 'member', $r['range'] );
        }
        else
        {
            $n = DH::createElement( DH::createElement( $st, 'recurring' ), $type );
            if( $type === 'daily' )
                foreach( $ranges as $r )
                    DH::createElement( $n, 'member', $r['range'] );
            else
                foreach( self::SCHEDULE_DAYS as $day )
                {
                    $list = array_values( array_filter( $ranges, function( $r ) use ( $day ) { return $r['day'] === $day; } ) );
                    if( count( $list ) == 0 )
                        continue;
                    $d = DH::createElement( $n, $day );
                    foreach( $list as $r )
                        DH::createElement( $d, 'member', $r['range'] );
                }
        }
        $this->recurring_type = null;
        $this->recurring_array = array();
        $this->load_from_domxml( $this->xmlroot );
    }

    /** name-rename: the object and every user that names it (references) */
    public function editRename( string $newName ): int
    {
        if( $this->isTmp() )
            throw new Exception( 'a tmp object can not be changed' );
        if( !preg_match( '/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,30}$/', $newName ) )
            throw new Exception( "name '" . $newName . "': 1-31 characters, letters, digits, blank, . _ -" );
        if( $newName === $this->name() )
            throw new Exception( 'the name is the same' );
        if( $this->owner->find( $newName, null, FALSE ) !== null )
            throw new Exception( "'" . $newName . "' exists already" );
        $this->setName( $newName );
        return count( $this->getReferences() );
    }

    /** a range more (same type as the schedule has) */
    public function editRangeAdd( string $type, string $day, string $range ): string
    {
        $this->checkEditable();
        $day = self::checkType( $type, $day );
        $range = self::normaliseRange( $type, $range );
        $current = $this->recurring_type;
        if( $current !== null && $current !== $type )
            throw new Exception( 'the schedule is ' . $current . ' - type-set to change the type' );
        $list = $this->ranges();
        foreach( $list as $r )
            if( $r['day'] === ( $day === '' ? null : $day ) && $r['range'] === $range )
                throw new Exception( "'" . $range . "' is set already" );
        $list[] = array( 'type' => $type, 'day' => $day === '' ? null : $day, 'range' => $range );
        $this->writeRanges( $type, $list );
        return $range;
    }

    /** a range less - the last one stays (PAN-OS needs one) */
    public function editRangeRemove( string $type, string $day, string $range ): string
    {
        $this->checkEditable();
        $day = self::checkType( $type, $day );
        $range = self::normaliseRange( $type, $range );
        $list = $this->ranges();
        $kept = array_values( array_filter( $list, function( $r ) use ( $type, $day, $range ) {
            return !( $r['type'] === $type && $r['day'] === ( $day === '' ? null : $day ) && $r['range'] === $range );
        } ) );
        if( count( $kept ) == count( $list ) )
            throw new Exception( "'" . $range . "' is not set" );
        if( count( $kept ) == 0 )
            throw new Exception( 'the last range of a schedule can not be removed' );
        $this->writeRanges( $type, $kept );
        return $range;
    }

    /** type-set: the schedule type with one range (every other range goes) */
    public function editTypeSet( string $type, string $day, string $range ): string
    {
        $this->checkEditable();
        $day = self::checkType( $type, $day );
        $range = self::normaliseRange( $type, $range );
        $this->writeRanges( $type, array( array( 'type' => $type, 'day' => $day === '' ? null : $day, 'range' => $range ) ) );
        return $range;
    }


    public function getRecurring()
    {
        return $this->recurring_array;
    }

    public function getRecurringType()
    {
        return $this->recurring_type;
    }

    public function isExpired( $futuredate = 0, $operator = "<" )
    {
        if( $this->recurring_type != 'non-recurring' )
            return false;

        $d_actual = time();
        $char_counter_array = count_chars($futuredate,1);
        if( strpos( $futuredate, "/" ) !== FALSE )
        {
            $d2 = DateTime::createFromFormat('Y/m/d', $futuredate);
            $d = $d2->getTimestamp();
        }
        elseif(  isset($char_counter_array['-']) and $char_counter_array['-'] == 2)
        {
            $d2 = DateTime::createFromFormat('d-m-Y', $futuredate);
            $d = $d2->getTimestamp();
        }

        else
        {
            $d = $d_actual;
            if( $futuredate !== 0 )
            {
                if( !is_numeric($futuredate) )
                    derr("schedule filter: the value has to be a number of days or a date ( YYYY/MM/DD or DD-MM-YYYY )", null, FALSE);
                $d = $d_actual + ($futuredate)*24*3600;
            }
        }

        // 'object expire.in.days 5' / 'object expired.at.date …' come without a math operator: before the date
        if( !isset(RQuery::$mathOps[$operator]) )
            $operator = '<';

        $expired = false;
        foreach( $this->recurring_array['non-recurring'] as $member )
        {
            $d2 = DateTime::createFromFormat('Y/m/d@H:i', $member['end']);
            $timestamp = $d2->getTimestamp();

            if( $operator === "<" && $futuredate !== 0 && $futuredate > 0 )
                $matched = RQuery::mathCompare( $timestamp, $operator, $d ) && $timestamp > $d_actual;
            else
                $matched = RQuery::mathCompare( $timestamp, $operator, $d );

            #print "timestamp_schedule end: ".$timestamp." |operator: ".$operator."| calculated: ".$d."\n";

            if( $matched )
                $expired = true;
            else
                $expired = false;
        }

        return $expired;
    }

    function validateDate($date, $format = 'Y-m-d@H:i')
    {
        $d = DateTime::createFromFormat($format, $date);
        return $d && $d->format($format) == $date;
    }

    /**
     * @param $otherObject Schedule
     * @return bool
     */
    public function equals($otherObject)
    {
        if( !$otherObject->isSchedule() )
            return FALSE;

        if( $otherObject->name != $this->name )
            return FALSE;

        return $this->sameValue($otherObject);
    }

    public function sameValue(Schedule $otherObject)
    {
        if( $this->isTmp() && !$otherObject->isTmp() )
            return FALSE;

        if( $otherObject->isTmp() && !$this->isTmp() )
            return FALSE;


        return TRUE;
    }
}

