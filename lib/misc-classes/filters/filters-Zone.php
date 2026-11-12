<?php

// <editor-fold desc=" ***** Zone filters *****" defaultstate="collapsed" >
RQuery::$defaultFilters['zone']['object']['operators']['is.visible'] = array(
    'Function' => function (ZoneRQueryContext $context) {
        return $context->object->isVisible();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['zone']['logprof']['operators']['is.set'] = array(
    'Function' => function (ZoneRQueryContext $context) {
        /** @var Zone $zone */
        $zone = $context->object;
        if( $zone->isTmp() )
            return FALSE;

        if( $zone->logsetting === null || $zone->logsetting == '' )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['zone']['logprof']['operators']['is'] = array(
    'Function' => function (ZoneRQueryContext $context) {

        /** @var Zone $zone */
        $zone = $context->object;
        if( $zone->isTmp() )
            return FALSE;

        if( $zone->logsetting === null )
            return FALSE;

        if( $zone->logsetting == $context->value )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'return true if Log Forwarding Profile is the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  log_to_panorama)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['zone']['zpp']['operators']['is.set'] = array(
    'Function' => function (ZoneRQueryContext $context) {
        /** @var Zone $zone */
        $zone = $context->object;
        if( $zone->isTmp() )
            return FALSE;

        if( $zone->zoneProtectionProfile === null || $zone->zoneProtectionProfile == '' )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['zone']['zpp']['operators']['is'] = array(
    'Function' => function (ZoneRQueryContext $context) {

        /** @var Zone $zone */
        $zone = $context->object;
        if( $zone->isTmp() )
            return FALSE;

        if( $zone->zoneProtectionProfile === null )
            return FALSE;

        if( $zone->zoneProtectionProfile == $context->value )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'return true if Zone Protection Profile is the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  log_to_panorama)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['zone']['userid']['operators']['is.enabled'] = array(
    'Function' => function (ZoneRQueryContext $context) {
        return $context->object->userID;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['zone']['interface']['operators']['is.set'] = array(
    'Function' => function (ZoneRQueryContext $context) {
        $object = $context->object;

        $interfaces = $object->attachedInterfaces->getAll();
        if( count($interfaces) > 0)
            return TRUE;
        else
            return FALSE;
    },
    'arg' => FALSE
);

RQuery::$defaultFilters['zone']['type']['operators']['is'] = array(
    'Function' => function (ZoneRQueryContext $context) {
        $object = $context->object;


        if( !in_array( $context->value, $object->getZoneTypes() ) )
        {
            derr( "Zone type filter not supported: '".$context->value."' | please pick a supported one: '".implode( ", ", $object->getZoneTypes() ), null, FALSE );
        }


        if( $object->type == $context->value )
            return TRUE;

        return null;
    },
    'arg' => TRUE
);









// </editor-fold>