<?php

// <editor-fold desc=" ***** Region filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['region']['object']['operators']['is.custom'] = array(
    'Function' => function (RegionRQueryContext $context) {
        return !$context->object->isPredefined();
    },
    'arg' => false,
    'help' => 'a region of the configuration (not a predefined region / country code)',
);

RQuery::$defaultFilters['region']['address']['operators']['has'] = array(
    'Function' => function (RegionRQueryContext $context) {
        return in_array( trim( (string)$context->value ), $context->object->members(), TRUE );
    },
    'arg' => true,
    'help' => 'the region has this address (ip-netmask / ip-range, as written)',
    'ci' => array(
        'fString' => '(%PROP% 192.0.2.0/24)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['region']['address']['operators']['is.empty'] = array(
    'Function' => function (RegionRQueryContext $context) {
        return !$context->object->isPredefined() && count( $context->object->members() ) == 0;
    },
    'arg' => false,
    'help' => 'a custom region without addresses',
);

RQuery::$defaultFilters['region']['address.count']['operators']['>,<,=,!'] = array(
    'eval' => 'count( $object->members() ) !operator! !value!',
    'arg' => true,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['region']['geo-location']['operators']['is.set'] = array(
    'Function' => function (RegionRQueryContext $context) {
        return $context->object->latitude() !== null || $context->object->longitude() !== null;
    },
    'arg' => false,
);

// </editor-fold>
