<?php

// <editor-fold desc=" ***** Interface filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['interface']['name']['operators']['eq'] = Array(
    'Function' => function(InterfaceRQueryContext $context )
    {
        return $context->object->name() == $context->value;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% ethernet1/1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['interface']['ipv4']['operators']['includes'] = Array(
    'Function' => function(InterfaceRQueryContext $context )
    {
        $ip4_map = new IP4Map();
        $ip4_addresses = $context->object->getLayer3IPv4Addresses();
        foreach( $ip4_addresses as $ip4_address )
        {
            $ip4_map->addMap(IP4Map::mapFromText($ip4_address));
        }

        return $ip4_map->includesOtherMap( IP4Map::mapFromText($context->value) );
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% ethernet1/1)',
        'input' => 'input/panorama-8.0.xml'
    )
);


// </editor-fold>