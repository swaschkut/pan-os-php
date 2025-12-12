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

RQuery::$defaultFilters['interface']['name']['operators']['regex'] = array(
    'Function' => function (InterfaceRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        $matching = preg_match($value, $object->name());
        if( $matching === FALSE )
            derr("regular expression error on '{$value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /tcp/)',
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

RQuery::$defaultFilters['interface']['object']['operators']['is.subinterface'] = Array(
    'Function' => function(InterfaceRQueryContext $context )
    {
        $object = $context->object;

        if( $object->type == "layer3" || $object->type == "virtual-wire" || $object->type == "layer2" ) {
            if ($object->isSubInterface())
                return TRUE;
        }

        return FALSE;
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP% ethernet1/1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['interface']['object']['operators']['is.aggregate-group'] = Array(
    'Function' => function(InterfaceRQueryContext $context )
    {
        $object = $context->object;

        return $object->type == "aggregate-group";
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP% ethernet1/1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['interface']['object']['operators']['is.layer3'] = Array(
    'Function' => function(InterfaceRQueryContext $context )
    {
        $object = $context->object;

        return $object->type == "layer3";
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP% ethernet1/1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['interface']['object']['operators']['is.layer2'] = Array(
    'Function' => function(InterfaceRQueryContext $context )
    {
        $object = $context->object;

        return $object->type == "layer2";
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP% ethernet1/1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['interface']['object']['operators']['is.tunnel'] = Array(
    'Function' => function(InterfaceRQueryContext $context )
    {
        $object = $context->object;

        return $object->type == "tunnel";
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP% ethernet1/1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['interface']['object']['operators']['is.virtual-wire'] = Array(
    'Function' => function(InterfaceRQueryContext $context )
    {
        $object = $context->object;

        return $object->type == "virtual-wire";
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP% ethernet1/1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['interface']['object']['operators']['is.vlan'] = Array(
    'Function' => function(InterfaceRQueryContext $context )
    {
        $object = $context->object;

        return $object->type == "vlan";
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP% ethernet1/1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['interface']['type']['operators']['is.ethernet'] = Array(
    'Function' => function(InterfaceRQueryContext $context )
    {
        $object = $context->object;

        return $object->isEthernetType();
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP% ethernet1/1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['interface']['type']['operators']['is.aggregate'] = Array(
    'Function' => function(InterfaceRQueryContext $context )
    {
        $object = $context->object;

        return $object->isAggregateType();
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP% ethernet1/1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['interface']['mgmt-profile']['operators']['is.set'] = Array(
    'Function' => function(InterfaceRQueryContext $context )
    {
        $object = $context->object;

        if( method_exists($object, 'getMgmtProfileName') )
            return $object->getMgmtProfileName() !== null;
        else
            return null;
    },
    'arg' => false
);
// </editor-fold>