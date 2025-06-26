<?php
RQuery::$defaultFilters['gpgateway-tunnel']['name']['operators']['eq'] = array(
    'Function' => function (GPGatewaytunnelRQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
);