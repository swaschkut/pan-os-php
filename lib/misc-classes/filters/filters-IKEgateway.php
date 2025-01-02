<?php
RQuery::$defaultFilters['ike-gateway']['name']['operators']['eq'] = array(
    'Function' => function (IKEgatewayRQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
);