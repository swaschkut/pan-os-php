<?php
RQuery::$defaultFilters['ipsec-tunnel']['name']['operators']['eq'] = array(
    'Function' => function (IPSECtunnelRQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
);