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
RQuery::$defaultFilters['ipsec-tunnel']['object']['operators']['is.unused'] = array(
    'Function' => function (IPSECtunnelRQueryContext $context) {
        return $context->object->countReferences() == 0;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);