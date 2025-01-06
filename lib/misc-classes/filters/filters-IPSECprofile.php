<?php
RQuery::$defaultFilters['ipsec-profile']['name']['operators']['eq'] = array(
    'Function' => function (IPSECprofileRQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
);