<?php
RQuery::$defaultFilters['ike-profile']['name']['operators']['eq'] = array(
    'Function' => function (IKEprofileRQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
);