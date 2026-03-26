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
RQuery::$defaultFilters['ike-profile']['object']['operators']['is.unused'] = array(
    'Function' => function (IKEprofileRQueryContext $context) {
        return $context->object->countReferences() == 0;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['ike-profile']['authentication']['operators']['eq'] = array(
    'Function' => function (IKEprofileRQueryContext $context) {

        if( !in_array( $context->value, IkeCryptoProfil::$hashs ) )
            derr( 'not supported hash: '.$context->value." | supported once: ".implode(",", IkeCryptoProfil::$hashs), null, false );

        return in_array($context->value, $context->object->hash );
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['ike-profile']['dhgroup']['operators']['eq'] = array(
    'Function' => function (IKEprofileRQueryContext $context) {

        if( !in_array( $context->value, IkeCryptoProfil::$dhgroups ) )
            derr( 'not supported dhgroup: '.$context->value." | supported once: ".implode(",", IkeCryptoProfil::$dhgroups), null, false );

        return in_array($context->value, $context->object->dhgroup );
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['ike-profile']['encryption']['operators']['eq'] = array(
    'Function' => function (IKEprofileRQueryContext $context) {

        if( !in_array( $context->value, IkeCryptoProfil::$encryptions ) )
            derr( 'not supported encryption: '.$context->value." | supported once: ".implode(",", IkeCryptoProfil::$encryptions), null, false );

        return in_array($context->value, $context->object->encryption );
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);