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
RQuery::$defaultFilters['ipsec-profile']['object']['operators']['is.unused'] = array(
    'Function' => function (IPSECprofileRQueryContext $context) {
        return $context->object->countReferences() == 0;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['ipsec-profile']['authentication']['operators']['eq'] = array(
    'Function' => function (IPSECprofileRQueryContext $context) {

        if( !in_array( $context->value, IPSecCryptoProfil::$authentications ) )
            derr( 'not supported hash: '.$context->value." | supported onces: ".implode(",", IPSecCryptoProfil::$authentications), null, false );

        //todo: migrate to array
        return $context->object->hash == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['ipsec-profile']['dhgroup']['operators']['eq'] = array(
    'Function' => function (IPSECprofileRQueryContext $context) {

        if( !in_array( $context->value, IPSecCryptoProfil::$dhgroups ) )
            derr( 'not supported dhgroup: '.$context->value." | supported onces: ".implode(",", IPSecCryptoProfil::$dhgroups), null, false );

        //todo: migrate to array
        return $context->object->dhgroup == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['ipsec-profile']['encryption']['operators']['eq'] = array(
    'Function' => function (IPSECprofileRQueryContext $context) {

        if( !in_array( $context->value, IPSecCryptoProfil::$encryptions ) )
            derr( 'not supported encryption: '.$context->value." | supported onces: ".implode(",", IPSecCryptoProfil::$encryptions), null, false );

        //todo: migrate to array
        return $context->object->encryption == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);