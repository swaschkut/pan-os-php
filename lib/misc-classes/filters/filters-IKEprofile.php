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
        //sha1/sha256/sha384/non-auth/sha512
        #$hash_array = array('md5','sha1','sha256','sha384','non-auth','sha512');
        if( !in_array( $context->value, IkeCryptoProfil::$hashs ) )
            derr( 'not supported hash: '.$context->value." | supported onces: ".implode(",", IkeCryptoProfil::$hashs), null, false );

        return $context->object->hash == $context->value;
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
            derr( 'not supported dhgroup: '.$context->value." | supported onces: ".implode(",", IkeCryptoProfil::$dhgroups), null, false );

        return $context->object->dhgroup == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['ike-profile']['encryption']['operators']['eq'] = array(
    'Function' => function (IKEprofileRQueryContext $context) {
        $hash_array = array('3des',
            'aes-128-cbc','aes-192-cbc','aes-256-cbc',
            'aes-128-ccm', 'null',
            'aes-128-gcm','aes-256-gcm');
        if( !in_array( $context->value, IkeCryptoProfil::$encryptions ) )
            derr( 'not supported encryption: '.$context->value." | supported onces: ".implode(",", IkeCryptoProfil::$encryptions), null, false );

        return $context->object->encryption == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);