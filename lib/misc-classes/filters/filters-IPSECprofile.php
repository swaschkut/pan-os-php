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

RQuery::$defaultFilters['ipsec-profile']['hash']['operators']['eq'] = array(
    'Function' => function (IPSECprofileRQueryContext $context) {
        //sha1/sha256/sha384/non-auth/sha512
        $hash_array = array('md5','sha1','sha256','sha384','non-auth','sha512');
        if( !in_array( $context->value, $hash_array ) )
            derr( 'not supported hash: '.$context->value." | supported onces: ".explode(",",$hash_array), null, false );

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
        $hash_array = array('group1','group2','group5',
            'group14','group15','group16','group19',
            'group20','group21');
        if( !in_array( $context->value, $hash_array ) )
            derr( 'not supported dhgroup: '.$context->value." | supported onces: ".explode(",",$hash_array), null, false );

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
        $hash_array = array('3des',
            'aes-128-cbc','aes-192-cbc','aes-256-cbc',
            'aes-128-gcm','aes-256-gcm');
        if( !in_array( $context->value, $hash_array ) )
            derr( 'not supported encryption: '.$context->value." | supported onces: ".explode(",",$hash_array), null, false );

        return $context->object->encryption == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);