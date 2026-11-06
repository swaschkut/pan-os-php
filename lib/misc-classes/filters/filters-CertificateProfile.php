<?php

// <editor-fold desc=" ***** CertificateProfile filters *****" defaultstate="collapsed" >

// name filters (eq, eq.nocase, contains, contains.nocase, regex, is.in.file): filters-Common.php

RQuery::$defaultFilters['certificate-profile']['ca']['operators']['has'] = Array(
    'Function' => function(CertificateProfileRQueryContext $context )
    {
        return isset( $context->object->caCertificates[$context->value] );
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% RootCA)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['certificate-profile']['ca']['operators']['has.regex'] = Array(
    'Function' => function(CertificateProfileRQueryContext $context )
    {
        foreach( $context->object->caCertificateNames() as $caName )
        {
            $matching = preg_match($context->value, $caName);
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }
        return FALSE;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% /root/i)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['certificate-profile']['ca']['operators']['has.unresolved'] = Array(
    'Function' => function(CertificateProfileRQueryContext $context )
    {
        foreach( $context->object->caCertificateNames() as $caName )
            if( $context->object->findCertificate($caName) === null )
                return TRUE;
        return FALSE;
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['certificate-profile']['ca']['operators']['is.empty'] = Array(
    'Function' => function(CertificateProfileRQueryContext $context )
    {
        return count( $context->object->caCertificates ) == 0;
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['certificate-profile']['setting']['operators']['is.yes'] = Array(
    'Function' => function(CertificateProfileRQueryContext $context )
    {
        return isset( $context->object->settings[$context->value] ) && $context->object->settings[$context->value] === 'yes';
    },
    'arg' => true,
    'help' => 'setting name, e.g. use-ocsp, use-crl, block-expired-cert, block-unknown-cert',
    'ci' => Array(
        'fString' => '(%PROP% block-expired-cert)',
        'input' => 'input/panorama-8.0.xml'
    )
);

// </editor-fold>
