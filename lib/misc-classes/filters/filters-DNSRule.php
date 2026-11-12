<?php

// <editor-fold desc=" ***** DNS-Rule filters *****" defaultstate="collapsed" >



RQuery::$defaultFilters['dns-rule']['log-level']['operators']['eq'] = array(
    'Function' => function (DNSRuleRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( $object->logLevel() == $value )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% default )',
        'input' => 'input/panorama-8.0.xml'
    )
);
// </editor-fold>