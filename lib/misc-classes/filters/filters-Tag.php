<?php

// <editor-fold desc=" ***** Tag filters *****" defaultstate="collapsed" >
RQuery::$defaultFilters['tag']['color']['operators']['eq'] = array(
    'Function' => function (TagRQueryContext $context) {
        return $context->object->getColor() == strtolower($context->value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% none)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['tag']['comments']['operators']['regex'] = array(
    'Function' => function (TagRQueryContext $context) {
        $name = $context->object->getComments();
        $matching = preg_match($context->value, $name);
        if( $matching === FALSE )
            derr("regular expression error on '{$context->value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /test/)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['tag']['comments']['operators']['is.empty'] = array(
    'Function' => function (TagRQueryContext $context) {
        $desc = $context->object->getComments();

        if( $desc === null || strlen($desc) == 0 )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
// </editor-fold>