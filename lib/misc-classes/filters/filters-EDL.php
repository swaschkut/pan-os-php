<?php

// <editor-fold desc=" ***** Schedule filters *****" defaultstate="collapsed" >



RQuery::$defaultFilters['edl']['type']['operators']['is.ip'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;

        return $object->type() == 'ip';
    },
    'arg' => false,
);

RQuery::$defaultFilters['edl']['type']['operators']['is.url'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;

        return $object->type() == 'url';
    },
    'arg' => false,
);

RQuery::$defaultFilters['edl']['type']['operators']['is.domain'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;

        return $object->type() == 'domain';
    },
    'arg' => false,
);
RQuery::$defaultFilters['edl']['type']['operators']['is.imei'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;

        return $object->type() == 'imei';
    },
    'arg' => false,
);
RQuery::$defaultFilters['edl']['type']['operators']['is.imsi'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;

        return $object->type() == 'imsi';
    },
    'arg' => false,
);
RQuery::$defaultFilters['edl']['type']['operators']['is.predefined-ip'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;

        return $object->type() == 'predefined-ip';
    },
    'arg' => false,
);
RQuery::$defaultFilters['edl']['type']['operators']['is.predefined-url'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;

        return $object->type() == 'predefined-url';
    },
    'arg' => false,
);

RQuery::$defaultFilters['edl']['url']['operators']['regex'] = array(
    'Function' => function (EDLRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( strlen($value) > 0 && $value[0] == '%' )
        {
            $value = substr($value, 1);
            if( !isset($context->nestedQueries[$value]) )
                derr("regular expression filter makes reference to unknown string alias '{$value}'");

            $value = $context->nestedQueries[$value];
        }

        $matching = preg_match($value, $object->url());
        if( $matching === FALSE )
            derr("regular expression error on '{$value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /-group/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
// </editor-fold>