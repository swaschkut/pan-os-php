<?php

// <editor-fold desc=" ***** Threat filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['threat']['name']['operators']['eq'] = array(
    'Function' => function (ThreatRQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% ftp)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['threat']['name']['operators']['contains'] = array(
    'Function' => function (ThreatRQueryContext $context) {
        return strpos($context->object->name(), $context->value) !== FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% -)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['threat']['threatname']['operators']['eq'] = array(
    'Function' => function (ThreatRQueryContext $context) {
        return $context->object->threatname() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% ftp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat']['severity']['operators']['eq'] = array(
    'Function' => function (ThreatRQueryContext $context) {
        return $context->object->severity() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% ftp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat']['default-action']['operators']['eq'] = array(
    'Function' => function (ThreatRQueryContext $context) {
        if( $context->value == 'null' )
            return $context->object->defaultAction() == null;
        else
            return $context->object->defaultAction() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% ftp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat']['category']['operators']['eq'] = array(
    'Function' => function (ThreatRQueryContext $context) {
            return $context->object->category() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% ftp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat']['cve']['operators']['contains'] = array(
    'Function' => function (ThreatRQueryContext $context) {

        $string = implode(",", $context->object->cve());

        return strpos($string, $context->value) !== FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% -)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['threat']['engine-version']['operators']['>,<,=,!'] = array(
    'eval' => "\$object->engine_version !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
// </editor-fold>