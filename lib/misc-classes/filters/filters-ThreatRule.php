<?php

// <editor-fold desc=" ***** Threat-Rule filters *****" defaultstate="collapsed" >




RQuery::$defaultFilters['threat-rule']['severity']['operators']['has'] = array(
    'Function' => function (ThreatRuleRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( $value == "any" )
            return TRUE;

        if( in_array( $value, $object->severity) )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% critical )',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat-rule']['severity']['operators']['is.any'] = array(
    'Function' => function (ThreatRuleRQueryContext $context) {
        $object = $context->object;

        if( in_array( "any", $object->severity) )
            return TRUE;

        return FALSE;
    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP% critical )',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat-rule']['category']['operators']['eq'] = array(
    'Function' => function (ThreatRuleRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( $value == "any" )
            return TRUE;

        if( $object->category == $value )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% brute-force )',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat-rule']['category']['operators']['is.any'] = array(
    'Function' => function (ThreatRuleRQueryContext $context) {
        $object = $context->object;

        if( $object->category == "any" )
            return TRUE;

        return FALSE;
    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP% brute-force )',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat-rule']['host']['operators']['eq'] = array(
    'Function' => function (ThreatRuleRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( $value == "any" )
            return TRUE;

        if( $object->host == $value )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% client )',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat-rule']['host']['operators']['is.any'] = array(
    'Function' => function (ThreatRuleRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( $object->host == "any" )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% client )',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat-rule']['threatname']['operators']['eq'] = array(
    'Function' => function (ThreatRuleRQueryContext $context) {
        $object = $context->object;
        $value = $context->value;

        if( $value == "any" )
            return TRUE;

        if( $object->host == $value )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% client )',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat-rule']['threatname']['operators']['is.any'] = array(
    'Function' => function (ThreatRuleRQueryContext $context) {
        $object = $context->object;

        if( $object->host == "any" )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP% client )',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat-rule']['application']['operators']['is.any'] = array(
    'Function' => function (ThreatRuleRQueryContext $context) {
        $object = $context->object;

        if( in_array("any", $object->application()) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP% client )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['threat-rule']['application']['operators']['has'] = array(
    'Function' => function (ThreatRuleRQueryContext $context) {
        $object = $context->object;

        if( in_array($context->value, $object->application()) )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% client )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['threat-rule']['filetype']['operators']['is.any'] = array(
    'Function' => function (ThreatRuleRQueryContext $context) {
        $object = $context->object;

        if( in_array("any", $object->filetype()) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP% client )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['threat-rule']['filetype']['operators']['has'] = array(
    'Function' => function (ThreatRuleRQueryContext $context) {
        $object = $context->object;

        if( in_array($context->value, $object->filetype()) )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% client )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['threat-rule']['direction']['operators']['is.both'] = array(
    'Function' => function (ThreatRuleRQueryContext $context) {
        $object = $context->object;

        if( $object->direction() == "both" )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP% client )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['threat-rule']['direction']['operators']['eq'] = array(
    'Function' => function (ThreatRuleRQueryContext $context) {
        $object = $context->object;

        if( $object->direction() == $context->value )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% client )',
        'input' => 'input/panorama-8.0.xml'
    )
);
// </editor-fold>