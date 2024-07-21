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
RQuery::$defaultFilters['threat']['min-engine-version']['operators']['>,<,=,!'] = array(
    'eval' => "!empty(\$object->min_engine_version) && \$object->min_engine_version !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['threat']['max-engine-version']['operators']['>,<,=,!'] = array(
    'eval' => "!empty(\$object->max_engine_version) && \$object->max_engine_version !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat']['max-engine-version']['operators']['is.empty'] = array(
    'eval' => "empty(\$object->max_engine_version)",
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat']['type']['operators']['is.vulnerability'] = array(
    'Function' => function (ThreatRQueryContext $context) {
        return $context->object->type() == "vulnerability";
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP% ftp)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['threat']['type']['operators']['is.spyware'] = array(
    'Function' => function (ThreatRQueryContext $context) {
        return $context->object->type() == "spyware";
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP% ftp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat']['object']['operators']['is.disabled'] = array(
    'Function' => function (ThreatRQueryContext $context) {
        return $context->object->disabled == TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP% ftp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['threat']['object']['operators']['is.unused'] = array(
    'Function' => function (ThreatRQueryContext $context) {
        $object = $context->object;

        #return $object->objectIsUnused();
        return $object->countReferences() == 0;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['threat']['object']['operators']['has.excemption'] = array(
    'Function' => function (ThreatRQueryContext $context) {
        $object = $context->object;

        return $object->countReferences() > 0;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
// </editor-fold>