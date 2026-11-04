<?php

// <editor-fold desc=" ***** LogProfile filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['log-profile']['type']['operators']['auth.is.set'] = array(
    'Function' => function (LogProfileRQueryContext $context)
    {
        if( isset($context->object->type['auth']['notSet']) )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE
);

RQuery::$defaultFilters['log-profile']['type']['operators']['data.is.set'] = array(
    'Function' => function (LogProfileRQueryContext $context)
    {
        if( isset($context->object->type['data']['notSet']) )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE
);

RQuery::$defaultFilters['log-profile']['type']['operators']['decryption.is.set'] = array(
    'Function' => function (LogProfileRQueryContext $context)
    {
        if( isset($context->object->type['decryption']) )
            if( isset($context->object->type['decryption']['notSet']) )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE
);

RQuery::$defaultFilters['log-profile']['type']['operators']['traffic.is.set'] = array(
    'Function' => function (LogProfileRQueryContext $context)
    {
        if( isset($context->object->type['traffic']['notSet']) )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE
);

RQuery::$defaultFilters['log-profile']['type']['operators']['tunnel.is.set'] = array(
    'Function' => function (LogProfileRQueryContext $context)
    {
        if( isset($context->object->type['tunnel']['notSet']) )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE
);

RQuery::$defaultFilters['log-profile']['type']['operators']['url.is.set'] = array(
    'Function' => function (LogProfileRQueryContext $context)
    {
        if( isset($context->object->type['url']['notSet']) )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE
);

RQuery::$defaultFilters['log-profile']['type']['operators']['wildfire.is.set'] = array(
    'Function' => function (LogProfileRQueryContext $context)
    {
        if( isset($context->object->type['wildfire']['notSet']) )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['log-profile']['type']['operators']['dns-security.is.set'] = array(
    'Function' => function (LogProfileRQueryContext $context)
    {
        if( isset($context->object->type['dns-security']) )
            if( isset($context->object->type['dns-security']['notSet']) )
                return FALSE;

        return TRUE;
    },
    'arg' => FALSE
);

RQuery::$defaultFilters['log-profile']['send-to-panorama']['operators']['is.set'] = array(
    'Function' => function (LogProfileRQueryContext $context)
    {
        foreach( $context->object->type_available as $type )
        {
            if( isset($context->object->type[$type]['notSet']) )
                return FALSE;
            elseif( isset( $context->object->type[$type]['sent-to-panorama'] ) )
            {
                if( $context->object->type[$type]['sent-to-panorama'] == 'no' )
                    return FALSE;
            }
        }

        return TRUE;
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['log-profile']['filter']['operators']['is.all-logs'] = array(
    'Function' => function (LogProfileRQueryContext $context)
    {
        foreach( $context->object->type_available as $type )
        {
            if( isset($context->object->type[$type]['notSet']) )
                return FALSE;
            elseif( isset( $context->object->type[$type]['filter'] ) )
            {
                if( $context->object->type[$type]['filter'] !== 'All Logs' )
                    return FALSE;
            }
        }

        return TRUE;
    },
    'arg' => FALSE
);

// </editor-fold>