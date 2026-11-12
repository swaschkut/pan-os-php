<?php

// <editor-fold desc=" ***** Schedule filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['schedule']['object']['operators']['is.expired'] = array(
    'Function' => function (ScheduleRQueryContext $context) {
        $value = $context->object;

        return $value->isExpired();
    },
    'arg' => false,
);
RQuery::$defaultFilters['schedule']['object']['operators']['expire.in.days'] = array(
    'Function' => function (ScheduleRQueryContext $context) {
        $value = $context->object;

        $operator = $context->operator;
        if( $operator == '=' )
            $operator = '==';

        return $value->isExpired( $context->value, $operator );
    },
    'arg' => true,
);
RQuery::$defaultFilters['schedule']['object']['operators']['expired.at.date'] = array(
    'Function' => function (ScheduleRQueryContext $context) {
        $value = $context->object;

        $operator = $context->operator;
        if( $operator == '=' )
            $operator = '==';

        return $value->isExpired( $context->value, $operator );
    },
    'arg' => true,
);

RQuery::$defaultFilters['schedule']['expire.in.days']['operators']['>,<,=,!'] = array(
    'Function' => function (ScheduleRQueryContext $context) {
        $value = $context->object;

        $operator = $context->operator;
        if( $operator == '=' )
            $operator = '==';

        return $value->isExpired( $context->value, $operator );
    },
    'arg' => true,
);
RQuery::$defaultFilters['schedule']['expired.at.date']['operators']['>,<,=,!'] = array(
    'Function' => function (ScheduleRQueryContext $context) {
        $value = $context->object;

        $operator = $context->operator;
        if( $operator == '=' )
            $operator = '==';

        return $value->isExpired( $context->value, $operator );
    },
    'arg' => true,
    'help' => 'returns TRUE if rule name matches the specified timestamp MM/DD/YYYY [american] / DD-MM-YYYY [european]'
);
// </editor-fold>