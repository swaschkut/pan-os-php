<?php

// <editor-fold desc=" ***** Zone filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['zone-protection-profile']['object']['operators']['is.visibility'] = array(
    'Function' => function (ZoneProtectionProfileRQueryContext $context) {

        if( $context->object->is_visibility())
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE
);











// </editor-fold>