<?php

// <editor-fold desc=" ***** Interface-ManagementProfile filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['interface-management-profile']['permitted-ip']['operators']['is.set'] = array(
    'Function' => function (InterfaceManagementProfileRQueryContext $context) {
        $object = $context->object;

        return !empty($object->permittedIPs);
    },
    'arg' => FALSE
);

RQuery::$defaultFilters['interface-management-profile']['enabled-service']['operators']['has'] = array(
    'Function' => function (InterfaceManagementProfileRQueryContext $context) {
        $object = $context->object;

        $value = $context->value;
        $value = strtolower($value);

        if( isset($object->enabledServices[$value]) )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE
);

RQuery::$defaultFilters['interface-management-profile']['enabled-service']['operators']['has.only'] = array(
    'Function' => function (InterfaceManagementProfileRQueryContext $context) {
        $object = $context->object;

        $value = $context->value;
        $value = strtolower($value);

        if( count($object->enabledServices) == 1 && isset($object->enabledServices[$value]) )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE
);

RQuery::$defaultFilters['interface-management-profile']['enabled-service']['operators']['has.ping'] = array(
    'Function' => function (InterfaceManagementProfileRQueryContext $context) {
        $object = $context->object;

        if( isset($object->enabledServices['ping']) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['interface-management-profile']['enabled-service']['operators']['has.ssh'] = array(
    'Function' => function (InterfaceManagementProfileRQueryContext $context) {
        $object = $context->object;

        if( isset($object->enabledServices['ssh']) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['interface-management-profile']['enabled-service']['operators']['has.https'] = array(
    'Function' => function (InterfaceManagementProfileRQueryContext $context) {
        $object = $context->object;

        if( isset($object->enabledServices['https']) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['interface-management-profile']['enabled-service']['operators']['has.http'] = array(
    'Function' => function (InterfaceManagementProfileRQueryContext $context) {
        $object = $context->object;

        if( isset($object->enabledServices['http']) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['interface-management-profile']['enabled-service']['operators']['has.telnet'] = array(
    'Function' => function (InterfaceManagementProfileRQueryContext $context) {
        $object = $context->object;

        if( isset($object->enabledServices['telnet']) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['interface-management-profile']['enabled-service']['operators']['has.userid-service'] = array(
    'Function' => function (InterfaceManagementProfileRQueryContext $context) {
        $object = $context->object;

        if( isset($object->enabledServices['userid-service']) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['interface-management-profile']['enabled-service']['operators']['has.response-pages'] = array(
    'Function' => function (InterfaceManagementProfileRQueryContext $context) {
        $object = $context->object;

        if( isset($object->enabledServices['response-pages']) )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE
);

// </editor-fold>