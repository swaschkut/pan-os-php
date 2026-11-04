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
RQuery::$defaultFilters['schedule']['location']['operators']['is.child.of'] = array(
    'Function' => function (ScheduleRQueryContext $context) {
        $schedule_location = $context->object->getLocationString();

        $sub = $context->object->owner;
        while( get_class($sub) == "ScheduleStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
            $sub = $sub->owner;

        if( get_class($sub) == "PANConf" )
            derr("filter location is.child.of is not working against a firewall configuration");

        if( strtolower($context->value) == 'shared' )
            return TRUE;

        $DG = $sub->findDeviceGroup($context->value);
        if( $DG == null )
        {
            PH::print_stdout("ERROR: location '$context->value' was not found. Here is a list of available ones:" );
            PH::print_stdout( " - shared" );
            foreach( $sub->getDeviceGroups() as $sub1 )
            {
                PH::print_stdout( " - " . $sub1->name() );
            }
            PH::print_stdout();
            exit(1);
        }

        $childDeviceGroups = $DG->childDeviceGroups(TRUE);

        if( strtolower($context->value) == strtolower($schedule_location) )
            return TRUE;

        foreach( $childDeviceGroups as $childDeviceGroup )
        {
            if( $childDeviceGroup->name() == $schedule_location )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches / is child the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  Datacenter-Firewalls)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['schedule']['location']['operators']['is.parent.of'] = array(
    'Function' => function (ScheduleRQueryContext $context) {
        $schedule_location = $context->object->getLocationString();

        $sub = $context->object->owner;
        while( get_class($sub) == "ScheduleStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
            $sub = $sub->owner;

        if( get_class($sub) == "PANConf" )
        {
            PH::print_stdout( "ERROR: filter location is.child.of is not working against a firewall configuration" );
            return FALSE;
        }

        if( strtolower($context->value) == 'shared' )
            return TRUE;

        $DG = $sub->findDeviceGroup($context->value);
        if( $DG == null )
        {
            PH::print_stdout( "ERROR: location '$context->value' was not found. Here is a list of available ones:" );
            PH::print_stdout( " - shared" );
            foreach( $sub->getDeviceGroups() as $sub1 )
            {
                PH::print_stdout( " - " . $sub1->name() );
            }
            PH::print_stdout();
            exit(1);
        }

        $parentDeviceGroups = $DG->parentDeviceGroups();

        if( strtolower($context->value) == strtolower($schedule_location) )
            return TRUE;

        if( $schedule_location == 'shared' )
            return TRUE;

        foreach( $parentDeviceGroups as $childDeviceGroup )
        {
            if( $childDeviceGroup->name() == $schedule_location )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches / is parent the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  Datacenter-Firewalls)',
        'input' => 'input/panorama-8.0.xml'
    )
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