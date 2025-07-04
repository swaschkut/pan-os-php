<?php


// <editor-fold desc=" ***** Rule filters *****" defaultstate="collapsed" >

//                                              //
//                Zone Based Actions            //
//                                              //
RQuery::$defaultFilters['rule']['from']['operators']['has'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( $object->isPbfRule() && !$object->isZoneBased() )
            return $object->from->hasInterface($value) === TRUE;

        if( $object->isDoSRule() && !$object->isZoneBasedFrom() )
            return $object->from->hasInterface($value) === TRUE;

        return $object->from->hasZone($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->from->parentCentralStore->find('!value!');"


);
RQuery::$defaultFilters['rule']['from']['operators']['has.only'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( $object->isPbfRule() && !$object->isZoneBased() )
            return $object->from->hasInterface($value) === TRUE && $object->from->count() == 1;
        if( $object->isDoSRule() && !$object->isZoneBasedFrom() )
            return $object->from->hasInterface($value) === TRUE && $object->from->count() == 1;

        return $object->from->count() == 1 && $object->from->hasZone($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->from->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['from']['operators']['has.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( $rule->from->isAny() )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");


        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('zone');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $rule->from->getAll() as $key => $zone )
        {
            if( $zone !== null )
            {
                if( $rQuery->matchSingleObject(array('object' => $zone, 'nestedQueries' => &$context->nestedQueries)) )
                    return TRUE;
            }
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'example: \'filter=(from has.from.query subquery1)\' \'subquery1=(zpp is.set)\'',
);
RQuery::$defaultFilters['rule']['from']['operators']['all.has.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( $rule->from->isAny() )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('zone');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        $found = FALSE;
        foreach( $rule->from->getAll() as $key => $zone )
        {
            /** @var Zone $zone */
            if( $zone !== null )
            {
                if( $rQuery->matchSingleObject(array('object' => $zone, 'nestedQueries' => &$context->nestedQueries)) )
                    $found = TRUE;
                else
                    return FALSE;
            }
        }

        return $found;
    },
    'arg' => TRUE,
    'help' => 'example: \'filter=(from all.has.from.query subquery1)\' \'subquery1=(zpp is.set)\'',
);

RQuery::$defaultFilters['rule']['to']['operators']['has'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( $object->isPbfRule() )
            return FALSE;

        if( $object->isDoSRule() && !$object->isZoneBasedTo() )
            return $object->to->hasInterface($value) === TRUE;

        return $object->to->hasZone($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => function ($object, $argument) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( $object->isPbfRule() )
            return FALSE;

        return $object->to->parentCentralStore->find($argument);
    },
    'help' => 'returns TRUE if field TO is using zone mentionned in argument. Ie: "(to has Untrust)"'
);
RQuery::$defaultFilters['rule']['to']['operators']['has.only'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( $object->isPbfRule() )
            return FALSE;

        if( $object->isDoSRule() && !$object->isZoneBasedFrom() )
            return $object->to->hasInterface($value) === TRUE && $object->to->count() == 1;

        return $object->to->count() == 1 && $object->to->hasZone($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->to->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['to']['operators']['has.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( $rule->to->isAny() )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");


        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('zone');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $rule->to->getAll() as $key => $zone )
        {
            if( $zone !== null )
            {
                if( $rQuery->matchSingleObject(array('object' => $zone, 'nestedQueries' => &$context->nestedQueries)) )
                    return TRUE;
            }
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'example: \'filter=(to has.from.query subquery1)\' \'subquery1=(zpp is.set)\'',
);
RQuery::$defaultFilters['rule']['to']['operators']['all.has.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( $rule->to->isAny() )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");


        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('zone');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        $found = FALSE;
        foreach( $rule->to->getAll() as $key => $zone )
        {
            if( $zone !== null )
            {
                if( $rQuery->matchSingleObject(array('object' => $zone, 'nestedQueries' => &$context->nestedQueries)) )
                    return FALSE;
                else
                    $found = TRUE;
            }
        }

        return $found;
    },
    'arg' => TRUE,
    'help' => 'example: \'filter=(to all.has.from.query subquery1)\' \'subquery1=(zpp is.set)\'',
);

RQuery::$defaultFilters['rule']['from']['operators']['has.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        foreach( $context->object->from->zones() as $zone )
        {
            $matching = preg_match($context->value, $zone->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }
        return FALSE;
    },
    'arg' => TRUE,
);
RQuery::$defaultFilters['rule']['to']['operators']['has.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->isPbfRule() )
            return FALSE;

        foreach( $context->object->to->zones() as $zone )
        {
            $matching = preg_match($context->value, $zone->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }
        return FALSE;
    },
    'arg' => TRUE,
);

RQuery::$defaultFilters['rule']['from.count']['operators']['>,<,=,!'] = array(
    'eval' => "!\$object->isPbfRule() && \$object->from->count() !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['to.count']['operators']['>,<,=,!'] = array(
    'eval' => "!\$object->isPbfRule() && \$object->to->count() !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['from']['operators']['is.any'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->isPbfRule() )
            return FALSE;

        return $context->object->from->isAny();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['to']['operators']['is.any'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->isPbfRule() )
            return FALSE;

        return $context->object->to->isAny();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['from']['operators']['is.in.file'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $object = $context->object;

        if( !isset($context->cachedList) )
        {
            $text = file_get_contents($context->value);

            if( $text === FALSE )
                derr("cannot open file '{$context->value}");

            $lines = explode("\n", $text);
            foreach( $lines as $line )
            {
                $line = trim($line);
                if( strlen($line) == 0 )
                    continue;
                $list[$line] = TRUE;
            }

            $context->cachedList = &$list;
        }
        else
            $list = &$context->cachedList;

        $return = FALSE;
        foreach( $list as $zone => $truefalse )
        {
            if( $object->from->hasZone($zone) )
                $return = TRUE;
        }

        return $return;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if rule name matches one of the names found in text file provided in argument'
);

RQuery::$defaultFilters['rule']['to']['operators']['is.in.file'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $object = $context->object;

        if( !isset($context->cachedList) )
        {
            $text = file_get_contents($context->value);

            if( $text === FALSE )
                derr("cannot open file '{$context->value}");

            $lines = explode("\n", $text);
            foreach( $lines as $line )
            {
                $line = trim($line);
                if( strlen($line) == 0 )
                    continue;
                $list[$line] = TRUE;
            }

            $context->cachedList = &$list;
        }
        else
            $list = &$context->cachedList;

        $return = FALSE;
        foreach( $list as $zone => $truefalse )
        {
            if( $object->to->hasZone($zone) )
                $return = TRUE;
        }

        return $return;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if rule name matches one of the names found in text file provided in argument'
);
RQuery::$defaultFilters['rule']['from']['operators']['has.same.to.zone'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->isPbfRule() )
            return null;

        $fromZones = $context->object->from;
        $toZones = $context->object->to;

        if( count($fromZones->zones()) === count($toZones->zones()))
        {
            if( $fromZones->includesContainer( $toZones ) && $toZones->includesContainer( $fromZones ) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['to']['operators']['has.same.from.zone'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->isPbfRule() )
            return null;

        $fromZones = $context->object->from;
        $toZones = $context->object->to;

        if( count($fromZones->zones()) === count($toZones->zones()))
        {
            if( $fromZones->includesContainer( $toZones ) && $toZones->includesContainer( $fromZones ) )
            return TRUE;
        }

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
//                                              //
//                NAT Based Filters     //
//
RQuery::$defaultFilters['rule']['natruletype']['operators']['is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( !$context->object->isNatRule() )
            return FALSE;

        if( !in_array( $context->value, $context->object->getNatRuleTypeArray() ) )
        {
            mwarning( "Nat Rule Type: ". $context->value ." is not suppoerted. Please pick a supported one: ".implode(",", $context->object->getNatRuleTypeArray()) );
            return False;
        }

        if( $context->object->getNatRuleType() == $context->value )
            return True;

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'supported filter: \'ipv4\', \'nat64\', \'ptv6\'',
);
//                                              //
//                NAT Dst/Src Based Filters     //
//                                              //
RQuery::$defaultFilters['rule']['snatinterface']['operators']['has.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( !$context->object->isNatRule() )
            return FALSE;

        if( $context->object->snatinterface === null )
            return FALSE;

        $matching = preg_match($context->value, $context->object->snatinterface );
        if( $matching === FALSE )
            derr("regular expression error on '{$context->value}'");
        if( $matching === 1 )
            return TRUE;
        else
            return FALSE;
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['rule']['snatinterface']['operators']['is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( !$context->object->isNatRule() )
            return FALSE;

        if( $context->object->snatinterface === null )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSe
);
RQuery::$defaultFilters['rule']['snathost']['operators']['has'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( !$object->isNatRule() ) return FALSE;

        return $object->snathosts->has($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->owner->owner->addressStore->find('!value!');"

);
RQuery::$defaultFilters['rule']['snathost']['operators']['has.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $object = $context->object;

        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( !$object->isNatRule() ) return FALSE;

        if( $object->snathosts->count() == 0 )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('address');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->snathosts->all() as $member )
        {
            if( $rQuery->matchSingleObject(array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'example: \'filter=(snathost has.from.query subquery1)\' \'subquery1=(netmask < 32)\'',
);
RQuery::$defaultFilters['rule']['snathost.count']['operators']['>,<,=,!'] = array(
    'eval' => "\$object->isNatRule() && \$object->snathosts->count() !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dnathost']['operators']['has'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( !$object->isNatRule() ) return FALSE;
        if( $object->dnathost === null ) return FALSE;

        return $object->dnathost === $value;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->owner->owner->addressStore->find('!value!');"
);

RQuery::$defaultFilters['rule']['dnathost']['operators']['included-in.full'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return null;
        if( $context->object->dnathost === null ) return null;
        return $context->object->dnathost->includedInIP4Network($context->value) == 1;
    },
    'arg' => TRUE,
    'argDesc' => 'ie: 192.168.0.0/24 | 192.168.50.10/32 | 192.168.50.10 | 10.0.0.0-10.33.0.0',
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dnathost']['operators']['included-in.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return null;
        if( $context->object->dnathost === null ) return null;
        return $context->object->dnathost->includedInIP4Network($context->value) == 2;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dnathost']['operators']['included-in.full.or.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return null;
        if( $context->object->dnathost === null ) return null;
        return $context->object->dnathost->includedInIP4Network($context->value) > 0;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dnathost']['operators']['includes.full'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return null;
        if( $context->object->dnathost === null ) return null;
        return $context->object->dnathost->includesIP4Network($context->value) == 1;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dnathost']['operators']['includes.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return null;
        if( $context->object->dnathost === null ) return null;
        return $context->object->dnathost->includesIP4Network($context->value) == 2;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dnathost']['operators']['includes.full.or.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return null;
        if( $context->object->dnathost === null ) return null;
        return $context->object->dnathost->includesIP4Network($context->value) > 0;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);


RQuery::$defaultFilters['rule']['dnatport']['operators']['eq'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( !$object->isNatRule() ) return FALSE;
        if( $object->dnatports === null ) return FALSE;

        return $object->dnatports === $value;
    },
    'arg' => TRUE,
    'argDesc' => 'service port e.g. 80'
);
RQuery::$defaultFilters['rule']['dnatport']['operators']['is.set'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( !$object->isNatRule() ) return FALSE;
        if( $object->dnatports === null ) return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
);


RQuery::$defaultFilters['rule']['dnattype']['operators']['is.static'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return null;
        if( $context->object->dnathost === null ) return null;
        if( $context->object->dnattype == 'static' )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['rule']['dnattype']['operators']['is.dynamic'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return null;
        if( $context->object->dnathost === null ) return null;
        if( $context->object->dnattype == 'dynamic' )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE
);


RQuery::$defaultFilters['rule']['dnatdistribution']['operators']['is.round-robin'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( !$object->isNatRule() ) return FALSE;
        if( $object->dnattype !== "dynamic" ) return FALSE;

        return $object->dnatdistribution === "round-robin";
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['rule']['dnatdistribution']['operators']['is.source-ip-hash'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( !$object->isNatRule() ) return FALSE;
        if( $object->dnattype !== "dynamic" ) return FALSE;

        return $object->dnatdistribution === "source-ip-hash";
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['rule']['dnatdistribution']['operators']['is.ip-modulo'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( !$object->isNatRule() ) return FALSE;
        if( $object->dnattype !== "dynamic" ) return FALSE;

        return $object->dnatdistribution === "ip-modulo";
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['rule']['dnatdistribution']['operators']['is.ip-hash'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( !$object->isNatRule() ) return FALSE;
        if( $object->dnattype !== "dynamic" ) return FALSE;

        return $object->dnatdistribution === "ip-hash";
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['rule']['dnatdistribution']['operators']['is.least-sessions'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( !$object->isNatRule() ) return FALSE;
        if( $object->dnattype !== "dynamic" ) return FALSE;

        return $object->dnatdistribution === "least-sessions";
    },
    'arg' => FALSE
);
//                                              //
//                SNAT Based Actions            //
//                                              //
RQuery::$defaultFilters['rule']['snat']['operators']['is.static'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return FALSE;
        if( !$context->object->sourceNatTypeIs_Static() ) return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['snat']['operators']['is.dynamic-ip'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return FALSE;
        if( !$context->object->sourceNatTypeIs_Dynamic() ) return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['snat']['operators']['is.dynamic-ip-and-port'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() )
            return FALSE;

        if( !$context->object->sourceNatTypeIs_DIPP() )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['snat']['operators']['is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return FALSE;
        if( $context->object->sourceNatTypeIs_None() ) return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

//                                              //
//                SNAT interface Based Actions            //
//                                              //
RQuery::$defaultFilters['rule']['dst-interface']['operators']['is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() )
            return FALSE;

        return $context->object->hasDestinationInterface();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

//                                              //
//                DNAT Based Actions            //
//                                              //
RQuery::$defaultFilters['rule']['dnat']['operators']['is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() ) return FALSE;
        if( !$context->object->destinationNatIsEnabled() ) return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

//                                              //
//                Dst/Src Based Actions            //
//                                              //



RQuery::$commonFilters['src-dst']['xxx-get.list'] = function (RuleRQueryContext $context) {
    $list = &$context->value;

    if( !isset($context->cachedIP4Mapping) )
    {
        $listMapping = new IP4Map();

        foreach( $list as $item )
            $listMapping->addMap(IP4Map::mapFromText($item), FALSE);

        $listMapping->sortAndRecalculate();

        $context->cachedIP4Mapping = $listMapping;
    }
    else
        $listMapping = $context->cachedIP4Mapping;

    return $listMapping;
};

RQuery::$commonFilters['src-dst']['xxx-is.fully.included.in.list'] = function (RuleRQueryContext $context, AddressRuleContainer $srcOrDst) {
    $f = RQuery::$commonFilters['src-dst']['xxx-get.list'];
    $listMapping = $f($context);

    return $srcOrDst->getIP4Mapping()->includedInOtherMap($listMapping) == 1;
};

RQuery::$commonFilters['src-dst']['xxx-is.partially.included.in.list'] = function (RuleRQueryContext $context, AddressRuleContainer $srcOrDst) {
    $f = RQuery::$commonFilters['src-dst']['xxx-get.list'];
    $listMapping = $f($context);

    return $srcOrDst->getIP4Mapping()->includedInOtherMap($listMapping) == 2;
};

RQuery::$commonFilters['src-dst']['xxx-is.partially.or.fully.included.in.list'] = function (RuleRQueryContext $context, AddressRuleContainer $srcOrDst) {
    $f = RQuery::$commonFilters['src-dst']['xxx-get.list'];
    $listMapping = $f($context);

    return $srcOrDst->getIP4Mapping()->includedInOtherMap($listMapping) > 0;
};

RQuery::$commonFilters['src-dst']['xxx-get.file'] = function (RuleRQueryContext $context) {
    if( !isset($context->cachedList) )
    {
        $text = file_get_contents($context->value);

        if( $text === FALSE )
            derr("cannot open file '{$context->value}");

        $lines = explode("\n", $text);
        foreach( $lines as $line )
        {
            $line = trim($line);
            if( strlen($line) == 0 )
                continue;
            $list[$line] = $line;
        }
        $context->cachedList = &$list;
    }
    else
        $list = &$context->cachedList;


    /** @var IP4Map $lisMapping */
    if( !isset($context->cachedIP4Mapping) )
    {
        $listMapping = new IP4Map();

        foreach( $list as $item )
            $listMapping->addMap(IP4Map::mapFromText($item), FALSE);

        $listMapping->sortAndRecalculate();

        $context->cachedIP4Mapping = $listMapping;
    }
    else
        $listMapping = $context->cachedIP4Mapping;

    return $listMapping;
};

RQuery::$commonFilters['src-dst']['xxx-is.fully.included.in.file'] = function (RuleRQueryContext $context, AddressRuleContainer $srcOrDst) {
    $f = RQuery::$commonFilters['src-dst']['xxx-get.file'];
    $listMapping = $f($context);

    return $srcOrDst->getIP4Mapping()->includedInOtherMap($listMapping) == 1;
};

RQuery::$commonFilters['src-dst']['xxx-is.partially.included.in.file'] = function (RuleRQueryContext $context, AddressRuleContainer $srcOrDst) {
    $f = RQuery::$commonFilters['src-dst']['xxx-get.file'];
    $listMapping = $f($context);

    return $srcOrDst->getIP4Mapping()->includedInOtherMap($listMapping) == 2;
};

RQuery::$commonFilters['src-dst']['xxx-is.partially.or.fully.included.in.file'] = function (RuleRQueryContext $context, AddressRuleContainer $srcOrDst) {
    $f = RQuery::$commonFilters['src-dst']['xxx-get.file'];
    $listMapping = $f($context);

    return $srcOrDst->getIP4Mapping()->includedInOtherMap($listMapping) > 0;
};


RQuery::$defaultFilters['rule']['src']['operators']['has'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->source->has($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->source->parentCentralStore->find('!value!');"

);
RQuery::$defaultFilters['rule']['src']['operators']['has.edl'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->source->hasEDL() === TRUE;
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['rule']['src']['operators']['has.only'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->source->count() == 1 && $object->source->has($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->source->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['src']['operators']['has.recursive'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->source->hasObjectRecursive($value, FALSE) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->source->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['src']['operators']['has.recursive.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $members = $context->object->source->membersExpanded(TRUE);

        foreach( $members as $member )
        {
            $matching = preg_match($context->value, $member->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }
        return FALSE;
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['rule']['dst']['operators']['has'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->destination->has($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->destination->parentCentralStore->find('!value!');"

);
RQuery::$defaultFilters['rule']['dst']['operators']['has.edl'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->destination->hasEDL() === TRUE;
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['rule']['dst']['operators']['has.only'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->destination->count() == 1 && $object->destination->has($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->destination->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['dst']['operators']['has.recursive'] = array(
    'eval' => '$object->destination->hasObjectRecursive(!value!, false) === true',
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->destination->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['dst']['operators']['has.recursive.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $members = $context->object->destination->membersExpanded(TRUE);

        foreach( $members as $member )
        {
            $matching = preg_match($context->value, $member->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }
        return FALSE;
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['rule']['src']['operators']['is.any'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->source->count() == 0;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dst']['operators']['is.any'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->destination->count() == 0;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['src']['operators']['is.negated'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->isNatRule() || $context->object->isDefaultSecurityRule() )
            return FALSE;

        return $context->object->sourceIsNegated();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dst']['operators']['is.negated'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->isNatRule() || $context->object->isDefaultSecurityRule() )
            return FALSE;

        return $context->object->destinationIsNegated();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['src']['operators']['included-in.full'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->source->includedInIP4Network($context->value) == 1;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['src']['operators']['included-in.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->source->includedInIP4Network($context->value) == 2;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['src']['operators']['included-in.full.or.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->source->includedInIP4Network($context->value) > 0;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['src']['operators']['includes.full'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->source->includesIP4Network($context->value) == 1;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['src']['operators']['includes.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->source->includesIP4Network($context->value) == 2;
    },
    'arg' => TRUE
,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['src']['operators']['includes.full.or.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->source->includesIP4Network($context->value) > 0;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['src']['operators']['is.fully.included.in.list'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $f = RQuery::$commonFilters['src-dst']['xxx-is.fully.included.in.list'];
        return $f($context, $context->object->source);
    },
    'arg' => TRUE,
    'argType' => 'commaSeparatedList'
);
RQuery::$defaultFilters['rule']['src']['operators']['is.partially.or.fully.included.in.list'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $f = RQuery::$commonFilters['src-dst']['xxx-is.partially.or.fully.included.in.list'];
        return $f($context, $context->object->source);
    },
    'arg' => TRUE,
    'argType' => 'commaSeparatedList'
);
RQuery::$defaultFilters['rule']['src']['operators']['is.partially.included.in.list'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $f = RQuery::$commonFilters['src-dst']['xxx-is.partially.included.in.list'];
        return $f($context, $context->object->source);
    },
    'arg' => TRUE,
    'argType' => 'commaSeparatedList'
);

RQuery::$defaultFilters['rule']['src']['operators']['is.fully.included.in.file'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $f = RQuery::$commonFilters['src-dst']['xxx-is.fully.included.in.file'];
        return $f($context, $context->object->source);
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['rule']['src']['operators']['is.partially.or.fully.included.in.file'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $f = RQuery::$commonFilters['src-dst']['xxx-is.partially.or.fully.included.in.file'];
        return $f($context, $context->object->source);
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['rule']['src']['operators']['is.partially.included.in.file'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $f = RQuery::$commonFilters['src-dst']['xxx-is.partially.included.in.file'];
        return $f($context, $context->object->source);
    },
    'arg' => TRUE
);

RQuery::$defaultFilters['rule']['dst']['operators']['included-in.full'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->destination->includedInIP4Network($context->value) == 1;
    },
    'arg' => TRUE,
    'argDesc' => 'ie: 192.168.0.0/24 | 192.168.50.10/32 | 192.168.50.10 | 10.0.0.0-10.33.0.0',
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dst']['operators']['included-in.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->destination->includedInIP4Network($context->value) == 2;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dst']['operators']['included-in.full.or.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->destination->includedInIP4Network($context->value) > 0;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dst']['operators']['includes.full'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->destination->includesIP4Network($context->value) == 1;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dst']['operators']['includes.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->destination->includesIP4Network($context->value) == 2;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['dst']['operators']['includes.full.or.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->destination->includesIP4Network($context->value) > 0;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['src']['operators']['has.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->source->count() == 0 )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('address');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->source->all() as $member )
        {
            if( $rQuery->matchSingleObject(array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'example: \'filter=(src has.from.query subquery1)\' \'subquery1=(value ip4.includes-full 10.10.0.1)\'',
);
RQuery::$defaultFilters['rule']['dst']['operators']['has.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->destination->count() == 0 )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('address');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->destination->all() as $member )
        {
            if( $rQuery->matchSingleObject(array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'example: \'filter=(dst has.from.query subquery1)\' \'subquery1=(value ip4.includes-full 10.10.0.1)\'',
);
RQuery::$defaultFilters['rule']['src']['operators']['has.recursive.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->source->count() == 0 )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('address');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->source->membersExpanded() as $member )
        {
            if( $rQuery->matchSingleObject(array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['rule']['dst']['operators']['has.recursive.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->destination->count() == 0 )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('address');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        #foreach( $context->object->destination->all() as $member )
        foreach( $context->object->destination->membersExpanded() as $member )
        {
            if( $rQuery->matchSingleObject(array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['rule']['service']['operators']['has.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->services->count() == 0 )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('service');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->services->all() as $member )
        {
            if( $rQuery->matchSingleObject(array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'example: \'filter=(service has.from.query subquery1)\' \'subquery1=(value regex 8443)\'',
);
RQuery::$defaultFilters['rule']['service']['operators']['has.recursive.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->services->count() == 0 )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('service');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->services->all() as $member )
        {
            if( $rQuery->matchSingleObject(array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE
);

RQuery::$defaultFilters['rule']['dst']['operators']['is.fully.included.in.list'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $f = RQuery::$commonFilters['src-dst']['xxx-is.fully.included.in.list'];
        return $f($context, $context->object->destination);
    },
    'arg' => TRUE,
    'argType' => 'commaSeparatedList'
);
RQuery::$defaultFilters['rule']['dst']['operators']['is.partially.or.fully.included.in.list'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $f = RQuery::$commonFilters['src-dst']['xxx-is.partially.or.fully.included.in.list'];
        return $f($context, $context->object->destination);
    },
    'arg' => TRUE,
    'argType' => 'commaSeparatedList'
);
RQuery::$defaultFilters['rule']['dst']['operators']['is.partially.included.in.list'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $f = RQuery::$commonFilters['src-dst']['xxx-is.partially.included.in.list'];
        return $f($context, $context->object->destination);
    },
    'arg' => TRUE,
    'argType' => 'commaSeparatedList'
);

RQuery::$defaultFilters['rule']['dst']['operators']['is.fully.included.in.file'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $f = RQuery::$commonFilters['src-dst']['xxx-is.fully.included.in.file'];
        return $f($context, $context->object->destination);
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['rule']['dst']['operators']['is.partially.or.fully.included.in.file'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $f = RQuery::$commonFilters['src-dst']['xxx-is.partially.or.fully.included.in.file'];
        return $f($context, $context->object->destination);
    },
    'arg' => TRUE
);
RQuery::$defaultFilters['rule']['dst']['operators']['is.partially.included.in.file'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $f = RQuery::$commonFilters['src-dst']['xxx-is.partially.included.in.file'];
        return $f($context, $context->object->destination);
    },
    'arg' => TRUE
);

//                                                //
//                Tag Based filters              //
//                                              //
RQuery::$defaultFilters['rule']['tag']['operators']['has'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->tags->hasTag($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->tags->parentCentralStore->find('!value!');",
    'ci' => array(
        'fString' => '(%PROP% test.tag)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['tag']['operators']['has.nocase'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->tags->hasTag($context->value, FALSE) === TRUE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% test.tag)',
        'input' => 'input/panorama-8.0.xml'
    )

);
RQuery::$defaultFilters['rule']['tag']['operators']['has.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {

        if( !isset( $context->object->tags ) )
            return FALSE;

        foreach( $context->object->tags->tags() as $tag )
        {
            $matching = preg_match($context->value, $tag->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /test-/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['tag.count']['operators']['>,<,=,!'] = array(
    'eval' => "\$object->tags->count() !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
//                                                //
//                Group-Tag Based filters              //
//                                              //
RQuery::$defaultFilters['rule']['group-tag']['operators']['is'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->grouptag->hasTag( $value ) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->tags->parentCentralStore->find('!value!');",
    'ci' => array(
        'fString' => '(%PROP% test.tag)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['group-tag']['operators']['is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDoSRule() &&  !$rule->isPbfRule() && !$rule->isQoSRule() )
            return FALSE;

        if( count($rule->grouptag->getAll() ) > 0 )
            return TRUE;

        return FALSE;
    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['group-tag']['operators']['is.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {

        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDoSRule() &&  !$rule->isPbfRule() && !$rule->isQoSRule() )
            return FALSE;

        $grouptags = $rule->grouptag->getAll();
        foreach($grouptags as $grouptag)
        {
            if( is_object( $grouptag ) )
            {
                $matching = preg_match($context->value, $grouptag->name());
                if( $matching === FALSE )
                    derr("regular expression error on '{$context->value}'");
                if( $matching === 1 )
                    return TRUE;
            }
        }


        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /test-/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
//                                              //
//          Application properties              //
//                                              //
RQuery::$defaultFilters['rule']['app']['operators']['is.any'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        return ($rule->isSecurityRule() || $rule->isQoSRule()) && $rule->apps->isAny();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['app']['operators']['has'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->apps->hasApp($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->apps->parentCentralStore->find('!value!');",
);
RQuery::$defaultFilters['rule']['app']['operators']['has.nocase'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        return ($rule->isSecurityRule() || $rule->isQoSRule()) && $rule->apps->hasApp($context->value, FALSE) === TRUE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% icmp)',
        'input' => 'input/panorama-8.0.xml'
    )
    //'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->tags->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['app']['operators']['has.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( !isset( $context->object->apps ) )
            return FALSE;

        foreach( $context->object->apps->apps() as $app )
        {
            $matching = preg_match($context->value, $app->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /test-/)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['app']['operators']['has.recursive'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !isset( $rule->apps ) )
            return FALSE;

        foreach( $rule->apps->getAll() as $app)
        {

            if( !$app->isApplicationGroup() &&  !$app->isContainer())
                continue;

            $member = $app->owner->find( $context->value );
            if( $member !== null)
            {
                $references = $member->getReferences();
                foreach( $references as $ref )
                {
                    /** @var ReferenceableObject $ref */
                    if( get_class( $ref->owner ) == "AppStore" )
                    {
                        if( $ref === $app )
                            return TRUE;
                    }
                }
            }
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% ssl)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['app']['operators']['includes.full.or.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !isset( $rule->apps ) )
            return FALSE;

        /** @var Rule|SecurityRule|AppOverrideRule|PbfRule|QoSRule $object */
        return $rule->apps->includesApp($context->value) === TRUE;
    },
    'arg' => TRUE,
    #'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->apps->parentCentralStore->find('!value!');",
    'ci' => array(
        'fString' => '(%PROP% ssl)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['app']['operators']['includes.full.or.partial.nocase'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !isset( $rule->apps ) )
            return FALSE;

        return $rule->apps->includesApp($context->value, FALSE) === TRUE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% ssl)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['app']['operators']['included-in.full.or.partial'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !isset( $rule->apps ) )
            return FALSE;

        /** @var Rule|SecurityRule|AppOverrideRule|PbfRule|QoSRule $object */
        return $rule->apps->includedInApp($context->value) === TRUE;
    },
    'arg' => TRUE,
    #'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->apps->parentCentralStore->find('!value!');",
    'ci' => array(
        'fString' => '(%PROP% ssl)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['app']['operators']['included-in.full.or.partial.nocase'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !isset( $rule->apps ) )
            return FALSE;

        return $rule->apps->includedInApp($context->value, FALSE) === TRUE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% ssl)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['app']['operators']['custom.has.signature'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !isset( $rule->apps ) )
            return FALSE;

        /** @var Rule|SecurityRule|AppOverrideRule|PbfRule|QoSRule $object */
        return $rule->apps->customApphasSignature();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['app']['operators']['has.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->apps->count() == 0 )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('application');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->apps->getAll() as $member )
        {
            if( $rQuery->matchSingleObject(array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'example: \'filter=(app has.from.query subquery1)\' \'subquery1=(object is.application-group)\'',
);

RQuery::$defaultFilters['rule']['app']['operators']['has.seen.fast'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        #if( !$context->isAPI )
        #    derr( "this filter is only supported in API mode", null, false );

        $rule_array = $rule->API_apps_seen();

        if( isset($rule_array['apps-seen']) && in_array( $context->value, array_keys($rule_array['apps-seen'])) )
            return TRUE;

        return null;
    },
    'arg' => TRUE,
    'help' => 'example: \'filter=(app has.seen.fast unknown-tcp)\'',
);

//                                              //
//          Services properties                 //
//                                              //
RQuery::$defaultFilters['rule']['service']['operators']['is.any'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isNatRule() )
            return $rule->service === null;

        if( $rule->services ===  null )
            return false;

        return $rule->services->isAny();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['service']['operators']['is.application-default'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->isSecurityRule() && $context->object->services->isApplicationDefault();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['service']['operators']['no.app-default.ports'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
            return FALSE;

        if( $rule->services->isApplicationDefault())
            return false;

        if( $rule->services->isAny() && $rule->apps->isAny())
            return false;

        $service_ports = $rule->ServiceResolveSummary(  );
        $service_ports_appdefault = $rule->ServiceAppDefaultResolveSummary(  );

        foreach( $service_ports as $key => $service_port )
        {
            if( !array_key_exists( $key, $service_ports_appdefault ) )
                return true;
        }

        return false;
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['service']['operators']['has'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        return $object->isSecurityRule() && $object->services->has($value) === TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->services->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['service']['operators']['has.only'] = array(
    'eval' => function ($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|PbfRule|QoSRule|DoSRule $object */
        if( $object->isNatRule() )
        {
            if( $object->service === null )
                return FALSE;
            return $object->service === $value;
        }
        if( $object->services === null )
            return FALSE;

        if( $object->services->count() != 1 || !$object->services->has($value) )
            return FALSE;

        return TRUE;
    },
    'arg' => TRUE,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->services->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['service']['operators']['has.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( $rule->isNatRule() )
        {
            if( $rule->service === null )
                return FALSE;
            $matching = preg_match($context->value, $rule->service->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
            return FALSE;
        }

        if( $rule->services === null )
            return FALSE;

        foreach( $rule->services->all() as $service )
        {
            $matching = preg_match($context->value, $service->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /tcp-/)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['service']['operators']['has.recursive'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        /** @var Service|ServiceGroup $value */
        $value = $context->value;

        if( $rule->isNatRule() )
        {
            if( $rule->service === null )
                return FALSE;

            if( $rule->service->name() == $value )
                return TRUE;

            if( !$rule->service->isGroup() )
                return FALSE;

            return $rule->service->hasNamedObjectRecursive($value);
        }

        if( $rule->services === null )
            return FALSE;

        return $rule->services->hasNamedObjectRecursive($value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% tcp-80)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['service']['operators']['is.tcp.only'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( $rule->isNatRule() )
        {
            mwarning("this filter does not yet support NAT Rules");
            return FALSE;
        }

        if( $rule->services === null )
            return FALSE;

        /** @var Service|ServiceGroup $value */
        $objects = $rule->services->all();

        foreach( $objects as $object )
        {
            if( $object->isTmpSrv() )
                return FALSE;

            if( $object->isGroup() )
            {
                $port_mapping = $object->dstPortMapping();
                $port_mapping_text = $port_mapping->mappingToText();

                if( strpos($port_mapping_text, "udp") !== FALSE )
                    return FALSE;
            }
            elseif( $object->isUdp() )
                return FALSE;
        }

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['service']['operators']['is.udp.only'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( $rule->isNatRule() )
        {
            mwarning("this filter does not yet support NAT Rules");
            return FALSE;
        }

        if( $rule->services === null )
            return FALSE;

        /** @var Service|ServiceGroup $value */
        $objects = $rule->services->all();
        foreach( $objects as $object )
        {
            if( $object->isTmpSrv() )
                return FALSE;

            if( $object->isGroup() )
            {
                $port_mapping = $object->dstPortMapping();
                $port_mapping_text = $port_mapping->mappingToText();

                if( strpos($port_mapping_text, "tcp") !== FALSE )
                    return FALSE;
            }
            elseif( $object->isTcp() )
                return FALSE;
        }

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['service']['operators']['is.tcp'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $isTCP = FALSE;
        $rule = $context->object;

        if( $rule->isNatRule() )
        {
            mwarning("this filter does not yet support NAT Rules");
            return FALSE;
        }

        if( $rule->services === null )
            return FALSE;

        /** @var Service|ServiceGroup $value */
        $objects = $rule->services->all();

        foreach( $objects as $object )
        {
            if( $object->isTmpSrv() )
                return FALSE;

            if( $object->isGroup() )
            {
                $port_mapping = $object->dstPortMapping();
                $port_mapping_text = $port_mapping->mappingToText();

                if( strpos($port_mapping_text, "tcp") !== FALSE )
                    $isTCP = TRUE;
            }
            elseif( $object->isTcp() )
                $isTCP = TRUE;
        }

        return $isTCP;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['service']['operators']['is.udp'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $isUDP = FALSE;
        $rule = $context->object;

        if( $rule->isNatRule() )
        {
            mwarning("this filter does not yet support NAT Rules");
            return FALSE;
        }

        if( $rule->services === null )
            return FALSE;

        /** @var Service|ServiceGroup $value */
        $objects = $rule->services->all();
        foreach( $objects as $object )
        {
            if( $object->isTmpSrv() )
                return FALSE;

            if( $object->isGroup() )
            {
                $port_mapping = $object->dstPortMapping();
                $port_mapping_text = $port_mapping->mappingToText();

                if( strpos($port_mapping_text, "udp") !== FALSE )
                    $isUDP = TRUE;
            }
            elseif( $object->isUdp() )
                $isUDP = TRUE;
        }

        return $isUDP;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['service']['operators']['has.value.recursive'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $value = $context->value;
        $rule = $context->object;

        if( $rule->isNatRule() )
        {
            mwarning("this filter does not yet support NAT Rules");
            return FALSE;
        }

        if( $rule->services === null )
            return FALSE;

        return $rule->services->hasValue($value, TRUE);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 443)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['service']['operators']['has.value'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $value = $context->value;
        $rule = $context->object;

        if( $rule->isNatRule() )
        {
            mwarning("this filter does not yet support NAT Rules");
            return FALSE;
        }

        if( $rule->services === null )
            return FALSE;

        return $rule->services->hasValue($value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 443)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['service']['operators']['has.value.only'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $value = $context->value;
        $rule = $context->object;

        if( $rule->isNatRule() )
        {
            mwarning("this filter does not yet support NAT Rules");
            return FALSE;
        }

        if( $rule->services === null )
            return FALSE;

        if( $rule->services->count() != 1 )
            return FALSE;

        return $rule->services->hasValue($value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 443)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['service']['operators']['timeout.is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $value = $context->value;
        $rule = $context->object;

        if( $rule->isNatRule() )
        {
            mwarning("this filter does not yet support NAT Rules");
            return FALSE;
        }

        if( $rule->services === null )
            return FALSE;

        foreach( $rule->services->getAll() as $object )
        {
            /** @var Service|ServiceGroup $object */
            if( $object->isService() && !empty( $object->getTimeout()) )
                return true;
            elseif( $object->isGroup() && $object->hasTimeoutRecursive() )
                return true;
        }

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['service.port.count']['operators']['>,<,=,!'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $counter = $context->value;
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
        {
            mwarning("this filter does only yet support Security Rules", null, FALSE);
            return FALSE;
        }

        $calculatedCounter = $context->ServiceCount( $rule, "both");

        $operator = $context->operator;
        if( $operator == '=' )
            $operator = '==';

        $operator_string = $calculatedCounter." ".$operator." ".$counter;
        if( eval("return $operator_string;" ) )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 443)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['service.port.tcp.count']['operators']['>,<,=,!'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $counter = $context->value;
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
        {
            mwarning("this filter does only yet support Security Rules", null, FALSE);
            return FALSE;
        }

        $calculatedCounter = $context->ServiceCount( $rule, "tcp");

        $operator = $context->operator;
        if( $operator == '=' )
            $operator = '==';

        $operator_string = $calculatedCounter." ".$operator." ".$counter;
        if( eval("return $operator_string;" ) )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 443)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['service.port.udp.count']['operators']['>,<,=,!'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $counter = $context->value;
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
        {
            mwarning("this filter does only yet support Security Rules", null, FALSE);
            return FALSE;
        }

        $calculatedCounter = $context->ServiceCount( $rule, "udp");

        $operator = $context->operator;
        if( $operator == '=' )
            $operator = '==';

        $operator_string = $calculatedCounter." ".$operator." ".$counter;
        if( eval("return $operator_string;" ) )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 443)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['service.object.count']['operators']['>,<,=,!'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $counter = $context->value;
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
        {
            mwarning("this filter does only yet support Security Rules", null, FALSE);
            return FALSE;
        }

        $calculatedCounter = 0;
        foreach( $rule->services->getAll() as $object )
        {
            /** @var Service|ServiceGroup $object */
            if( $object->isService() )
                $calculatedCounter++;
            elseif( $object->isGroup() )
                $calculatedCounter = $calculatedCounter + $object->countObjectsRecursive();
        }

        $operator = $context->operator;
        if( $operator == '=' )
            $operator = '==';

        $operator_string = $calculatedCounter." ".$operator." ".$counter;
        if( eval("return $operator_string;" ) )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 443)',
        'input' => 'input/panorama-8.0.xml'
    )
);
//
//                                              //
//                SecurityProfile properties    //
//                                              //
RQuery::$defaultFilters['rule']['secprof']['operators']['not.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() && !$context->object->isDefaultSecurityRule() )
            return FALSE;

        return $context->object->securityProfileIsBlank();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() && !$context->object->isDefaultSecurityRule() )
            return FALSE;

        return !$context->object->securityProfileIsBlank();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['type.is.profile'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;
        return  !$context->object->securityProfileIsBlank()
            && $context->object->securityProfileType() == "profile";
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['type.is.group'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;
        return  !$context->object->securityProfileIsBlank()
            && $context->object->securityProfileType() == "group";
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['group.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;

        return $rule->securityProfileType() == "group"
            && $rule->securityProfileGroup() == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% secgroup-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['group.is.undefined'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;

        if( $rule->secprofgroupUndefined === null )
            return FALSE;

        return !$rule->secprofgroupUndefined;
    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['is.best-practice'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        return $rule->SP_isBestPractice();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['is.visibility'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        return $rule->SP_isVisibility();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['av-profile.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();
        if( !isset($profiles['virus']) )
            return FALSE;

        if( is_object($profiles['virus']) )
            return $profiles['virus']->name() == $context->value;
        else
            return $profiles['virus'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% av-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['as-profile.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();
        if( !isset($profiles['spyware']) )
            return FALSE;

        if( is_object($profiles['spyware']) )
            return $profiles['spyware']->name() == $context->value;
        else
            return $profiles['spyware'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% as-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['url-profile.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();
        if( !isset($profiles['url-filtering']) )
            return FALSE;

        if( is_object($profiles['url-filtering']) )
            return $profiles['url-filtering']->name() == $context->value;
        else
            return $profiles['url-filtering'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% url-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['wf-profile.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();
        if( !isset($profiles['wildfire-analysis']) )
            return FALSE;

        if( is_object($profiles['wildfire-analysis']) )
            return $profiles['wildfire-analysis']->name() == $context->value;
        else
            return $profiles['wildfire-analysis'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% wf-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['vuln-profile.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();
        if( !isset($profiles['vulnerability']) )
            return FALSE;

        if( is_object($profiles['vulnerability']) )
            return $profiles['vulnerability']->name() == $context->value;
        else
            return $profiles['vulnerability'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% vuln-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['file-profile.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();
        if( !isset($profiles['file-blocking']) )
            return FALSE;

        if( is_object($profiles['file-blocking']) )
            return $profiles['file-blocking']->name() == $context->value;
        else
            return $profiles['file-blocking'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% vuln-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['data-profile.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
            return FALSE;

        $profiles = $rule->securityProfiles();
        if( !isset($profiles['data-filtering']) )
            return FALSE;

        if( is_object($profiles['data-filtering']) )
            return $profiles['data-filtering']->name() == $context->value;
        else
            return $profiles['data-filtering'] == $context->value;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% vuln-production)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['av-profile.is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
        {
            /** @var SecurityProfileGroup $tmp_group */
            $tmp_group =  $rule->owner->owner->securityProfileGroupStore->find( $rule->securityProfileGroup() );
            $secprof_objects = $tmp_group->securityProfiles();
        }
        else
            $secprof_objects = $rule->securityProfiles();

        return isset($secprof_objects['virus']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['as-profile.is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
        {
            /** @var SecurityProfileGroup $tmp_group */
            $tmp_group =  $rule->owner->owner->securityProfileGroupStore->find( $rule->securityProfileGroup() );
            $secprof_objects = $tmp_group->securityProfiles();
        }
        else
            $secprof_objects = $rule->securityProfiles();

        return isset($secprof_objects['spyware']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['url-profile.is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
        {
            /** @var SecurityProfileGroup $tmp_group */
            $tmp_group =  $rule->owner->owner->securityProfileGroupStore->find( $rule->securityProfileGroup() );
            $secprof_objects = $tmp_group->securityProfiles();
        }
        else
            $secprof_objects = $rule->securityProfiles();

        return isset($secprof_objects['url-filtering']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['wf-profile.is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
        {
            /** @var SecurityProfileGroup $tmp_group */
            $tmp_group =  $rule->owner->owner->securityProfileGroupStore->find( $rule->securityProfileGroup() );
            $secprof_objects = $tmp_group->securityProfiles();
        }
        else
            $secprof_objects = $rule->securityProfiles();

        return isset($secprof_objects['wildfire-analysis']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['vuln-profile.is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
        {
            /** @var SecurityProfileGroup $tmp_group */
            $tmp_group =  $rule->owner->owner->securityProfileGroupStore->find( $rule->securityProfileGroup() );
            $secprof_objects = $tmp_group->securityProfiles();
        }
        else
            $secprof_objects = $rule->securityProfiles();

        return isset($secprof_objects['vulnerability']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['file-profile.is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
        {
            /** @var SecurityProfileGroup $tmp_group */
            $tmp_group =  $rule->owner->owner->securityProfileGroupStore->find( $rule->securityProfileGroup() );
            $secprof_objects = $tmp_group->securityProfiles();
        }
        else
            $secprof_objects = $rule->securityProfiles();

        return isset($secprof_objects['file-blocking']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['data-profile.is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;

        if( $rule->securityProfileIsBlank() )
            return FALSE;

        if( $rule->securityProfileType() == "group" )
        {
            /** @var SecurityProfileGroup $tmp_group */
            $tmp_group =  $rule->owner->owner->securityProfileGroupStore->find( $rule->securityProfileGroup() );
            $secprof_objects = $tmp_group->securityProfiles();
        }
        else
            $secprof_objects = $rule->securityProfiles();

        return isset($secprof_objects['data-filtering']);
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['secprof']['operators']['has.from.query'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( $context->object->securityProfileIsBlank() )
            return FALSE;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");


        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('securityprofile');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === FALSE )
                derr('nested query execution error : ' . $errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        if( $rule->securityProfileType() == "group" )
        {
            /** @var SecurityProfileGroup $tmp_group */
            $tmp_group =  $rule->owner->owner->securityProfileGroupStore->find( $rule->securityProfileGroup() );
            $secprof_objects = $tmp_group->securityProfiles();
        }
        else
            $secprof_objects = $rule->securityProfiles();

        foreach( $secprof_objects as $key => $member )
        {
            if( $member !== null )
            {
                if( $rQuery->matchSingleObject(array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                    return TRUE;
            }
        }

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'example: \'filter=(secprof has.from.query subquery1)\' \'subquery1=(av is.best-practice)\'',
);

//                                              //
//                Other properties              //
//                                              //
RQuery::$defaultFilters['rule']['action']['operators']['is.deny'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() && !$context->object->isDefaultSecurityRule() )
            return FALSE;
        return $context->object->actionIsDeny();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['action']['operators']['is.negative'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() && !$context->object->isDefaultSecurityRule() )
            return FALSE;
        return $context->object->actionIsNegative();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['action']['operators']['is.allow'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() && !$context->object->isDefaultSecurityRule() )
            return FALSE;
        return $context->object->actionIsAllow();
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['rule']['action']['operators']['is.drop'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() && !$context->object->isDefaultSecurityRule() )
            return FALSE;
        return $context->object->actionIsDrop();
    },
    'arg' => FALSE
);
RQuery::$defaultFilters['rule']['log']['operators']['at.start'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() && !$context->object->isDefaultSecurityRule() )
            return FALSE;
        return $context->object->logStart();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['log']['operators']['at.end'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() && !$context->object->isDefaultSecurityRule() )
            return FALSE;
        return $context->object->logEnd();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['logprof']['operators']['is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;

        if( $rule->logSetting() === null || $rule->logSetting() == '' )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['logprof']['operators']['is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDefaultSecurityRule() )
            return FALSE;

        if( $rule->logSetting() === null )
            return FALSE;

        if( $rule->logSetting() == $context->value )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'return true if Log Forwarding Profile is the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  log_to_panorama)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.prerule'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->isPreRule();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.postrule'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->isPostRule();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.disabled'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->isDisabled();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.enabled'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->isEnabled();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.dsri'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() )
            return FALSE;
        return $context->object->isDSRIEnabled();
    },
    'arg' => FALSE,
    'help' => 'return TRUE if Disable Server Response Inspection has been enabled'
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.bidir.nat'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() )
            return FALSE;

        return $context->object->isBiDirectional();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['rule']['operators']['has.source.nat'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() )
            return FALSE;

        if( !$context->object->sourceNatTypeIs_None() )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['rule']['operators']['has.destination.nat'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isNatRule() )
            return FALSE;

        if( $context->object->destinationNatIsEnabled() )
            return TRUE;

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['rule']['operators']['is.universal'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( !$context->object->isSecurityRule() )
            return TRUE;

        if( $context->object->type() != 'universal' )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['rule']['operators']['is.intrazone'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->owner->owner->version < 61 )
            return FALSE;

        if( !$context->object->isSecurityRule() )
            return FALSE;

        if( $context->object->type() != 'intrazone' )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['rule']['operators']['is.interzone'] = array(
    'Function' => function (RuleRQueryContext $context) {
        if( $context->object->owner->owner->version < 61 )
            return FALSE;

        if( !$context->object->isSecurityRule() )
            return FALSE;

        if( $context->object->type() != 'interzone' )
            return FALSE;

        return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['location']['operators']['is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $owner = $context->object->owner->owner;
        if( strtolower($context->value) == 'shared' )
        {
            if( $owner->isPanorama() )
                return TRUE;
            if( $owner->isFirewall() )
                return TRUE;
            return FALSE;
        }
        if( strtolower($context->value) == strtolower($owner->name()) )
            return TRUE;

        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  Datacenter)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['location']['operators']['regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $name = $context->object->getLocationString();
        $matching = preg_match($context->value, $name);
        if( $matching === FALSE )
            derr("regular expression error on '{$context->value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches the regular expression specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  /DC/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['location']['operators']['is.child.of'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule_location = $context->object->getLocationString();

        $sub = $context->object->owner;
        while( get_class($sub) == "RuleStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
            $sub = $sub->owner;

        if( get_class($sub) == "PANConf" )
            derr("filter location is.child.of is not working against a firewall configuration");

        if( strtolower($context->value) == 'shared' )
            return TRUE;

        $DG = $sub->findDeviceGroup($context->value);
        if( $DG == null )
        {
            PH::print_stdout( "ERROR: location '$context->value' was not found. Here is a list of available ones:" );
            PH::print_stdout( " - shared" );
            foreach( $sub->getDeviceGroups() as $sub1 )
            {
                PH::print_stdout( " - " . $sub1->name()  );
            }
            PH::print_stdout();
            exit(1);
        }

        $childDeviceGroups = $DG->childDeviceGroups(TRUE);

        if( strtolower($context->value) == strtolower($rule_location) )
            return TRUE;

        foreach( $childDeviceGroups as $childDeviceGroup )
        {
            if( $childDeviceGroup->name() == $rule_location )
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
RQuery::$defaultFilters['rule']['location']['operators']['is.parent.of'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule_location = $context->object->getLocationString();

        $sub = $context->object->owner;
        while( get_class($sub) == "RuleStore" || get_class($sub) == "DeviceGroup" || get_class($sub) == "VirtualSystem" )
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
                PH::print_stdout( " - " . $sub1->name() . "" );
            }
            PH::print_stdout( "\n" );
            exit(1);
        }

        $parentDeviceGroups = $DG->parentDeviceGroups();

        if( strtolower($context->value) == strtolower($rule_location) )
            return TRUE;

        if( $rule_location == 'shared' )
            return TRUE;

        foreach( $parentDeviceGroups as $childDeviceGroup )
        {
            if( $childDeviceGroup->name() == $rule_location )
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
RQuery::$defaultFilters['rule']['rule']['operators']['is.unused.fast'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $object = $context->object;

        if( !$object->isSecurityRule() && !$object->isNatRule() )
            derr("unsupported filter : rule type " . $object->ruleNature() . " is not supported yet. " . $object->toString());



        return $object->ruleUsageFast( $context, 'hit-count' );

    },
    'arg' => false
);

RQuery::$defaultFilters['rule']['timestamp-last-hit.fast']['operators']['>,<,=,!'] = array(
#RQuery::$defaultFilters['rule']['rule']['operators']['last-hit-timestamp'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $object = $context->object;

        if( !$object->isSecurityRule() && !$object->isNatRule() )
            derr("unsupported filter : rule type " . $object->ruleNature() . " is not supported yet. " . $object->toString());

        $str = $context->value;
        if (($timestamp = strtotime($str)) === false)
        {
            #echo "The string ($str) is bogus"."\n";
        }
        else
        {
            #echo "$str == " . date('l dS \o\f F Y h:i:s A', $timestamp)."\n";
        }

        return $object->ruleUsageFast( $context, 'last-hit-timestamp' );
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if rule name matches the specified timestamp MM/DD/YYYY [american] / DD-MM-YYYY [european] / 21 September 2021 / -90 days',
);

RQuery::$defaultFilters['rule']['timestamp-first-hit.fast']['operators']['>,<,=,!'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $object = $context->object;

        if( !$object->isSecurityRule() && !$object->isNatRule() )
            derr("unsupported filter : rule type " . $object->ruleNature() . " is not supported yet. " . $object->toString());

        $str = $context->value;
        if (($timestamp = strtotime($str)) === false)
        {
            #echo "The string ($str) is bogus"."\n";
        }
        else
        {
            #echo "$str == " . date('l dS \o\f F Y h:i:s A', $timestamp)."\n";
        }

        return $object->ruleUsageFast( $context, 'first-hit-timestamp' );
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if rule name matches the specified timestamp MM/DD/YYYY [american] / DD-MM-YYYY [european] / 21 September 2021 / -90 days',
);
RQuery::$defaultFilters['rule']['timestamp-rule-creation.fast']['operators']['>,<,=,!'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $object = $context->object;

        if( !$object->isSecurityRule() && !$object->isNatRule() )
            derr("unsupported filter : rule type " . $object->ruleNature() . " is not supported yet. " . $object->toString());

        $str = $context->value;
        if (($timestamp = strtotime($str)) === false)
        {
            #echo "The string ($str) is bogus"."\n";
        }
        else
        {
            #echo "$str == " . date('l dS \o\f F Y h:i:s A', $timestamp)."\n";
        }

        return $object->ruleUsageFast( $context, 'rule-creation-timestamp' );
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if rule name matches the specified timestamp MM/DD/YYYY [american] / DD-MM-YYYY [european] / 21 September 2021 / -90 days',
);
RQuery::$defaultFilters['rule']['timestamp-rule-modification.fast']['operators']['>,<,=,!'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $object = $context->object;

        if( !$object->isSecurityRule() && !$object->isNatRule() )
            derr("unsupported filter : rule type " . $object->ruleNature() . " is not supported yet. " . $object->toString());

        $str = $context->value;
        if (($timestamp = strtotime($str)) === false)
        {
            #echo "The string ($str) is bogus"."\n";
        }
        else
        {
            #echo "$str == " . date('l dS \o\f F Y h:i:s A', $timestamp)."\n";
        }

        return $object->ruleUsageFast( $context, 'rule-modification-timestamp' );
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if rule name matches the specified timestamp MM/DD/YYYY [american] / DD-MM-YYYY [european] / 21 September 2021 / -90 days',
);
RQuery::$defaultFilters['rule']['hit-count.fast']['operators']['>,<,=,!'] = array(
#RQuery::$defaultFilters['rule']['rule']['operators']['last-hit-timestamp'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $object = $context->object;

        if( !$object->isSecurityRule() && !$object->isNatRule() )
            derr("unsupported filter : rule type " . $object->ruleNature() . " is not supported yet. " . $object->toString());

        return $object->ruleUsageFast( $context, 'hit-count' );
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if rule name matches the specified hit count value',
);


RQuery::$defaultFilters['rule']['name']['operators']['eq'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->name() == $context->value;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if rule name matches the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  rule1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['name']['operators']['regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $matching = preg_match($context->value, $context->object->name());
        if( $matching === FALSE )
            derr("regular expression error on '{$context->value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if rule name matches the regular expression provided in argument',
    'ci' => array(
        'fString' => '(%PROP%  /^example/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['name']['operators']['eq.nocase'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return strtolower($context->object->name()) == strtolower($context->value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP%  rule1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['name']['operators']['contains'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return stripos($context->object->name(), $context->value) !== FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP%  searchME)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['name']['operators']['is.in.file'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $object = $context->object;

        if( !isset($context->cachedList) )
        {
            $text = file_get_contents($context->value);

            if( $text === FALSE )
                derr("cannot open file '{$context->value}");

            $lines = explode("\n", $text);
            foreach( $lines as $line )
            {
                $line = trim($line);
                if( strlen($line) == 0 )
                    continue;
                $list[$line] = TRUE;
            }

            $context->cachedList = &$list;
        }
        else
            $list = &$context->cachedList;

        return isset($list[$object->name()]);
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if rule name matches one of the names found in text file provided in argument'
);
RQuery::$defaultFilters['rule']['name']['operators']['has.wrong.characters'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $object = $context->object;

        $newName = htmlspecialchars_decode( $object->name() );
        preg_match_all('/[^\w $\-.]/', $newName, $matches , PREG_SET_ORDER, 0);

        if( count($matches) == 0 )
            return FALSE;
        else
            return TRUE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

//                                              //
//                UserID properties             //
//                                              //
RQuery::$defaultFilters['rule']['user']['operators']['is.any'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isDecryptionRule() )
            return FALSE;
        if( $rule->isNatRule() )
            return FALSE;
        if( $rule->isAppOverrideRule() )
            return FALSE;
        if( $rule->isDefaultSecurityRule() )
            return FALSE;

        return $rule->userID_IsAny();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['user']['operators']['is.known'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isDecryptionRule() )
            return FALSE;
        if( $rule->isNatRule() )
            return FALSE;
        if( $rule->isAppOverrideRule() )
            return FALSE;
        if( $rule->isDefaultSecurityRule() )
            return FALSE;

        return $rule->userID_IsKnown();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['user']['operators']['is.unknown'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isDecryptionRule() )
            return FALSE;
        if( $rule->isNatRule() )
            return FALSE;
        if( $rule->isAppOverrideRule() )
            return FALSE;
        if( $rule->isDefaultSecurityRule() )
            return FALSE;

        return $rule->userID_IsUnknown();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['user']['operators']['is.prelogon'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isDecryptionRule() )
            return FALSE;
        if( $rule->isNatRule() )
            return FALSE;
        if( $rule->isAppOverrideRule() )
            return FALSE;
        if( $rule->isDefaultSecurityRule() )
            return FALSE;

        return $rule->userID_IsPreLogon();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['user']['operators']['has'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isDecryptionRule() )
            return FALSE;
        if( $rule->isNatRule() )
            return FALSE;
        if( $rule->isAppOverrideRule() )
            return FALSE;
        if( $rule->isDefaultSecurityRule() )
            return FALSE;

        $users = $rule->userID_getUsers();

        if (in_array($context->value, $users)) {
            return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% CN=xyz,OU=Network)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['user']['operators']['has.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( $rule->isDecryptionRule() )
            return FALSE;
        if( $rule->isNatRule() )
            return FALSE;
        if( $rule->isAppOverrideRule() )
            return FALSE;
        if( $rule->isDefaultSecurityRule() )
            return FALSE;

        $users = $rule->userID_getUsers();

        foreach( $users as $user )
        {
            $searchString = str_replace( "\\", "\\\\", $context->value);

            $matching = preg_match($searchString, $user);
            if( $matching === FALSE )
                derr("regular expression error on '{$searchString}'");
            if( $matching === 1 )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /^test/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['user']['operators']['is.in.file'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $object = $context->object;
        if( $object->isDecryptionRule() )
            return FALSE;
        if( $object->isNatRule() )
            return FALSE;
        if( $object->isAppOverrideRule() )
            return FALSE;
        if( $object->isDefaultSecurityRule() )
            return FALSE;

        if( !isset($context->cachedList) )
        {
            $text = file_get_contents($context->value);

            if( $text === FALSE )
                derr("cannot open file '{$context->value}");

            $lines = explode("\n", $text);
            foreach( $lines as $line )
            {
                $line = trim($line);
                if( strlen($line) == 0 )
                    continue;
                $list[$line] = TRUE;
            }

            $context->cachedList = &$list;
        }
        else
            $list = &$context->cachedList;

        $return = FALSE;
        foreach( $list as $listuser => $truefalse )
        {
            $searchString = str_replace( "\\", "\\\\", $listuser);
            $searchString = "/".$searchString."/";

            $users = $object->userID_getUsers();

            foreach( $users as $user )
            {
                $matching = preg_match($searchString, $user);
                if( $matching === 1 )
                    return TRUE;
            }
        }

        return $return;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if rule name matches one of the names found in text file provided in argument'
);
RQuery::$defaultFilters['rule']['user.count']['operators']['>,<,=,!'] = array(
    'eval' => "\$object->isSecurityRule() && \$object->userID_count() !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);

//                                              //
//                Url.category properties             //
//                                              //
RQuery::$defaultFilters['rule']['url.category']['operators']['is.any'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return null;

        return $rule->urlCategoryIsAny();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['url.category']['operators']['has'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return null;

        return $rule->urlCategoriesHas($context->value);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% adult)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['url.category.count']['operators']['>,<,=,!'] = array(
    'eval' => "\$object->isSecurityRule() && \$object->urlCategoriescount() !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['target']['operators']['is.any'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->target_isAny();
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['target']['operators']['has'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $vsys = null;

        $ex = explode('/', $context->value);

        if( count($ex) > 2 )
            derr("unsupported syntax for target: '{$context->value}'. Expected something like : 00F120CCC/vsysX");

        if( count($ex) == 1 )
            $serial = $context->value;
        else
        {
            $serial = $ex[0];
            $vsys = $ex[1];
        }

        return $context->object->target_hasDeviceAndVsys($serial, $vsys);
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP%  00YC25C)',
        'input' => 'input/panorama-8.0.xml'
    )
);


RQuery::$defaultFilters['rule']['description']['operators']['is.empty'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $desc = $context->object->description();

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


RQuery::$defaultFilters['rule']['description']['operators']['regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $matching = preg_match($context->value, $context->object->description());
        if( $matching === FALSE )
            derr("regular expression error on '{$context->value}'");
        if( $matching === 1 )
            return TRUE;
        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /input a string here/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['description.length']['operators']['>,<,=,!'] = array(
    'eval' => "strlen(\$object->description() ) !operator! !value!",
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);


RQuery::$defaultFilters['rule']['app']['operators']['category.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
            return null;

        if( $rule->apps->count() < 1 )
            return null;

        foreach( $rule->apps->membersExpanded() as $app )
        {
            if( $app->type == "application-filter" )
            {
                if( isset($app->app_filter_details['category'][$context->value]) )
                    return TRUE;
            }
            elseif( $app->category == $context->value )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% media)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['app']['operators']['subcategory.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
            return null;

        foreach( $rule->apps->membersExpanded() as $app )
        {
            if( $app->type == "application-filter" )
            {
                if( isset($app->app_filter_details['subcategory'][$context->value]) )
                    return TRUE;
            }
            elseif( $app->subCategory == $context->value )
                return TRUE;
        }

        if( $rule->apps->count() < 1 )
            return null;

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% gaming)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['app']['operators']['technology.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
            return null;

        if( $rule->apps->count() < 1 )
            return null;

        foreach( $rule->apps->membersExpanded() as $app )
        {
            if( $app->type == "application-filter" )
            {
                if( isset($app->app_filter_details['technology'][$context->value]) )
                    return TRUE;
            }
            elseif( $app->technology == $context->value )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% client-server)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['app']['operators']['risk.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
            return null;

        if( $rule->apps->count() < 1 )
            return null;

        foreach( $rule->apps->getAll() as $app )
        {
            if( $app->type == "application-filter" )
            {
                if( isset($app->app_filter_details['risk'][$context->value]) )
                    return TRUE;
            }
            elseif( $app->risk == $context->value )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% client-server)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['app']['operators']['risk.recursive.is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
            return null;

        if( $rule->apps->count() < 1 )
            return null;

        foreach( $rule->apps->membersExpanded() as $app )
        {
            if( $app->risk == $context->value )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% client-server)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['app']['operators']['characteristic.has'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
            return null;

        if( $rule->apps->count() < 1 )
            return null;

        $sanitizedValue = strtolower($context->value);


        if( !isset(App::$_supportedCharacteristics[$sanitizedValue]) )
            derr("Characteristic named '{$sanitizedValue}' does not exist. Supported values are: " . PH::list_to_string(App::$_supportedCharacteristics));

        foreach( $rule->apps->membersExpanded() as $app )
        {
            if( isset($app->_characteristics[$sanitizedValue]) && $app->_characteristics[$sanitizedValue] === TRUE )
                return TRUE;

        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% evasive)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['app']['operators']['has.missing.dependencies'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
            return null;

        if( $rule->apps->count() < 1 )
            return null;

        $app_depends_on = array();
        $app_array = array();
        $missing_dependencies = FALSE;
        foreach( $rule->apps->membersExpanded() as $app )
        {
            $app_array[$app->name()] = $app->name();
            foreach( $app->calculateDependencies() as $dependency )
            {
                $app_depends_on[$dependency->name()] = $dependency->name();
            }
        }

        $first = TRUE;
        $string = "";
        foreach( $app_depends_on as $app => $dependencies )
        {
            if( !isset($app_array[$app]) )
            {
                if( $first )
                {
                    $first = FALSE;
                    $string = "   - app-id: ";
                }
                $string .= $app . ", ";
                $missing_dependencies = TRUE;
            }
        }

        PH::print_stdout( $string );

        if( $missing_dependencies )
        {
            PH::print_stdout( " |  is missing in rule:" );
            return TRUE;
        }

        return FALSE;
    },
    'arg' => FALSE,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['schedule']['operators']['is'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDoSRule() &&  !$rule->isPbfRule() && !$rule->isQoSRule() )
            return FALSE;

        $schedule = $rule->schedule();

        if( is_object( $schedule ) )
        {
            if( $schedule->name() == $context->value )
                return TRUE;
        }

        return FALSE;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% demo)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['schedule']['operators']['is.set'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDoSRule() &&  !$rule->isPbfRule() && !$rule->isQoSRule() )
            return FALSE;

        $schedule = $rule->schedule();

        if( is_object( $schedule ) )
        {
            return TRUE;
        }

        return FALSE;
    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['schedule']['operators']['has.regex'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDoSRule() &&  !$rule->isPbfRule() && !$rule->isQoSRule() )
            return FALSE;

        $schedule = $rule->schedule();

        if( is_object( $schedule ) )
        {
            $matching = preg_match($context->value, $schedule->name() );
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return TRUE;
            else
                return FALSE;
        }
        else
            return null;
    },
    'arg' => TRUE,
    'ci' => array(
        'fString' => '(%PROP% /day/)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['rule']['schedule']['operators']['is.expired'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDoSRule() &&  !$rule->isPbfRule() && !$rule->isQoSRule() )
            return FALSE;

        $schedule = $rule->schedule();

        if( is_object( $schedule ) )
        {
            return $schedule->isExpired( );
        }
        else
            return null;
    },
    'arg' => false,
    'ci' => array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['schedule.expire.in.days']['operators']['>,<,=,!'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDoSRule() &&  !$rule->isPbfRule() && !$rule->isQoSRule() )
            return FALSE;

        /** @var Schedule $schedule */
        $schedule = $rule->schedule();

        if( is_object( $schedule ) )
        {
            $operator = $context->operator;
            if( $operator == '=' )
                $operator = '==';

            return $schedule->isExpired( $context->value, $operator );
        }
        else
            return null;
    },
    'arg' => true,
    'ci' => array(
        'fString' => '(%PROP% 5 )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['schedule.expired.at.date']['operators']['>,<,=,!'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;
        if( !$rule->isSecurityRule() && !$rule->isDoSRule() &&  !$rule->isPbfRule() && !$rule->isQoSRule() )
            return FALSE;

        /** @var Schedule $schedule */
        $schedule = $rule->schedule();

        if( is_object( $schedule ) )
        {
            $operator = $context->operator;
            if( $operator == '=' )
                $operator = '==';

            return $schedule->isExpired( $context->value, $operator );
        }
        else
            return null;
    },
    'arg' => true,
    'ci' => array(
        'fString' => '(%PROP% 5 )',
        'input' => 'input/panorama-8.0.xml'
    ),
    'help' => 'returns TRUE if rule name matches the specified timestamp MM/DD/YYYY [american] / DD-MM-YYYY [european]'
);
RQuery::$defaultFilters['rule']['uuid']['operators']['eq'] = array(
    'Function' => function (RuleRQueryContext $context) {
        return $context->object->uuid() == $context->value;
    },
    'arg' => TRUE,
    'help' => 'returns TRUE if rule uuid matches the one specified in argument',
    'ci' => array(
        'fString' => '(%PROP%  1234567890)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['rule']['threat-log.occurrence.date.fast']['operators']['>,<,=,!'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
            return null;

        $operator = $context->operator;
        if( $operator == '=' )
            $operator = '==';

        /////////////////
        $futuredate = $context->value;

        $string = "";
        $return = false;
        $threatArray = $rule->getRuleThreatLog( $futuredate,$context,$operator, false);

        if(isset($threatArray[$rule->name()]))
        {
            $threatLogs = $threatArray[$rule->name()];
            foreach( $threatLogs as $threat_log )
            {
                $tmp_subtype = $threat_log['subtype'];
                $tmp_log = $threat_log['threat_name'];
                $tmp_time_generated = $threat_log['time_generated'];
                $tmp_severity = $threat_log['severity'];
                $tmp_action = $threat_log['action'];

                $string .=  "          "." - time_generated: '".$tmp_time_generated."' | type: '".$tmp_subtype."' | threat_name: '".$tmp_log."' | severity: '".$tmp_severity."' | action: '".$tmp_action."'"."\n";

                $return = true;
            }

            PH::print_stdout( "------------------------------------------------------------------------");
            PH::print_stdout( $string );
        }

        return $return;
    },
    'arg' => true,
    'help' => 'returns TRUE if rule name matches the specified timestamp MM/DD/YYYY [american] / DD-MM-YYYY [european]'
);
RQuery::$defaultFilters['rule']['threat-log.occurrence.per-rule.date.fast']['operators']['>,<,=,!'] = array(
    'Function' => function (RuleRQueryContext $context) {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
            return null;

        $operator = $context->operator;
        if( $operator == '=' )
            $operator = '==';

        /////////////////
        $futuredate = $context->value;

        $string = "";
        $return = false;
        $threatArray = $rule->getRuleThreatLog( $futuredate,$context,$operator, true);

        if(isset($threatArray[$rule->name()]))
        {
            $threatLogs = $threatArray[$rule->name()];
            foreach( $threatLogs as $threat_log )
            {
                $tmp_subtype = $threat_log['subtype'];
                $tmp_log = $threat_log['threat_name'];
                $tmp_time_generated = $threat_log['time_generated'];
                $tmp_severity = $threat_log['severity'];
                $tmp_action = $threat_log['action'];

                $string .=  "          "." - time_generated: '".$tmp_time_generated."' | type: '".$tmp_subtype."' | threat_name: '".$tmp_log."' | severity: '".$tmp_severity."' | action: '".$tmp_action."'"."\n";

                $return = true;
            }

            PH::print_stdout( "------------------------------------------------------------------------");
            PH::print_stdout( $string );
        }

        return $return;
    },
    'arg' => true,
    'help' => 'returns TRUE if rule name matches the specified timestamp MM/DD/YYYY [american] / DD-MM-YYYY [european]'
);
// </editor-fold>

