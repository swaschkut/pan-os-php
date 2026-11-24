<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
 * Copyright (c) 2019, Palo Alto Networks Inc.
 * Copyright (c) 2024, Sven Waschkut - pan-os-php@waschkut.net
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/** @ignore */
class CallContext
{
    public $arguments = array();
    public $rawArguments = array();

    /** @var  Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $object */
    public $object;
    public $objectList;

    public $actionRef;

    public $debug = false;

    public $isAPI = FALSE;
    public $isSaseAPI = FALSE;
    public $isSCMAPI = FALSE;
    public $projectFolder = null;

    public $deviceType =  null;
    public $first;
    public $uuid;

    /** @var  $baseObject PANConf|PanoramaConf */
    public $baseObject;

    /** @var  $subSystem VirtualSystem|PANConf|PanoramaConf|DeviceGroup */
    public $subSystem;

    public $store;

    /** @var  $ruletype array */
    public $ruletype;

    /** @var PanAPIConnector|PanSaseAPIConnector|PanSCMAPIConnector */
    public $connector = null;

    public $padding = '';

    public $nestedQueries;

    /** @var UTIL $util */
    public $util = null;

    public function __construct($actionProperties, $arguments, $nestedQueries = null, $util = null)
    {
        $this->util = $util;
        if( $this->util !== null )
            $this->projectFolder = $util->projectFolder;

        $this->actionRef = $actionProperties;
        $this->prepareArgumentsForAction($arguments);

        if( $nestedQueries === null )
            $this->nestedQueries = array();
        else
            $this->nestedQueries = &$nestedQueries;
    }

    /**
     * @param $object Address|AddressGroup|Service|ServiceGroup|Rule
     */
    public function executeAction($object)
    {
        $this->object = $object;

        $name = $object->name();
        // the key in the JSON output: the name (a DNS rule / threat rule: "<profile>/<name>" - PH::jsonObjectKey)
        $key = PH::jsonObjectKey( $object );
        $saseID = "";
        if( $object->getSaseID() !== null )
        {
            PH::$JSON_TMP['sub']['object'][$key]['id'] = $object->getSaseID();
            $saseID = "Sase-ID: '" . $object->getSaseID()."'";
        }
        $tmp_txt = "   - object '" . PH::boldText($name) . "' ".$saseID." passing through Action='{$this->actionRef['name']}'";

        PH::$JSON_TMP['sub']['object'][$key]['name'] = $name;
        // an object of a Panorama template / template stack (certificates, IKE, GlobalProtect, interfaces, …): its
        // template - the location alone (shared / vsys1) does not say which one
        $tpl = PH::findTemplateOwner( $object );
        if( $tpl !== null )
            PH::$JSON_TMP['sub']['object'][$key]['template'] = $tpl->name();
        if( $key !== $name )
            PH::$JSON_TMP['sub']['object'][$key]['profile'] = $object->owner->name();
        PH::$JSON_TMP['sub']['object'][$key]['actions'][$this->actionRef['name']]['name'] = $this->actionRef['name'];

        // API object model (SCM shape, todo/json-object-model.md): with shadow-json, 'display' adds it for every
        // class ApiObjectModel knows - the one place for all types
        if( PH::$shadow_json && $this->actionRef['name'] === 'display' && ( $apiModel = ApiObjectModel::item( $object ) ) !== null )
            PH::$JSON_TMP['sub']['object'][$key]['model'] = $apiModel;

        if( count($this->arguments) != 0 )
        {
            $tmp_txt .= " Args: ";
            foreach( $this->arguments as $argName => $argValue )
            {
                $tmp_arg = "";
                if( is_bool($argValue) )
                    $tmp_arg = boolYesNo($argValue);
                elseif( is_array($argValue) )
                    $tmp_arg = PH::list_to_string($argValue, '|');
                else
                    $tmp_arg = $argValue;

                PH::$JSON_TMP['sub']['object'][$key]['actions'][$this->actionRef['name']]['arg'][$argName] = $tmp_arg;
                $tmp_txt .= $argName . "=" . $tmp_arg . ", ";
            }
        }

        // read-only objects (temporary, predefined, GlobalProtect gateway tunnel): the config viewer shows them read only
        $readOnly = self::readOnlyReason( $object );
        if( $readOnly !== null && PH::$shadow_json && $this->actionRef['name'] === 'display' )
            PH::$JSON_TMP['sub']['object'][$key]['readonly'] = $readOnly;

        PH::print_stdout( $tmp_txt );

        // an action that changes the object itself is not done on a read-only object (an action for its users - e.g.
        // removewhereused, replacewithobject of a value used directly in a rule - is)
        if( $readOnly !== null && empty( $this->actionRef['readonlyObjects'] ) && self::changesObject( $this->actionRef['name'] ) )
        {
            PH::ACTIONstatus( $this, "SKIPPED", "read-only object: " . $readOnly );
            return;
        }

        $this->actionRef['MainFunction']($this);
    }

    /**
     * why an object can not be changed - null: it can. A GlobalProtect gateway tunnel (helper object of a GlobalProtect
     * gateway), a predefined object, a temporary object (a value used directly in a rule / a name pan-os-php did not
     * find in the configuration).
     */
    static public function readOnlyReason( $object ): ?string
    {
        if( !is_object( $object ) )
            return null;
        if( $object instanceof GPGatewayTunnel )
            return "a GlobalProtect gateway tunnel is a helper object of the GlobalProtect gateway";
        if( method_exists( $object, 'isPredefined' ) && $object->isPredefined() )
            return "predefined";
        foreach( array( 'isTmpAddr', 'isTmpSrv', 'isTmp' ) as $m )
            if( method_exists( $object, $m ) && $object->$m() )
                return "temporary - a value used directly (e.g. in a rule) or a name that is not an object of the configuration";
        return null;
    }

    /** an action that changes the object itself (by its name) - not one that only reads or changes the users of the object */
    static public function changesObject( string $action ): bool
    {
        $a = strtolower( $action );
        return (bool)preg_match( '/^(name-|description-|tag-|value-|color-|comments-|sourceport-|timeout-|protocol-set|dstport-set|add-member|remove-member|'
            . 'delete|decommission|move|interface-|ip-|mtu-|link-state|zpp-|logsetting-|packetbufferprotection|userid-|local-|peer-|tunnel-|disabled-|upload-|url\.)/', $a )
            || (bool)preg_match( '/-(set|add|remove|rename|append|prepend|delete|replace)$/', $a );
    }

    public function hasGlobalInitAction()
    {
        return isset($this->actionRef['GlobalInitFunction']);
    }

    public function executeGlobalInitAction()
    {
        PH::print_stdout("   - action '{$this->actionRef['name']}' has tasks to process before start." );
        $this->actionRef['GlobalInitFunction']($this);
    }

    public function hasGlobalFinishAction()
    {
        return isset($this->actionRef['GlobalFinishFunction']);
    }

    public function executeGlobalFinishAction()
    {
        PH::print_stdout("   - action '{$this->actionRef['name']}' has tasks to process before shutdown." );
        $this->actionRef['GlobalFinishFunction']($this);
    }

    public function prepareArgumentsForAction($arguments)
    {
        $this->arguments = array();
        $this->rawArguments = array();

        if( strlen($arguments) != 0 && !isset($this->actionRef['args']) )
            $this->util->display_error_usage_exit("error while processing argument '{$this->actionRef['name']}' : arguments were provided while they are not supported by this action");

        if( !isset($this->actionRef['args']) || $this->actionRef['args'] === FALSE )
            return;

        $ex = explode(',', $arguments);

        if( count($ex) > count($this->actionRef['args']) )
            $this->util->display_error_usage_exit("error while processing argument '{$this->actionRef['name']}' : too many arguments provided");

        $count = -1;
        foreach( $this->actionRef['args'] as $argName => &$properties )
        {
            $count++;

            $argValue = null;
            if( isset($ex[$count]) )
                $argValue = $ex[$count];

            $this->rawArguments[$argName] = $argValue;

            if( (!isset($properties['default']) || $properties['default'] == '*nodefault*') && ($argValue === null || strlen($argValue)) == 0 )
                derr("action '{$this->actionRef['name']}' argument#{$count} '{$argName}' requires a value, it has no default one", null, FALSE);

            if( $argValue !== null && strlen($argValue) > 0 )
            {
                if (ctype_space($argValue))
                {

                }
                else
                    $argValue = trim($argValue);
            }
            else
                $argValue = $properties['default'];

            if( $properties['type'] == 'string' )
            {
                if( isset($properties['choices']) )
                {
                    foreach( $properties['choices'] as $choice )
                    {
                        $tmpChoice[strtolower($choice)] = TRUE;
                    }
                    $argValue = strtolower($argValue);
                    if( !isset($tmpChoice[$argValue]) )
                        derr("unsupported value '{$argValue}' for action '{$this->actionRef['name']}' arg#{$count} '{$argName}'");
                }
            }
            elseif( $properties['type'] == 'pipeSeparatedList' )
            {
                $tmpArray = array();

                if( $argValue != $properties['default'] )
                {
                    if( isset($properties['choices']) )
                    {
                        $tmpChoices = array();
                        foreach( $properties['choices'] as $choice )
                        {
                            $tmpChoices[strtolower($choice)] = $choice;
                        }

                        $inputChoices = explode('|', $argValue);

                        foreach( $inputChoices as $inputValue )
                        {
                            $inputValue = strtolower(trim($inputValue));

                            if( !isset($tmpChoices[$inputValue]) )
                                derr("unsupported value '{$argValue}' for action '{$this->actionRef['name']}' arg#{$count} '{$argName}'. Available choices are:" . PH::list_to_string($properties['choices']));

                            $tmpArray[$tmpChoices[$inputValue]] = $tmpChoices[$inputValue];
                        }
                    }
                    else
                    {
                        $inputChoices = explode('|', $argValue);

                        foreach( $inputChoices as $inputValue )
                        {
                            $tmpArray[$inputValue] = $inputValue;
                        }
                    }
                }

                $argValue = &$tmpArray;
            }
            elseif( $properties['type'] == 'boolean' || $properties['type'] == 'bool' )
            {
                if( $argValue == '1' || strtolower($argValue) == 'true' || strtolower($argValue) == 'yes' )
                    $argValue = TRUE;
                elseif( $argValue == '0' || strtolower($argValue) == 'false' || strtolower($argValue) == 'no' )
                    $argValue = FALSE;
                else
                    derr("unsupported argument value '{$argValue}' which should of type '{$properties['type']}' for  action '{$this->actionRef['name']}' arg#{$count} helper#'{$argName}'");
            }
            elseif( $properties['type'] == 'integer' )
            {
                if( !is_integer($argValue) )
                    derr("unsupported argument value '{$argValue}' which should of type '{$properties['type']}' for  action '{$this->actionRef['name']}' arg#{$count} helper#'{$argName}'");
            }
            else
            {
                derr("unsupported argument type '{$properties['type']}' for  action '{$this->actionRef['name']}' arg#{$count} helper#'{$argName}'");
            }

            if( $argName === "filename" && $this->projectFolder !== null )
            {
                $this->arguments[$argName] = $this->projectFolder."/".$argValue;
            }
            else
                $this->arguments[$argName] = $argValue;
        }

    }

    public function toString()
    {
        $ret = '';

        $ret .= "Action:'{$this->actionRef['name']}'";

        if( count($this->arguments) != 0 )
        {
            $ret .= " / Args: ";
            foreach( $this->arguments as $argName => $argValue )
            {
                if( is_bool($argValue) )
                    $ret .= "$argName=" . boolYesNo($argValue) . ", ";
                if( is_array($argValue) )
                    $ret .= "$argName=" . PH::list_to_string($argValue) . ", ";
                else
                    $ret .= "$argName=$argValue, ";
            }
        }

        return $ret;
    }

    /**
     * An action with the same definition for several object types (the counterpart of RQuery::registerFilter): written
     * once in actions-common.php and registered for every listed CallContext class. A type-specific action of the same
     * name wins - it is kept, the common one is not added for that type.
     * @param string[] $contextClasses e.g. array( 'AddressCallContext', 'ServiceCallContext' )
     */
    static public function registerAction( array $contextClasses, array $definition ): void
    {
        $key = strtolower( $definition['name'] );
        foreach( $contextClasses as $class )
        {
            foreach( $class::$supportedActions as $k => $a )
                if( strtolower( is_string( $k ) ? $k : $a['name'] ) === $key )
                    continue 2;
            $class::$supportedActions[$key] = $definition;
            ksort( $class::$supportedActions );
        }
    }

    /**
     * an action that changes a network object with one of its edit… methods (NetworkObjectEdit): offline only (an XML
     * file, the config viewer); an invalid value stops with its reason. $fn( $object, $arguments ) returns the log line.
     */
    public function runEdit( callable $fn ): void
    {
        if( $this->isAPI )
        {
            PH::ACTIONstatus( $this, "SKIPPED", "offline only (an XML file / the config viewer) - not with an API connection" );
            return;
        }
        try
        {
            $msg = $fn( $this->object, $this->arguments );
        }
        catch( Exception $e )
        {
            // refused: SKIPPED with the reason - a run over many objects goes on; the config viewer shows a SKIPPED
            // that changed nothing as an error at the field
            PH::ACTIONstatus( $this, "SKIPPED", $e->getMessage() );
            return;
        }
        if( is_string( $msg ) && $msg !== '' )
            PH::ACTIONlog( $this, $msg );
    }

    /**
     * exportToExcel / exportToHtml: the cells "template" and "location" of a network / device object that is not in a
     * firewall or template configuration (PANConf) - SCM (folder, snippet, device): "---" and its name; Panorama: "---"
     * and "shared". Always both cells, so the columns of the row stay in place.
     */
    public function encloseTemplateLocationOther( $object ): string
    {
        $loc = PH::getLocationString( $object );
        return $this->encloseFunction( "---" ) . $this->encloseFunction( is_string( $loc ) && $loc !== '' ? $loc : "---" );
    }

    public function encloseFunction( $value, $nowrap = TRUE )
    {
        if( $value == NULL )
            $output = "---";
        elseif( is_string($value) )
            // Convert newlines to <br /> for proper HTML display of multi-line values
            $output = nl2br(PH::panosphp_htmlspecialchars($value));
        elseif( is_array($value) )
        {
            $output = '';
            $first = TRUE;
            foreach( $value as $subValue )
            {
                if( !$first )
                {
                    $output .= '<br />';
                }
                else
                    $first = FALSE;

                if( is_string($subValue) || is_numeric($subValue) )
                    $output .= PH::panosphp_htmlspecialchars($subValue);
                elseif( is_object($subValue) )
                    $output .= PH::panosphp_htmlspecialchars($subValue->name());
                else
                    $output .= "";
            }
        }
        elseif( is_object($value) )
        {
            $output = PH::panosphp_htmlspecialchars( $value->name() );
        }
        else
            derr('TYPE: '.gettype($value).' unsupported', null, false);

        if( $nowrap )
            return '<td style="white-space: nowrap">' . $output . '</td>';

        return '<td>' . $output . '</td>';
    }
}
