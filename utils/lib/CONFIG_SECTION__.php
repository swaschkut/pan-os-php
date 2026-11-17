<?php
/**
 * ISC License
 *
 * Copyright (c) 2026, Sven Waschkut - pan-os-php@waschkut.net
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

require_once dirname(__FILE__) . '/../common/ConfigSection.php';

/**
 * pan-os-php type=config-section - device / Panorama settings with named entries that pan-os-php does not model as
 * objects (registry: utils/common/config_sections.json). See utils/README_config-section.md.
 */
class CONFIG_SECTION__ extends UTIL
{
    const ACTIONS = array( 'display', 'references', 'exporttohtml', 'get', 'set', 'add-member', 'remove-member', 'remove-field', 'delete' );
    const WRITE_ACTIONS = array( 'set', 'add-member', 'remove-member', 'remove-field', 'delete' );

    public function utilStart()
    {
        $this->supportedArguments = array();
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml or in=api://192.168.1.1', 'argDesc' => '[filename]|[api://IP]');
        $this->supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file, required for changes of an offline configuration', 'argDesc' => '[filename]');
        $this->supportedArguments['section'] = array('niceName' => 'section', 'shortHelp' => 'config section of utils/common/config_sections.json, section=list shows them', 'argDesc' => 'deployment-update-schedule');
        $this->supportedArguments['entry'] = array('niceName' => 'entry', 'shortHelp' => 'entries of the section (default: all); set on a missing entry creates it', 'argDesc' => 'name1[,name2]');
        $this->supportedArguments['template'] = array('niceName' => 'template', 'shortHelp' => 'Panorama: section of a template instead of Panorama itself', 'argDesc' => 'template');
        $this->supportedArguments['actions'] = array('niceName' => 'actions', 'shortHelp' => 'display (default) | references | exportToHtml:FILE | get:xml|set|json | set:PATH,VALUE | add-member:PATH,VALUE | remove-member:PATH,VALUE | remove-field:PATH | delete - PATH: elements joined by "." (named entries as [name])', 'argDesc' => 'action[:args]');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['shadow-json'] = array('niceName' => 'shadow-json', 'shortHelp' => 'output as JSON');
        $this->supportedArguments['shadow-nojson'] = array('niceName' => 'shadow-nojson', 'shortHelp' => 'output as text');

        $this->usageMsg = PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " type=config-section in=config.xml section=deployment-update-schedule [entry=NAME] [actions=display]\n"
            . "       pan-os-php type=config-section section=list\n"
            . "php " . basename(__FILE__) . " help          : more help messages\n";

        $this->prepareSupportedArgumentsArray();
        PH::processCliArgs();
        $this->help( PH::$args );

        if( !isset(PH::$args['section']) )
            $this->display_error_usage_exit( '"section" argument is not set (section=list shows the known sections)' );
        if( PH::$args['section'] === 'list' )
        {
            $this->listSections();
            return;
        }

        $this->init_arguments();
        $this->load_config();
        $this->main();
    }

    private function listSections()
    {
        $rows = array();
        foreach( ConfigSection::registry() as $n => $s )
        {
            PH::print_stdout( " - " . str_pad($n, 32) . " " . implode(',', $s['scope']) . "  " . $s['path'] . "  - " . $s['description'] );
            $rows[$n] = $s;
        }
        PH::print_stdout( $rows, false, 'sections' );
    }

    /** "name:arg1,arg2" => array( name, args ) - the value of set / add-member may contain ',' */
    public static function parseAction( $a )
    {
        $p = strpos( $a, ':' );
        $name = strtolower( $p === FALSE ? $a : substr($a, 0, $p) );
        $arg = $p === FALSE ? '' : substr( $a, $p + 1 );
        if( !in_array($name, self::ACTIONS, TRUE) )
            derr( "action '" . $name . "' not supported - supported: " . implode(', ', self::ACTIONS), null, FALSE );
        if( in_array($name, array( 'set', 'add-member', 'remove-member' ), TRUE) )
        {
            $parts = explode( ',', $arg, 2 );
            if( count($parts) != 2 || $parts[0] === '' )
                derr( "actions=" . $name . ":PATH,VALUE - PATH and VALUE are required", null, FALSE );
            return array( $name, $parts );
        }
        if( ( $name == 'remove-field' || $name == 'exporttohtml' ) && $arg === '' )
            derr( "actions=" . $name . " needs an argument", null, FALSE );
        if( $name == 'get' && !in_array($arg === '' ? 'xml' : $arg, array( 'xml', 'set', 'json' ), TRUE) )
            derr( "actions=get:xml|set|json", null, FALSE );
        return array( $name, $arg === '' ? array() : array( $arg ) );
    }

    public function main()
    {
        $section = ConfigSection::section( PH::$args['section'] );
        $template = isset(PH::$args['template']) && PH::$args['template'] !== 'any' ? PH::$args['template'] : null;
        $isPanorama = $this->pan->isPanorama();
        ConfigSection::checkScope( $section, $isPanorama, $template );

        $actions = array();
        // actions separated by '/', a literal '/' (file path) is written as '//' (as for all pan-os-php actions)
        $raw = str_replace( '//', "\0", isset(PH::$args['actions']) ? PH::$args['actions'] : 'display' );
        foreach( explode( '/', $raw ) as $a )
            if( $a !== '' )
                $actions[] = self::parseAction( str_replace( "\0", '/', $a ) );
        $writes = count( array_filter( $actions, function( $a ) { return in_array($a[0], self::WRITE_ACTIONS, TRUE); } ) );
        $isAPI = $this->configInput['type'] == 'api';
        // the dispatcher sets out=/dev/null when out= is not given
        if( $writes && !$isAPI && ( !isset(PH::$args['out']) || PH::$args['out'] === '/dev/null' || PH::$args['out'] === '' ) )
            derr( "changes of an offline configuration need out=", null, FALSE );

        $doc = $this->xmlDoc;
        $selected = isset(PH::$args['entry']) ? explode( ',', PH::$args['entry'] ) : null;
        $createEntries = $selected !== null && count( array_filter( $actions, function( $a ) { return in_array($a[0], array( 'set', 'add-member' ), TRUE); } ) ) > 0;
        $container = ConfigSection::container( $doc, $section, $template, $createEntries );

        $entries = array();
        if( $container !== null )
        {
            $all = ConfigSection::entries( $container );
            if( $selected === null )
                $entries = $all;
            else
                foreach( $selected as $n )
                {
                    $e = ConfigSection::entry( $container, $n, $createEntries );
                    if( $e === null )
                        mwarning( "entry '" . $n . "' not found in section " . $section['name'], null, FALSE );
                    else
                        $entries[$n] = $e;
                }
        }

        $names = $isPanorama && !empty($section['references']) ? ConfigSection::panoramaNames( $doc ) : array();
        $where = $section['name'] . ( $template !== null ? ' (template ' . $template . ')' : '' );
        PH::print_stdout( "config section " . $where . ": " . count($entries) . " entr" . ( count($entries) == 1 ? 'y' : 'ies' )
            . ( $selected !== null ? " selected" : '' ) . " - " . ConfigSection::xpath($section, $template) );

        $changed = array(); $deleted = array();
        foreach( $actions as $act )
        {
            list( $name, $args ) = $act;
            switch( $name )
            {
                case 'display':
                case 'references':
                    foreach( $entries as $n => $e )
                    {
                        $fields = ConfigSection::flatten( $e );
                        $refs = count($names) ? ConfigSection::references( $e, $names ) : array();
                        PH::print_stdout( "  * " . $n );
                        if( $name == 'display' )
                            foreach( $fields as $k => $v )
                                PH::print_stdout( "      " . $k . ": " . $v );
                        foreach( $refs as $r )
                            PH::print_stdout( "      -> " . $r['kind'] . " " . $r['name'] . " (" . $r['path'] . ")" );
                        PH::print_stdout( array( 'name' => $n, 'fields' => $fields, 'references' => $refs ), false, $section['name'] );
                    }
                    break;

                case 'exporttohtml':
                    $this->exportToHtml( $args[0], $section, $entries, $names );
                    PH::print_stdout( "  exported to " . $args[0] );
                    break;

                case 'get':
                    $format = count($args) ? $args[0] : 'xml';
                    foreach( $entries as $n => $e )
                    {
                        if( $format == 'xml' )
                            PH::print_stdout( DH::dom_to_xml( $e, 0, TRUE, -1 ) );
                        elseif( $format == 'set' )
                            foreach( ConfigSection::setCommands( $section, $e, $template ) as $l )
                                PH::print_stdout( $l );
                        else
                            PH::print_stdout( json_encode( array( 'name' => $n, 'fields' => ConfigSection::flatten($e) ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
                    }
                    break;

                case 'set':
                case 'add-member':
                case 'remove-member':
                case 'remove-field':
                    foreach( $entries as $n => $e )
                    {
                        if( $name == 'set' ) $c = ConfigSection::setValue( $e, $args[0], $args[1] );
                        elseif( $name == 'add-member' ) $c = ConfigSection::addMember( $e, $args[0], $args[1] );
                        elseif( $name == 'remove-member' ) $c = ConfigSection::removeMember( $e, $args[0], $args[1] );
                        else $c = ConfigSection::removeField( $e, $args[0] );
                        PH::print_stdout( "  * " . $n . ": " . $name . " " . implode( ' ', $args ) . ( $c ? '' : ' - no change' ) );
                        if( $c ) $changed[$n] = $e;
                    }
                    break;

                case 'delete':
                    foreach( $entries as $n => $e )
                    {
                        $e->parentNode->removeChild( $e );
                        $deleted[$n] = TRUE;
                        unset( $changed[$n] );
                        PH::print_stdout( "  * " . $n . ": deleted" );
                    }
                    $entries = array();
                    break;
            }
        }

        if( count($changed) || count($deleted) )
        {
            if( $isAPI )
            {
                $con = $this->pan->connector;
                $base = ConfigSection::xpath( $section, $template );
                foreach( $changed as $n => $e )
                    $con->sendEditRequest( $base . "/entry[@name='" . $n . "']", $e );
                foreach( array_keys($deleted) as $n )
                    $con->sendDeleteRequest( $base . "/entry[@name='" . $n . "']" );
                PH::print_stdout( "  sent via API to the candidate configuration - commit required" );
            }
            else
                $this->save_our_work();
        }
    }

    private function exportToHtml( $filename, array $section, array $entries, array $names )
    {
        $rows = array(); $columns = array();
        foreach( $entries as $n => $e )
        {
            $f = ConfigSection::flatten( $e );
            $rows[$n] = $f;
            foreach( array_keys($f) as $k ) $columns[$k] = TRUE;
        }
        $esc = function( $v ) { return htmlspecialchars( (string)$v, ENT_QUOTES ); };
        $headers = '<th>name</th>';
        foreach( array_keys($columns) as $c ) $headers .= '<th>' . $esc($c) . '</th>';
        if( count($names) ) $headers .= '<th>references</th>';
        $lines = '';
        foreach( $rows as $n => $f )
        {
            $lines .= '<tr><td>' . $esc($n) . '</td>';
            foreach( array_keys($columns) as $c ) $lines .= '<td>' . $esc( isset($f[$c]) ? $f[$c] : '' ) . '</td>';
            if( count($names) )
                $lines .= '<td>' . $esc( implode( ', ', array_map( function( $r ) { return $r['kind'] . ' ' . $r['name']; }, ConfigSection::references( $entries[$n], $names ) ) ) ) . '</td>';
            $lines .= "</tr>\n";
        }
        require_once dirname(__FILE__) . '/ExportToHtmlHelper.php';
        ExportToHtmlHelper::writeHtmlExport( $filename, $headers, $lines );
    }
}
