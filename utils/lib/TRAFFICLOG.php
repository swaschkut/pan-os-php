<?php
/**
 * ISC License
 *
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

class TRAFFICLOG extends UTIL
{
    public $utilType = null;


    public function utilStart()
    {

        $this->supportedArguments = Array();
        $this->supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file ie: in=config.xml', 'argDesc' => '[filename]');
        $this->supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS', 'argDesc' => 'vsys1|shared|dg1');
        $this->supportedArguments['actions'] = Array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each rule matched by Filter. ie: actions=from-Add:net-Inside,netDMZ', 'argDesc' => 'action:arg1[,arg2]' );
        $this->supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['filter'] = Array('niceName' => 'Filter', 'shortHelp' => "filters logs based on a query. ie: 'filter=( (subtype eq auth) and ( receive_time geq !TIME! ) )'", 'argDesc' => '(field operator value)');
        $this->supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['stats'] = Array('niceName' => 'Stats', 'shortHelp' => 'display stats after changes');
        $this->supportedArguments['hours'] = Array('niceName' => 'Hours', 'shortHelp' => 'display log for the last few hours');
        $this->supportedArguments['apitimeout'] = Array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to anwer, increase this value (default=60)');

        $this->usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api://192.168.55.100 location=shared [Actions=display] ['Filter=(subtype eq pppoe)'] ...";


        $this->prepareSupportedArgumentsArray();


        $this->utilInit();


        $this->main();


        
    }

    public function main()
    {

        #$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
        #$util->utilInit();
#$util->load_config();

        #if( !$this->pan->isFirewall() )
        #    derr( "only PAN-OS FW is supported" );

#if( !$util->apiMode && !$offline_config_test )
        if( !$this->apiMode )
            derr( "only PAN-OS API connection is supported" );

        $inputConnector = $this->pan->connector;

########################################################################################################################

        if( isset(PH::$args['hours']) )
            $hours = PH::$args['hours'];
        else
            $hours = 0.25;
        PH::print_stdout( " - argument 'hours' set to '{$hours}'" );

        $this->setTimezone();

        $time = time() - ($hours * 3600);
        $time = date('Y/m/d H:i:s', $time);


        if( isset(PH::$args['filter']) )
        {
            $query = "(".PH::$args['filter'].")";
            $query = str_replace( "!TIME!", "'".$time."'", $query );
        }
        else
        {
            $query = '';
        }

        if( isset(PH::$args['actions']) )
        {
            $actions = PH::$args['actions'];
        }
        else
            $actions =  "display";

########################################################################################################################

        $inputConnector->refreshSystemInfos();
        $inputConnector->setShowApiCalls( $this->debugAPI );


        $apiArgs = Array();
        $apiArgs['type'] = 'log';
        $apiArgs['log-type'] = 'traffic';
        if( !empty($query) )
            $apiArgs['query'] = $query;


        $output = $inputConnector->getLog($apiArgs);



        PH::print_stdout();
        PH::print_stdout( "##########################################" );
        PH::print_stdout( "traffic log filter: '".$query."'" );
        PH::print_stdout();

        if( !empty($output) )
        {
            if( $actions == "exporttoexcel" )
            {
                $filename = "trafficLog.html";
                $count = 0;
                $lines = "";
                $headers = null;
            }

            foreach( $output as $key => $log )
            {
                if( $actions === "display" )
                {
                    PH::print_stdout(  " - ".http_build_query($log,'',' | ') );
                    PH::print_stdout();

                    PH::$JSON_OUT['traffic-log'][] = $log;
                }
                elseif( $actions == "exporttoexcel" )
                {
                    if( $key == 0 )
                    {
                        $headers = $log;
                    }
                    $this->exportToExcel_Threat_log_line( $log, $count, $lines);
                }
            }

            if( $actions == "exporttoexcel" )
            {
                //Todo: 20241103 swaschkut not all response lines does have all headers, fix it
                $this->exportToExcel_Table_Headers($lines, $headers, $filename);
            }
        }
        else
        {
            PH::print_stdout( "nothing found" );
            PH::print_stdout();

            PH::$JSON_OUT['traffic-log'] = array();
        }

        PH::print_stdout( "##########################################" );
        PH::print_stdout();
    }

    public function exportToExcel_Threat_log_line( $log, &$count, &$lines)
    {
        $wrap = TRUE;

        $count++;

        /** @var SecurityRule|NatRule $rule */
        if( $count % 2 == 1 )
            $lines .= "<tr>\n";
        else
            $lines .= "<tr bgcolor=\"#DDDDDD\">";

        $lines .= $this->encloseFunction( (string)$count );

        $first = true;
        foreach( $log as $fieldName => $fieldID )
        {
            if( $first )
            {
                $first = false;
                continue;
            }
            $lines .= $this->encloseFunction(strval($fieldID), $wrap);
        }

        $lines .= "</tr>\n";
    }

    public function exportToExcel_Table_Headers( $lines, $headers, $filename )
    {
        $tableHeaders = '';
        foreach( $headers as $fieldName => $value )
        {
            $tableHeaders .= "<th>{$fieldName}</th>\n";
        }

        $content = file_get_contents(dirname(__FILE__) . '/../common/html/export-template.html');

        $content = str_replace('%TableHeaders%', $tableHeaders, $content);

        $content = str_replace('%lines%', $lines, $content);

        $jscontent = file_get_contents(dirname(__FILE__) . '/../common/html/jquery.min.js');
        $jscontent .= "\n";
        $jscontent .= file_get_contents(dirname(__FILE__) . '/../common/html/jquery.stickytableheaders.min.js');
        $jscontent .= "\n\$('table').stickyTableHeaders();\n";

        $content = str_replace('%JSCONTENT%', $jscontent, $content);

        file_put_contents($filename, $content);
    }

    public function encloseFunction( $value, $nowrap = TRUE )
    {
        if( $value == NULL )
            $output = "---";
        elseif( is_string($value) )
            $output = htmlspecialchars($value);
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
                    $output .= htmlspecialchars($subValue);
                elseif( is_object($subValue) )
                    $output .= htmlspecialchars($subValue->name());
                else
                    $output .= "";
            }
        }
        elseif( is_object($value) )
        {
            $output = htmlspecialchars( $value->name() );
        }
        else
            derr('TYPE: '.gettype($value).' unsupported', null, false);

        if( $nowrap )
            return '<td style="white-space: nowrap">' . $output . '</td>';

        return '<td>' . $output . '</td>';
    }


}