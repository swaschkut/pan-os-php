<?php
/**
 * ISC License
 *
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
require_once dirname(__FILE__) . "/../../appid-toolbox/lib/common.php";

require_once dirname(__FILE__) . "/../../appid-toolbox/lib/trait/lib_1_rule_marker.php";

require_once dirname(__FILE__) . "/../../appid-toolbox/lib/trait/lib_2_report_generator.php";
require_once dirname(__FILE__) . "/../../appid-toolbox/lib/trait/lib_3_rule_cloner.php";
require_once dirname(__FILE__) . "/../../appid-toolbox/lib/trait/lib_5_rule_activation.php";
require_once dirname(__FILE__) . "/../../appid-toolbox/lib/trait/lib_6_rule_cleaner.php";


class APPIDTOOLBOX extends UTIL
{
    use lib_1_rule_marker;
    use lib_2_report_generator;
    use lib_3_rule_cloner;
    use lib_5_rule_activation;
    use lib_6_rule_cleaner;

    private $phase = null;

    public function utilStart()
    {
        PH::processCliArgs();

        $this->supportedArguments = Array();
        $this->supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input filename', 'argDesc' => '[filename]');
        $this->supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output filename ie: out=[PATH]/save-config.xml', 'argDesc' => '[filename]');
        #$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['phase'] = Array('niceName' => 'phase', 'shortHelp' => 'also possible with phase=[phase1|phase2|phase3|phase5|phase6]', 'argDesc' => '[rule-marker|report-generator|rule-cloner|rule-activation|rule-cleaner]');
        $this->supportedArguments['location'] = array('niceName' => 'Location', 'shortHelp' => 'there is a need to limit your query to a VSYS/DG. ie: location=vsys1 or location={DGname}', 'argDesc' => 'sub1');
        #$this->supportedArguments['filter'] = array('niceName' => 'Filter', 'shortHelp' => "filters objects based on a query. ie: 'filter=((from has external) or (source has privateNet1) and (to has external))'", 'argDesc' => '(field operator [value])');


        $this->usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." phase=";

        $this->usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=api://192.168.1.1 phase=[]\n" .
            "   php ".basename(__FILE__)." help          : more help messages\n" .
            "\n" .
            "more details are documented here:\n" .
            "https://github.com/swaschkut/pan-os-php/blob/main/appid-toolbox/doc/AppID%20Toolbox%20-%20PAN-OS-PHP.pdf \n" .
            "\n" .
            "   - phase=p1-marker     [phase=phase1] [phase=rule-marker] \n" .
            "   - phase=p2-generator  [phase=phase2] [phase=report-generator] \n" .
            "   - phase=p3-cloner  [phase=phase3] [phase=rule-cloner] \n" .
            "   - [phase=phase4] -- no script available; manual review task \n" .
            "   - phase=p5-activation [phase=phase5] [phase=rule-activation] \n" .
            "   - phase=p6-cleaner    [phase=phase6] [phase=rule-cleaner] \n" .
            "";


        $this->prepareSupportedArgumentsArray();


        #$this->utilInit();


        $this->main();


    }

    public function main()
    {


        if( isset(PH::$args['phase']) )
        {
            $this->phase = PH::$args['phase'];

            $phase = PH::$args['phase'];

            if( $phase == "rule-marker" || $phase == "phase1" || $phase == "p1-marker" )
                $this->ruleMarker_Phase1_init();
            elseif( $phase == "report-generator" || $phase == "phase2" || $phase == "p2-generator" )
                $this->logAnalysis_Phase2();
            elseif( $phase == "rule-cloner" || $phase == "phase3" || $phase == "p3-cloner" )
                $this->ruleCloner_Phase3_init();
            elseif( $phase == "phase4" || $phase == "p4" )
                derr( "appid-toolboox phase4 - AppID Rules Review - manual task. \n\n - please check: \n\nhttps://github.com/swaschkut/pan-os-php/blob/main/appid-toolbox/doc/AppID%20Toolbox%20-%20PAN-OS-PHP.pdf \n\n", null, False );
            elseif( $phase == "rule-activation" || $phase == "phase5" || $phase == "p5-activation" )
                $this->ruleActivation_Phase5_init();
            elseif( $phase == "rule-cleaner" || $phase == "phase6" || $phase == "p6-cleaner" )
                $this->ruleCleaner_Phase6_init();
            else
                derr( "appid-toolboox phase: '".$phase."' not available. \n\n - please check: \n\nhttps://github.com/swaschkut/pan-os-php/blob/main/appid-toolbox/doc/AppID%20Toolbox%20-%20PAN-OS-PHP.pdf \n\n", null, False );
        }
        elseif( isset(PH::$args['help']) )
            $this->help(PH::$args);

    }

    public function endOfScript()
    {

    }
}