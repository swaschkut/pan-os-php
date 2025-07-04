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

set_include_path( dirname(__FILE__).'/../'. PATH_SEPARATOR . get_include_path() );
require_once(dirname(__FILE__)."/../common/actions.php");

require_once(dirname(__FILE__)."/logWriter.php");
require_once(dirname(__FILE__)."/RULEUTIL.php");
require_once(dirname(__FILE__)."/STATSUTIL.php");
require_once(dirname(__FILE__)."/SECURITYPROFILEUTIL.php");
require_once(dirname(__FILE__)."/DEVICEUTIL.php");
require_once(dirname(__FILE__)."/NETWORKUTIL.php");

require_once(dirname(__FILE__)."/MERGER.php");
require_once(dirname(__FILE__)."/RULEMERGER.php");


use CzProject\GitPhp\Git as Git;


require_once(dirname(__FILE__)."/KEYMANGER.php");
require_once(dirname(__FILE__)."/PREDEFINED.php");
require_once(dirname(__FILE__)."/UPLOAD.php");
require_once(dirname(__FILE__)."/XMLISSUE.php");
require_once(dirname(__FILE__)."/DIFF.php");
require_once(dirname(__FILE__)."/OVERRIDEFINDER.php");
require_once(dirname(__FILE__)."/APPIDENABLER.php");
require_once(dirname(__FILE__)."/CONFIGSIZE.php");
require_once(dirname(__FILE__)."/BPAGENERATOR.php");
require_once(dirname(__FILE__)."/XMLOPJSON.php");
require_once(dirname(__FILE__)."/REGISTERIP.php");
require_once(dirname(__FILE__)."/USERIDMGR.php");

require_once(dirname(__FILE__)."/RUNSSH.php");


require_once(dirname(__FILE__)."/SOFTWAREREMOVE.php");
require_once(dirname(__FILE__)."/TRAFFICLOG.php");
require_once(dirname(__FILE__)."/THREATLOG.php");
require_once(dirname(__FILE__)."/SYSTEMLOG.php");
require_once(dirname(__FILE__)."/GARPSEND.php");
require_once(dirname(__FILE__)."/SESSIONBROWSER.php");

require_once(dirname(__FILE__)."/CUSTOMREPORT.php");

require_once(dirname(__FILE__)."/SOFTWARE_DOWNLOAD.php");
require_once(dirname(__FILE__)."/SOFTWARE_PREPARATION__.php");
require_once(dirname(__FILE__)."/LICENSE__.php");
require_once(dirname(__FILE__)."/CONFIG_DOWNLOAD_ALL__.php");

require_once(dirname(__FILE__)."/SPIFFY__.php");
require_once(dirname(__FILE__)."/CONFIG_COMMIT__.php");

require_once dirname(__FILE__)."/MAXMIND__.php";
require_once dirname(__FILE__)."/PLAYBOOK__.php";
require_once dirname(__FILE__)."/UTIL_GET_ACTION_FILTER.php";
require_once dirname(__FILE__)."/IRONSKILLET_UPDATE__.php";

require_once(dirname(__FILE__)."/PROTOCOLL_NUMBERS__.php");

require_once(dirname(__FILE__)."/HTMLmerger__.php");
require_once(dirname(__FILE__)."/TSF__.php");
require_once(dirname(__FILE__)."/XPATH.php");

require_once dirname(__FILE__)."/../../phpseclib/Net/SSH2.php";
require_once dirname(__FILE__)."/../../phpseclib/Crypt/RSA.php";

require_once(dirname(__FILE__)."/SSH_CONNECTOR__.php");

require_once(dirname(__FILE__)."/GCP.php");

require_once dirname(__FILE__)."/../../migration/parser/lib/CONVERTER.php";
require_once dirname(__FILE__)."/../../migration/parser/lib/PARSER.php";
require_once dirname(__FILE__)."/../../migration/parser/lib/SHAREDNEW.php";

require_once dirname(__FILE__)."/APPIDTOOLBOX.php";

require_once dirname(__FILE__)."/RULE_COMPARE.php";


class UTIL
{
    public $argv = null;
    public $argc = null;

    public $configType = null;
    public $configInput = null;
    public $configOutput = null;
    public $doActions = null;
    public $dryRun = FALSE;
    public $apiTimeoutValue = 60;
    public $objectsLocation = 'shared';

    public $objectsLocationCounter = 0;
    public $objectsTemplate = 'any';
    public $templateName = "";
    public $templateNameCounter = 0;

    public $objectsFilter = null;
    public $errorMessage = '';
    public $debugAPI = FALSE;
    public $debugLoadTime = FALSE;

    public $projectFolder = null;

    /** @var DOMDocument $xmlDoc */
    public $xmlDoc = null;

    /** @var PANConf|PanoramaConf|FawkesConf $pan  */
    public $pan = null;

    public $nestedQueries = array();
    public $objectFilterRQuery = null;
    public $objectsToProcess = array();
    public $totalObjectsProcessed = 0;
    public $totalObjectsOfSelectedStores = 0;
    public $supportedArguments = array();
    public $usageMsg = "";
    public $apiMode = FALSE;

    public $runStartTime = 0;

    public $loadStartTime = 0;
    public $loadStartMem = 0;
    public $loadElapsedTime = 0;
    public $loadUsedMem = 0;
    public $loadArrayMem = array( "0", "b");

    public $expedition = null;
    public $expedition_db_ip = null;
    public $expedition_db_user = null;
    public $expedition_db_pw = null;
    protected $taskId = 0;
    public $log = null;

    public $utilType = "";
    public $PHP_FILE = null;


    public $location = null;
    public $sub = null;
    public $template = null;

    public $auditComment = null;

    public $outputformatset = FALSE;
    public $outputformatsetFile = null;
    public $origXmlDoc = null;

    public $diff_set = array();
    public $diff_delete = array();

    public $cycleConnectedFirewalls = FALSE;

    public $loadEndTime;
    public $loadEndMem;

    public $scope = null;

    public $networkUsedObjects = array();

    function __construct($utilType, $argv, $argc, $PHP_FILE, $_supportedArguments = array(), $_usageMsg = "", $projectFolder = "")
    {
        PanAPIConnector::$projectfolder = $projectFolder;

        $this->argv = $argv;
        $this->argc = $argc;

        $this->PHP_FILE = $PHP_FILE;
        $this->utilType = $utilType;
        $this->runStartTime = microtime(TRUE);
        $tmp_ph = new PH($argv, $argc);

        if( $this->utilType != "custom" )
        {
            PH::print_stdout();
            PH::print_stdout("***********************************************");
            PH::print_stdout("*********** " . basename($this->PHP_FILE) . " UTILITY **************");
            PH::print_stdout();
        }

        if( empty($_supportedArguments) )
            $this->supportedArguments();
        else
            $this->supportedArguments = $_supportedArguments;

        if( !empty($_usageMsg) )
            $this->usageMsg = $_usageMsg;

        //vulnarability??
        //$this->utilLogger();
        //$this->log->info("start UTIL: " . $this->PHP_FILE . " | " . implode(", ", $argv));



        if( $this->utilType != "custom" )
        {
            PH::print_stdout( " - PAN-OS-PHP version: ".PH::frameworkVersion() . " [".PH::frameworkInstalledOS()."]" . " [" . phpversion() ."]" );
            PH::print_stdout( array( "version" => PH::frameworkVersion(), "os" => PH::frameworkInstalledOS(), "php-version" => phpversion() ), false, 'PAN-OS-PHP');
            $this->utilStart();
        }

    }

    public function utilStart()
    {
        $this->utilInit();


        $this->utilActionFilter();


        $this->location_filter_object();


        $this->time_to_process_objects();


        $this->GlobalFinishAction();


        PH::print_stdout();
        PH::print_stdout( "**** PROCESSING OF $this->totalObjectsProcessed OBJECTS DONE ****" );
        PH::print_stdout();

        PH::print_stdout( array("PROCESSING OF $this->totalObjectsProcessed OBJECTS DONE"), false,'summary' );

        $this->stats();

        $this->save_our_work(TRUE);

        //vulnarability?
        //$this->log->info("END UTIL: " . $this->PHP_FILE);

        
    }

    /*
     *
     */
    public function utilLogger()
    {
        $this->log = new logWriter( "", array(), $this );
    }

    public function supportedArguments()
    {
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
        $this->supportedArguments['location'] = array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1 or location={DGname}:excludeMaindg [only childDGs of {DGname}] or location={DGname}:includechilddgs [{DGname} + all childDGs]', 'argDesc' => 'sub1[,sub2]');
        $this->supportedArguments['listactions'] = array('niceName' => 'ListActions', 'shortHelp' => 'lists available Actions');
        $this->supportedArguments['listfilters'] = array('niceName' => 'ListFilters', 'shortHelp' => 'lists available Filters');
        $this->supportedArguments['stats'] = array('niceName' => 'Stats', 'shortHelp' => 'display stats after changes');
        $this->supportedArguments['actions'] = array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each rule matched by Filter. ie: actions=from-Add:net-Inside,netDMZ', 'argDesc' => 'action:arg1[,arg2]');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['debugloadtime'] = array('niceName' => 'DebugLoadTime', 'shortHelp' => 'print LoadTime of specific config parts');
        $this->supportedArguments['filter'] = array('niceName' => 'Filter', 'shortHelp' => "filters objects based on a query. ie: 'filter=((from has external) or (source has privateNet1) and (to has external))'", 'argDesc' => '(field operator [value])');
        $this->supportedArguments['loadplugin'] = array('niceName' => 'loadPlugin', 'shortHelp' => 'a PHP file which contains a plugin to expand capabilities of this script', 'argDesc' => '[filename]');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');

        $this->supportedArguments['expedition'] = array('niceName' => 'expedition', 'shortHelp' => 'only used if called from Expedition Tool');
        $this->supportedArguments['template'] = array('niceName' => 'template', 'shortHelp' => 'specify if you want to limit your query to a TEMPLATE. By default template=any for Panorama', 'argDesc' => 'template');

        $this->supportedArguments['loadpanoramapushedconfig'] = array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules');

        $this->supportedArguments['git'] = array('niceName' => 'Git', 'shortHelp' => 'if argument git is used, git repository is created to track changes for input file');

        $this->supportedArguments['apitimeout'] = array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to anwer, increase this value (default=60)', 'argDesc' => '60');

        $this->supportedArguments['cycleconnectedfirewalls'] = array('niceName' => 'cycleConnectedFirewalls', 'shortHelp' => 'a listing of all devices connected to Panorama will be collected through API then each firewall will be queried for bpa generator');

        $this->supportedArguments['auditcomment'] = array('niceName' => 'AuditComment', 'shortHelp' => 'set custom AuditComment instead of predefined: "PAN-OS-PHP $actions $time"', 'argDesc' => 'CustomAuditComment');

        $this->supportedArguments['outputformatset'] = array('niceName' => 'outputformatset', 'shortHelp' => 'get all PAN-OS set commands about the task the UTIL script is doing. outputformatset=FILENAME -> store set commands in file', 'argDesc' => 'outputformatset');

        $this->supportedArguments['projectfolder'] = array('niceName' => 'projectFolder', 'shortHelp' => 'the project folder where all outputfiles are stored. projectfolder=FILENAME -> store all created files into this folder', 'argDesc' => 'projectfolder');

        $this->supportedArguments['shadow-disableoutputformatting'] = array('niceName' => 'shadow-disableoutputformatting', 'shortHelp' => 'XML output in offline config is not in cleaned PHP DOMDocument structure');
        $this->supportedArguments['shadow-enablexmlduplicatesdeletion']= array('niceName' => 'shadow-enablexmlduplicatesdeletion', 'shortHelp' => 'if duplicate objects are available, keep only one object of the same name');
        $this->supportedArguments['shadow-ignoreinvalidaddressobjects']= array('niceName' => 'shadow-ignoreinvalidaddressobjects', 'shortHelp' => 'PAN-OS allow to have invalid address objects available, like object without value or type');
        $this->supportedArguments['shadow-apikeyhidden'] = array('niceName' => 'shadow-apikeyhidden', 'shortHelp' => 'send API-KEY hidden via POST. this is possible for all PAN-OS version >=9.0 if API mode is used. ');
        $this->supportedArguments['shadow-apikeynohidden'] = array('niceName' => 'shadow-apikeynohidden', 'shortHelp' => 'send API-KEY in clear text via URL. this is needed for all PAN-OS version <9.0 if API mode is used. ');
        $this->supportedArguments['shadow-apikeynosave']= array('niceName' => 'shadow-apikeynosave', 'shortHelp' => 'do not store API key in .panconfkeystore file');
        $this->supportedArguments['shadow-displaycurlrequest']= array('niceName' => 'shadow-displaycurlrequest', 'shortHelp' => 'display curl information if running in API mode');
        $this->supportedArguments['shadow-reducexml']= array('niceName' => 'shadow-reducexml', 'shortHelp' => 'store reduced XML, without newline and remove blank characters in offline mode');
        $this->supportedArguments['shadow-json']= array('niceName' => 'shadow-json', 'shortHelp' => 'BETA command to display output on stdout not in text but in JSON format');
        $this->supportedArguments['shadow-nojson']= array('niceName' => 'shadow-nojson', 'shortHelp' => 'BETA command to display output on stdout in text format');
        $this->supportedArguments['shadow-displayxmlnode']= array('niceName' => 'shadow-displayxmlnode', 'shortHelp' => 'command to display XML node in addition to for actions=display');
        $this->supportedArguments['shadow-saseapiqa']= array('niceName' => 'shadow-saseapiqa', 'shortHelp' => 'command to use QA URLs for SASE API');
        $this->supportedArguments['shadow-loadreduce']= array('niceName' => 'shadow-loadreduce', 'shortHelp' => 'during config load do NOT load dynamic-addressgroup information from address objects TAG based part');
        $this->supportedArguments['shadow-loaddghierarchy']= array('niceName' => 'shadow-loaddghierarchy', 'shortHelp' => 'load for location=DG the full hierarchy');
        $this->supportedArguments['shadow-bpjsonfile']= array('niceName' => 'shadow-bpjsonfile', 'shortHelp' => 'use custom defined bestpractice and visibility to validate the configuration');
    }

    public function utilInit()
    {
        PH::processCliArgs();


        $this->loadplugin();


        $this->help(PH::$args);

        $this->arg_validation();

        $this->listactions();

        $this->listfilters();

        $this->init_arguments();
    }

    public function utilActionFilter( $utilType = null)
    {
        $this->extracting_actions( $utilType );
        $this->createRQuery();


        $this->load_config();

        $this->location_filter();
    }

    public function listfilters()
    {
        if( isset(PH::$args['listfilters']) )
        {
            $tmp_utilType = $this->utilType;
            if( $tmp_utilType == "address-merger" || $tmp_utilType == "addressgroup-merger"  )
                $tmp_utilType = "address";
            elseif( $tmp_utilType == "service-merger" || $tmp_utilType == "servicegroup-merger"  )
                $tmp_utilType = "service";
            elseif( $tmp_utilType == "tag-merger" )
                $tmp_utilType = "tag";
            elseif( $tmp_utilType == "custom-url-category-merger" )
                $tmp_utilType = "securityprofile";
            elseif( $tmp_utilType == "rule-merger" )
                $tmp_utilType = "rule";


            ksort(RQuery::$defaultFilters[$tmp_utilType]);

            PH::print_stdout( "Listing of supported filters:" );
            PH::print_stdout();
            PH::print_stdout();

            foreach( RQuery::$defaultFilters[$tmp_utilType] as $index => &$filter )
            {
                PH::print_stdout( "* " . $index . "" );
                PH::$JSON_TMP[$index]['name'] = $index;

                ksort($filter['operators']);

                foreach( $filter['operators'] as $oindex => &$operator )
                {
                    //if( $operator['arg'] )
                    $output = "    - $oindex";
                    $output = str_pad($output, 40);
                    if( isset($operator['help']) )
                        $output .= ": ".$operator['help'];

                    PH::print_stdout( $output . "" );
                    PH::$JSON_TMP[$index]['operators'][$oindex]['name'] = $oindex;
                    PH::$JSON_TMP[$index]['operators'][$oindex]['operator'] = $operator;
                }
                PH::print_stdout();
            }

            PH::print_stdout( PH::$JSON_TMP, false, 'listfilters' );
            PH::$JSON_TMP = array();
            if( PH::$shadow_json )
            {
                PH::$JSON_OUT['log'] = PH::$JSON_OUTlog;
                print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
                #print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT|JSON_FORCE_OBJECT );
            }

            exit(0);
        }
    }

    public function supportedActions()
    {
        $tmp_array = array();

        if( $this->utilType == 'tag' )
            $tmp_array = &TagCallContext::$supportedActions;
        elseif( $this->utilType == 'address' )
            $tmp_array = &AddressCallContext::$supportedActions;
        elseif( $this->utilType == 'service' )
            $tmp_array = &ServiceCallContext::$supportedActions;
        elseif( $this->utilType == 'rule' )
            $tmp_array = &RuleCallContext::$supportedActions;
        elseif( $this->utilType == 'zone' )
            $tmp_array = &ZoneCallContext::$supportedActions;
        elseif( $this->utilType == 'securityprofile' )
            $tmp_array = &SecurityProfileCallContext::$supportedActions;
        elseif( $this->utilType == 'securityprofilegroup' )
            $tmp_array = &SecurityProfileGroupCallContext::$supportedActions;
        elseif( $this->utilType == 'schedule' )
            $tmp_array = &ScheduleCallContext::$supportedActions;
        elseif( $this->utilType == 'edl' )
            $tmp_array = &EDLCallContext::$supportedActions;
        elseif( $this->utilType == 'application' )
            $tmp_array = &ApplicationCallContext::$supportedActions;
        elseif( $this->utilType == 'threat' )
            $tmp_array = &ThreatCallContext::$supportedActions;
        elseif( $this->utilType == 'threat-rule' )
            $tmp_array = &ThreatRuleCallContext::$supportedActions;
        elseif( $this->utilType == 'dns-rule' )
            $tmp_array = &DNSRuleCallContext::$supportedActions;

        elseif( $this->utilType == 'device' )
            $tmp_array = &DeviceCallContext::$supportedActions;
        elseif( $this->utilType == 'vsys' )
            $tmp_array = &VsysCallContext::$supportedActions;

        elseif( $this->utilType == 'virtualwire' )
            $tmp_array = &VirtualWireCallContext::$supportedActions;
        elseif( $this->utilType == 'routing' )
            $tmp_array = &RoutingCallContext::$supportedActions;
        elseif( $this->utilType == 'interface' )
            $tmp_array = &InterfaceCallContext::$supportedActions;
        elseif( $this->utilType == 'dhcp' )
            $tmp_array = &DHCPCallContext::$supportedActions;
        elseif( $this->utilType == 'certificate' )
            $tmp_array = &CertificateCallContext::$supportedActions;
        elseif( $this->utilType == 'static-route' )
            $tmp_array = &StaticRouteCallContext::$supportedActions;

        elseif( $this->utilType == 'gp-gateway' )
            $tmp_array = &GPGatewayCallContext::$supportedActions;
        elseif( $this->utilType == 'gp-portal' )
            $tmp_array = &GPPortalCallContext::$supportedActions;

        elseif( $this->utilType == 'ike-profile' )
            $tmp_array = &IKEprofileCallContext::$supportedActions;
        elseif( $this->utilType == 'ike-gateway' )
            $tmp_array = &IKEgatewayCallContext::$supportedActions;
        elseif( $this->utilType == 'ipsec-profile' )
            $tmp_array = &IPsecprofileCallContext::$supportedActions;
        elseif( $this->utilType == 'ipsec-tunnel' )
            $tmp_array = &IPsectunnelCallContext::$supportedActions;
        elseif( $this->utilType == 'gre-tunnel' )
            $tmp_array = &GREtunnelCallContext::$supportedActions;
        elseif( $this->utilType == 'gpgateway-tunnel' )
            $tmp_array = &GPGatewaytunnelCallContext::$supportedActions;

        return $tmp_array;
    }

    public function listactions()
    {
        if( isset(PH::$args['listactions']) )
        {
            $tmp_array = $this->supportedActions();

            ksort($tmp_array);

            PH::print_stdout( "Listing of supported actions:" );
            PH::print_stdout();
            PH::print_stdout();

            PH::print_stdout( str_pad('', 100, '-') . "" );
            PH::print_stdout( str_pad('Action name', 28, ' ', STR_PAD_BOTH) . "|" . str_pad("Argument:Type", 24, ' ', STR_PAD_BOTH) . " |" .
                str_pad("Def. Values", 12, ' ', STR_PAD_BOTH) . "|   Choices" );
            PH::print_stdout( str_pad('', 100, '-') );

            foreach( $tmp_array as &$action )
            {

                $output = "* " . $action['name'];
                PH::$JSON_TMP['arg'][$action['name']]['name'] = $action['name'];
                $output = str_pad($output, 28) . '|';

                if( isset($action['args']) )
                {
                    $first = TRUE;
                    $count = 1;
                    foreach( $action['args'] as $argName => &$arg )
                    {
                        if( !$first )
                            $output .= "\n" . str_pad('', 28) . '|';

                        $output .= " " . str_pad("#$count $argName:{$arg['type']}", 24) . "| " . str_pad("{$arg['default']}", 12) . "| ";
                        PH::$JSON_TMP['arg'][$action['name']]['arguments'][$count]['argument'] = $argName;
                        PH::$JSON_TMP['arg'][$action['name']]['arguments'][$count]['type'] = $arg['type'];
                        PH::$JSON_TMP['arg'][$action['name']]['arguments'][$count]['default'] = $arg['default'];

                        if( isset($arg['choices']) )
                        {
                            $output .= PH::list_to_string($arg['choices']);
                            PH::$JSON_TMP['arg'][$action['name']]['arguments'][$count]['choices'] = $arg['choices'];
                        }

                        if( isset($arg['help']) )
                            $output .= "\n     : ".$arg['help'];

                        $count++;
                        $first = FALSE;
                    }
                }


                PH::print_stdout( $output );
                PH::print_stdout( str_pad('', 100, '=') );
            }

            PH::print_stdout( PH::$JSON_TMP, false, 'listactions' );
            PH::$JSON_TMP = array();
            if( PH::$shadow_json )
            {
                PH::$JSON_OUT['log'] = PH::$JSON_OUTlog;
                print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
                #print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT|JSON_FORCE_OBJECT );
            }

            exit(0);
        }

    }

    public function loadplugin()
    {
        if( isset(PH::$args['loadplugin']) )
        {
            $pluginFile = PH::$args['loadplugin'];
            PH::print_stdout( " * loadPlugin was used. Now loading file: '{$pluginFile}'..." );

            require_once $pluginFile;

            if( $this->utilType == 'tag' )
                TagCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'address' )
                AddressCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'service' )
                ServiceCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'rule' )
                RuleCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'zone' )
                ZoneCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'vsys' )
                VsysCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'securityprofile' )
                SecurityProfileCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'securityprofilegroup' )
                SecurityProfileGroupCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'schedule' )
                ScheduleCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'edl' )
                EDLCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'application' )
                ApplicationCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'threat' )
                ThreatCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'threat-rule' )
                ThreatRuleCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'dns-rule' )
                DNSRuleCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'device' )
                DeviceCallContext::prepareSupportedActions();
            elseif( $this->utilType == 'certificate' )
                CertificateCallContext::prepareSupportedActions();


        }
    }

    public function help($argv)
    {
        if( isset(PH::$args['help']) )
        {
            if( isset(PH::$args['filter']) )
            {
                $tmp_utilType = $this->utilType;
                if( $tmp_utilType == "address-merger" || $tmp_utilType == "addressgroup-merger"  )
                    $tmp_utilType = "address";
                elseif( $tmp_utilType == "service-merger" || $tmp_utilType == "servicegroup-merger"  )
                    $tmp_utilType = "service";
                elseif( $tmp_utilType == "tag-merger" )
                    $tmp_utilType = "tag";
                elseif( $tmp_utilType == "custom-url-category-merger" )
                    $tmp_utilType = "securityprofile";
                elseif( $tmp_utilType == "rule-merger" )
                    $tmp_utilType = "rule";


                ksort(RQuery::$defaultFilters[$tmp_utilType]);


                $pos = array_search('help', PH::$args);

                if( $pos === FALSE )
                    $this->display_usage_and_exit(FALSE);

                $keys = array_keys(PH::$args);

                if( $pos == end($keys) )
                    $this->display_usage_and_exit(FALSE);

                $key_search = array_search($pos, $keys);
                #$action = PH::$args[(array_search($pos, $keys) +1)];
                $filter = $keys[($key_search + 2)];

                if( !isset(RQuery::$defaultFilters[$tmp_utilType][$filter]) )
                {
                    mwarning("request help for filter '{$filter}' but it does not exist", null, false);

                    PH::$args['listfilters'] = "listfilters";
                    $this->listfilters();
                }


                $args = array();
                if( isset($filter['args']) )
                {
                    foreach( $filter['args'] as $argName => &$argDetails )
                    {
                        if( $argDetails['default'] == '*nodefault*' )
                            $args[] = "{$argName}";
                        else
                            $args[] = "[{$argName}]";
                    }
                }

                $args = PH::list_to_string($args);
                PH::print_stdout( "*** help for Filter " . PH::boldText($filter) . ":" . $args );
                PH::print_stdout();

                foreach( RQuery::$defaultFilters[$tmp_utilType] as $index => &$filter_name )
                {
                    if($filter !== $index)
                        continue;

                    PH::print_stdout( "* " . $index . "" );
                    PH::$JSON_TMP[$index]['name'] = $index;

                    ksort($filter_name['operators']);

                    foreach( $filter_name['operators'] as $oindex => &$operator )
                    {
                        //if( $operator['arg'] )
                        $output = "    - $oindex";
                        $output = str_pad($output, 40);
                        if( isset($operator['help']) )
                            $output .= ": ".$operator['help'];

                        PH::print_stdout( $output . "" );
                        PH::$JSON_TMP[$index]['operators'][$oindex]['name'] = $oindex;
                        PH::$JSON_TMP[$index]['operators'][$oindex]['operator'] = $operator;
                    }
                    PH::print_stdout();
                }
            }
            else
            {
                $tmp_array = self::supportedActions();

                $pos = array_search('help', PH::$args);

                if( $pos === FALSE )
                    $this->display_usage_and_exit(FALSE);

                $keys = array_keys(PH::$args);

                if( $pos == end($keys) )
                    $this->display_usage_and_exit(FALSE);

                $key_search = array_search($pos, $keys);
                #$action = PH::$args[(array_search($pos, $keys) +1)];
                $action = $keys[($key_search + 1)];

                if( !isset($tmp_array[strtolower($action)]) )
                {
                    $this->listactions();
                    derr("request help for action '{$action}' but it does not exist", null, false);
                }


                $action = &$tmp_array[strtolower($action)];

                $args = array();
                if( isset($action['args']) )
                {
                    foreach( $action['args'] as $argName => &$argDetails )
                    {
                        if( $argDetails['default'] == '*nodefault*' )
                            $args[] = "{$argName}";
                        else
                            $args[] = "[{$argName}]";
                    }
                }

                $args = PH::list_to_string($args);
                PH::print_stdout( "*** help for Action " . PH::boldText($action['name']) . ":" . $args );

                if( isset($action['help']) )
                    PH::print_stdout( $action['help'] );

                if( !isset($args) || !isset($action['args']) )
                {
                    PH::print_stdout( "\n\n**No arguments required**" );
                }
                else
                {
                    PH::print_stdout( "\nListing arguments:" );
                    PH::print_stdout();
                    PH::print_stdout();
                    foreach( $action['args'] as $argName => &$argDetails )
                    {
                        PH::print_stdout( "-- " . PH::boldText($argName) . " :" );
                        if( $argDetails['default'] != "*nodefault" )
                            PH::print_stdout( " OPTIONAL" );
                        PH::print_stdout( " type={$argDetails['type']}" );
                        if( isset($argDetails['choices']) )
                        {
                            PH::print_stdout( "     choices: " . PH::list_to_string($argDetails['choices']) );
                        }
                        PH::print_stdout();
                        if( isset($argDetails['help']) )
                            PH::print_stdout( " " . str_replace("\n", "\n ", $argDetails['help']) );
                        else
                            PH::print_stdout( "  *no help available*" );
                        PH::print_stdout();
                        PH::print_stdout();
                    }

                }
            }



            PH::print_stdout();
            PH::print_stdout();

            exit(0);
        }
    }

    public function arg_validation()
    {
        foreach( PH::$args as $index => &$arg )
        {
            if( !isset($this->supportedArguments[$index]) )
            {
                if( strpos($index, 'subquery') === 0 )
                {
                    $this->nestedQueries[$index] = &$arg;
                    continue;
                }
                //var_dump($supportedArguments);
                $this->display_error_usage_exit("unsupported argument provided: '$index'");
            }
        }
    }

    public function display_error_usage_exit($msg)
    {
        if( PH::$shadow_json )
            PH::$JSON_OUT['error'] = $msg;
        else
            fwrite(STDERR, PH::boldText("\n**ERROR** ") . $msg . "\n\n");
        $this->display_usage_and_exit(TRUE, $msg );
    }

    public function usageMessage()
    {
        $string = PH::boldText("USAGE: ") . "php " . $this->PHP_FILE . " in=inputfile.xml out=outputfile.xml location=any|shared|sub " .
                "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']\n";

        $string .= "php " . $this->PHP_FILE . " listactions   : list supported actions\n";

        $string .= "php " . $this->PHP_FILE . " listfilters   : list supported filter\n";

        $string .= "php " . $this->PHP_FILE . " help          : more help messages";

        $string .= PH::boldText("\nExamples:\n");

        $string .= " - php " . $this->PHP_FILE . " in=api://192.169.50.10 location=DMZ-Firewall-Group actions=displayReferences 'filter=(name eq Mail-Host1)'";

        $string .= " - php " . $this->PHP_FILE . " in=config.xml out=output.xml location=any actions=delete\n";

        $string .= "\n\n";

        $string .= PH::boldText("PAN-OS API connections for version < 9.0 now need additional argument: 'shadow-apikeynohidden'")."\n";


        PH::print_stdout( $string );
        PH::$JSON_TMP['usage'] = $string;
    }

    public function display_usage_and_exit($shortMessage = FALSE, $warningString = "")
    {
        if( $this->usageMsg == "" )
            $this->usageMessage();
        else
        {
            PH::print_stdout( $this->usageMsg );
            PH::$JSON_TMP['usage'] = $this->usageMsg;
        }

        PH::print_stdout();
        PH::print_stdout();

        if( !$shortMessage )
        {
            PH::print_stdout( PH::boldText("\nListing available arguments") );
            PH::print_stdout();
            PH::print_stdout();

            ksort($this->supportedArguments);
            foreach( $this->supportedArguments as &$arg )
            {

                PH::$JSON_TMP['arguments'][$arg['niceName']]['name'] = $arg['niceName'];

                $tmp_text = PH::boldText($arg['niceName']);
                if( isset($arg['argDesc']) )
                {
                    $tmp_text .= '=' . $arg['argDesc'] ;
                    PH::$JSON_TMP['arguments'][$arg['niceName']]['argdescription'] = $arg['argDesc'];
                }

                //."=";
                PH::print_stdout( " - " .$tmp_text );
                PH::$JSON_TMP['arguments'][$arg['niceName']]['example'] = $tmp_text;



                if( isset($arg['shortHelp']) )
                {
                    PH::print_stdout( "     " . $arg['shortHelp'] );
                    PH::$JSON_TMP['arguments'][$arg['niceName']]['shorthelp'] = $arg['shortHelp'];
                }


                PH::print_stdout();
            }

            PH::print_stdout( PH::$JSON_TMP, false, 'help' );
            PH::$JSON_TMP = array();


            PH::print_stdout();

        }

        if( PH::$shadow_json )
        {
            PH::$JSON_OUT['log'] = PH::$JSON_OUTlog;
            print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
            #print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT|JSON_FORCE_OBJECT );
        }
        if( !empty($warningString) )
            mwarning( $warningString, null, false );
        exit(1);
    }

    public function prepareSupportedArgumentsArray()
    {
        $tmpArgs = array();
        foreach( $this->supportedArguments as &$arg )
        {
            $tmpArgs[strtolower($arg['niceName'])] = $arg;
        }
        $this->supportedArguments = $tmpArgs;
    }

    public function init_arguments()
    {
        $this->inDebugapiArgument();


        if( !isset(PH::$args['actions']) )
        {
            PH::$args['actions'] = "display";
        }

        $this->doActions = PH::$args['actions'];
        if( !is_string($this->doActions) || strlen($this->doActions) < 1 )
            $this->display_error_usage_exit('"actions" argument is not a valid string');


        if( isset(PH::$args['dryrun']) )
        {
            $this->dryRun = PH::$args['dryrun'];
            if( $this->dryRun === 'yes' ) $this->dryRun = TRUE;
            if( $this->dryRun !== TRUE || $this->dryRun !== FALSE )
                $this->display_error_usage_exit('"dryrun" argument has an invalid value');
        }

        //
        // Rule filter provided in CLI ?
        //
        if( isset(PH::$args['filter']) )
        {
            $this->objectsFilter = PH::$args['filter'];
            if( !is_string($this->objectsFilter) || strlen($this->objectsFilter) < 1 )
                $this->display_error_usage_exit('"filter" argument is not a valid string');
        }

        if( isset(PH::$args['apiTimeout']) )
            $this->apiTimeoutValue = PH::$args['apiTimeout'];


        if( isset(PH::$args['expedition']) )
        {
            $this->expedition = PH::$args['expedition'];
            $tmp_expedition = explode(",", $this->expedition);

            if( isset($tmp_expedition[0]) && isset($tmp_expedition[1]) && isset($tmp_expedition[2]) && isset($tmp_expedition[3]) )
            {
                $this->expedition_db_ip = $tmp_expedition[0];
                $this->expedition_db_user = $tmp_expedition[1];
                $this->expedition_db_pw = $tmp_expedition[2];
                $this->taskId = $tmp_expedition[3];
            }
            else
            {
                $this->display_error_usage_exit('"expedition" argument has an invalid value. This argument can be only used directly from Expedition Tool');
            }
            unset($tmp_expedition);
        }

        if( isset(PH::$args['auditcomment']) )
        {
            $this->auditComment = PH::$args['auditcomment'];
        }

        if( isset(PH::$args['projectfolder']) )
        {
            $this->projectFolder = PH::$args['projectfolder'];
            if (!file_exists($this->projectFolder)) {
                mkdir($this->projectFolder, 0777, true);
            }
        }

        if( isset(PH::$args['outputformatset']) )
        {
            $this->outputformatset = TRUE;
            $this->origXmlDoc = new DOMDocument();

            if( !is_bool(PH::$args['outputformatset']) )
            {
                $this->outputformatsetFile = PH::$args['outputformatset'];

                if( $this->projectFolder !== null )
                {
                    if( strpos($this->outputformatsetFile, $this->projectFolder) === FALSE )
                        $this->outputformatsetFile = $this->projectFolder."/".$this->outputformatsetFile;
                }

            }
        }

        if( isset(PH::$args['cycleconnectedfirewalls']) )
            $this->cycleConnectedFirewalls = TRUE;


        $this->inputValidation();


        $this->location_provided();
    }

    public function inDebugapiArgument()
    {
        if( !isset(PH::$args['in']) )
        {
            if( $this->utilType == "threat" || $this->utilType == "application" )
            {
                PH::$args['location'] = "shared";
                PH::$args['in'] = dirname(__FILE__)."/../../migration/parser/panos_baseconfig.xml";
            }
            else
                $this->display_error_usage_exit('"in" is missing from arguments');
        }

        $this->configInput = PH::$args['in'];
        if( !is_string($this->configInput) || strlen($this->configInput) < 1 )
            $this->display_error_usage_exit('"in" argument is not a valid string');

        if( isset(PH::$args['debugapi']) )
        {
            $this->debugAPI = TRUE;
        }

        if( isset(PH::$args['debugloadtime']) )
        {
            $this->debugLoadTime = TRUE;
        }

    }

    public function inputValidation()
    {
        //
        // What kind of config input do we have.
        //     File or API ?
        //
        // <editor-fold desc="  ****  input method validation and PANOS vs Panorama auto-detect  ****" defaultstate="collapsed" >
        $this->configInput = PH::processIOMethod($this->configInput, TRUE);

        if( $this->configInput['status'] == 'fail' )
        {
            if( isset( $_SERVER['REQUEST_METHOD'] ) )
            {
                throw new Exception( "**ERROR** " . $this->configInput['msg'], 404);
            }
            else
            {
                $message = "\n\n**ERROR** " . $this->configInput['msg'] . "\n\n";
                if( !PH::$shadow_json )
                    fwrite(STDERR, $message);
                else
                {
                    $e = new Exception($message, 404);
                    print json_encode(["error" => $e->getMessage() ]);
                }
                exit(1);
            }
        }

        if( $this->configInput['type'] == 'file' )
        {
            if( !isset(PH::$args['out']) )
            {
                PH::$args['out'] = "/dev/null";
            }
            if( isset(PH::$args['out']) )
            {
                $this->configOutput = PH::$args['out'];
                if( !is_string($this->configOutput) || strlen($this->configOutput) < 1 )
                    $this->display_error_usage_exit('"out" argument is not a valid string');
            }

            $this->apiMode = FALSE;
            if( !file_exists($this->configInput['filename']) )
                derr("file '{$this->configInput['filename']}' not found");

            $this->xmlDoc = new DOMDocument();
            PH::print_stdout( " - Reading XML file from disk... ".$this->configInput['filename'] );
            if( !$this->xmlDoc->load($this->configInput['filename'], XML_PARSE_BIG_LINES) )
                derr("error while reading xml config file");

            if( $this->outputformatset )
                $this->origXmlDoc->load($this->configInput['filename'], XML_PARSE_BIG_LINES);
        }
        elseif( $this->configInput['type'] == 'api' )
        {
            if( $this->debugAPI )
                $this->configInput['connector']->setShowApiCalls(TRUE);
            $this->apiMode = TRUE;

            $this->configInput['connector']->setUTILtype( $this->utilType );
            if( !empty(PH::$args['actions']) )
                $this->configInput['connector']->setUTILaction( PH::$args['actions'] );


            PH::print_stdout( " - Downloading config from API... " );


            if( !isset($this->configInput['filename']) || $this->configInput['filename'] == '' || $this->configInput['filename'] == 'candidate-config' )
            {
                $this->xmlDoc = $this->configInput['connector']->getCandidateConfig( $this->apiTimeoutValue );
                if( $this->outputformatset )
                    $this->origXmlDoc = $this->configInput['connector']->getCandidateConfig( $this->apiTimeoutValue );
            }
            elseif( $this->configInput['filename'] == 'running-config' )
            {
                $this->xmlDoc = $this->configInput['connector']->getRunningConfig();
                if( $this->outputformatset )
                    $this->origXmlDoc = $this->configInput['connector']->getRunningConfig();
            }
            elseif( $this->configInput['filename'] == 'merged-config' || $this->configInput['filename'] == 'merged' )
            {
                $this->xmlDoc = $this->configInput['connector']->getMergedConfig();
                if( $this->outputformatset )
                    $this->origXmlDoc = $this->configInput['connector']->getMergedConfig();
            }
            elseif( $this->configInput['filename'] == 'panorama-pushed-config' || $this->configInput['filename'] == 'panorama-pushed' )
            {
                $this->xmlDoc = $this->configInput['connector']->getPanoramaPushedConfig();
                if( $this->outputformatset )
                    $this->origXmlDoc = $this->configInput['connector']->getPanoramaPushedConfig();
            }
            else
            {
                $this->xmlDoc = $this->configInput['connector']->getSavedConfig($this->configInput['filename']);
                if( $this->outputformatset )
                    $this->origXmlDoc = $this->configInput['connector']->getSavedConfig($this->configInput['filename']);
            }
        }
        elseif( $this->configInput['type'] == 'sase-api')
        {
            if( $this->debugAPI )
                $this->configInput['connector']->setShowApiCalls(TRUE);
            $this->apiMode = TRUE;
/*
            $this->configInput['connector']->setUTILtype( $this->utilType );
            if( !empty(PH::$args['actions']) )
                $this->configInput['connector']->setUTILaction( PH::$args['actions'] );
*/
            $this->scope = $this->configInput['connector']->scope;

            if( isset(PH::$args['out']) )
            {
                $this->configOutput = PH::$args['out'];
                if( !is_string($this->configOutput) || strlen($this->configOutput) < 1 )
                    $this->display_error_usage_exit('"out" argument is not a valid string');
            }

            ##############################################
            //- load fawkes base config into $this->xmldoc
            $fawkes_filename = dirname(__FILE__)."/../develop/fawkes_baseconfig.xml";
            $this->configType = 'fawkes';
            $this->pan = new FawkesConf();

            $this->xmlDoc = new DOMDocument();
            PH::print_stdout( " - Reading XML file from disk... ".$fawkes_filename );
            if( !$this->xmlDoc->load($fawkes_filename, XML_PARSE_BIG_LINES) )
                derr("error while reading xml config file");

            if( $this->outputformatset )
                $this->origXmlDoc->load($fawkes_filename, XML_PARSE_BIG_LINES);

            PH::print_stdout( " - Loading configuration through PAN-OS-PHP library... " );

            $this->pan->load_from_domxml($this->xmlDoc, XML_PARSE_BIG_LINES);

            ##############################################
            PanAPIConnector::loadConnectorsFromUserHome();
            $TSGid = str_replace( "tsg_id:", "", $this->scope);

            $sase_connector =  new PanSaseAPIConnector($TSGid);
            if( $this->debugAPI )
                $sase_connector->showApiCalls = TRUE;
            $sase_connector->findOrCreateConnectorFromHost($TSGid);

            $folderArray = PanSaseAPIConnector::$folderArray;
            foreach( $folderArray as $folder )
            {
                if( $folder === "Shared" )
                    $sub = $this->pan->findContainer( "Prisma Access");
                else
                {
                    $sub = $this->pan->findContainer( $folder);
                    if( $sub === null )
                    {
                        $sub = $this->pan->findDeviceCloud( $folder);
                        if( $sub === null )
                            $sub = $this->pan->createDeviceCloud( $folder, "Prisma Access" );
                    }
                }

                //Todo: 20240326 swaschkut - do not always load full config
                #$sase_connector->loadSaseConfig($folder, $sub, $this->utilType);
            }
        }
        else
            derr('not supported yet');

        $this->determineConfigType();
    }

    public function determineConfigType()
    {
        //
        // Determine if PANOS or Panorama
        //
        $xpathResult = DH::findXPath('/config', $this->xmlDoc);
        $xpathResult = $xpathResult->item(0);

        $buckbeak_config_version = null;
        $fawkes_config_version = null;
        if( $xpathResult != null )
        {
            //BUCKBEAK
            $buckbeak_config_version = DH::findAttribute('buckbeak', $xpathResult);

            //FAWKES
            $fawkes_config_version = DH::findAttribute('fawkes-config-version', $xpathResult);
            if( $fawkes_config_version == null )
                $fawkes_config_version = DH::findAttribute('fawkes-config', $xpathResult);

            if( $fawkes_config_version != null )
            {
                PH::print_stdout( " - FAWKES-CONFIG-VERSION: ".$fawkes_config_version );
                PH::print_stdout( array( $fawkes_config_version ), false, "fawkes-config-version" );
            }
        }


        $xpathResult = DH::findXPath('/config/devices/entry/vsys', $this->xmlDoc);
        if( $xpathResult === FALSE )
            derr('XPath error happened');
        if( $xpathResult->length < 1 )
        {
            if( $buckbeak_config_version != null )
                $this->configType = 'buckbeak';
            elseif( $fawkes_config_version != null )
                $this->configType = 'fawkes';
            else
                $this->configType = 'panorama';
        }

        else
            $this->configType = 'panos';
        unset($xpathResult);


        if( isset($this->configInput['type']) && $this->configInput['type'] !== 'sase-api')
        {
            if( $this->configType == 'panos' )
            {
                if( isset(PH::$args['loadpanoramapushedconfig']) )
                {
                    $inputConnector = $this->configInput['connector'];

                    PH::print_stdout( " - 'loadPanoramaPushedConfig' was requested, downloading it through API..." );
                    $this->pan = $inputConnector->loadPanoramaPushdedConfig( $this->apiTimeoutValue );
                }
                else
                    $this->pan = new PANConf();
            }
            elseif( $this->configType == 'panorama' )
                $this->pan = new PanoramaConf();
            elseif( $this->configType == 'fawkes' )
                $this->pan = new FawkesConf();
            elseif( $this->configType == 'buckbeak' )
                $this->pan = new BuckbeakConf();
            else
                derr( "configType: ".$this->configType." not supported." );
        }

        PH::print_stdout( " - Detected platform type is '{$this->configType}'" );
        PH::print_stdout( array( get_class( $this->pan ) ), false, "platform" );

        if( isset($this->configInput['type']) && ( $this->configInput['type'] == 'api' || $this->configInput['type'] == 'sase-api' ) )
            $this->pan->connector = $this->configInput['connector'];
        // </editor-fold>
    }

    public function location_provided()
    {
        //
        // Location provided in CLI ?
        //
        if( isset(PH::$args['location']) )
        {
            $this->objectsLocation = PH::$args['location'];
            if( !is_string($this->objectsLocation) || strlen($this->objectsLocation) < 1 )
                $this->display_error_usage_exit('"location" argument is not a valid string');
        }
        else
        {
            if( $this->configType == 'panos' )
                $this->objectsLocation = 'vsys1';
            elseif( $this->configType == 'panorama' )
                $this->objectsLocation = 'shared';
            elseif( $this->configType == 'fawkes' || $this->configType == 'buckbeak')
                $this->objectsLocation = 'All';

            if( get_class( $this ) == "NETWORKUTIL" )
                $this->objectsLocation = 'any';

            PH::print_stdout( " - No 'location' provided so using default ='".$this->objectsLocation."'" );
        }
        PH::print_stdout( array( $this->objectsLocation ), false, "location");
        //
        // Template provided in CLI ?
        //
        if( isset(PH::$args['template']) )
        {
            $this->objectsTemplate = PH::$args['template'];
            if( !is_string($this->objectsTemplate) || strlen($this->objectsTemplate) < 1 )
                $this->display_error_usage_exit('"location" argument is not a valid string');
        }
        else
        {
            if( $this->configType == 'panos' )
                $this->objectsTemplate = 'any';
            elseif( $this->configType == 'panorama' )
                $this->objectsTemplate = 'any';
            elseif( $this->configType == 'fawkes' || $this->configType == 'buckbeak')
                $this->objectsTemplate = 'any';

            if( get_class( $this ) == "NETWORKUTIL" )
                $this->objectsTemplate = 'any';

            PH::print_stdout( " - No 'template' provided so using default ='".$this->objectsTemplate."'" );
        }
        PH::print_stdout( array( $this->objectsTemplate ), false, "template");
    }

    public function extracting_actions( $utilType = null)
    {
        if( $utilType != null )
            $this->utilType = $utilType;

        $tmp_array = $this->supportedActions();

        //
        // Extracting actions
        //
        $tmp_doactions = str_replace( "//", "****", $this->doActions );
        $explodedActions = explode('/', $tmp_doactions);

        /** @var TagCallContext[] $doActions */
        $this->doActions = array();
        foreach( $explodedActions as &$exAction )
        {
            $exAction = str_replace( "****", "/", $exAction );

            $explodedAction = explode(':', $exAction);
            if( count($explodedAction) > 2 )
                $this->display_error_usage_exit('"actions" argument has illegal syntax: ' . PH::$args['actions']);

            $actionName = strtolower($explodedAction[0]);

            if( !isset($tmp_array[$actionName]) )
            {
                $this->display_error_usage_exit('unsupported Action: "' . $actionName . '"');
            }

            if( count($explodedAction) == 1 )
                $explodedAction[1] = '';

            //variable based on which util script is calling the method
            if( $this->utilType == 'tag' )
                $context = new TagCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'address' )
                $context = new AddressCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'service' )
                $context = new ServiceCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'rule' )
                $context = new RuleCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);

            elseif( $this->utilType == 'securityprofile' )
                $context = new SecurityProfileCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'securityprofilegroup' )
                $context = new SecurityProfileGroupCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'schedule' )
                $context = new ScheduleCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'edl' )
                $context = new EDLCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'application' )
                $context = new ApplicationCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'threat' )
                $context = new ThreatCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'threat-rule' )
                $context = new ThreatRuleCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'dns-rule' )
                $context = new DNSRuleCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);

            elseif( $this->utilType == 'device' )
                $context = new DeviceCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'vsys' )
                $context = new VsysCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);

            elseif( $this->utilType == 'zone' )
                $context = new ZoneCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'virtualwire' )
                $context = new VirtualWireCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'routing' )
                $context = new RoutingCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'interface' )
                $context = new InterfaceCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'dhcp' )
                $context = new DHCPCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'certificate' )
                $context = new CertificateCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'static-route' )
                $context = new StaticRouteCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'gp-gateway' )
                $context = new GPGatewayCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'gp-portal' )
                $context = new GPPortalCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'ike-profile' )
                $context = new IKEprofileCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'ike-gateway' )
                $context = new IKEgatewayCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'ipsec-profile' )
                $context = new IPsecprofileCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'ipsec-tunnel' )
                $context = new IPsectunnelCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'gre-tunnel' )
                $context = new GREtunnelCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);
            elseif( $this->utilType == 'gpgateway-tunnel' )
                $context = new GPGatewaytunnelCallContext($tmp_array[$actionName], $explodedAction[1], $this->nestedQueries, $this);

            $context->baseObject = $this->pan;
            if( isset($this->configInput['type'])  )
            {
                if( $this->configInput['type'] == 'api' )
                    $context->isAPI = TRUE;
                elseif( $this->configInput['type'] == 'sase-api' )
                {
                    $context->isAPI = TRUE;
                    $context->isSaseAPI = TRUE;
                }


                $context->connector = $this->pan->connector;
            }

            if( $this->projectFolder !== null )
            {
                $context->projectFolder = $this->projectFolder;
            }

            $this->doActions[] = $context;
        }
//
// ---------
    }


    public function createRQuery()
    {
        //
        // create a RQuery if a filter was provided
        //
        /**
         * @var RQuery $objectFilterRQuery
         */

        if( $this->objectsFilter !== null )
        {
            /*
            if( isset($this->configInput['type'])  ) {
                if ($this->configInput['type'] == 'api')
                    $this->objectFilterRQuery = new RQuery($this->utilType, 0, TRUE);
            }
            else
            */
                $this->objectFilterRQuery = new RQuery($this->utilType);

            $res = $this->objectFilterRQuery->parseFromString($this->objectsFilter, $errorMessage);
            if( $res === FALSE )
            {
                fwrite(STDERR, "\n\n**ERROR** Rule filter parser: " . $errorMessage . "\n\n");
                exit(1);
            }

            PH::print_stdout( " - filter after sanitization : " . $this->objectFilterRQuery->sanitizedString() );
            PH::print_stdout( array( $this->objectFilterRQuery->sanitizedString() ), false, "filter");
        }
        // --------------------
    }

    #static public function load_config( $pan, $xmlDoc )
    public function load_config()
    {
        //
        // load the config
        //
        if( $this->configInput['type'] !== "sase-api" )
            PH::print_stdout( " - Loading configuration through PAN-OS-PHP library... " );

        $this->loadStart();

        if( $this->configInput['type'] !== "sase-api" )
            $this->pan->load_from_domxml($this->xmlDoc, $this->debugLoadTime);


        $this->loadEnd();

        if( isset($this->configInput['type']) && $this->configInput['type'] == 'api' )
        {
            //Todo: if AuditComment are only needed if setting _auditComment is forced, please think about additional check
            #if( isset($this->pan->_auditComment) ){
                #$this->configInput['connector']->setAuditCommentBool( $this->pan->_auditComment );
                $this->configInput['connector']->setAuditCommentBool( TRUE );
                if( $this->auditComment !== null )
                    $this->configInput['connector']->setAuditComment( $this->auditComment);
            #}
        }


        PH::print_stdout( "   ($this->loadElapsedTime seconds, $this->loadUsedMem memory)" );
        PH::print_stdout( array( "value" => $this->loadElapsedTime, "type" => " seconds") , false, "loadtime");

        PH::print_stdout( array( "value" => $this->loadArrayMem[0], "type" => $this->loadArrayMem[1]) , false, "loadmemory");
        // --------------------

        $panc_version = $this->pan->appStore->predefinedStore_appid_version;
        PH::print_stdout( " - PAN-OS-PHP APP-ID version: ".$panc_version );
        PH::print_stdout( array( $panc_version ), false, "PAN-OS-PHP APP-ID version" );

        PH::print_stdout();
        if($this->configInput['type'] == 'api')
        {
            PH::print_stdout( " - PAN-OS APP-ID version: ".$this->configInput['connector']->info_app_version );
            PH::print_stdout( array( $this->configInput['connector']->info_app_version ), false, "PAN-OS APP-ID version" );

            PH::print_stdout( " - PAN-OS AV version: ".$this->configInput['connector']->info_av_version );
            PH::print_stdout( array( $this->configInput['connector']->info_av_version ), false, "PAN-OS AV version" );

            PH::print_stdout( " - PAN-OS WF version: ".$this->configInput['connector']->info_wildfire_version );
            PH::print_stdout( array( $this->configInput['connector']->info_wildfire_version ), false, "PAN-OS WF version" );

            PH::print_stdout( " - PAN-OS THREAT version: ".$this->configInput['connector']->info_threat_version );
            PH::print_stdout( array( $this->configInput['connector']->info_threat_version ), false, "PAN-OS THREAT version" );
        }
        PH::print_stdout( " - PAN-OS version: {$this->pan->version}" );
        PH::print_stdout( array( $this->pan->version ), false, "PAN-OS version" );


        if( isset( $this->pan->timezone ) && $this->pan->timezone !== null )
            PH::print_stdout( " - PAN-OS Device timezone: ".$this->pan->timezone ." is used. actual time: ".date('Y/m/d H:i:s') );

        /*
        //if API and Git store it
        if( isset(PH::$args['git']) && PH::$args['git'] )
        {
            $directory = dirname(__FILE__).'/../../projects';
            $filename = 'test.xml';

            $printMessage = TRUE;
            $lineReturn = TRUE;
            $indentingXml = 0;
            $indentingXmlIncreament = 1;

            $this->pan->save_to_file($directory."/".$filename, $printMessage, $lineReturn, $indentingXml, $indentingXmlIncreament);


            /** @var Git $git */
        /*
            $git = new Git();


            //$directory = dirname( "../../projects/".$this->configInput );
            //$filename = basename( $this->configInput['filename'] );

            $repo = $git->init($directory);
            $repo->addFile($directory."/".$filename);
            #$repo->addAllChanges();

            $repo->commit($directory."/".$filename.' before save of: '.$this->PHP_FILE );

            //this is only for API
            //$this->configOutput = $this->configInput['filename'];
        }
        */
    }

    public function loadStart()
    {
        $this->loadStartMem = memory_get_usage(TRUE);
        $this->loadStartTime = microtime(TRUE);

        PH::$loadStartTime = $this->loadStartTime;
        PH::$loadStartMem = $this->loadStartMem;
    }

    public function loadEnd()
    {
        $this->loadEndTime = microtime(TRUE);
        $this->loadEndMem = memory_get_usage(TRUE);
        $this->loadElapsedTime = number_format(($this->loadEndTime - $this->loadStartTime), 2, '.', '');
        $this->loadUsedMem = convert($this->loadEndMem - $this->loadStartMem, $this->loadArrayMem);
    }

    public function location_filter()
    {
        //
        // Location Filter Processing
        //

        if( strpos( $this->objectsLocation, "," ) !== FALSE )
        {
            if( strpos( $this->objectsLocation, ":" ) !== FALSE )
                derr( "location argument can only handle ',' or ':' not both", null, FALSE );
            else
            {
                // <editor-fold desc=" ****  Location Filter Processing  ****" defaultstate="collapsed" >
                /**
                 * @var RuleStore[] $ruleStoresToProcess
                 */
                $this->objectsLocation = explode(',', $this->objectsLocation);

                foreach( $this->objectsLocation as $key => &$location )
                {
                    if( strtolower($location) == 'shared' )
                        $this->objectsLocation[$key] = 'shared';
                    else if( strtolower($location) == 'any' )
                        $this->objectsLocation[$key] = 'any';
                    else if( strtolower($location) == 'all' )
                    {
                        if( $this->configType == 'fawkes' || $this->configType == 'buckbeak')
                            $this->objectsLocation[$key] = 'All';
                        else
                            $this->objectsLocation[$key] = 'any';
                    }
                }
                unset($location);
            }
        }
        elseif( strpos( $this->objectsLocation, ":" ) !== FALSE )
        {
            $loc_explode = explode( ":", $this->objectsLocation );

            if( count( $loc_explode ) > 2 )
                derr( "location argument with ':' found, can only handle one argument", null, FALSE );

            $rootDG = $loc_explode[0];
            $opt_argument = strtolower($loc_explode[1]);

            if( $this->configType == 'panos' )
            {
                if( $rootDG == "shared" )
                {
                    $DG = $this->pan;
                    $childDGs = $this->pan->getVirtualSystems();
                }
                else
                {
                    $DG = $this->pan->findVirtualSystem( $rootDG );
                    if( $DG === null )
                        $this->locationNotFound($rootDG);
                    $childDGs = array();
                }
            }
            elseif($this->configType == 'panorama')
            {
                $DG = $this->pan->findDeviceGroup( $rootDG );
                if( $DG === null )
                    $this->locationNotFound($rootDG);

                $childDGs = $DG->childDeviceGroups( TRUE );
            }


            $this->objectsLocation = array();

            $optArgArray = array( "includechilddgs", "excludemaindg" );
            if( !in_array( $opt_argument, $optArgArray ) )
                derr( "location has an optional argument which is not supported: '".$opt_argument."' - supported onces: ".implode( ", ", $optArgArray ), null, FALSE );

            if( $opt_argument == "includechilddgs" )
                $this->objectsLocation[] = $rootDG;
            elseif( $opt_argument == "excludemaindg" )
            {}

            foreach( $childDGs as  $dgs )
                $this->objectsLocation[] = $dgs->name();
        }
        else
            $this->objectsLocation = explode(',', $this->objectsLocation);



        $this->objectsLocation = array_unique($this->objectsLocation);
        if( count( $this->objectsLocation ) == 1 )
        {
            $this->location = $this->objectsLocation[0];
            if( $this->location == 'shared' )
            {
                $this->sub = $this->pan;
            }
            elseif( $this->location == 'any' )
            {
                #
            }
            else
            {
                $this->sub = $this->pan->findSubSystemByName($this->location);
                if( $this->sub === null )
                {
                    $this->locationNotFound($this->location);
                }
            }
        }

        //
        // Template Filter Processing
        //

        // <editor-fold desc=" ****  Location Filter Processing  ****" defaultstate="collapsed" >
        $this->objectsTemplate = explode(',', $this->objectsTemplate);

        foreach( $this->objectsTemplate as $key => &$location )
        {
            if( strtolower($location) == 'any' )
                $this->objectsTemplate[$key] = 'any';
            else if( strtolower($location) == 'all' )
            {
                $this->objectsTemplate[$key] = 'any';
            }
        }
        unset($location);

        $this->objectsTemplate = array_unique($this->objectsTemplate);

        if( count( $this->objectsTemplate ) == 1 )
        {
            $this->templateName = $this->objectsTemplate[0];

            if( $this->templateName == 'shared' )
            {
                #$this->sub = $this->pan;
            }
            elseif( $this->templateName == 'any' )
            {
                #
            }
            else
            {
                $this->template = $this->pan->findTemplate($this->templateName);
                if( $this->template === null )
                {
                    $this->template = $this->pan->findTemplateStack($this->templateName);

                    if( $this->template === null )
                    {
                        PH::print_stdout( "");
                        PH::print_stdout("");
                        PH::print_stdout( "  - available Templates:");
                        foreach( $this->pan->templates as $template )
                            PH::print_stdout( "   - ".$template->name() );

                        PH::print_stdout("");
                        PH::print_stdout( "  - available TemplateStack:");
                        foreach( $this->pan->templatestacks as $templateStack )
                            PH::print_stdout( "   - ".$templateStack->name() );

                        derr("template: '" . $this->templateName . "' not found!", null, FALSE);
                        #$this->locationNotFound($this->location);
                    }
                }
            }
        }
    }

    public function location_filter_object()
    {
        $sub = null;

        //location_filter() must run before;
        foreach( $this->objectsLocation as $location )
        {
            $locationFound = FALSE;

            if( $this->configType == 'panos' )
            {
                if( $location == 'shared' || $location == 'any' )
                {
                    if( $this->utilType == 'address' )
                    {
                        $this->objectsToProcess[] = array('store' => $this->pan->addressStore, 'objects' => $this->pan->addressStore->all(null, TRUE));
                    }
                    elseif( $this->utilType == 'service' )
                        $this->objectsToProcess[] = array('store' => $this->pan->serviceStore, 'objects' => $this->pan->serviceStore->all(null, TRUE));
                    elseif( $this->utilType == 'tag' )
                        $this->objectsToProcess[] = array('store' => $this->pan->tagStore, 'objects' => $this->pan->tagStore->getall());
                    elseif( $this->utilType == 'vsys' )
                        $this->objectsToProcess[] = array('store' => $this->pan, 'objects' => $this->pan->getVirtualSystems());
                    elseif( $this->utilType == 'securityprofilegroup' )
                        $this->objectsToProcess[] = array('store' => $this->pan->securityProfileGroupStore, 'objects' => $this->pan->securityProfileGroupStore->getAll());
                    elseif( $this->utilType == 'schedule' )
                        $this->objectsToProcess[] = array('store' => $this->pan->scheduleStore, 'objects' => $this->pan->scheduleStore->getall());
                    elseif( $this->utilType == 'edl' )
                        $this->objectsToProcess[] = array('store' => $this->pan->EDLStore, 'objects' => $this->pan->EDLStore->getall());
                    elseif( $this->utilType == 'application' )
                        $this->objectsToProcess[] = array('store' => $this->pan->appStore, 'objects' => $this->pan->appStore->apps());
                    elseif( $this->utilType == 'threat' )
                        $this->objectsToProcess[] = array('store' => $this->pan->threatStore, 'objects' => $this->pan->threatStore->getAll());
                    elseif( $this->utilType == 'threat-rule' )
                        $this->objectsToProcess[] = array('store' => $this->pan->ThreatPolicyStore, 'objects' => $this->pan->ThreatPolicyStore->getAll());
                    elseif( $this->utilType == 'dns-rule' )
                        $this->objectsToProcess[] = array('store' => $this->pan->DNSPolicyStore, 'objects' => $this->pan->DNSPolicyStore->getAll());

                    $locationFound = TRUE;
                    self::GlobalInitAction($this->pan);
                }
                foreach( $this->pan->getVirtualSystems() as $sub )
                {
                    if( isset(PH::$args['loadpanoramapushedconfig']) )
                    {
                        if( $this->utilType == 'address' )
                            $this->objectsToProcess[] = array('store' => $sub->addressStore, 'objects' => $sub->addressStore->resultingObjectSet());
                        elseif( $this->utilType == 'service' )
                            $this->objectsToProcess[] = array('store' => $sub->serviceStore, 'objects' => $sub->serviceStore->resultingObjectSet());
                        elseif( $this->utilType == 'tag' )
                            $this->objectsToProcess[] = array('store' => $sub->tagStore, 'objects' => $sub->tagStore->resultingObjectSet());
                        elseif( $this->utilType == 'securityprofilegroup' )
                            $this->objectsToProcess[] = array('store' => $sub->securityProfileGroupStore, 'objects' => $sub->securityProfileGroupStore->resultingObjectSet());
                        elseif( $this->utilType == 'schedule' )
                            $this->objectsToProcess[] = array('store' => $sub->scheduleStore, 'objects' => $sub->scheduleStore->resultingObjectSet());
                        elseif( $this->utilType == 'edl' )
                            $this->objectsToProcess[] = array('store' => $sub->EDLStore, 'objects' => $sub->EDLStore->resultingObjectSet());
                        elseif( $this->utilType == 'application' )
                            $this->objectsToProcess[] = array('store' => $sub->appStore, 'objects' => $sub->appStore->resultingObjectSet());
                        elseif( $this->utilType == 'threat-rule' )
                            $this->objectsToProcess[] = array('store' => $sub->ThreatPolicyStore, 'objects' => $sub->ThreatPolicyStore->resultingObjectSet());
                        elseif( $this->utilType == 'dns-rule' )
                            $this->objectsToProcess[] = array('store' => $sub->DNSPolicyStore, 'objects' => $sub->DNSPolicyStore->resultingObjectSet());

                        $locationFound = TRUE;
                        self::GlobalInitAction($sub);
                    }
                    elseif( ($location == 'any' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                    {
                        if( $this->utilType == 'address' )
                            $this->objectsToProcess[] = array('store' => $sub->addressStore, 'objects' => $sub->addressStore->all(null, TRUE));
                        elseif( $this->utilType == 'service' )
                            $this->objectsToProcess[] = array('store' => $sub->serviceStore, 'objects' => $sub->serviceStore->all(null, TRUE));
                        elseif( $this->utilType == 'tag' )
                            $this->objectsToProcess[] = array('store' => $sub->tagStore, 'objects' => $sub->tagStore->getall());
                        elseif( $this->utilType == 'securityprofilegroup' )
                            $this->objectsToProcess[] = array('store' => $sub->securityProfileGroupStore, 'objects' => $sub->securityProfileGroupStore->getAll());
                        elseif( $this->utilType == 'schedule' )
                            $this->objectsToProcess[] = array('store' => $sub->scheduleStore, 'objects' => $sub->scheduleStore->getall());
                        elseif( $this->utilType == 'edl' )
                            $this->objectsToProcess[] = array('store' => $sub->EDLStore, 'objects' => $sub->EDLStore->getall());
                        elseif( $this->utilType == 'application' )
                            $this->objectsToProcess[] = array('store' => $sub->appStore, 'objects' => $sub->appStore->apps());
                        elseif( $this->utilType == 'threat-rule' )
                            $this->objectsToProcess[] = array('store' => $sub->ThreatPolicyStore, 'objects' => $sub->ThreatPolicyStore->getall());
                        elseif( $this->utilType == 'dns-rule' )
                            $this->objectsToProcess[] = array('store' => $sub->DNSPolicyStore, 'objects' => $sub->DNSPolicyStore->getall());

                        $locationFound = TRUE;
                        self::GlobalInitAction($sub);
                    }
                }

                foreach( $this->pan->getSharedGateways() as $sub )
                {
                    if( ($location == 'any' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()])) )
                    {
                        if( $this->utilType == 'address' )
                            $this->objectsToProcess[] = array('store' => $sub->addressStore, 'objects' => $sub->addressStore->all(null, TRUE));
                        elseif( $this->utilType == 'service' )
                            $this->objectsToProcess[] = array('store' => $sub->serviceStore, 'objects' => $sub->serviceStore->all(null, TRUE));
                        elseif( $this->utilType == 'tag' )
                            $this->objectsToProcess[] = array('store' => $sub->tagStore, 'objects' => $sub->tagStore->getall());
                        elseif( $this->utilType == 'securityprofilegroup' )
                            $this->objectsToProcess[] = array('store' => $sub->securityProfileGroupStore, 'objects' => $sub->securityProfileGroupStore->getAll());
                        elseif( $this->utilType == 'schedule' )
                            $this->objectsToProcess[] = array('store' => $sub->scheduleStore, 'objects' => $sub->scheduleStore->getall());
                        elseif( $this->utilType == 'edl' )
                            $this->objectsToProcess[] = array('store' => $sub->EDLStore, 'objects' => $sub->EDLStore->getall());
                        elseif( $this->utilType == 'application' )
                            $this->objectsToProcess[] = array('store' => $sub->appStore, 'objects' => $sub->appStore->apps());
                        elseif( $this->utilType == 'threat-rule' )
                            $this->objectsToProcess[] = array('store' => $sub->ThreatPolicyStore, 'objects' => $sub->ThreatPolicyStore->getall());
                        elseif( $this->utilType == 'dns-rule' )
                            $this->objectsToProcess[] = array('store' => $sub->DNSPolicyStore, 'objects' => $sub->DNSPolicyStore->getall());

                        $locationFound = TRUE;
                        self::GlobalInitAction($this->pan);
                    }
                }

            }
            else
            {
                if( $this->configType == 'panorama' && ($location == 'shared' || $location == 'any') || PH::$shadow_loaddghierarchy )
                {
                    if( $this->utilType == 'address' )
                        $this->objectsToProcess[] = array('store' => $this->pan->addressStore, 'objects' => $this->pan->addressStore->all(null, TRUE));
                    elseif( $this->utilType == 'service' )
                        $this->objectsToProcess[] = array('store' => $this->pan->serviceStore, 'objects' => $this->pan->serviceStore->all(null, TRUE));

                    elseif( $this->utilType == 'tag' )
                        $this->objectsToProcess[] = array('store' => $this->pan->tagStore, 'objects' => $this->pan->tagStore->getall());
                    elseif( $this->utilType == 'securityprofilegroup' )
                        $this->objectsToProcess[] = array('store' => $this->pan->securityProfileGroupStore, 'objects' => $this->pan->securityProfileGroupStore->getAll());
                    elseif( $this->utilType == 'schedule' )
                        $this->objectsToProcess[] = array('store' => $this->pan->scheduleStore, 'objects' => $this->pan->scheduleStore->getall());
                    elseif( $this->utilType == 'edl' )
                        $this->objectsToProcess[] = array('store' => $this->pan->EDLStore, 'objects' => $this->pan->EDLStore->getall());
                    elseif( $this->utilType == 'application' )
                        $this->objectsToProcess[] = array('store' => $this->pan->appStore, 'objects' => $this->pan->appStore->apps());
                    elseif( $this->utilType == 'threat' )
                        $this->objectsToProcess[] = array('store' => $this->pan->threatStore, 'objects' => $this->pan->threatStore->getAll());
                    elseif( $this->utilType == 'threat-rule' )
                        $this->objectsToProcess[] = array('store' => $this->pan->ThreatPolicyStore, 'objects' => $this->pan->ThreatPolicyStore->getall());
                    elseif( $this->utilType == 'dns-rule' )
                        $this->objectsToProcess[] = array('store' => $this->pan->DNSPolicyStore, 'objects' => $this->pan->DNSPolicyStore->getall());

                    $locationFound = TRUE;
                    self::GlobalInitAction($this->pan);
                }
                elseif( $this->configType == 'fawkes' && ($location == 'ANY' || $location == 'any') )
                {
                    if( $this->utilType == 'application' )
                        $this->objectsToProcess[] = array('store' => $this->pan->appStore, 'objects' => $this->pan->appStore->apps());
                    elseif( $this->utilType == 'threat' )
                        $this->objectsToProcess[] = array('store' => $this->pan->threatStore, 'objects' => $this->pan->threatStore->getAll());
                    elseif( $this->utilType == 'threat-rule' )
                        $this->objectsToProcess[] = array('store' => $this->pan->ThreatPolicyStore, 'objects' => $this->pan->ThreatPolicyStore->getall());
                    elseif( $this->utilType == 'dns-rule' )
                        $this->objectsToProcess[] = array('store' => $this->pan->DNSPolicyStore, 'objects' => $this->pan->DNSPolicyStore->getall());

                    $locationFound = TRUE;
                    self::GlobalInitAction($this->pan);
                }


                if( $this->configType == 'panorama' )
                    $subGroups = $this->pan->getDeviceGroups();
                elseif( $this->configType == 'fawkes' || $this->configType == 'buckbeak' )
                {
                    $subGroups = $this->pan->getContainers();
                    $subGroups2 = $this->pan->getDeviceClouds();

                    $subGroups = array_merge( $subGroups, $subGroups2 );

                    $subGroups2 = $this->pan->getDeviceOnPrems();
                    $subGroups = array_merge( $subGroups, $subGroups2 );

                    $subGroups2 = $this->pan->getSnippets();
                    $subGroups = array_merge( $subGroups, $subGroups2 );
                }

                foreach( $subGroups as $sub )
                {
                    $parentDGS = array();
                    if( PH::$shadow_loaddghierarchy )
                    {
                        $DG_object = $this->pan->findDeviceGroup($location);
                        $parentDGS = $DG_object->parentDeviceGroups();
                    }

                    #if( ($location == 'any' || $location == 'all' || $location == $sub->name()) && !isset($ruleStoresToProcess[$sub->name() . '%pre']) )
                    if( ($location == 'any' || $location == $sub->name()) && !isset($ruleStoresToProcess[$sub->name() . '%pre']) || isset( $parentDGS[$sub->name()] ) )
                    {
                        if( $this->utilType == 'address' )
                            $this->objectsToProcess[] = array('store' => $sub->addressStore, 'objects' => $sub->addressStore->all(null, TRUE));
                        elseif( $this->utilType == 'service' )
                            $this->objectsToProcess[] = array('store' => $sub->serviceStore, 'objects' => $sub->serviceStore->all(null, TRUE));

                        elseif( $this->utilType == 'tag' )
                            $this->objectsToProcess[] = array('store' => $sub->tagStore, 'objects' => $sub->tagStore->getall());
                        elseif( $this->utilType == 'securityprofilegroup' )
                            $this->objectsToProcess[] = array('store' => $sub->securityProfileGroupStore, 'objects' => $sub->securityProfileGroupStore->getAll());
                        elseif( $this->utilType == 'schedule' )
                            $this->objectsToProcess[] = array('store' => $sub->scheduleStore, 'objects' => $sub->scheduleStore->getall());
                        elseif( $this->utilType == 'edl' )
                            $this->objectsToProcess[] = array('store' => $sub->EDLStore, 'objects' => $sub->EDLStore->getall());
                        elseif( $this->utilType == 'application' )
                            $this->objectsToProcess[] = array('store' => $sub->appStore, 'objects' => $sub->appStore->apps());
                        elseif( $this->utilType == 'threat-rule' )
                            $this->objectsToProcess[] = array('store' => $sub->ThreatPolicyStore, 'objects' => $sub->ThreatPolicyStore->getall());
                        elseif( $this->utilType == 'dns-rule' )
                            $this->objectsToProcess[] = array('store' => $sub->DNSPolicyStore, 'objects' => $sub->DNSPolicyStore->getall());

                        $locationFound = TRUE;
                        $this->GlobalInitAction($sub);
                    }
                }
            }

            if( !$locationFound )
            {
                $this->locationNotFound($location);
            }
        }
    }

    public function locationNotFound($location, $configType = null, $pan = null)
    {
        if( $this->configType == null )
            $this->configType = $configType;
        if( $this->pan == null )
            $this->pan = $pan;

        PH::print_stdout();
        $errorString = "ERROR: location '$location' was not found. Here is a list of available ones:";
        PH::print_stdout( $errorString );
        if( PH::$shadow_json )
            PH::$JSON_OUT['error'] = $errorString;

        if( $this->configType != 'fawkes' && $this->configType != 'buckbeak' )
            PH::print_stdout( " - shared" );
        if( $this->configType == 'panos' )
        {
            foreach( $this->pan->getVirtualSystems() as $sub )
            {
                PH::print_stdout( " - " . $sub->name() . " [".$sub->alternativeName()."]" );
                PH::$JSON_OUT['error-location'][] = $sub->name();
            }
            foreach( $this->pan->getSharedGateways() as $sub )
            {
                PH::print_stdout( " - " . $sub->name() . " [".$sub->alternativeName()."]" );
                PH::$JSON_OUT['error-location'][] = $sub->name();
            }
        }
        else
        {
            if( $this->configType == 'panorama' )
                $subGroups = $this->pan->getDeviceGroups();
            elseif( $this->configType == 'fawkes' || $this->configType == 'buckbeak' )
            {
                $subGroups = $this->pan->getContainers();
                $subGroups2 = $this->pan->getDeviceClouds();

                $subGroups = array_merge( $subGroups, $subGroups2 );

                $subGroups2 = $this->pan->getDeviceOnPrems();
                $subGroups = array_merge( $subGroups, $subGroups2 );

                $subGroups2 = $this->pan->getSnippets();
                $subGroups = array_merge( $subGroups, $subGroups2 );
            }

            foreach( $subGroups as $sub )
            {
                PH::print_stdout( " - " . $sub->name() );
                PH::$JSON_OUT['error-location'][] = $sub->name();
            }
        }
        PH::print_stdout();
        PH::print_stdout();

        if( PH::$shadow_json )
        {
            PH::$JSON_OUT['log'] = PH::$JSON_OUTlog;
            print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
            #print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT|JSON_FORCE_OBJECT );
        }
        exit(1);
    }

    public function GlobalInitAction($sub, $ruletype = null)
    {
        foreach( $this->doActions as $doAction )
        {
            if( $doAction->hasGlobalInitAction() )
            {
                $doAction->subSystem = $sub;
                if( $ruletype != null )
                    $doAction->ruletype = $ruletype;
                $doAction->executeGlobalInitAction();
            }
        }
    }

    public function time_to_process_objects()
    {
        //
        // It's time to process Rules !!!!
        //

        // <editor-fold desc=" *****  Object Processing  *****" defaultstate="collapsed" >
        foreach( $this->objectsToProcess as &$objectsRecord )
        {
            $subObjectsProcessed = 0;

            $store = $objectsRecord['store'];
            $objects = &$objectsRecord['objects'];

            PH::print_stdout();
            $string = "* processing store '" . PH::boldText($store->toString()) . "' that holds " . count($objects) . " objects";
            PH::print_stdout( $string );

            PH::$JSON_TMP = array();
            PH::$JSON_TMP['header'] = $string;

            foreach( $this->doActions as $doAction )
            {
                if( is_object($store->owner) )
                {
                    $doAction->subSystem = $store->owner;
                    PH::$JSON_TMP['sub']['name'] = $store->owner->name();
                    PH::$JSON_TMP['sub']['type'] = get_class( $store->owner );
                }

                else
                {
                    $doAction->subSystem = $store;
                    PH::$JSON_TMP['sub']['name'] = $store->name();
                    PH::$JSON_TMP['sub']['type'] = "shared";
                }

            }

            PH::$JSON_TMP['sub']['store'] = get_class( $store );

            if( count($objects) > 0 )
            {
                foreach( $objects as $object )
                {
                    /** @var Address|AddressGroup $object */
                    if( $this->objectFilterRQuery !== null )
                    {
                        $queryResult = $this->objectFilterRQuery->matchSingleObject(array('object' => $object, 'nestedQueries' => &$this->nestedQueries));
                        if( !$queryResult )
                            continue;
                    }

                    $this->totalObjectsProcessed++;
                    $subObjectsProcessed++;

                    //mwarning($object->name());

                    foreach( $this->doActions as $doAction )
                    {
                        $doAction->padding = '     ';
                        $doAction->executeAction($object);
                        PH::print_stdout();
                    }
                }
            }

            if( is_object($store->owner) )
                $tmp_name = $store->owner->name();
            elseif( is_object($store) )
                $tmp_name = $store->name();

            if( isset($store->owner->owner) && is_object($store->owner->owner) )
                $tmp_platform = get_class( $store->owner->owner );
            elseif( isset($store->owner) && is_object($store->owner) )
                $tmp_platform = get_class( $store->owner );
            else
                $tmp_platform = get_class( $store );


            PH::print_stdout();
            if( $this->pan->isPanorama() )
                $typeString = "DG";
            elseif( $this->pan->isFirewall() )
                $typeString = "Vsys";
            elseif( $this->pan->isFawkes() || $this->pan->isBuckbeak() )
                $typeString = "Container/DeviceCloud/DeviceOnPrem/Snippet";
            PH::print_stdout( "* objects processed in ".$typeString." '{$tmp_name}' : $subObjectsProcessed" );
            PH::print_stdout();
            PH::$JSON_TMP['sub']['summary']['processed'] = $subObjectsProcessed;
            PH::$JSON_TMP['sub']['summary']['available'] = $store->count();

            PH::print_stdout( PH::$JSON_TMP, false, $tmp_platform );
            PH::$JSON_TMP = array();
        }
        // </editor-fold>
    }

    public function GlobalFinishAction()
    {
        $first = TRUE;
        foreach( $this->doActions as $doAction )
        {
            if( $doAction->hasGlobalFinishAction() )
            {
                $first = FALSE;
                $doAction->executeGlobalFinishAction();
            }
        }
    }

    public function stats( $debug = false, $actions = "display" )
    {
        if( isset(PH::$args['stats']) )
        {
            /** @var PANConf|PanoramaConf|FawkesConf $pan */
            $pan = $this->pan;

            $mainConnector = null;
            if( $this->configInput['type'] == 'api' )
                $mainConnector = findConnector($pan);

            $pan->display_statistics( $mainConnector, $debug, $actions );

            $processedLocations = array();
            foreach( $this->objectsToProcess as &$record )
            {

                if( (get_class($record['store']->owner) != 'PanoramaConf' && get_class($record['store']->owner) != 'PANConf') )
                {
                    /** @var DeviceGroup|VirtualSystem|Container|DeviceCloud $sub */
                    $sub = $record['store']->owner;
                    if( isset($processedLocations[$sub->name()]) )
                        continue;

                    $processedLocations[$sub->name()] = TRUE;

                    if( isset(PH::$args['loadpanoramapushedconfig']) && get_class( $this->pan ) != 'PanoramaConf' )
                    {
                        if( $sub->parentDeviceGroup !== null )
                        {
                            $sub->parentDeviceGroup->display_statistics( $debug, $actions );
                        }
                    }

                    
                    $sub->display_statistics( $debug, $actions );
                }
            }

            if( $this->cycleConnectedFirewalls && $this->configType == 'panorama' && $this->configInput['type'] == 'api' )
            {
                $managedSerials = $pan->managedFirewallsSerialsModel;
                foreach( $managedSerials as $serial => $fw )
                {
                    $fwconnector = new PanAPIConnector($mainConnector->apihost, $mainConnector->apikey, 'panos-via-panorama', $serial);
                    $fwconnector->setShowApiCalls( $mainConnector->showApiCalls );

                    $firewall = $fwconnector->loadPanoramaPushdedConfig( $this->apiTimeoutValue );
                    $firewall->connector = $fwconnector;

                    $doc = $fwconnector->getMergedConfig();
                    $firewall->load_from_domxml( $doc );

                    $firewall->display_statistics( $fwconnector, $actions );

                    $firewall->display_bp_statistics( $actions );
                }

            }
        }
    }

    public function save_our_work($additional_output = FALSE, $printMessage = TRUE, $lineReturn = TRUE, $indentingXml = 0, $indentingXmlIncreament = 1)
    {
        if( PH::$shadow_reducexml )
        {
            $lineReturn = false;
            $indentingXml = -1;
            $indentingXmlIncreament = 0;

            //remove empty XML nodes
            $xpath = new DOMXPath($this->pan->xmlroot->ownerDocument);
            foreach( $xpath->query('//*[not(node())]') as $node )
                $node->parentNode->removeChild($node);

        }


        if( isset(PH::$args['git']) && PH::$args['git'] )
        {
            if( $this->configInput['type'] == 'api' )
            {
                //
            }
            else
            {
                /** @var Git $git */
                $git = new Git();

                $directory = dirname( $this->configInput['filename'] );
                $filename = basename( $this->configInput['filename'] );

                $repo = $git->init($directory);
                $repo->addFile($filename);
                #$repo->addAllChanges();

                $repo->commit($filename.' before save of: '.$this->PHP_FILE );

                $this->configOutput = $this->configInput['filename'];
            }
        }

        // save our work !!!
        if( $this->configOutput !== null )
        {
            if( $this->configOutput != '/dev/null' )
            {
                if( $this->configOutput != 'true' )
                {
                    if( PH::$shadow_json )
                    {
                        //store it JSON out
                        PH::$JSON_TMP['xmldoc'] = &DH::dom_to_xml($this->pan->xmlroot, $indentingXml, $lineReturn, -1, $indentingXmlIncreament);
                        PH::print_stdout(PH::$JSON_TMP, false, "out");
                        PH::$JSON_TMP = array();
                    }


                    // destroy destination file if it exists
                    if( file_exists($this->configOutput) && is_file($this->configOutput) )
                        unlink($this->configOutput);


                    $this->pan->save_to_file($this->configOutput, $printMessage, $lineReturn, $indentingXml, $indentingXmlIncreament);

                    if( isset(PH::$args['git']) && PH::$args['git'] )
                    {
                        $repo = $git->init($directory);

                        if( PH::$args['git'] != "" && !boolYesNo(PH::$args['git']) )
                            $repo = $repo->createBranch(PH::$args['git'], TRUE);

                        $repo->addFile($filename);
                        $repo->commit($this->PHP_FILE . " | " . implode(", ", PH::$args));

                        if( PH::$args['git'] != "" && !boolYesNo(PH::$args['git']) )
                            $repo->merge(PH::$args['git']);
                        //todo: merge branch to master

                    }
                }
            }
        }

        if( $additional_output )
        {
            $arg_array = array();
            if( $this->configInput['type'] != 'api' && $this->configOutput == "/dev/null" )
            {
                PH::print_stdout();
                PH::print_stdout( "argument 'out' was used with '/dev/null' - nothing is saved to an output file" );
                $arg_array['out'] = "/dev/null";
            }

            if( isset(PH::$args['actions']) && PH::$args['actions'] == "display" )
            {
                PH::print_stdout( "argument 'actions' was used with 'display'" );
                $arg_array['actions'] = "display";
            }
            PH::print_stdout( $arg_array, false, 'argument' );
        }

        //vulnerability??
        //$this->log->info("END UTIL: " . $this->PHP_FILE);
    }

    public function setTimezone()
    {
        /*
        if( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' )
        {
            $system_timezone = exec('tzutil /g');

            $temp = explode(' ', $system_timezone);
            $result = '';
            foreach( $temp as $t )
                $result .= $t[0];

            $system_timezone = strtoupper($result);
        }
        else
        {
            $system_timezone = exec('date +%Z');
        }

        $timezone_name = timezone_name_from_abbr($system_timezone);
        if( !$timezone_name )
            $timezone_name = "GMT";

        date_default_timezone_set($timezone_name);
        */

        if( $this->xmlDoc !== false && $this->xmlDoc !== null )
        {
            $configroot = DH::findFirstElementOrDie('config', $this->xmlDoc);
            $devicesroot = DH::findFirstElementOrDie('devices', $configroot);


            $localhostroot = DH::findFirstElementByNameAttrOrDie('entry', 'localhost.localdomain', $devicesroot);


            $deviceconfigroot = DH::findFirstElement('deviceconfig', $localhostroot);

            $systemroot = DH::findFirstElement('system', $deviceconfigroot);
            if( $systemroot !== FALSE )
            {
                $timezone = DH::findFirstElement('timezone', $systemroot);
                if( $timezone )
                {

                    PH::enableExceptionSupport();
                    try
                    {
                        $this->pan->timezone = $timezone->textContent;
                        date_default_timezone_set( $timezone->textContent );
                        PH::print_stdout( " - PAN-OS Device timezone: ".$this->pan->timezone ." is used. actual time: ".date('Y/m/d H:i:s') );
                    }
                    catch(Exception $e)
                    {
                        $timezone_backward = PH::timezone_backward_migration( $this->timezone );
                        if( $timezone_backward !== null )
                        {
                            $this->pan->timezone = $timezone_backward;
                            date_default_timezone_set($timezone_backward);

                            PH::print_stdout("   --------------");
                            PH::print_stdout( " X Timezone: $timezone->textContent is not supported with this PHP version. ".$this->timezone." is used." );
                            PH::print_stdout("   - the timezone is IANA deprecated. Please change to a supported one:");


                            PH::print_stdout();
                            PH::print_stdout("   -- '".$this->timezone."'");
                            PH::print_stdout("   --------------");
                            PH::print_stdout();
                        }
                        else
                        {
                            PH::print_stdout("timezone: '".$this->timezone."' not supported by IANA");
                        }
                    }
                    PH::disableExceptionSupport();
                }
            }
        }
    }

    static public function shadow_ignoreInvalidAddressObjects()
    {
        PH::$ignoreInvalidAddressObjects = TRUE;
    }

    public function endOfScript()
    {

        $runtime = number_format((microtime(TRUE) - $this->runStartTime), 2, '.', '');
        PH::print_stdout( array( 'value' => $runtime, 'type' => "seconds" ), false,'runtime' );

        if( PH::$shadow_json )
        {
            PH::$JSON_OUT['log'] = PH::$JSON_OUTlog;
            print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
            #print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT|JSON_FORCE_OBJECT );
        }

        if( $this->utilType !== "custom" )
        {
            PH::print_stdout();
            PH::print_stdout("************* END OF SCRIPT " . basename($this->PHP_FILE) . " ************");
            PH::print_stdout();
        }

        if( $this->outputformatset )
        {
            PH::print_stdout(" * script was called with argument 'outputformatset' - please wait for calculation");
            $utilDiff = new DIFF( "custom", array(), array(), "" );
            $utilDiff->outputFormatSet = TRUE;
            $utilDiff->outputformatsetFile = $this->outputformatsetFile;
            $utilDiff->pan = $this->pan;

            $utilDiff->configType = $this->configType;

            if( $this->debugAPI )
                $utilDiff->debugAPI = TRUE;


            $doc2 = new DOMDocument();
            $node = $doc2->importNode($this->pan->xmlroot, true);
            $doc2->appendChild($node);
            //print $doc2->saveXML();

            $utilDiff->runDiff( $this->origXmlDoc, $doc2 );

            $utilDiff->display_outputformatset();
        }
    }

    public function useException()
    {
        PH::$useExceptions = TRUE;
    }

    public function enableExceptionSupport()
    {
        PH::$doNotDisableExceptions = FALSE;
        if( PH::$useExceptions )
            PH::$doNotDisableExceptions = TRUE;

        PH::$useExceptions = TRUE;
    }

    public function disableExceptionSupport()
    {
        if( !PH::$doNotDisableExceptions )
            PH::$useExceptions = FALSE;
    }
}