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

/**
 * type=scm-export-xml
 *
 * The whole SCM configuration of a scm_pa_export.php folder (all containers, all types the pan-os-php loader knows)
 * as one XML file - offline. The same XML that scm_pa_xml_to_change.php uses as the original.
 */
class SCMEXPORTXML extends UTIL
{
    public function utilStart()
    {
        $this->usageMsg = PH::boldText('USAGE: ') . "\n" .
            "  - pan-os-php type=scm-export-xml in=scm-export://<export folder> out=SCM.xml\n" .
            "\n" .
            "  in    folder written by scm_pa_export.php: <outdir>/<TSG>/<timestamp>, or <outdir>/<TSG> / <outdir> (newest export\n" .
            "        with a config area)\n" .
            "  out   XML file (BuckbeakConf) - input for any pan-os-php utility (in=SCM.xml)\n";

        PH::processCliArgs();

        if( isset(PH::$args['help']) )
        {
            PH::print_stdout($this->usageMsg);
            exit(0);
        }

        $this->main();
    }

    public function supportedArguments()
    {
        $this->supportedArguments = array();
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'scm-export://<folder written by scm_pa_export.php>', 'argDesc' => 'scm-export://[folder]');
        $this->supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'XML file', 'argDesc' => '[filename]');
        $this->supportedArguments['projectfolder'] = array('niceName' => 'projectfolder', 'shortHelp' => 'folder for the output file', 'argDesc' => '[folder]');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
    }

    public function main()
    {
        if( !isset(PH::$args['in']) || !isset(PH::$args['out']) || !is_string(PH::$args['out']) )
            $this->display_error_usage_exit('"in=scm-export://<folder>" and "out=<file.xml>" are required');

        $in = PH::$args['in'];
        $dir = strpos($in, 'scm-export://') === 0 ? substr($in, strlen('scm-export://')) : $in;
        $out = PH::$args['out'];
        if( isset(PH::$args['projectfolder']) )
        {
            $this->projectFolder = PH::$args['projectfolder'];
            if( !file_exists($this->projectFolder) )
                mkdir($this->projectFolder, 0777, TRUE);
            if( strpos($out, $this->projectFolder) === FALSE )
                $out = $this->projectFolder . "/" . $out;
        }

        $connector = new PanSCMExportConnector($dir);
        PH::print_stdout( " - SCM export folder: " . $connector->exportDir . " (TSG " . str_replace("tsg_id:", "", $connector->scope) . ", offline)" );

        $pan = new BuckbeakConf();
        $doc = new DOMDocument();
        if( !$doc->load(dirname(__FILE__) . "/../develop/buckbeak_baseconfig.xml", XML_PARSE_BIG_LINES) )
            derr( "buckbeak base configuration not readable", null, FALSE );
        $pan->load_from_domxml($doc);

        $loaded = $connector->loadAll($pan);
        PH::print_stdout();
        PH::print_stdout( " - " . count($loaded) . " container(s) loaded" );

        if( file_exists($out) && is_file($out) )
            unlink($out);
        $pan->save_to_file($out);
    }
}
