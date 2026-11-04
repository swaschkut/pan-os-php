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

/**
 * type=scm-import
 *
 * Puts a Panorama or firewall configuration into an SCM configuration (see SCMImporter for the mapping)
 * and, with changes=, writes the SCM API requests that create it (type=scm-changes against scm=).
 */
class SCMIMPORT extends UTIL
{
    public function utilStart()
    {
        $this->usageMsg = PH::boldText('USAGE: ') . "\n" .
            "  Panorama:\n" .
            "  - pan-os-php type=scm-import in=panorama.xml scm=SCM.xml out=SCM-import.xml changes=import.json\n" .
            "        [shared=snippet|global] [shared-snippet=NAME]\n" .
            "  Firewall:\n" .
            "  - pan-os-php type=scm-import in=firewall.xml target=folder|snippet scm=SCM.xml out=SCM-import.xml changes=import.json\n" .
            "        [name=NAME] [vsys=vsys1] [serial=SERIAL]\n" .
            "\n" .
            "  scm       SCM configuration of the target tenant (in=scm-api://TSG_ID out=SCM.xml);\n" .
            "            without it an empty SCM configuration is used\n" .
            "  out       SCM configuration with the import (XML)\n" .
            "  changes   SCM API requests that create the import in the tenant (see type=scm-apply)\n" .
            "  shared    Panorama shared: 'snippet' (default, a snippet attached to All) or 'global' (directly into All)\n" .
            "  target    firewall: 'folder' (a new folder below the firewall folder) or 'snippet'\n" .
            "  name      firewall: name of the folder / snippet (default: hostname)\n" .
            "  serial    firewall with target=folder: attach this firewall (it must be onboarded in SCM)\n" .
            "  keep-zone-interfaces   keep the interfaces of zones (default: removed, interfaces are not imported)\n" .
            "\n" .
            "  Panorama mapping: device-group -> folder below the firewall folder (hierarchy kept), template and\n" .
            "  template-stack -> snippet, firewall -> device in the folder of its device-group with the snippets\n" .
            "  of its template-stack (stack first, then the templates in stack order).\n";

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
        foreach( array('in', 'scm', 'out', 'changes', 'shared', 'shared-snippet', 'target', 'name', 'vsys', 'serial',
                     'keep-zone-interfaces', 'projectfolder', 'help') as $a )
            $this->supportedArguments[$a] = array('niceName' => $a);
    }

    public function main()
    {
        foreach( array('in', 'out') as $a )
            if( !isset(PH::$args[$a]) || is_bool(PH::$args[$a]) )
                $this->display_error_usage_exit('"' . $a . '" is required');

        $in = PH::$args['in'];
        $out = PH::$args['out'];
        $changes = PH::$args['changes'] ?? null;
        if( isset(PH::$args['projectfolder']) )
        {
            $pf = PH::$args['projectfolder'];
            if( !file_exists($pf) )
                mkdir($pf, 0777, TRUE);
            foreach( array('out', 'changes') as $v )
                if( $$v !== null && strpos($$v, $pf) === FALSE )
                    $$v = $pf . "/" . $$v;
        }

        $scmFile = PH::$args['scm'] ?? dirname(__FILE__) . "/../develop/buckbeak_baseconfig.xml";
        foreach( array($in, $scmFile) as $f )
            if( !file_exists($f) )
                derr("file '" . $f . "' not found", null, FALSE);

        // target: SCM configuration
        $scmDoc = new DOMDocument();
        $scmDoc->load($scmFile, XML_PARSE_BIG_LINES);
        if( !$scmDoc->documentElement->hasAttribute('buckbeak') )
            derr("'" . $scmFile . "' is not an SCM configuration (in=scm-api://)", null, FALSE);
        PH::print_stdout(" - SCM configuration: " . $scmFile);
        $scm = new BuckbeakConf();
        $scm->load_from_domxml($scmDoc);

        // source: Panorama or firewall
        $srcDoc = new DOMDocument();
        if( !$srcDoc->load($in, XML_PARSE_BIG_LINES) )
            derr("error while reading xml file '" . $in . "'", null, FALSE);
        $xp = new DOMXPath($srcDoc);
        $isPanorama = $xp->query("/config/devices/entry/device-group|/config/devices/entry/template|/config/panorama")->length > 0;
        if( $srcDoc->documentElement->hasAttribute('buckbeak') || $srcDoc->documentElement->hasAttribute('fawkes') )
            derr("'" . $in . "' is an SCM / SASE configuration, in= must be a Panorama or firewall configuration", null, FALSE);

        $importer = new SCMImporter($scm);
        $importer->keepZoneInterfaces = isset(PH::$args['keep-zone-interfaces']);

        if( $isPanorama )
        {
            PH::print_stdout(" - Panorama configuration: " . $in);
            $shared = PH::$args['shared'] ?? 'snippet';
            if( !in_array($shared, array('snippet', 'global')) )
                $this->display_error_usage_exit("shared= must be 'snippet' or 'global'");
            $pano = new PanoramaConf();
            $pano->load_from_domxml($srcDoc);
            $importer->importPanorama($pano, $shared, PH::$args['shared-snippet'] ?? 'Panorama-Shared');
        }
        else
        {
            PH::print_stdout(" - firewall configuration: " . $in);
            $target = PH::$args['target'] ?? null;
            if( !in_array($target, array('folder', 'snippet'), TRUE) )
                $this->display_error_usage_exit("firewall: target=folder or target=snippet is required");
            $importer->importFirewall($srcDoc, $target, PH::$args['name'] ?? null, PH::$args['vsys'] ?? 'vsys1', PH::$args['serial'] ?? null);
        }

        $scm->save_to_file($out);

        PH::print_stdout();
        PH::print_stdout(" * imported: " . json_encode($importer->summary, JSON_UNESCAPED_SLASHES));
        foreach( $importer->warnings as $w )
            PH::print_stdout("   - WARNING: " . $w);
        PH::print_stdout(" * SCM configuration with the import: " . $out);

        if( $changes !== null )
        {
            PH::print_stdout();
            SCMCHANGES::generate($scmFile, $out, $changes);
            PH::print_stdout("send them with: pan-os-php type=scm-apply changes=" . $changes . " tsg=TSG_ID [dry-run]");
        }
    }
}
