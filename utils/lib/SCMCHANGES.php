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
 * type=scm-changes
 *
 * Compares an SCM configuration as downloaded by pan-os-php (file1) with the same configuration after
 * pan-os-php changed it (file2) and writes one SCM API request per added, changed or deleted object
 * into a JSON file. type=scm-apply sends that file to Strata Cloud Manager.
 */
class SCMCHANGES extends UTIL
{
    public $file1 = null;
    public $file2 = null;
    public $outFile = null;
    public $schemaFile = null;

    public function utilStart()
    {
        $this->usageMsg = PH::boldText('USAGE: ') . "\n" .
            "  - php " . basename(__FILE__) . " type=scm-changes file1=ORIGINAL_SCM.xml file2=CHANGED_SCM.xml out=changes.json\n" .
            "\n" .
            "  file1   configuration as downloaded with in=scm-api://TSG_ID out=ORIGINAL_SCM.xml\n" .
            "  file2   the same configuration after pan-os-php changed it (e.g. a playbook with out=CHANGED_SCM.xml)\n" .
            "  out     JSON file with one SCM API request per changed object; without out= it is printed\n" .
            "  schema  optional, SCM schema file (default lib/resources/scm/scm-ngfw-config-schema.json)\n" .
            "\n" .
            "  send it with: pan-os-php type=scm-apply changes=changes.json tsg=TSG_ID [dry-run]\n";

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
        $this->supportedArguments['file1'] = array('niceName' => 'file1', 'shortHelp' => 'SCM configuration as downloaded (XML)', 'argDesc' => '[filename]');
        $this->supportedArguments['file2'] = array('niceName' => 'file2', 'shortHelp' => 'the same SCM configuration after the changes (XML)', 'argDesc' => '[filename]');
        $this->supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'JSON file for the SCM API requests', 'argDesc' => '[filename]');
        $this->supportedArguments['schema'] = array('niceName' => 'schema', 'shortHelp' => 'SCM schema file', 'argDesc' => '[filename]');
        $this->supportedArguments['projectfolder'] = array('niceName' => 'projectfolder', 'shortHelp' => 'folder for the output file', 'argDesc' => '[folder]');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
    }

    public function main()
    {
        if( !isset(PH::$args['file1']) || !isset(PH::$args['file2']) )
            $this->display_error_usage_exit('"file1" and "file2" are required');

        $this->file1 = PH::$args['file1'];
        $this->file2 = PH::$args['file2'];
        if( isset(PH::$args['out']) )
            $this->outFile = PH::$args['out'];
        if( isset(PH::$args['schema']) )
            $this->schemaFile = PH::$args['schema'];

        if( isset(PH::$args['projectfolder']) && $this->outFile !== null )
        {
            $this->projectFolder = PH::$args['projectfolder'];
            if( !file_exists($this->projectFolder) )
                mkdir($this->projectFolder, 0777, TRUE);
            if( strpos($this->outFile, $this->projectFolder) === FALSE )
                $this->outFile = $this->projectFolder . "/" . $this->outFile;
        }

        $json = self::generate($this->file1, $this->file2, $this->outFile, $this->schemaFile);

        if( $this->outFile === null )
            PH::print_stdout($json);
    }

    /**
     * Also used by the playbook (argument outputformatscmjson=).
     * @return string the JSON document
     */
    static public function generate($file1, $file2, $outFile = null, $schemaFile = null)
    {
        $docs = array();
        foreach( array($file1, $file2) as $file )
        {
            if( !file_exists($file) )
                derr("file '" . $file . "' not found", null, FALSE);
            $doc = new DOMDocument();
            if( !$doc->load($file, XML_PARSE_BIG_LINES) )
                derr("error while reading xml file '" . $file . "'", null, FALSE);
            if( !$doc->documentElement->hasAttribute('buckbeak') )
                derr("'" . $file . "' is not an SCM configuration (in=scm-api://)", null, FALSE);
            $docs[] = $doc;
        }

        $gen = new SCMChangeGenerator($schemaFile);
        $gen->file1 = $file1;
        $gen->file2 = $file2;
        $result = $gen->run($docs[0], $docs[1]);
        $json = $gen->toJSON();

        $s = $result['summary'];
        PH::print_stdout(" * SCM API requests: POST " . $s['POST'] . ", PUT " . $s['PUT'] . ", DELETE " . $s['DELETE'] . " (to review: " . $s['review'] . ")");
        foreach( $result['warnings'] as $w )
            PH::print_stdout("   - WARNING: " . $w);
        foreach( $result['requests'] as $r )
            if( $r['review'] )
                PH::print_stdout("   - REVIEW request " . $r['seq'] . " " . $r['method'] . " " . $r['object']['resource'] . " '" . $r['object']['name'] . "': " . implode(" | ", $r['warnings']));

        if( $outFile !== null )
        {
            file_put_contents($outFile, $json);
            PH::print_stdout(" * SCM API requests are stored in FILE: " . $outFile);
        }

        return $json;
    }
}
