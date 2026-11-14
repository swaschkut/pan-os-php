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
 * scm_pa_report.php - as-built documentation of a Prisma Access / SCM tenant from a scm_pa_export.php folder
 *
 * php scm_pa_report.php in=<export folder> [out=<directory>]
 * pan-os-php type=scm-report in=<export folder> [out=<directory>]
 *
 * writes report.md, report.html and prisma-access.drawio (network plans; draw.io, Lucidchart import)
 */

set_include_path(dirname(__FILE__) . '/../../../../' . PATH_SEPARATOR . get_include_path());
require_once("lib/pan_php_framework.php");
require_once(dirname(__FILE__) . "/lib/SCMPrismaAccessExport.php");
require_once(dirname(__FILE__) . "/lib/SCMPrismaAccessReport.php");

$usage = "USAGE: php " . basename(__FILE__) . " in=<export folder> [out=<directory>]\n"
    . "  in    folder written by scm_pa_export.php (<outdir>/<TSG>/<timestamp>, or <outdir>/<TSG> = newest export)\n"
    . "  out   output directory (default: report next to the export: <export>/report)\n"
    . "  writes report.md (Markdown), report.html (self-contained, print to PDF), prisma-access.drawio (network plans:\n"
    . "  draw.io / diagrams.net, Lucidchart: File > Import > draw.io)\n";

$args = array();
foreach( array_slice($argv, 1) as $a )
{
    $p = strpos($a, "=");
    $args[ $p === FALSE ? $a : substr($a, 0, $p) ] = $p === FALSE ? TRUE : substr($a, $p + 1);
}
if( isset($args['help']) || !isset($args['in']) )
{
    print $usage;
    exit( isset($args['help']) ? 0 : 1 );
}
$in = strpos($args['in'], 'scm-export://') === 0 ? substr($args['in'], strlen('scm-export://')) : $args['in'];

PH::print_stdout();
PH::print_stdout( "*********** " . basename(__FILE__) . " **************" );
$report = new SCMPrismaAccessReport( $in );
PH::print_stdout( " * export: " . $report->dir );
$report->build();
$out = isset($args['out']) ? $args['out'] : $report->dir . "/report";
$files = $report->write( $out );
PH::print_stdout( " * sections: " . count($report->sections) . ", network plan pages: " . implode(", ", array_keys($report->pages)) );
foreach( $files as $f )
    PH::print_stdout( " * written: " . $f );
PH::print_stdout();
