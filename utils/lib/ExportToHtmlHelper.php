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
 * Shared helper for generating HTML export files.
 *
 * All actions=exportToExcel / actions=exportToHtml calls funnel through
 * here so that template loading, jQuery CDN+fallback injection, sticky
 * headers initialisation, and file writing are defined exactly once.
 *
 * jQuery strategy
 * ----------------
 * The local copy of jquery.min.js is embedded inline in every generated
 * HTML file so exports are fully self-contained and work in air-gapped
 * environments with no external dependencies.
 *
 * Note: the bundled copy is jQuery 3.6.0. jQuery 4.0 introduced breaking
 * changes that may affect the stickyTableHeaders plugin, so an upgrade
 * should be tested carefully before bumping the version.
 */
class ExportToHtmlHelper
{
    /** Absolute path to the html assets directory. */
    private static function htmlDir(): string
    {
        return dirname(__FILE__) . '/../common/html/';
    }

    /**
     * Build and return the HTML export content string without writing it.
     *
     * Use this when the calling code needs to post-process $content or
     * decides the output filename conditionally after building.
     *
     * @param string $headers  HTML <th> elements for the table header row
     * @param string $lines    HTML <tr> elements for the table body
     * @param string $extraJs  Optional JS appended after sticky-header init
     * @return string          Complete HTML document as a string
     */
    public static function buildHtmlExport(string $headers, string $lines, string $extraJs = ''): string
    {
        // the same table as data for the JSON output (shadow-json: "export-table") - e.g. the config viewer shows
        // the additional fields of exportToExcel as columns of its list, from this one code path
        if( class_exists( 'PH', FALSE ) && PH::$shadow_json )
            PH::$JSON_OUT['export-table'] = self::tableData( $headers, $lines );

        $htmlDir = self::htmlDir();

        $content = file_get_contents($htmlDir . 'export-template.html');
        $content = str_replace('%TableHeaders%', $headers, $content);
        $content = str_replace('%lines%', $lines, $content);

        // Embed jQuery inline — fully self-contained, no external requests
        $content = str_replace('%JQUERY_INLINE%', file_get_contents($htmlDir . 'jquery.min.js'), $content);

        $jscontent = '';
        //$jscontent  .= file_get_contents($htmlDir . 'jquery.stickytableheaders.min.js');
        //$jscontent .= "\n\$('table').stickyTableHeaders();\n";
        $jscontent .= $extraJs;
        $jscontent .= "\n" . file_get_contents($htmlDir . 'table-filter.js');

        $content = str_replace('%JSCONTENT%', $jscontent, $content);

        return $content;
    }

    /**
     * the table of an export as data: array( 'columns' => header texts, 'rows' => list of cells; a cell with several
     * lines (<br />) is a list of strings ) - from the HTML the export actions build
     */
    public static function tableData(string $headers, string $lines): array
    {
        $doc = new DOMDocument();
        $prev = libxml_use_internal_errors( TRUE );
        $doc->loadHTML( '<?xml encoding="UTF-8"?><html><body><table><thead><tr>' . $headers . '</tr></thead><tbody>' . $lines . '</tbody></table></body></html>',
            LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_PARSEHUGE );
        libxml_clear_errors();
        libxml_use_internal_errors( $prev );
        $columns = array();
        foreach( $doc->getElementsByTagName( 'th' ) as $th )
            $columns[] = trim( $th->textContent );
        $rows = array();
        foreach( $doc->getElementsByTagName( 'tbody' )->item( 0 )->childNodes ?? array() as $tr )
        {
            if( !$tr instanceof DOMElement || $tr->nodeName !== 'tr' )
                continue;
            $cells = array();
            foreach( $tr->childNodes as $td )
            {
                if( !$td instanceof DOMElement || ( $td->nodeName !== 'td' && $td->nodeName !== 'th' ) )
                    continue;
                // lines of a cell (<br />) as a list
                $parts = array( '' );
                foreach( $td->childNodes as $n )
                {
                    if( $n instanceof DOMElement && $n->nodeName === 'br' )
                        $parts[] = '';
                    else
                        $parts[count( $parts ) - 1] .= $n->textContent;
                }
                $parts = array_map( 'trim', $parts );
                $cells[] = count( $parts ) > 1 ? array_values( array_filter( $parts, 'strlen' ) ) : $parts[0];
            }
            if( $cells )
                $rows[] = $cells;
        }
        return array( 'columns' => $columns, 'rows' => $rows );
    }

    /**
     * Build the HTML export content and write it to $filename in one step.
     *
     * This is the convenience wrapper used by the vast majority of export
     * actions where the filename is known before the content is built.
     *
     * @param string $filename  Destination file path
     * @param string $headers   HTML <th> elements for the table header row
     * @param string $lines     HTML <tr> elements for the table body
     * @param string $extraJs   Optional JS appended after sticky-header init
     */
    public static function writeHtmlExport(string $filename, string $headers, string $lines, string $extraJs = ''): void
    {
        #file_put_contents($filename, self::buildHtmlExport($headers, $lines, $extraJs));

        require_once dirname(__FILE__) . '/FilePutContents.php';
        FilePutContents::putContents($filename, self::buildHtmlExport($headers, $lines, $extraJs));
    }
}
