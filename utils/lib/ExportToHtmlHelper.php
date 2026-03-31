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
 * CDN strategy
 * ------------
 * The generated HTML tries to load jQuery from the CDN first.  If the
 * CDN is unreachable (e.g. air-gapped environments) the inline fallback
 * copy bundled inside the HTML file is used instead — so exports work
 * everywhere.
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
        $htmlDir = self::htmlDir();

        $content = file_get_contents($htmlDir . 'export-template.html');
        $content = str_replace('%TableHeaders%', $headers, $content);
        $content = str_replace('%lines%', $lines, $content);

        // Inline jQuery as CDN fallback (see export-template.html for the CDN tag)
        $content = str_replace('%JQUERY_INLINE%', file_get_contents($htmlDir . 'jquery.min.js'), $content);

        $jscontent  = file_get_contents($htmlDir . 'jquery.stickytableheaders.min.js');
        $jscontent .= "\n\$('table').stickyTableHeaders();\n";
        $jscontent .= $extraJs;
        $jscontent .= "\n" . file_get_contents($htmlDir . 'table-filter.js');

        $content = str_replace('%JSCONTENT%', $jscontent, $content);

        return $content;
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
        file_put_contents($filename, self::buildHtmlExport($headers, $lines, $extraJs));
    }

    /**
     * Resolve the output filename, prepending the web project path when
     * the script is running inside a web-request context.
     *
     * @param string $filename  Raw filename argument from action args
     * @return string           Resolved file path
     */
    public static function resolveFilename(string $filename): string
    {
        if (isset($_SERVER['REQUEST_METHOD'])) {
            return 'project/html/' . $filename;
        }
        return $filename;
    }
}
