/**
 * PAN-OS-PHP HTML export — in-browser column filter + auto-pagination
 *
 * The index-progress widget (#panos-index-widget) is static HTML in the
 * template so it appears as soon as the browser starts rendering the page.
 * JS only updates its content and fades it out when indexing completes.
 *
 * Features
 * --------
 *  - In-memory index built in 250-row chunks (setTimeout) — UI stays
 *    responsive during load of large tables.
 *  - Per-column filter inputs injected into <thead> (AND logic,
 *    case-insensitive substring match), disabled until indexing completes.
 *  - Automatic pagination activated for tables > 1000 rows (100 / 250 /
 *    500 / 1000 rows-per-page, prev / next, numbered page buttons).
 *  - All DOM visibility changes batched inside requestAnimationFrame.
 */
(function ($) {
    'use strict';

    /* ─── State ──────────────────────────────────────────────────────── */

    var CHUNK_SIZE     = 250;
    var INDEX          = [];    // [{domRow: <tr>, cells: ['lowercased text', …]}]
    var FILTERED_ROWS  = [];    // subset of INDEX matching current filters
    var ACTIVE_FILTERS = {};    // {colIdx(number): 'needle string'}
    var PAGINATION     = { enabled: false, currentPage: 1, pageSize: 100 };
    var TOTAL_ROWS     = 0;
    var DEBOUNCE_ID    = null;
    var T_START        = 0;

    /* ─── Widget progress updates ────────────────────────────────────── */

    function updateProgress(done) {
        var pct = TOTAL_ROWS > 0 ? Math.round(done / TOTAL_ROWS * 100) : 0;
        $('#panos-progress-fill').css('width', pct + '%');
        $('#panos-progress-text').text(fmt(done) + ' / ' + fmt(TOTAL_ROWS) + ' rows');
    }

    /* ─── Filter row ─────────────────────────────────────────────────── */

    function injectFilterRow() {
        var colCount = $('table thead tr:first th').length;
        if (colCount === 0) { return; }

        var cells = '';
        for (var i = 0; i < colCount; i++) {
            cells +=
                '<td><input type="text" class="panos-col-filter"' +
                ' data-col="' + i + '"' +
                ' placeholder="\u22EF"' +
                ' disabled' +
                ' title="Filter column ' + (i + 1) + '" /></td>';
        }
        $('table thead').append('<tr class="panos-filter-row">' + cells + '</tr>');
    }

    /* ─── Bottom bar (row info + pagination controls) ────────────────── */

    function injectBottomBar() {
        $('table').after(
            '<div id="panos-bottom-bar">' +
                '<span id="panos-row-info"></span>' +
                '<div id="panos-page-nav">' +
                    '<button id="panos-prev" disabled>\u2039\u00A0Prev</button>' +
                    '<span id="panos-page-nums"></span>' +
                    '<button id="panos-next" disabled>Next\u00A0\u203A</button>' +
                    '<label class="panos-page-size-label">Rows/page:\u00A0' +
                        '<select id="panos-page-size">' +
                            '<option value="100" selected>100</option>' +
                            '<option value="250">250</option>' +
                            '<option value="500">500</option>' +
                            '<option value="1000">1000</option>' +
                        '</select>' +
                    '</label>' +
                '</div>' +
            '</div>'
        );

        $('#panos-prev').on('click', function () {
            if (PAGINATION.currentPage > 1) { PAGINATION.currentPage--; renderPage(); }
        });
        $('#panos-next').on('click', function () {
            if (PAGINATION.currentPage < totalPages()) { PAGINATION.currentPage++; renderPage(); }
        });
        $('#panos-page-size').on('change', function () {
            PAGINATION.pageSize = +this.value;
            PAGINATION.currentPage = 1;
            renderPage();
        });
    }

    /* ─── Pagination helpers ──────────────────────────────────────────── */

    function totalPages() {
        return Math.max(1, Math.ceil(FILTERED_ROWS.length / PAGINATION.pageSize));
    }

    function renderPage() {
        var ps    = PAGINATION.pageSize;
        var cp    = PAGINATION.currentPage;
        var tp    = totalPages();
        var start = (cp - 1) * ps;
        var end   = Math.min(start + ps, FILTERED_ROWS.length);

        requestAnimationFrame(function () {
            for (var i = 0; i < FILTERED_ROWS.length; i++) {
                FILTERED_ROWS[i].domRow.style.display = (i >= start && i < end) ? '' : 'none';
            }
            updateRowInfo(start + 1, end, FILTERED_ROWS.length);
            renderPageNumbers(cp, tp);
        });
    }

    function renderPageNumbers(cp, tp) {
        var $nums = $('#panos-page-nums').empty();
        $('#panos-prev').prop('disabled', cp <= 1);
        $('#panos-next').prop('disabled', cp >= tp);

        var lo = Math.max(1, cp - 3);
        var hi = Math.min(tp, cp + 3);

        if (lo > 1) {
            appendPageBtn($nums, 1, cp);
            if (lo > 2) { $nums.append('<span class="panos-ellipsis">\u2026</span>'); }
        }
        for (var p = lo; p <= hi; p++) { appendPageBtn($nums, p, cp); }
        if (hi < tp) {
            if (hi < tp - 1) { $nums.append('<span class="panos-ellipsis">\u2026</span>'); }
            appendPageBtn($nums, tp, cp);
        }
    }

    function appendPageBtn($parent, page, currentPage) {
        var cls = 'panos-pg-btn' + (page === currentPage ? ' panos-pg-active' : '');
        $('<button class="' + cls + '">' + page + '</button>')
            .on('click', (function (p) {
                return function () { PAGINATION.currentPage = p; renderPage(); };
            }(page)))
            .appendTo($parent);
    }

    function updateRowInfo(from, to, total) {
        var txt;
        if (PAGINATION.enabled) {
            txt = 'Showing ' + fmt(from) + '\u2013' + fmt(to) + ' of ' + fmt(total) + ' rows';
        } else {
            txt = fmt(total) + '\u00A0/\u00A0' + fmt(TOTAL_ROWS) + ' rows';
        }
        $('#panos-row-info').text(txt);
    }

    function fmt(n) { return n.toLocaleString(); }

    /* ─── Chunked indexing ───────────────────────────────────────────── */

    function buildIndex(rows) {
        T_START    = Date.now();
        var offset = 0;

        (function chunk() {
            var end = Math.min(offset + CHUNK_SIZE, TOTAL_ROWS);
            for (var i = offset; i < end; i++) {
                var tds   = rows[i].getElementsByTagName('td');
                var cells = [];
                for (var c = 0; c < tds.length; c++) {
                    cells.push((tds[c].textContent || '').toLowerCase());
                }
                INDEX.push({ domRow: rows[i], cells: cells });
            }
            offset = end;
            updateProgress(offset);
            if (offset < TOTAL_ROWS) {
                setTimeout(chunk, 0);
            } else {
                onIndexingComplete();
            }
        }());
    }

    function onIndexingComplete() {
        var elapsed = ((Date.now() - T_START) / 1000).toFixed(1);
        FILTERED_ROWS = INDEX.slice();

        // Enable filter inputs
        $('.panos-col-filter')
            .prop('disabled', false)
            .attr('placeholder', 'filter\u2026');

        // Activate pagination if needed
        if (TOTAL_ROWS > 1000) {
            PAGINATION.enabled = true;
            $('#panos-page-nav').css('display', 'flex');
            renderPage();
        } else {
            updateRowInfo(1, TOTAL_ROWS, TOTAL_ROWS);
        }

        // Update widget to show completion, then slow 2-second fade out
        $('#panos-progress-fill').css('width', '100%');
        $('#panos-index-title').text(
            '\u2713\u00A0' + fmt(TOTAL_ROWS) + ' rows \u00B7 ' + elapsed + 's'
        );
        $('#panos-progress-text').text('Filters enabled');
        $('#panos-index-widget').delay(800).fadeOut(2000);

        // Wire filter inputs
        $('.panos-col-filter').on('input', function () {
            clearTimeout(DEBOUNCE_ID);
            DEBOUNCE_ID = setTimeout(applyFilters, 200);
        });
    }

    /* ─── Filter application ─────────────────────────────────────────── */

    function applyFilters() {
        ACTIVE_FILTERS = {};
        $('.panos-col-filter').each(function () {
            var v = this.value.trim().toLowerCase();
            if (v) { ACTIVE_FILTERS[+$(this).data('col')] = v; }
        });

        var cols = Object.keys(ACTIVE_FILTERS).map(Number);
        FILTERED_ROWS = [];

        for (var i = 0; i < INDEX.length; i++) {
            var entry = INDEX[i];
            var match = true;
            for (var f = 0; f < cols.length; f++) {
                var col    = cols[f];
                var needle = ACTIVE_FILTERS[col];
                if (!entry.cells[col] || entry.cells[col].indexOf(needle) === -1) {
                    match = false;
                    break;
                }
            }
            if (match) { FILTERED_ROWS.push(entry); }
        }

        if (PAGINATION.enabled) {
            requestAnimationFrame(function () {
                for (var j = 0; j < INDEX.length; j++) {
                    INDEX[j].domRow.style.display = 'none';
                }
                PAGINATION.currentPage = 1;
                renderPage();
            });
        } else {
            var matchSet = new Set(FILTERED_ROWS.map(function (e) { return e.domRow; }));
            requestAnimationFrame(function () {
                for (var j = 0; j < INDEX.length; j++) {
                    INDEX[j].domRow.style.display =
                        matchSet.has(INDEX[j].domRow) ? '' : 'none';
                }
                updateRowInfo(1, FILTERED_ROWS.length, FILTERED_ROWS.length);
            });
        }
    }

    /* ─── Bootstrap ──────────────────────────────────────────────────── */

    $(document).ready(function () {
        var rows = $('table tbody tr').toArray();
        TOTAL_ROWS = rows.length;

        // Minimize button is in the static template HTML — bind it here
        $('#panos-minimize-btn').on('click', function () {
            var $w = $('#panos-index-widget');
            $w.toggleClass('minimized');
            $(this).html($w.hasClass('minimized') ? '&#43;' : '&minus;');
        });

        injectFilterRow();
        injectBottomBar();

        // Re-init sticky headers so the new filter row is included in the
        // sticky clone (the inline init ran before this row was added).
        if ($.fn.stickyTableHeaders) {
            try { $('table').stickyTableHeaders('destroy'); } catch (ignore) {}
            $('table').stickyTableHeaders();
        }

        // Kick off indexing (progress widget already visible from static HTML)
        updateProgress(0);
        buildIndex(rows);
    });

}(jQuery));
