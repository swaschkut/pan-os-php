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
 *  - Per-column dropdown multi-select filter (Excel-style) with checkboxes
 *    for unique values. Disabled when >20 unique values unless the column
 *    header ends with "-profile".
 *  - Automatic pagination activated for tables > 1000 rows (100 / 250 /
 *    500 / 1000 rows-per-page, prev / next, numbered page buttons).
 *  - All DOM visibility changes batched inside requestAnimationFrame.
 */
(function ($) {
    'use strict';

    /* ─── State ──────────────────────────────────────────────────────── */

    var CHUNK_SIZE       = 250;
    var INDEX            = [];    // [{domRow: <tr>, cells: ['lowercased text', …]}]
    var FILTERED_ROWS    = [];    // subset of INDEX matching current filters
    var ACTIVE_FILTERS   = {};    // {colIdx(number): 'needle string'}
    var DROPDOWN_FILTERS = {};    // {colIdx(number): Set(allowed lowercase values)}
    var COLUMN_VALUES    = {};    // {colIdx: [{value: 'original', lower: 'lowercased'}, …]}
    var PAGINATION       = { enabled: false, currentPage: 1, pageSize: 100 };
    var TOTAL_ROWS       = 0;
    var DEBOUNCE_ID      = null;
    var T_START          = 0;
    var MAX_DROPDOWN_UNIQUES = 20;
    var ROWINFO_FADE_TIMER = null;  // Timer for row info widget fade

    /* ─── SVG icon for the dropdown button ───────────────────────────── */

    var FILTER_ICON_SVG =
        '<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">' +
        '<path d="M1 2a1 1 0 0 1 1-1h12a1 1 0 0 1 .8 1.6L10 9.5V14a1 1 0 0 1-.5.87l-2 1.15A1 1 0 0 1 6 15.13V9.5L1.2 2.6A1 1 0 0 1 1 2z"/>' +
        '</svg>';

    /* ─── Widget progress updates ────────────────────────────────────── */

    function updateProgress(done) {
        var pct = TOTAL_ROWS > 0 ? Math.round(done / TOTAL_ROWS * 100) : 0;
        $('#panos-progress-fill').css('width', pct + '%');
        $('#panos-progress-text').text(fmt(done) + ' / ' + fmt(TOTAL_ROWS) + ' rows');
    }

    /* ─── Filter row injection ───────────────────────────────────────── */

    function injectFilterRow() {
        var colCount = $('table thead tr:first th').length;
        if (colCount === 0) { return; }

        var cells = '';
        for (var i = 0; i < colCount; i++) {
            cells +=
                '<td><div class="panos-filter-cell">' +
                '<input type="text" class="panos-col-filter"' +
                ' data-col="' + i + '"' +
                ' placeholder="\u22EF"' +
                ' disabled' +
                ' title="Filter column ' + (i + 1) + '" />' +
                '<button class="panos-dropdown-btn disabled"' +
                ' data-col="' + i + '"' +
                ' disabled' +
                ' title="Loading\u2026">' +
                FILTER_ICON_SVG +
                '</button>' +
                '</div></td>';
        }
        $('table thead').append('<tr class="panos-filter-row">' + cells + '</tr>');
    }

    /* ─── Floating row info widget (top-right, auto-fade) ──────────── */

    function injectTopRowInfo() {
        // Insert into body so it's fixed-positioned relative to viewport
        $('body').append(
            '<div id="panos-top-rowinfo">' +
                '<div id="panos-top-rowinfo-left">' +
                    '<span id="panos-top-rowinfo-count"></span>' +
                    '<span id="panos-top-rowinfo-page"></span>' +
                '</div>' +
            '</div>'
        );
    }

    function showRowInfoWidget() {
        var $widget = $('#panos-top-rowinfo');
        $widget.removeClass('faded').addClass('visible');

        // Clear existing timer
        if (ROWINFO_FADE_TIMER) {
            clearTimeout(ROWINFO_FADE_TIMER);
        }

        // Start fade timer: 3.5 seconds delay, then fade over 1 second
        ROWINFO_FADE_TIMER = setTimeout(function () {
            $widget.addClass('faded');
        }, 3500);
    }

    function hideRowInfoWidget() {
        $('#panos-top-rowinfo').removeClass('visible faded');
        if (ROWINFO_FADE_TIMER) {
            clearTimeout(ROWINFO_FADE_TIMER);
            ROWINFO_FADE_TIMER = null;
        }
    }

    /* ─── Bottom bar (pagination controls only) ─────────────────────── */

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
        var txt, topCountTxt, topPageTxt;
        if (PAGINATION.enabled) {
            txt = 'Showing ' + fmt(from) + '\u2013' + fmt(to) + ' of ' + fmt(total) + ' rows';
            topCountTxt = fmt(total) + ' rows';
            topPageTxt = 'Page ' + PAGINATION.currentPage + '/' + totalPages();
        } else {
            txt = fmt(total) + '\u00A0/\u00A0' + fmt(TOTAL_ROWS) + ' rows';
            topCountTxt = fmt(total) + ' / ' + fmt(TOTAL_ROWS) + ' rows';
            topPageTxt = '';
        }
        $('#panos-row-info').text(txt);
        $('#panos-top-rowinfo-count').text(topCountTxt);
        $('#panos-top-rowinfo-page').text(topPageTxt);

        // Show widget and restart fade timer whenever row info updates
        showRowInfoWidget();
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
                    var raw = (tds[c].textContent || '').trim();
                    var low = raw.toLowerCase();
                    cells.push(low);

                    // Track unique values per column (split multi-line values)
                    if (!COLUMN_VALUES[c]) { COLUMN_VALUES[c] = {}; }

                    // E5: Treat multi-line cell values as separate filterable values
                    var lines = raw ? raw.split(/\r?\n/) : [''];
                    for (var l = 0; l < lines.length; l++) {
                        var lineRaw = lines[l].trim();
                        var lineLow = lineRaw.toLowerCase();
                        var key = lineLow || '\x00blank';
                        if (!COLUMN_VALUES[c][key]) {
                            COLUMN_VALUES[c][key] = { value: lineRaw, lower: lineLow, isBlank: !lineRaw };
                        }
                    }
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

    /* ─── Dropdown setup ─────────────────────────────────────────────── */

    function setupDropdowns() {
        var headers = $('table thead tr:first th');

        $('.panos-dropdown-btn').each(function () {
            var colIdx = +$(this).data('col');
            var vals = COLUMN_VALUES[colIdx] || {};
            var keys = Object.keys(vals);
            var uniqueCount = 0;
            for (var k = 0; k < keys.length; k++) {
                if (!vals[keys[k]].isBlank) { uniqueCount++; }
            }

            // Check if header ends with "-profile"
            var headerText = (headers.eq(colIdx).text() || '').trim().toLowerCase();
            var isProfileCol = /-profile$/.test(headerText);

            if (uniqueCount <= MAX_DROPDOWN_UNIQUES || isProfileCol) {
                $(this)
                    .removeClass('disabled')
                    .prop('disabled', false)
                    .attr('title', 'Filter by value');
            } else {
                $(this)
                    .addClass('disabled')
                    .prop('disabled', true)
                    .attr('title', 'Too many unique values, please manually input to filter');
            }
        });
    }

    /* ─── Dropdown panel ─────────────────────────────────────────────── */

    var $activePanel = null;
    var activePanelCol = -1;

    function closeDropdown() {
        if ($activePanel) {
            $activePanel.remove();
            $activePanel = null;
            activePanelCol = -1;
        }
    }

    function openDropdown(colIdx, anchorEl) {
        // Toggle if same column
        if (activePanelCol === colIdx) { closeDropdown(); return; }
        closeDropdown();

        activePanelCol = colIdx;
        var vals = COLUMN_VALUES[colIdx] || {};
        var keys = Object.keys(vals);

        // Separate blanks from real values, sort real values
        var realItems = [];
        var hasBlank = false;
        for (var k = 0; k < keys.length; k++) {
            var item = vals[keys[k]];
            if (item.isBlank) { hasBlank = true; }
            else { realItems.push(item); }
        }
        realItems.sort(function (a, b) {
            return a.value.localeCompare(b.value, undefined, { numeric: true, sensitivity: 'base' });
        });

        // Current dropdown filter state for this column
        var currentFilter = DROPDOWN_FILTERS[colIdx] || null;

        // Build panel HTML
        var html = '<div class="panos-dropdown-panel">';
        html += '<input type="text" class="panos-dropdown-search" placeholder="Search\u2026" />';
        html += '<div class="panos-dropdown-list">';

        // (Select All)
        var allChecked = !currentFilter; // if no filter, everything is selected
        html += '<div class="panos-dropdown-item select-all">' +
                '<input type="checkbox" id="panos-dd-all-' + colIdx + '"' +
                (allChecked ? ' checked' : '') + ' />' +
                '<label for="panos-dd-all-' + colIdx + '">(Select All)</label></div>';

        // Real values
        for (var r = 0; r < realItems.length; r++) {
            var v = realItems[r];
            var checked = !currentFilter || currentFilter.has(v.lower);
            html += '<div class="panos-dropdown-item" data-lower="' + escAttr(v.lower) + '">' +
                    '<input type="checkbox"' + (checked ? ' checked' : '') + ' />' +
                    '<label>' + escHtml(v.value) + '</label></div>';
        }

        // (Blanks)
        if (hasBlank) {
            var blankChecked = !currentFilter || currentFilter.has('');
            html += '<div class="panos-dropdown-item" data-lower="">' +
                    '<input type="checkbox"' + (blankChecked ? ' checked' : '') + ' />' +
                    '<label>(Blanks)</label></div>';
        }

        html += '</div></div>';

        $activePanel = $(html).appendTo('body');

        // Position below the anchor button
        var rect = anchorEl.getBoundingClientRect();

        // Use the bounding rect directly for viewport-relative positioning
        // and set the panel to 'fixed' to avoid scroll offset math issues.
        var panelLeft = rect.left;
        var panelTop = rect.bottom + 2;

        // Keep panel within viewport horizontally
        var panelWidth = $activePanel.outerWidth();
        if (panelLeft + panelWidth > window.innerWidth) {
            panelLeft = window.innerWidth - panelWidth - 8;
        }

        $activePanel.css({
            position: 'fixed', // Change from absolute to fixed
            top: panelTop + 'px',
            left: panelLeft + 'px'
        });

        $activePanel.css({ top: panelTop + 'px', left: panelLeft + 'px' });

        // Wire search
        $activePanel.find('.panos-dropdown-search').on('input', function () {
            var q = this.value.trim().toLowerCase();
            $activePanel.find('.panos-dropdown-item:not(.select-all)').each(function () {
                var text = $(this).find('label').text().toLowerCase();
                $(this).css('display', text.indexOf(q) !== -1 ? '' : 'none');
            });
        });

        // Wire (Select All)
        $activePanel.find('.select-all input').on('change', function () {
            var isChecked = this.checked;
            $activePanel.find('.panos-dropdown-item:not(.select-all) input[type=checkbox]').each(function () {
                // Only affect visible items
                if ($(this).closest('.panos-dropdown-item').css('display') !== 'none') {
                    this.checked = isChecked;
                }
            });
            onDropdownSelectionChange(colIdx);
        });

        // Wire individual checkboxes
        $activePanel.find('.panos-dropdown-item:not(.select-all) input[type=checkbox]').on('change', function () {
            updateSelectAllState(colIdx);
            onDropdownSelectionChange(colIdx);
        });
    }

    function updateSelectAllState(colIdx) {
        if (!$activePanel) { return; }
        var allChecked = true;
        $activePanel.find('.panos-dropdown-item:not(.select-all) input[type=checkbox]').each(function () {
            if (!this.checked) { allChecked = false; }
        });
        $activePanel.find('.select-all input').prop('checked', allChecked);
    }

    function onDropdownSelectionChange(colIdx) {
        if (!$activePanel) { return; }

        var allChecked = $activePanel.find('.select-all input').prop('checked');
        var totalItems = $activePanel.find('.panos-dropdown-item:not(.select-all)').length;
        var checkedItems = $activePanel.find('.panos-dropdown-item:not(.select-all) input:checked').length;

        if (allChecked || checkedItems === totalItems) {
            // All selected — remove dropdown filter for this column
            delete DROPDOWN_FILTERS[colIdx];
        } else {
            // Build set of allowed values
            var allowed = new Set();
            $activePanel.find('.panos-dropdown-item:not(.select-all)').each(function () {
                if ($(this).find('input').prop('checked')) {
                    allowed.add($(this).data('lower') + '');
                }
            });
            DROPDOWN_FILTERS[colIdx] = allowed;
        }

        applyFilters();
    }

    function escHtml(s) {
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;');
    }
    function escAttr(s) {
        return s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;')
                .replace(/>/g, '&gt;');
    }

    /* ─── Indexing complete ──────────────────────────────────────────── */

    function onIndexingComplete() {
        var elapsed = ((Date.now() - T_START) / 1000).toFixed(1);
        FILTERED_ROWS = INDEX.slice();

        // Enable filter inputs
        $('.panos-col-filter')
            .prop('disabled', false)
            .attr('placeholder', 'filter\u2026');

        // Setup dropdown buttons
        setupDropdowns();

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

        // Show row info widget after indexing widget has completely faded out
        // Indexing fade: 800ms delay + 2000ms fade = 2800ms total
        setTimeout(function () {
            showRowInfoWidget();
        }, 3000);

        // Wire filter inputs
        $('.panos-col-filter').on('input', function () {
            clearTimeout(DEBOUNCE_ID);
            DEBOUNCE_ID = setTimeout(applyFilters, 200);
        });

        // Wire dropdown buttons
        $('.panos-dropdown-btn:not(.disabled)').on('click', function (e) {
            e.stopPropagation();
            openDropdown(+$(this).data('col'), this);
        });
    }

    /* ─── Filter application ─────────────────────────────────────────── */

    function applyFilters() {
        ACTIVE_FILTERS = {};
        $('.panos-col-filter').each(function () {
            var v = this.value.trim().toLowerCase();
            if (v) { ACTIVE_FILTERS[+$(this).data('col')] = v; }
        });

        var textCols = Object.keys(ACTIVE_FILTERS).map(Number);
        var dropCols = Object.keys(DROPDOWN_FILTERS).map(Number);
        FILTERED_ROWS = [];

        for (var i = 0; i < INDEX.length; i++) {
            var entry = INDEX[i];
            var match = true;

            // Text filter: substring match (AND across columns)
            for (var f = 0; f < textCols.length; f++) {
                var col    = textCols[f];
                var needle = ACTIVE_FILTERS[col];
                if (!entry.cells[col] || entry.cells[col].indexOf(needle) === -1) {
                    match = false;
                    break;
                }
            }

            // Dropdown filter: value must be in allowed set (AND across columns)
            if (match) {
                for (var d = 0; d < dropCols.length; d++) {
                    var dc = dropCols[d];
                    var allowed = DROPDOWN_FILTERS[dc];
                    var cellVal = entry.cells[dc] || '';
                    if (!allowed.has(cellVal)) {
                        match = false;
                        break;
                    }
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

        // Close dropdown on click-outside or Escape
        $(document).on('click', function (e) {
            if ($activePanel && !$(e.target).closest('.panos-dropdown-panel, .panos-dropdown-btn').length) {
                closeDropdown();
            }
        });
        $(document).on('keydown', function (e) {
            if (e.key === 'Escape') { closeDropdown(); }
        });

        injectTopRowInfo();
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
