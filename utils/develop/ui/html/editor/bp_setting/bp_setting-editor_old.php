<?php
session_start();
include "../../../test/db_conn.php";
if( isset($_SESSION['folder']) && isset($_SESSION['id']) )
{
    $panconfkeystoreFILE = $_SESSION['folder']."/.panconfkeystore";
    $projectFOLDER = $_SESSION['folder'];
}
else
{
    $tmpFOLDER = '/../../../../../api/v1/project';
    $panconfkeystoreFILE = dirname(__FILE__) . $tmpFOLDER.'/.panconfkeystore';
    $projectFOLDER = dirname(__FILE__) . $tmpFOLDER;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BPA Master Configurator & Editor</title>
    <script src="d3.v7.min.js"></script>
    <script src="validation.js"></script>
    <style>
        :root {
            --excellent: #25B197; --poor: #E8121C; --bg: #ffffff;
            --nav-bg: #1a202c; --sidebar-bg: #2d3748; --accent: #3182ce;
        }
        body { font-family: 'Segoe UI', sans-serif; margin: 0; background: var(--bg); display: flex; height: 100vh; overflow: hidden; }
        .mode-sidebar { width: 180px; background: var(--sidebar-bg); color: white; display: flex; flex-direction: column; flex-shrink: 0; }
        .sidebar-header { padding: 20px; font-weight: 800; font-size: 0.9rem; border-bottom: 1px solid #4a5568; color: #63b3ed; }
        .mode-item { padding: 15px 20px; cursor: pointer; font-size: 0.85rem; border-left: 4px solid transparent; }
        .mode-item.active { background: rgba(49, 130, 206, 0.2); border-left: 4px solid var(--accent); font-weight: bold; }
        .wrapper { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
        .header { background: var(--nav-bg); color: white; padding: 0 20px; display: flex; justify-content: space-between; align-items: center; height: 50px; flex-shrink: 0; }
        .menu { display: flex; gap: 2px; height: 100%; }
        .menu-item { padding: 0 15px; height: 100%; display: flex; align-items: center; cursor: pointer; text-transform: uppercase; font-size: 0.7rem; font-weight: bold; color: #a0aec0; }
        .menu-item.active { color: white; background: var(--accent); }
        .main-content { display: flex; flex: 1; overflow: hidden; }
        .checkbox-sidebar { width: 320px; background: #f8f9fa; border-right: 1px solid #e2e8f0; display: flex; flex-direction: column; overflow: hidden; }
        .scroll-area { flex: 1; overflow-y: auto; padding: 15px; }
        .description-panel { height: 250px; background: #ffffff; border-top: 2px solid #e2e8f0; padding: 15px; overflow-y: auto; font-size: 0.85rem; color: #4a5568; }
        .diagram-pane { flex: 1; display: flex; justify-content: center; align-items: center; background: white; }
        .settings-pane { flex: 1; padding: 30px; overflow-y: auto; background: #fdfdfd; }
        .json-card { background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); max-width: 1100px; margin: 0 auto; }
        .settings-group { margin-bottom: 8px; padding-left: 10px; border-left: 1px solid #edf2f7; }
        .json-key { color: #2d3748; font-weight: bold; font-size: 0.8rem; margin-right: 10px; min-width: 160px; display: inline-block; }
        .edit-input { border: 1px solid #cbd5e0; border-radius: 4px; padding: 4px 8px; font-size: 0.85rem; width: 300px; }
        .array-item-box { background: #f7fafc; border: 1px solid #e2e8f0; padding: 15px; margin: 5px 0; border-radius: 6px; position: relative; }
        .array-controls { position: absolute; left: -35px; top: 10px; display: flex; flex-direction: column; gap: 5px; }
        .btn-action { width: 24px; height: 24px; border-radius: 4px; border: none; cursor: pointer; color: white; font-weight: bold; display: flex; align-items: center; justify-content: center; }
        .btn-plus { background: #25B197; } .btn-minus { background: #E8121C; }
        .btn-save { background: #25B197; color: white; border: none; padding: 8px 20px; border-radius: 4px; cursor: pointer; font-weight: bold; }
        .item { display: flex; align-items: center; padding: 5px; font-size: 0.75rem; border-bottom: 1px solid #f1f1f1; }
        .label-text { font-size: 10px; fill: #4a5568; font-weight: 600; pointer-events: none; }
        .validation-option { display: inline-flex; align-items: center; margin-right: 12px; font-size: 0.75rem; cursor: pointer; }
        .validation-option input { margin-right: 4px; }
        .disabled-option { opacity: 0.4; pointer-events: none; }

        /* Custom Input Styling */
        .custom-add-container { display: flex; align-items: center; gap: 8px; margin-top: 8px; border-top: 1px dashed #cbd5e0; padding-top: 8px; }
        .custom-add-input { padding: 4px 8px; border: 1px solid #cbd5e0; border-radius: 4px; font-size: 0.75rem; width: 150px; }
        .btn-custom-add { background: var(--accent); color: white; border: none; padding: 4px 12px; border-radius: 4px; cursor: pointer; font-size: 0.75rem; font-weight: bold; }

        /* Sub-Tab Navigation innerhalb der Settings */
        .sub-tab-container {
            display: flex;
            gap: 5px;
            border-bottom: 2px solid #e2e8f0;
            margin-bottom: 20px;
            padding-bottom: 0;
        }
        .sub-tab {
            padding: 10px 20px;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 600;
            color: #718096;
            border-bottom: 3px solid transparent;
            transition: all 0.2s;
        }
        .sub-tab:hover {
            color: var(--accent);
        }
        .sub-tab.active {
            color: var(--accent);
            border-bottom-color: var(--accent);
        }

        /* Modernisiertes Settings-Layout */
        .settings-pane h2 {
            font-size: 1.4rem;
            color: #1a202c;
            margin-top: 0;
            margin-bottom: 15px;
        }
        .json-card {
            background: white;
            border: none;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            max-width: 100%;
        }
        .settings-group {
            margin-bottom: 16px;
            padding: 12px;
            background: #f8fafc;
            border-left: 4px solid #cbd5e0;
            border-radius: 0 8px 8px 0;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .settings-group:focus-within {
            border-left-color: var(--accent);
            background: #f0f7ff;
        }
        .json-key {
            color: #4a5568;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .edit-input {
            width: 100%;
            max-width: 500px;
            padding: 8px 12px;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            font-size: 0.9rem;
            box-sizing: border-box;
        }
        .edit-input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(49, 130, 206, 0.15);
        }

        /* Array-Boxen Verschönerung */
        .array-item-box {
            background: white;
            border: 1px solid #e2e8f0;
            padding: 20px 20px 20px 45px;
            margin: 12px 0;
            border-radius: 8px;
            box-shadow: inset 0 2px 4px 0 rgba(0, 0, 0, 0.02);
        }
        .array-controls {
            left: 10px;
            top: 15px;
        }

        /* Sub-Sub-Tab Navigation (Visibility vs. BP) */
        .sub-sub-tab-container {
            display: flex;
            gap: 8px;
            margin-bottom: 15px;
            background: #edf2f7;
            padding: 4px;
            border-radius: 6px;
            width: fit-content;
        }
        .sub-sub-tab {
            padding: 6px 16px;
            cursor: pointer;
            font-size: 0.8rem;
            font-weight: 700;
            color: #4a5568;
            border-radius: 4px;
            transition: all 0.15s ease;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .sub-sub-tab:hover {
            background: rgba(255, 255, 255, 0.5);
        }
        .sub-sub-tab.active {
            background: white;
            color: var(--accent);
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body>
<div class="menu" style="border:1px solid black; padding: 10px;">
    <table class="table table-bordered" style="width:100%">
        <tr>
        <tr>
            <td><a href="../../../index.php">MAIN page</a></td>
            <td><a href="../../../bp_config.php">BP config page</a></td>
            <td><a href="../../../bp_secprof.php">BP secprof page</a></td>
            <td><a href="../../../single.php">single command</a></td>
            <td><a href="../../../playbook.php">JSON PLAYBOOK</a></td>
            <td><a href="../../../preparation.php">upload file / store APIkey</a></td>

            <td><a href="../../diagram/temp_diagram.php">Diagram</a></td>
            <td><a href="../bp_setting/bp_setting-editor.php">BP Setting Editor</a></td>
            <td><a href="../playbook/playbook-editor.php">Playbook Editor</a></td>

            <td><a href="../../../help.php">action / filter help</a></td>
            <?php
                if( isset($_SESSION['folder']) && isset($_SESSION['id']) )
                {
                    echo '<td>logged in as: <a href="../../../test/home.php">'.$_SESSION['name'].'</a>  |  <a href="../../../test/logout.php">LOGOUT</a></td>';
            }
            ?>
        </tr>
    </table>
</div>

<div class="mode-sidebar">
    <div class="sidebar-header">BPA ANALYZER</div>
    <div class="mode-item active" id="mode-diagram" onclick="setMode('diagram')">📊 Diagram View</div>
    <div class="mode-item" id="mode-settings" onclick="setMode('settings')">⚙️ BP Settings</div>
</div>

<div class="wrapper">
    <div class="header">
        <div class="menu" id="topMenu"></div>
        <div style="display:flex; gap:10px; align-items: center;">
            <input type="file" id="fileInput" accept=".json" style="font-size:0.7rem;">
            <button id="downloadBtn" class="btn-save" style="display:none">Export JSON</button>
        </div>
    </div>
    <div class="main-content" id="mainContent"></div>
</div>

<script>
    let jsonData = null;
    let appMode = 'diagram';
    let currentTab = '';

    let currentSubTab = '';
    let currentSubSubTab = 'visibility'; // Standardmäßig 'visibility' zuerst

    const profileToRules = {
        "Wildfire Analysis Profiles": ["Wildfire Analysis Rules", "Wildfire Analysis InLine ML"],
        "Antivirus Profiles": ["Antivirus Actions", "Antivirus InLine ML"],
        "Anti-Spyware Profiles": ["Anti-Spyware Rules", "Anti-Spyware InLine ML"],
        "Vulnerability Profiles": ["Vulnerability Rules", "Vulnerability InLine ML"]
    };

    const rulesToProfile = {};
    for (const [p, children] of Object.entries(profileToRules)) {
        children.forEach(c => rulesToProfile[c] = p);
    }

    document.getElementById('fileInput').addEventListener('change', (e) => {
        const reader = new FileReader();
        reader.onload = (event) => {
            jsonData = JSON.parse(event.target.result);
            document.getElementById('downloadBtn').style.display = 'block';
            setMode(appMode);
        };
        reader.readAsText(e.target.files[0]);
    });

    function setMode(mode) {
        appMode = mode;
        document.querySelectorAll('.mode-item').forEach(el => el.classList.remove('active'));
        document.getElementById(`mode-${mode}`).classList.add('active');
        if (!jsonData) return;
        const topMenu = document.getElementById('topMenu');
        topMenu.innerHTML = '';
        if (mode === 'diagram') {
            const tabs = ['visibility', 'best-practice', 'adoption'];
            currentTab = tabs.includes(currentTab) ? currentTab : tabs[0];
            tabs.forEach(t => createMenuItem(t, t));
            renderDiagramLayout();
        } else {
            const keys = Object.keys(jsonData).filter(k => k !== 'included-in-bpa');
            currentTab = keys.includes(currentTab) ? currentTab : keys[0];
            keys.forEach(k => createMenuItem(k, k));
            renderSettingsLayout();
        }
        refreshUI();
    }

    function createMenuItem(id, label) {
        const div = document.createElement('div');
        div.className = 'menu-item' + (currentTab === id ? ' active' : '');
        div.textContent = label;
        div.onclick = () => { currentTab = id; setMode(appMode); };
        document.getElementById('topMenu').appendChild(div);
    }

    function renderDiagramLayout() {
        document.getElementById('mainContent').innerHTML = `
            <div class="checkbox-sidebar">
                <div class="scroll-area" id="checkboxContainer"></div>
                <div class="description-panel" id="descPanel">
                    <div style="font-weight:bold; padding:10px; border-bottom:1px solid #eee">Details</div>
                    <div id="descContent" style="padding:10px">Select a rule to see coverage details.</div>
                </div>
            </div>
            <div class="diagram-pane" id="diagramContainer"></div>
        `;
    }

    function renderSettingsLayout() {
        document.getElementById('mainContent').innerHTML = `<div class="settings-pane" id="settingsContainer"></div>`;
    }

    function refreshUI() {
        if (!jsonData) return;
        appMode === 'diagram' ? updateDiagramView() : updateSettingsView();
    }

    function toggleBpa(key, isChecked) {
        const sectionData = jsonData["included-in-bpa"][currentTab];
        sectionData[key] = isChecked;
        if (profileToRules[key]) {
            profileToRules[key].forEach(child => { if (sectionData.hasOwnProperty(child)) sectionData[child] = !isChecked; });
        }
        if (rulesToProfile[key]) {
            const parent = rulesToProfile[key];
            if (sectionData.hasOwnProperty(parent) && isChecked) sectionData[parent] = false;
        }
        refreshUI();
    }

    function updateDiagramView() {
        const data = jsonData["included-in-bpa"][currentTab];
        const container = document.getElementById('checkboxContainer');
        container.innerHTML = `<h4 style="margin:0 0 10px 0">Active Components</h4>`;
        Object.entries(data).forEach(([key, val]) => {
            const div = document.createElement('div');
            div.className = 'item';
            div.innerHTML = `<input type="checkbox" id="c-${key}" ${val?'checked':''}><label for="c-${key}" style="flex:1; cursor:pointer">${key}</label>`;
            div.querySelector('input').onchange = (e) => toggleBpa(key, e.target.checked);
            container.appendChild(div);
        });
        renderD3(Object.entries(data));
    }

    function renderD3(entries) {
        const pane = d3.select("#diagramContainer");
        pane.selectAll("*").remove();
        const w = pane.node().getBoundingClientRect().width, h = pane.node().getBoundingClientRect().height;
        const radius = Math.min(w, h) / 3.2;
        const svg = pane.append("svg").attr("width", w).attr("height", h).append("g").attr("transform", `translate(${w/2}, ${h/2})`);
        const angle = d3.scaleBand().range([0, 2 * Math.PI]).domain(entries.map(d => d[0]));

        svg.selectAll("path").data(entries).enter().append("path")
            .attr("fill", d => d[1] ? "#25B197" : "#E8121C")
            /* OPACITY LOGIC: Faded red (0.3) for disabled, solid (1.0) for active */
            .attr("fill-opacity", d => d[1] ? 1.0 : 0.3)
            .attr("stroke", "#fff")
            .attr("stroke-width", 2)
            .attr("stroke-opacity", d => d[1] ? 1.0 : 0.5)
            .attr("d", d3.arc().innerRadius(60).outerRadius(radius).startAngle(d => angle(d[0])).endAngle(d => angle(d[0]) + angle.bandwidth()).padAngle(0.02).padRadius(60))
            .style("cursor", "pointer")
            .on("click", (e, d) => toggleBpa(d[0], !d[1]));

        svg.selectAll(".label-text").data(entries).enter().append("text").attr("class", "label-text")
            .each(function(d) {
                const a = angle(d[0]) + angle.bandwidth() / 2;
                const deg = (a * 180 / Math.PI) - 90;
                const flip = (deg > 90 && deg < 270);
                d3.select(this).attr("text-anchor", flip ? "end" : "start")
                    .attr("transform", `rotate(${deg}) translate(${radius + 15}) rotate(${flip ? 180 : 0})`)
                    /* TEXT OPACITY LOGIC: Dimmed labels for disabled items */
                    .style("opacity", d[1] ? 1.0 : 0.5)
                    .text(d[0].length > 20 ? d[0].substring(0, 18) + '...' : d[0]);
            });
    }

    function getRuleByPath(path) {
        if (typeof BP_VALIDATION === 'undefined') return null;
        let curr = BP_VALIDATION;
        for (const seg of path) {
            if (curr && curr[seg]) curr = curr[seg];
            else return null;
        }
        return (curr && curr.options) ? curr : null;
    }

    function updateSettingsView_old() {
        const container = document.getElementById('settingsContainer');
        container.innerHTML = `<h2>Best Practice Editor: ${currentTab.toUpperCase()}</h2>`;
        const card = document.createElement('div');
        card.className = 'json-card';
        buildEditor(jsonData[currentTab], card, [currentTab]);
        container.appendChild(card);
    }

    function updateSettingsView_new1() {
        const container = document.getElementById('settingsContainer');
        container.innerHTML = `<h2>Best Practice Editor: ${currentTab.toUpperCase()}</h2>`;

        const sectionData = jsonData[currentTab];
        if (!sectionData || typeof sectionData !== 'object') return;

        // Sub-Tabs generieren basierend auf den Keys der ersten Ebene
        const subKeys = Object.keys(sectionData);

        if (subKeys.length > 0) {
            // Fallback falls der aktuelle Sub-Tab nicht mehr existiert
            if (!subKeys.includes(currentSubTab)) {
                currentSubTab = subKeys[0];
            }

            // Sub-Tab Leere rendern
            const tabContainer = document.createElement('div');
            tabContainer.className = 'sub-tab-container';

            subKeys.forEach(key => {
                const tab = document.createElement('div');
                tab.className = `sub-tab ${currentSubTab === key ? 'active' : ''}`;
                tab.textContent = key;
                tab.onclick = () => {
                    currentSubTab = key;
                    refreshUI();
                };
                tabContainer.appendChild(tab);
            });
            container.appendChild(tabContainer);

            // Content-Card für den aktiven Sub-Tab rendern
            const card = document.createElement('div');
            card.className = 'json-card';

            // Starte den Editor eine Ebene tiefer beim ausgewählten Sub-Tab
            const activeData = sectionData[currentSubTab];

            if (typeof activeData === 'object' && activeData !== null) {
                buildEditor(activeData, card, [currentTab, currentSubTab]);
            } else {
                // Falls der Key direkt einen flachen Wert hält
                const fallbackObj = {};
                fallbackObj[currentSubTab] = activeData;
                buildEditor(fallbackObj, card, [currentTab]);
            }

            container.appendChild(card);
        }
    }

    function updateSettingsView() {
        const container = document.getElementById('settingsContainer');
        container.innerHTML = `<h2>Best Practice Editor: ${currentTab.toUpperCase()}</h2>`;

        const sectionData = jsonData[currentTab];
        if (!sectionData || typeof sectionData !== 'object') return;

        // 1. Ebene: Sub-Tabs generieren (z.B. die einzelnen Profil-Namen)
        const subKeys = Object.keys(sectionData);

        if (subKeys.length > 0) {
            if (!subKeys.includes(currentSubTab)) {
                currentSubTab = subKeys[0];
            }

            const tabContainer = document.createElement('div');
            tabContainer.className = 'sub-tab-container';

            subKeys.forEach(key => {
                const tab = document.createElement('div');
                tab.className = `sub-tab ${currentSubTab === key ? 'active' : ''}`;
                tab.textContent = key;
                tab.onclick = () => {
                    currentSubTab = key;
                    // Beim Wechsel des Haupt-Profils setzen wir den Sub-Sub-Tab zurück auf Visibility
                    currentSubSubTab = 'visibility';
                    refreshUI();
                };
                tabContainer.appendChild(tab);
            });
            container.appendChild(tabContainer);

            // Daten des aktuell ausgewählten Profils holen
            const activeData = sectionData[currentSubTab];

            // 2. Ebene: Sub-Sub-Tabs generieren (Unterscheidung Visibility vs. Best Practice)
            // Wir prüfen, ob die Struktur diese Unterscheidung anbietet
            const subSubTabContainer = document.createElement('div');
            subSubTabContainer.className = 'sub-sub-tab-container';

            // 'visibility' wird explizit als erstes Element definiert
            const availableSubSubTabs = ['visibility', 'bp'];

            availableSubSubTabs.forEach(type => {
                const subSubTab = document.createElement('div');
                subSubTab.className = `sub-sub-tab ${currentSubSubTab === type ? 'active' : ''}`;
                subSubTab.textContent = type === 'visibility' ? '👁️ Visibility' : '🛡️ Best Practice';
                subSubTab.onclick = () => {
                    currentSubSubTab = type;
                    refreshUI();
                };
                subSubTabContainer.appendChild(subSubTab);
            });
            container.appendChild(subSubTabContainer);

            // Inhalts-Card für die Formularfelder rendern
            const card = document.createElement('div');
            card.className = 'json-card';

            // Prüfen, ob das JSON die Struktur direkt unterteilt (z.B. activeData.visibility oder activeData['best-practice'])
            if (activeData && typeof activeData === 'object') {
                if (activeData[currentSubSubTab] !== undefined) {
                    // Wenn der Knoten existiert (z.B. activeData.visibility), rendern wir dessen Inhalt
                    buildEditor(activeData[currentSubSubTab], card, [currentTab, currentSubTab, currentSubSubTab]);
                } else {
                    // Fallback: Falls die Daten nicht tiefer unterteilt sind, zeigen wir einen Hinweis
                    card.innerHTML = `<div style="color: #718096; font-style: italic; text-align: center; padding: 20px;">
                                    Keine spezifischen Daten für "${currentSubSubTab}" in diesem Profil vorhanden.
                                  </div>`;
                }
            }

            container.appendChild(card);
        }
    }

    function buildEditor_old(data, container, path = []) {
        for (const key in data) {
            const val = data[key];
            const currentPath = [...path, key];
            const group = document.createElement('div');
            group.className = 'settings-group';

            if (Array.isArray(val) && val.length > 0 && typeof val[0] === 'object') {
                group.innerHTML = `<span class="json-key">${key}:</span>`;
                const arrayContainer = document.createElement('div');
                val.forEach((item, idx) => {
                    const itemBox = document.createElement('div');
                    itemBox.className = 'array-item-box';
                    const ctrl = document.createElement('div');
                    ctrl.className = 'array-controls';
                    const plus = document.createElement('button'); plus.className='btn-action btn-plus'; plus.innerText='+';
                    plus.onclick = () => { data[key].splice(idx+1, 0, JSON.parse(JSON.stringify(item))); refreshUI(); };
                    const minus = document.createElement('button'); minus.className='btn-action btn-minus'; minus.innerText='-';
                    minus.onclick = () => { if(data[key].length > 1) { data[key].splice(idx, 1); refreshUI(); } };
                    ctrl.appendChild(plus); ctrl.appendChild(minus);
                    itemBox.appendChild(ctrl);
                    buildEditor(item, itemBox, currentPath);
                    arrayContainer.appendChild(itemBox);
                });
                group.appendChild(arrayContainer);
            } else if (typeof val === 'object' && !Array.isArray(val) && val !== null) {
                group.innerHTML = `<span class="json-key">${key}:</span>`;
                buildEditor(val, group, currentPath);
            } else {
                group.innerHTML = `<span class="json-key">${key}:</span>`;
                const rule = getRuleByPath(currentPath);
                if (rule) {
                    const optDiv = document.createElement('div');
                    const curArr = Array.isArray(val) ? val : [val];
                    const hasAny = curArr.includes("any");
                    const isInclusive = rule.behavior === "inclusive";

                    // Merge default options with any existing custom values from JSON
                    const displayOptions = Array.from(new Set([...rule.options, ...curArr]));

                    displayOptions.forEach(opt => {
                        const label = document.createElement('label');
                        label.className = 'validation-option';
                        if (hasAny && opt !== "any" && !isInclusive) label.classList.add('disabled-option');
                        const input = document.createElement('input');
                        input.type = rule.multi ? "checkbox" : "radio";
                        input.checked = curArr.includes(opt);
                        if (hasAny && opt !== "any" && !isInclusive) input.disabled = true;

                        input.onchange = () => {
                            if (rule.multi) {
                                let selection = Array.isArray(data[key]) ? [...data[key]] : [data[key]];
                                if (opt === "any") {
                                    if (input.checked) isInclusive ? selection.push("any") : selection = ["any"];
                                    else selection = selection.filter(v => v !== "any");
                                } else {
                                    if (!isInclusive) selection = selection.filter(v => v !== "any");
                                    if (input.checked) { if (!selection.includes(opt)) selection.push(opt); }
                                    else selection = selection.filter(v => v !== opt);
                                }
                                data[key] = selection;
                            } else {
                                data[key] = opt;
                            }
                            refreshUI();
                        };
                        label.appendChild(input); label.appendChild(document.createTextNode(opt));
                        optDiv.appendChild(label);
                    });

                    // RENDER CUSTOM ADD FIELD IF ALLOWED
                    if (rule.multi && rule.allowCustom) {
                        const addContainer = document.createElement('div');
                        addContainer.className = 'custom-add-container';

                        const customInput = document.createElement('input');
                        customInput.type = 'text';
                        customInput.className = 'custom-add-input';
                        customInput.placeholder = 'Add custom option...';

                        const addBtn = document.createElement('button');
                        addBtn.className = 'btn-custom-add';
                        addBtn.innerText = 'Add';
                        addBtn.onclick = () => {
                            const newVal = customInput.value.trim();
                            if (newVal && !curArr.includes(newVal)) {
                                if (Array.isArray(data[key])) data[key].push(newVal);
                                else data[key] = [data[key], newVal];
                                refreshUI();
                            }
                        };

                        addContainer.appendChild(customInput);
                        addContainer.appendChild(addBtn);
                        optDiv.appendChild(addContainer);
                    }

                    group.appendChild(optDiv);
                } else {
                    const input = document.createElement('input');
                    input.className = 'edit-input';
                    input.value = Array.isArray(val) ? val.join(', ') : val;
                    input.onchange = (e) => { data[key] = Array.isArray(val) ? e.target.value.split(',').map(s => s.trim()) : e.target.value; };
                    group.appendChild(input);
                }
            }
            container.appendChild(group);
        }
    }

    function buildEditor_new1(data, container, path = []) {
        for (const key in data) {
            const val = data[key];
            const currentPath = [...path, key];
            const group = document.createElement('div');
            group.className = 'settings-group';

            if (Array.isArray(val) && val.length > 0 && typeof val[0] === 'object') {
                group.innerHTML = `<span class="json-key">${key}</span>`;
                const arrayContainer = document.createElement('div');
                val.forEach((item, idx) => {
                    const itemBox = document.createElement('div');
                    itemBox.className = 'array-item-box';
                    const ctrl = document.createElement('div');
                    ctrl.className = 'array-controls';

                    const plus = document.createElement('button'); plus.className='btn-action btn-plus'; plus.innerText='+';
                    plus.onclick = () => { data[key].splice(idx+1, 0, JSON.parse(JSON.stringify(item))); refreshUI(); };

                    const minus = document.createElement('button'); minus.className='btn-action btn-minus'; minus.innerText='-';
                    minus.onclick = () => { if(data[key].length > 1) { data[key].splice(idx, 1); refreshUI(); } };

                    ctrl.appendChild(plus); ctrl.appendChild(minus);
                    itemBox.appendChild(ctrl);
                    buildEditor(item, itemBox, currentPath);
                    arrayContainer.appendChild(itemBox);
                });
                group.appendChild(arrayContainer);
            } else if (typeof val === 'object' && !Array.isArray(val) && val !== null) {
                group.innerHTML = `<span class="json-key" style="color:var(--accent); font-weight:700;">${key}</span>`;
                const subGroupContainer = document.createElement('div');
                subGroupContainer.style.paddingLeft = "15px";
                subGroupContainer.style.borderLeft = "2px dashed #e2e8f0";
                buildEditor(val, subGroupContainer, currentPath);
                group.appendChild(subGroupContainer);
            } else {
                group.innerHTML = `<span class="json-key">${key}:</span>`;
                const rule = getRuleByPath(currentPath);
                if (rule) {
                    const optDiv = document.createElement('div');
                    const curArr = Array.isArray(val) ? val : [val];
                    const hasAny = curArr.includes("any");
                    const isInclusive = rule.behavior === "inclusive";
                    const displayOptions = Array.from(new Set([...rule.options, ...curArr]));

                    displayOptions.forEach(opt => {
                        const label = document.createElement('label');
                        label.className = 'validation-option';
                        if (hasAny && opt !== "any" && !isInclusive) label.classList.add('disabled-option');
                        const input = document.createElement('input');
                        input.type = rule.multi ? "checkbox" : "radio";
                        input.checked = curArr.includes(opt);
                        if (hasAny && opt !== "any" && !isInclusive) input.disabled = true;

                        input.onchange = () => {
                            if (rule.multi) {
                                let selection = Array.isArray(data[key]) ? [...data[key]] : [data[key]];
                                if (opt === "any") {
                                    if (input.checked) isInclusive ? selection.push("any") : selection = ["any"];
                                    else selection = selection.filter(v => v !== "any");
                                } else {
                                    if (!isInclusive) selection = selection.filter(v => v !== "any");
                                    if (input.checked) { if (!selection.includes(opt)) selection.push(opt); }
                                    else selection = selection.filter(v => v !== opt);
                                }
                                data[key] = selection;
                            } else {
                                data[key] = opt;
                            }
                            refreshUI();
                        };
                        label.appendChild(input); label.appendChild(document.createTextNode(opt));
                        optDiv.appendChild(label);
                    });

                    if (rule.multi && rule.allowCustom) {
                        const addContainer = document.createElement('div');
                        addContainer.className = 'custom-add-container';
                        const customInput = document.createElement('input');
                        customInput.type = 'text';
                        customInput.className = 'custom-add-input';
                        customInput.placeholder = 'Add custom option...';
                        const addBtn = document.createElement('button');
                        addBtn.className = 'btn-custom-add';
                        addBtn.innerText = 'Add';
                        addBtn.onclick = () => {
                            const newVal = customInput.value.trim();
                            if (newVal && !curArr.includes(newVal)) {
                                if (Array.isArray(data[key])) data[key].push(newVal);
                                else data[key] = [data[key], newVal];
                                refreshUI();
                            }
                        };
                        addContainer.appendChild(customInput); addContainer.appendChild(addBtn);
                        optDiv.appendChild(addContainer);
                    }
                    group.appendChild(optDiv);
                } else {
                    const input = document.createElement('input');
                    input.className = 'edit-input';
                    input.value = Array.isArray(val) ? val.join(', ') : val;
                    input.onchange = (e) => { data[key] = Array.isArray(val) ? e.target.value.split(',').map(s => s.trim()) : e.target.value; };
                    group.appendChild(input);
                }
            }
            container.appendChild(group);
        }
    }

    function buildEditor(data, container, path = []) {
        // Falls die Daten kein Objekt/Array sind, direkt abbrechen
        if (typeof data !== 'object' || data === null) return;

        for (const key in data) {
            const val = data[key];
            const currentPath = [...path, key];
            const group = document.createElement('div');
            group.className = 'settings-group';

            if (Array.isArray(val) && val.length > 0 && typeof val[0] === 'object') {
                group.innerHTML = `<span class="json-key">${key}</span>`;
                const arrayContainer = document.createElement('div');
                val.forEach((item, idx) => {
                    const itemBox = document.createElement('div');
                    itemBox.className = 'array-item-box';
                    const ctrl = document.createElement('div');
                    ctrl.className = 'array-controls';

                    const plus = document.createElement('button'); plus.className='btn-action btn-plus'; plus.innerText='+';
                    plus.onclick = () => { data[key].splice(idx+1, 0, JSON.parse(JSON.stringify(item))); refreshUI(); };

                    const minus = document.createElement('button'); minus.className='btn-action btn-minus'; minus.innerText='-';
                    minus.onclick = () => { if(data[key].length > 1) { data[key].splice(idx, 1); refreshUI(); } };

                    ctrl.appendChild(plus); ctrl.appendChild(minus);
                    itemBox.appendChild(ctrl);
                    buildEditor(item, itemBox, currentPath);
                    arrayContainer.appendChild(itemBox);
                });
                group.appendChild(arrayContainer);
            } else if (typeof val === 'object' && !Array.isArray(val) && val !== null) {
                group.innerHTML = `<span class="json-key" style="color:var(--accent); font-weight:700;">${key}</span>`;
                const subGroupContainer = document.createElement('div');
                subGroupContainer.style.paddingLeft = "15px";
                subGroupContainer.style.borderLeft = "2px dashed #e2e8f0";
                buildEditor(val, subGroupContainer, currentPath);
                group.appendChild(subGroupContainer);
            } else {
                group.innerHTML = `<span class="json-key">${key}:</span>`;
                const rule = getRuleByPath(currentPath);
                if (rule) {
                    const optDiv = document.createElement('div');
                    const curArr = Array.isArray(val) ? val : [val];
                    const hasAny = curArr.includes("any");
                    const isInclusive = rule.behavior === "inclusive";
                    const displayOptions = Array.from(new Set([...rule.options, ...curArr]));

                    displayOptions.forEach(opt => {
                        const label = document.createElement('label');
                        label.className = 'validation-option';
                        if (hasAny && opt !== "any" && !isInclusive) label.classList.add('disabled-option');
                        const input = document.createElement('input');
                        input.type = rule.multi ? "checkbox" : "radio";
                        input.checked = curArr.includes(opt);
                        if (hasAny && opt !== "any" && !isInclusive) input.disabled = true;

                        input.onchange = () => {
                            if (rule.multi) {
                                let selection = Array.isArray(data[key]) ? [...data[key]] : [data[key]];
                                if (opt === "any") {
                                    if (input.checked) isInclusive ? selection.push("any") : selection = ["any"];
                                    else selection = selection.filter(v => v !== "any");
                                } else {
                                    if (!isInclusive) selection = selection.filter(v => v !== "any");
                                    if (input.checked) { if (!selection.includes(opt)) selection.push(opt); }
                                    else selection = selection.filter(v => v !== opt);
                                }
                                data[key] = selection;
                            } else {
                                data[key] = opt;
                            }
                            refreshUI();
                        };
                        label.appendChild(input); label.appendChild(document.createTextNode(opt));
                        optDiv.appendChild(label);
                    });

                    if (rule.multi && rule.allowCustom) {
                        const addContainer = document.createElement('div');
                        addContainer.className = 'custom-add-container';
                        const customInput = document.createElement('input');
                        customInput.type = 'text';
                        customInput.className = 'custom-add-input';
                        customInput.placeholder = 'Add custom option...';
                        const addBtn = document.createElement('button');
                        addBtn.className = 'btn-custom-add';
                        addBtn.innerText = 'Add';
                        addBtn.onclick = () => {
                            const newVal = customInput.value.trim();
                            if (newVal && !curArr.includes(newVal)) {
                                if (Array.isArray(data[key])) data[key].push(newVal);
                                else data[key] = [data[key], newVal];
                                refreshUI();
                            }
                        };
                        addContainer.appendChild(customInput); addContainer.appendChild(addBtn);
                        optDiv.appendChild(addContainer);
                    }
                    group.appendChild(optDiv);
                } else {
                    const input = document.createElement('input');
                    input.className = 'edit-input';
                    input.value = Array.isArray(val) ? val.join(', ') : val;
                    input.onchange = (e) => { data[key] = Array.isArray(val) ? e.target.value.split(',').map(s => s.trim()) : e.target.value; };
                    group.appendChild(input);
                }
            }
            container.appendChild(group);
        }
    }

    document.getElementById('downloadBtn').onclick = () => {
        const blob = new Blob([JSON.stringify(jsonData, null, 4)], {type: "application/json"});
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = "updated_config.json";
        a.click();
    };
</script>
</body>
</html>