let currentSubTab = '';
let currentSubSubTab = 'visibility'; // Standardmäßig 'visibility' zuerst

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
        const availableSubSubTabs = ['visibility', 'best-practice'];

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