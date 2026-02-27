(function () {
  // @ts-ignore
  const vscode = acquireVsCodeApi();

  const RENDER_CHUNK = 500;

  let allModules = [];
  let allExports = [];
  let selectedModuleName = null;
  let selectedModuleInfo = null;
  let checkedFunctions = new Set();
  let filterDebounce = null;

  const $moduleList = document.getElementById('module-list');
  const $exportList = document.getElementById('export-list');
  const $moduleFilter = document.getElementById('module-filter');
  const $exportFilter = document.getElementById('export-filter');
  const $detailTitle = document.getElementById('detail-title');
  const $moduleInfo = document.getElementById('module-info');
  const $modPath = document.getElementById('mod-path');
  const $modRange = document.getElementById('mod-range');
  const $exportToolbar = document.getElementById('export-toolbar');
  const $selectAll = document.getElementById('select-all');
  const $exportCount = document.getElementById('export-count');
  const $btnHookBasic = document.getElementById('btn-hook-basic');
  const $btnHookSmart = document.getElementById('btn-hook-smart');
  const $selectionCount = document.getElementById('selection-count');
  const $actions = document.getElementById('actions');

  window.addEventListener('message', (event) => {
    const msg = event.data;
    switch (msg.type) {
      case 'setModules':
        allModules = msg.modules;
        renderModules();
        break;
      case 'setExports':
        allExports = msg.exports;
        checkedFunctions.clear();
        renderExports();
        $exportToolbar.style.display = '';
        $actions.style.display = 'flex';
        $exportFilter.value = '';
        $selectAll.checked = false;
        updateSelectionCount();
        break;
      case 'setLoading':
        if (msg.loading) {
          const target = msg.area === 'master' ? $moduleList : $exportList;
          target.innerHTML = '<div class="loading">Loading...</div>';
        }
        break;
      case 'error':
        showError(msg.message);
        break;
      case 'hookGenerated':
        setGenerating(false);
        break;
    }
  });

  $moduleFilter.addEventListener('input', () => {
    clearTimeout(filterDebounce);
    filterDebounce = setTimeout(renderModules, 150);
  });

  $exportFilter.addEventListener('input', () => {
    clearTimeout(filterDebounce);
    filterDebounce = setTimeout(renderExports, 150);
  });

  $selectAll.addEventListener('change', () => {
    const checked = $selectAll.checked;
    const query = $exportFilter.value.toLowerCase();
    const filtered = filterExports(query);

    if (checked) {
      filtered.forEach(e => checkedFunctions.add(e.name));
    } else {
      filtered.forEach(e => checkedFunctions.delete(e.name));
    }

    renderExports();
    updateSelectionCount();
  });

  $btnHookBasic.addEventListener('click', () => {
    if (checkedFunctions.size === 0) return;
    vscode.postMessage({
      type: 'generateHookBasic',
      module: selectedModuleName,
      functions: Array.from(checkedFunctions),
    });
  });

  $btnHookSmart.addEventListener('click', () => {
    if (checkedFunctions.size === 0) return;
    setGenerating(true);
    vscode.postMessage({
      type: 'generateHook',
      module: selectedModuleName,
      functions: Array.from(checkedFunctions),
    });
  });

  function filterModules(query) {
    if (!query) return allModules;
    return allModules.filter(m =>
      m.name.toLowerCase().includes(query) || m.path.toLowerCase().includes(query)
    );
  }

  function filterExports(query) {
    const fns = allExports.filter(e => e.type === 'function');
    if (!query) return fns;
    return fns.filter(e => e.name.toLowerCase().includes(query));
  }

  function renderModules() {
    const query = $moduleFilter.value.toLowerCase();
    const filtered = filterModules(query);

    $moduleList.innerHTML = '';
    renderChunk(filtered, 0, $moduleList, renderModuleRow);
  }

  function renderModuleRow(m) {
    const row = document.createElement('div');
    row.className = 'list-row' + (m.name === selectedModuleName ? ' selected' : '');
    const range = formatRange(m.base, m.size);
    row.innerHTML =
      '<span class="name" title="' + escapeAttr(m.path) + '">' + escapeHtml(m.name) + '</span>' +
      '<span class="address" title="' + escapeAttr(range) + '">' + escapeHtml(m.base) + '</span>';

    row.addEventListener('click', () => {
      selectedModuleName = m.name;
      selectedModuleInfo = m;
      $detailTitle.textContent = m.name;
      $moduleInfo.style.display = '';
      $modPath.textContent = m.path;
      $modRange.textContent = range;

      $moduleList.querySelectorAll('.list-row').forEach(r => r.classList.remove('selected'));
      row.classList.add('selected');

      vscode.postMessage({ type: 'loadExports', moduleName: m.name });
    });

    return row;
  }

  function renderExports() {
    const query = $exportFilter.value.toLowerCase();
    const filtered = filterExports(query);

    $exportCount.textContent = filtered.length + ' exports';
    $exportList.innerHTML = '';
    renderChunk(filtered, 0, $exportList, renderExportRow);
  }

  function renderExportRow(e) {
    const row = document.createElement('div');
    row.className = 'list-row';

    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = checkedFunctions.has(e.name);
    cb.addEventListener('change', () => {
      if (cb.checked) {
        checkedFunctions.add(e.name);
      } else {
        checkedFunctions.delete(e.name);
      }
      updateSelectionCount();
    });

    const nameSpan = document.createElement('span');
    nameSpan.className = 'name';
    nameSpan.textContent = e.name;
    nameSpan.title = e.address;

    const hookBtn = document.createElement('button');
    hookBtn.className = 'hook-btn';
    hookBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m17.586 11.414-5.93 5.93a1 1 0 0 1-8-8l3.137-3.137a.707.707 0 0 1 1.207.5V10"/><path d="M20.414 8.586 22 7"/><circle cx="19" cy="10" r="2"/></svg>';
    hookBtn.title = window.I18N.hook;
    hookBtn.addEventListener('click', (ev) => {
      ev.stopPropagation();
      vscode.postMessage({
        type: 'generateHookBasic',
        module: selectedModuleName,
        functions: [e.name],
      });
    });

    const hookAIBtn = document.createElement('button');
    hookAIBtn.className = 'hook-btn hook-btn-ai';
    hookAIBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11.017 2.814a1 1 0 0 1 1.966 0l1.051 5.558a2 2 0 0 0 1.594 1.594l5.558 1.051a1 1 0 0 1 0 1.966l-5.558 1.051a2 2 0 0 0-1.594 1.594l-1.051 5.558a1 1 0 0 1-1.966 0l-1.051-5.558a2 2 0 0 0-1.594-1.594l-5.558-1.051a1 1 0 0 1 0-1.966l5.558-1.051a2 2 0 0 0 1.594-1.594z"/><path d="M20 2v4"/><path d="M22 4h-4"/><circle cx="4" cy="20" r="2"/></svg>';
    hookAIBtn.title = window.I18N.hookAI;
    hookAIBtn.addEventListener('click', (ev) => {
      ev.stopPropagation();
      setGenerating(true);
      vscode.postMessage({
        type: 'generateHook',
        module: selectedModuleName,
        functions: [e.name],
      });
    });

    row.appendChild(cb);
    row.appendChild(nameSpan);
    row.appendChild(hookBtn);
    row.appendChild(hookAIBtn);
    return row;
  }

  function renderChunk(items, offset, container, rowFn) {
    const end = Math.min(offset + RENDER_CHUNK, items.length);
    const fragment = document.createDocumentFragment();
    for (let i = offset; i < end; i++) {
      fragment.appendChild(rowFn(items[i]));
    }
    container.appendChild(fragment);

    if (end < items.length) {
      requestAnimationFrame(() => renderChunk(items, end, container, rowFn));
    }
  }

  function updateSelectionCount() {
    const count = checkedFunctions.size;
    $selectionCount.textContent = count + ' selected';
    $btnHookBasic.disabled = count === 0;
    $btnHookSmart.disabled = count === 0;
  }

  function setGenerating(generating) {
    $btnHookBasic.disabled = generating;
    $btnHookSmart.disabled = generating;
    $btnHookSmart.innerText = generating ? window.I18N.generating : window.I18N.generateHookSmart;
    document.querySelectorAll('.hook-btn').forEach(btn => {
      btn.disabled = generating;
    });
  }

  function formatRange(base, size) {
    const baseNum = parseInt(base, 16);
    const endNum = baseNum + size;
    return '0x' + baseNum.toString(16) + '-0x' + endNum.toString(16);
  }

  function showError(message) {
    const toast = document.createElement('div');
    toast.className = 'error-toast';
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
  }

  function escapeHtml(s) {
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }

  function escapeAttr(s) {
    return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  vscode.postMessage({ type: 'ready' });
})();
