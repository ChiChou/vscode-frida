(function () {
  // @ts-ignore
  const vscode = acquireVsCodeApi();

  const RENDER_CHUNK = 500;

  let allModules = [];
  let allExports = [];
  let selectedModuleName = null;
  let selectedModuleInfo = null;
  let checkedFunctions = new Set(); // only function names (not variables)
  let filterDebounce = null;

  const $moduleList = document.getElementById('module-list');
  const $exportList = document.getElementById('export-list');
  const $moduleFilter = document.getElementById('module-filter');
  const $exportFilter = document.getElementById('export-filter');
  const $detailTitle = document.getElementById('detail-title');
  const $moduleInfo = document.getElementById('module-info');
  const $modPath = document.getElementById('mod-path');
  const $modBase = document.getElementById('mod-base');
  const $modSize = document.getElementById('mod-size');
  const $exportToolbar = document.getElementById('export-toolbar');
  const $selectAll = document.getElementById('select-all');
  const $exportCount = document.getElementById('export-count');
  const $btnHook = document.getElementById('btn-hook');
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

  $btnHook.addEventListener('click', () => {
    if (checkedFunctions.size === 0) return;
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
    row.innerHTML =
      '<span class="name" title="' + escapeAttr(m.path) + '">' + escapeHtml(m.name) + '</span>' +
      '<span class="address">' + escapeHtml(m.base) + '</span>';

    row.addEventListener('click', () => {
      selectedModuleName = m.name;
      selectedModuleInfo = m;
      $detailTitle.textContent = m.name;
      $moduleInfo.style.display = '';
      $modPath.textContent = m.path;
      $modBase.textContent = m.base;
      $modSize.textContent = formatSize(m.size);

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
    hookBtn.textContent = 'Hook';
    hookBtn.addEventListener('click', (ev) => {
      ev.stopPropagation();
      vscode.postMessage({
        type: 'generateHook',
        module: selectedModuleName,
        functions: [e.name],
      });
    });

    row.appendChild(cb);
    row.appendChild(nameSpan);
    row.appendChild(hookBtn);
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
    $btnHook.disabled = count === 0;
  }

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
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
