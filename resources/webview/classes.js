(function () {
  // @ts-ignore
  const vscode = acquireVsCodeApi();

  const RENDER_CHUNK = 500;

  let allClasses = [];
  let allMethods = [];     // MethodInfo objects: { name, display, args, returnType, isReturnObject, isStatic }
  let selectedClassName = null;
  let checkedMethods = new Map(); // name -> full MethodInfo with className
  let runtime = 'Generic';
  let filterDebounce = null;

  const $classList = document.getElementById('class-list');
  const $methodList = document.getElementById('method-list');
  const $classFilter = document.getElementById('class-filter');
  const $methodFilter = document.getElementById('method-filter');
  const $detailTitle = document.getElementById('detail-title');
  const $breadcrumb = document.getElementById('breadcrumb');
  const $methodToolbar = document.getElementById('method-toolbar');
  const $ownMethodsToggle = document.getElementById('own-methods-toggle');
  const $selectAll = document.getElementById('select-all');
  const $methodCount = document.getElementById('method-count');
  const $btnHook = document.getElementById('btn-hook');
  const $selectionCount = document.getElementById('selection-count');
  const $actions = document.getElementById('actions');

  window.addEventListener('message', (event) => {
    const msg = event.data;
    switch (msg.type) {
      case 'setClasses':
        allClasses = msg.classes;
        renderClasses();
        break;
      case 'setRuntime':
        runtime = msg.runtime;
        break;
      case 'setMethods':
        allMethods = msg.methods;
        checkedMethods.clear();
        renderMethods();
        $methodToolbar.style.display = '';
        $actions.style.display = 'flex';
        $methodFilter.value = '';
        $selectAll.checked = false;
        updateSelectionCount();
        break;
      case 'setSuperClasses':
        renderBreadcrumb(msg.className, msg.superClasses);
        break;
      case 'selectClass':
        selectClassByName(msg.className);
        break;
      case 'setLoading':
        if (msg.loading) {
          const target = msg.area === 'master' ? $classList : $methodList;
          target.innerHTML = '<div class="loading">Loading...</div>';
        }
        break;
      case 'error':
        showError(msg.message);
        break;
    }
  });

  $classFilter.addEventListener('input', () => {
    clearTimeout(filterDebounce);
    filterDebounce = setTimeout(renderClasses, 150);
  });

  $methodFilter.addEventListener('input', () => {
    clearTimeout(filterDebounce);
    filterDebounce = setTimeout(renderMethods, 150);
  });

  $ownMethodsToggle.addEventListener('change', () => {
    if (!selectedClassName) return;
    vscode.postMessage({
      type: 'loadMethods',
      className: selectedClassName,
      ownOnly: $ownMethodsToggle.checked,
    });
  });

  $selectAll.addEventListener('change', () => {
    const checked = $selectAll.checked;
    const query = $methodFilter.value.toLowerCase();
    const filtered = filterMethods(query);

    if (checked) {
      filtered.forEach(m => {
        checkedMethods.set(m.name, toSelection(m));
      });
    } else {
      filtered.forEach(m => checkedMethods.delete(m.name));
    }

    renderMethods();
    updateSelectionCount();
  });

  $btnHook.addEventListener('click', () => {
    if (checkedMethods.size === 0) return;
    vscode.postMessage({
      type: 'generateHook',
      selections: Array.from(checkedMethods.values()),
    });
  });

  function toSelection(m) {
    return {
      className: selectedClassName,
      name: m.name,
      display: m.display,
      args: m.args,
      returnType: m.returnType,
      isReturnObject: m.isReturnObject,
      isStatic: m.isStatic,
    };
  }

  function selectClassByName(className) {
    if (!allClasses.includes(className)) return;

    selectedClassName = className;
    $detailTitle.textContent = className;

    $classList.querySelectorAll('.list-row').forEach(r => {
      if (r.dataset.name === className) {
        r.classList.add('selected');
      } else {
        r.classList.remove('selected');
      }
    });

    vscode.postMessage({
      type: 'loadMethods',
      className: className,
      ownOnly: $ownMethodsToggle.checked,
    });
  }

  function filterClasses(query) {
    if (!query) return allClasses;
    return allClasses.filter(c => c.toLowerCase().includes(query));
  }

  function filterMethods(query) {
    if (!query) return allMethods;
    return allMethods.filter(m => m.display.toLowerCase().includes(query));
  }

  function renderClasses() {
    const query = $classFilter.value.toLowerCase();
    const filtered = filterClasses(query);

    $classList.innerHTML = '';
    renderChunk(filtered, 0, $classList, renderClassRow);
  }

  function renderClassRow(c) {
    const row = document.createElement('div');
    row.className = 'list-row' + (c === selectedClassName ? ' selected' : '');
    row.dataset.name = c;

    const nameSpan = document.createElement('span');
    nameSpan.className = 'name';
    nameSpan.textContent = c;
    row.appendChild(nameSpan);

    row.addEventListener('click', () => {
      selectedClassName = c;
      $detailTitle.textContent = c;

      $classList.querySelectorAll('.list-row').forEach(r => r.classList.remove('selected'));
      row.classList.add('selected');

      vscode.postMessage({
        type: 'loadMethods',
        className: c,
        ownOnly: $ownMethodsToggle.checked,
      });
    });

    return row;
  }

  function renderMethods() {
    const query = $methodFilter.value.toLowerCase();
    const filtered = filterMethods(query);

    $methodCount.textContent = filtered.length + ' methods';
    $methodList.innerHTML = '';
    renderChunk(filtered, 0, $methodList, renderMethodRow);
  }

  function renderMethodRow(m) {
    const row = document.createElement('div');
    row.className = 'list-row';

    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = checkedMethods.has(m.name);
    cb.addEventListener('change', () => {
      if (cb.checked) {
        checkedMethods.set(m.name, toSelection(m));
      } else {
        checkedMethods.delete(m.name);
      }
      updateSelectionCount();
    });

    const nameSpan = document.createElement('span');
    nameSpan.className = 'name';
    nameSpan.textContent = m.display;
    nameSpan.title = m.name;

    const hookBtn = document.createElement('button');
    hookBtn.className = 'hook-btn';
    hookBtn.textContent = 'Hook';
    hookBtn.addEventListener('click', (ev) => {
      ev.stopPropagation();
      vscode.postMessage({
        type: 'generateHook',
        selections: [toSelection(m)],
      });
    });

    row.appendChild(cb);
    row.appendChild(nameSpan);
    row.appendChild(hookBtn);
    return row;
  }

  function renderBreadcrumb(className, superClasses) {
    if (!superClasses || superClasses.length === 0) {
      $breadcrumb.style.display = 'none';
      return;
    }

    $breadcrumb.style.display = 'flex';
    $breadcrumb.innerHTML = '';

    // Current class (bold, not clickable)
    const current = document.createElement('span');
    current.className = 'breadcrumb-current';
    current.textContent = className;
    $breadcrumb.appendChild(current);

    // Superclasses in order: parent > grandparent > ...
    superClasses.forEach(sc => {
      const sep = document.createElement('span');
      sep.className = 'breadcrumb-separator';
      sep.textContent = '\u203A'; // ›
      $breadcrumb.appendChild(sep);

      const item = document.createElement('span');
      item.className = 'breadcrumb-item';
      item.textContent = sc;
      item.title = 'Navigate to ' + sc;
      item.addEventListener('click', () => {
        vscode.postMessage({ type: 'navigateClass', className: sc });
      });
      $breadcrumb.appendChild(item);
    });
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
    const count = checkedMethods.size;
    $selectionCount.textContent = count + ' selected';
    $btnHook.disabled = count === 0;
  }

  function showError(message) {
    const toast = document.createElement('div');
    toast.className = 'error-toast';
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
  }

  vscode.postMessage({ type: 'ready' });
})();
