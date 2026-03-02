(function () {
  // @ts-ignore
  const vscode = acquireVsCodeApi();

  // Indexed data built from Record<string, string> sent by agent
  let names = null;     // string[]
  let parentOf = null;  // number[] — parentOf[i] = parent index, -1 for root
  let children = null;  // number[][] — children[i] = direct subclass indices
  let roots = null;     // number[] — root class indices

  let expandedNodes = new Set(); // set of indices
  let filterDebounce = null;

  const $treeBody = document.getElementById('tree-body');
  const $treeFilter = document.getElementById('tree-filter');
  const $btnExpandAll = document.getElementById('btn-expand-all');
  const $btnCollapseAll = document.getElementById('btn-collapse-all');

  window.addEventListener('message', (event) => {
    const msg = event.data;
    switch (msg.type) {
      case 'setData':
        buildFromRecord(msg.hierarchy);
        for (let i = 0; i < roots.length; i++) expandedNodes.add(roots[i]);
        renderTree();
        break;
      case 'setLoading':
        if (msg.loading) {
          $treeBody.innerHTML = '<div class="loading">Loading Objective-C class hierarchy...</div>';
        }
        break;
      case 'error':
        showError(msg.message);
        break;
    }
  });

  $treeFilter.addEventListener('input', () => {
    clearTimeout(filterDebounce);
    filterDebounce = setTimeout(renderTree, 150);
  });

  $btnExpandAll.addEventListener('click', () => {
    if (!names) return;
    for (let i = 0; i < names.length; i++) {
      if (children[i].length > 0) expandedNodes.add(i);
    }
    renderTree();
  });

  $btnCollapseAll.addEventListener('click', () => {
    expandedNodes.clear();
    renderTree();
  });

  function buildFromRecord(hierarchy) {
    names = Object.keys(hierarchy);
    const indexMap = {};
    for (let i = 0; i < names.length; i++) indexMap[names[i]] = i;
    parentOf = new Array(names.length);
    children = new Array(names.length);
    for (let i = 0; i < names.length; i++) children[i] = [];
    roots = [];
    for (let i = 0; i < names.length; i++) {
      const parent = hierarchy[names[i]];
      if (parent && parent in indexMap) {
        parentOf[i] = indexMap[parent];
        children[parentOf[i]].push(i);
      } else {
        parentOf[i] = -1;
        roots.push(i);
      }
    }
  }

  function renderTree() {
    if (!names) return;
    const query = $treeFilter.value.toLowerCase();
    $treeBody.innerHTML = '';
    const fragment = document.createDocumentFragment();
    if (query) {
      const visible = findMatching(query);
      renderFiltered(fragment, roots, 0, visible);
    } else {
      renderNodes(fragment, roots, 0);
    }
    $treeBody.appendChild(fragment);
  }

  function findMatching(query) {
    const visible = new Set();
    for (let i = 0; i < names.length; i++) {
      if (names[i].toLowerCase().includes(query)) {
        // Mark this node and all its ancestors
        let idx = i;
        while (idx !== -1 && !visible.has(idx)) {
          visible.add(idx);
          idx = parentOf[idx];
        }
      }
    }
    return visible;
  }

  function sortedByName(indices) {
    return indices.slice().sort((a, b) => {
      return names[a] < names[b] ? -1 : names[a] > names[b] ? 1 : 0;
    });
  }

  function renderFiltered(container, indices, depth, visible) {
    const sorted = sortedByName(indices.filter((i) => visible.has(i)));
    for (let j = 0; j < sorted.length; j++) {
      const i = sorted[j];
      const childCount = children[i].length;
      const isLeaf = childCount === 0;
      container.appendChild(createRow(i, depth, isLeaf, true, childCount));
      if (!isLeaf) renderFiltered(container, children[i], depth + 1, visible);
    }
  }

  function renderNodes(container, indices, depth) {
    const sorted = sortedByName(indices);
    for (let j = 0; j < sorted.length; j++) {
      const i = sorted[j];
      const childCount = children[i].length;
      const isLeaf = childCount === 0;
      const expanded = expandedNodes.has(i);
      container.appendChild(createRow(i, depth, isLeaf, expanded, childCount));
      if (expanded && !isLeaf) {
        renderNodes(container, children[i], depth + 1);
      }
    }
  }

  function createRow(idx, depth, isLeaf, expanded, childCount) {
    const row = document.createElement('div');
    row.className = 'tree-node' + (isLeaf ? ' tree-leaf' : '');

    const inner = document.createElement('div');
    inner.className = 'tree-row';

    const indent = document.createElement('span');
    indent.className = 'tree-indent';
    indent.style.width = (depth * 16) + 'px';

    const toggle = document.createElement('span');
    toggle.className = 'tree-toggle';
    if (!isLeaf) toggle.textContent = expanded ? '\u25BC' : '\u25B6';

    const label = document.createElement('span');
    label.className = 'tree-label';
    label.textContent = names[idx];

    inner.appendChild(indent);
    inner.appendChild(toggle);
    inner.appendChild(label);

    if (!isLeaf && childCount > 0) {
      const count = document.createElement('span');
      count.className = 'tree-count';
      count.textContent = '(' + childCount + ')';
      inner.appendChild(count);
    }

    if (!isLeaf) {
      inner.addEventListener('click', () => {
        if (expandedNodes.has(idx)) expandedNodes.delete(idx);
        else expandedNodes.add(idx);
        renderTree();
      });
    }

    row.appendChild(inner);
    return row;
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
