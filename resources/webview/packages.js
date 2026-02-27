(function () {
  // @ts-ignore
  const vscode = acquireVsCodeApi();

  let rootNodes = null;
  let expandedNodes = new Set();
  let filterDebounce = null;

  const $treeBody = document.getElementById('tree-body');
  const $treeFilter = document.getElementById('tree-filter');
  const $btnExpandAll = document.getElementById('btn-expand-all');
  const $btnCollapseAll = document.getElementById('btn-collapse-all');

  window.addEventListener('message', (event) => {
    const msg = event.data;
    switch (msg.type) {
      case 'setClasses':
        rootNodes = buildTree(msg.classes);
        initExpanded(rootNodes, 0);
        renderTree();
        break;
      case 'setLoading':
        if (msg.loading) {
          $treeBody.innerHTML = '<div class="loading">Loading classes...</div>';
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
    if (rootNodes) collectAllKeys(rootNodes, expandedNodes);
    renderTree();
  });

  $btnCollapseAll.addEventListener('click', () => {
    expandedNodes.clear();
    renderTree();
  });

  function buildTree(classes) {
    // Build trie
    const trie = {};
    for (const cls of classes) {
      const parts = cls.split('.');
      let node = trie;
      for (const part of parts) {
        if (!node[part]) node[part] = {};
        node = node[part];
      }
    }
    // Merge single-child non-leaf chains
    return mergeNode(trie);
  }

  function mergeNode(node) {
    const result = {};
    for (const key of Object.keys(node)) {
      let mergedKey = key;
      let child = node[key];
      // Merge while child has exactly 1 key and that key is also non-leaf
      while (true) {
        const childKeys = Object.keys(child);
        if (childKeys.length === 1) {
          const onlyKey = childKeys[0];
          const grandchild = child[onlyKey];
          if (Object.keys(grandchild).length > 0) {
            // grandchild is non-leaf, merge
            mergedKey = mergedKey + '.' + onlyKey;
            child = grandchild;
            continue;
          }
        }
        break;
      }
      result[mergedKey] = mergeNode(child);
    }
    return result;
  }

  function initExpanded(node, depth) {
    if (depth < 1) {
      for (const key of Object.keys(node)) {
        expandedNodes.add(key);
      }
    }
  }

  function renderTree() {
    if (!rootNodes) return;

    const query = $treeFilter.value.toLowerCase();
    $treeBody.innerHTML = '';

    if (query) {
      const matching = findMatching(rootNodes, query);
      const fragment = document.createDocumentFragment();
      renderFilteredNodes(fragment, rootNodes, 0, matching);
      $treeBody.appendChild(fragment);
    } else {
      const fragment = document.createDocumentFragment();
      renderNodes(fragment, rootNodes, 0);
      $treeBody.appendChild(fragment);
    }
  }

  function findMatching(node, query) {
    const result = new Set();
    findMatchingHelper(node, query, [], result);
    return result;
  }

  function findMatchingHelper(node, query, ancestors, result) {
    for (const key of Object.keys(node)) {
      if (key.toLowerCase().includes(query)) {
        result.add(key);
        for (const a of ancestors) result.add(a);
      }
      findMatchingHelper(node[key], query, [...ancestors, key], result);
    }
  }

  function renderFilteredNodes(container, node, depth, matching) {
    const keys = Object.keys(node).filter(k => matching.has(k));
    keys.sort();
    for (const key of keys) {
      const children = node[key];
      const childCount = Object.keys(children).length;
      const isLeaf = childCount === 0;

      const row = createRow(key, depth, isLeaf, true, childCount);
      container.appendChild(row);
      renderFilteredNodes(container, children, depth + 1, matching);
    }
  }

  function renderNodes(container, node, depth) {
    const keys = Object.keys(node);
    keys.sort();
    for (const key of keys) {
      const children = node[key];
      const childCount = Object.keys(children).length;
      const isLeaf = childCount === 0;
      const expanded = expandedNodes.has(key);

      const row = createRow(key, depth, isLeaf, expanded, childCount);
      container.appendChild(row);

      if (expanded && !isLeaf) {
        renderNodes(container, children, depth + 1);
      }
    }
  }

  function createRow(name, depth, isLeaf, expanded, childCount) {
    const row = document.createElement('div');
    row.className = 'tree-node' + (isLeaf ? ' tree-leaf' : '');

    const inner = document.createElement('div');
    inner.className = 'tree-row';

    const indent = document.createElement('span');
    indent.className = 'tree-indent';
    indent.style.width = (depth * 16) + 'px';

    const toggle = document.createElement('span');
    toggle.className = 'tree-toggle';
    if (!isLeaf) {
      toggle.textContent = expanded ? '\u25BC' : '\u25B6';
    }

    const label = document.createElement('span');
    label.className = 'tree-label';
    label.textContent = name;

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
        if (expandedNodes.has(name)) {
          expandedNodes.delete(name);
        } else {
          expandedNodes.add(name);
        }
        renderTree();
      });
    }

    row.appendChild(inner);
    return row;
  }

  function collectAllKeys(node, set) {
    for (const key of Object.keys(node)) {
      if (Object.keys(node[key]).length > 0) {
        set.add(key);
        collectAllKeys(node[key], set);
      }
    }
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
