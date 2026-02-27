(function () {
  // @ts-ignore
  const vscode = acquireVsCodeApi();

  // Indexed data built from [names, parents] sent by agent
  var names = null;     // string[]
  var parentOf = null;  // number[] — parentOf[i] = parent index, -1 for root
  var children = null;  // number[][] — children[i] = direct subclass indices
  var roots = null;     // number[] — root class indices

  var expandedNodes = new Set(); // set of indices
  var filterDebounce = null;

  var $treeBody = document.getElementById('tree-body');
  var $treeFilter = document.getElementById('tree-filter');
  var $btnExpandAll = document.getElementById('btn-expand-all');
  var $btnCollapseAll = document.getElementById('btn-collapse-all');

  window.addEventListener('message', function (event) {
    var msg = event.data;
    switch (msg.type) {
      case 'setData':
        buildFromFlat(msg.names, msg.parents);
        for (var i = 0; i < roots.length; i++) expandedNodes.add(roots[i]);
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

  $treeFilter.addEventListener('input', function () {
    clearTimeout(filterDebounce);
    filterDebounce = setTimeout(renderTree, 150);
  });

  $btnExpandAll.addEventListener('click', function () {
    if (!names) return;
    for (var i = 0; i < names.length; i++) {
      if (children[i].length > 0) expandedNodes.add(i);
    }
    renderTree();
  });

  $btnCollapseAll.addEventListener('click', function () {
    expandedNodes.clear();
    renderTree();
  });

  function buildFromFlat(n, parents) {
    names = n;
    parentOf = parents;
    children = new Array(names.length);
    for (var i = 0; i < names.length; i++) children[i] = [];
    roots = [];
    for (var i = 0; i < names.length; i++) {
      if (parents[i] === -1) {
        roots.push(i);
      } else {
        children[parents[i]].push(i);
      }
    }
  }

  function renderTree() {
    if (!names) return;
    var query = $treeFilter.value.toLowerCase();
    $treeBody.innerHTML = '';
    var fragment = document.createDocumentFragment();
    if (query) {
      var visible = findMatching(query);
      renderFiltered(fragment, roots, 0, visible);
    } else {
      renderNodes(fragment, roots, 0);
    }
    $treeBody.appendChild(fragment);
  }

  function findMatching(query) {
    var visible = new Set();
    for (var i = 0; i < names.length; i++) {
      if (names[i].toLowerCase().includes(query)) {
        // Mark this node and all its ancestors
        var idx = i;
        while (idx !== -1 && !visible.has(idx)) {
          visible.add(idx);
          idx = parentOf[idx];
        }
      }
    }
    return visible;
  }

  function sortedByName(indices) {
    return indices.slice().sort(function (a, b) {
      return names[a] < names[b] ? -1 : names[a] > names[b] ? 1 : 0;
    });
  }

  function renderFiltered(container, indices, depth, visible) {
    var sorted = sortedByName(indices.filter(function (i) { return visible.has(i); }));
    for (var j = 0; j < sorted.length; j++) {
      var i = sorted[j];
      var childCount = children[i].length;
      var isLeaf = childCount === 0;
      container.appendChild(createRow(i, depth, isLeaf, true, childCount));
      if (!isLeaf) renderFiltered(container, children[i], depth + 1, visible);
    }
  }

  function renderNodes(container, indices, depth) {
    var sorted = sortedByName(indices);
    for (var j = 0; j < sorted.length; j++) {
      var i = sorted[j];
      var childCount = children[i].length;
      var isLeaf = childCount === 0;
      var expanded = expandedNodes.has(i);
      container.appendChild(createRow(i, depth, isLeaf, expanded, childCount));
      if (expanded && !isLeaf) {
        renderNodes(container, children[i], depth + 1);
      }
    }
  }

  function createRow(idx, depth, isLeaf, expanded, childCount) {
    var row = document.createElement('div');
    row.className = 'tree-node' + (isLeaf ? ' tree-leaf' : '');

    var inner = document.createElement('div');
    inner.className = 'tree-row';

    var indent = document.createElement('span');
    indent.className = 'tree-indent';
    indent.style.width = (depth * 16) + 'px';

    var toggle = document.createElement('span');
    toggle.className = 'tree-toggle';
    if (!isLeaf) toggle.textContent = expanded ? '\u25BC' : '\u25B6';

    var label = document.createElement('span');
    label.className = 'tree-label';
    label.textContent = names[idx];

    inner.appendChild(indent);
    inner.appendChild(toggle);
    inner.appendChild(label);

    if (!isLeaf && childCount > 0) {
      var count = document.createElement('span');
      count.className = 'tree-count';
      count.textContent = '(' + childCount + ')';
      inner.appendChild(count);
    }

    if (!isLeaf) {
      (function (i) {
        inner.addEventListener('click', function () {
          if (expandedNodes.has(i)) expandedNodes.delete(i);
          else expandedNodes.add(i);
          renderTree();
        });
      })(idx);
    }

    row.appendChild(inner);
    return row;
  }

  function showError(message) {
    var toast = document.createElement('div');
    toast.className = 'error-toast';
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(function () { toast.remove(); }, 5000);
  }

  vscode.postMessage({ type: 'ready' });
})();
