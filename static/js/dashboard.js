(function() {
    var list = document.getElementById('sortableList');
    if (!list) return;

    var csrfToken = list.dataset.csrfToken;
    var dragItem = null;
    var startY = 0;
    var rects = [];

    list.onmousedown = function(e) {
        var el = e.target;
        while (el && el !== list) {
            if (el.classList && el.classList.contains('sortable-handle')) {
                e.preventDefault();
                var item = el.closest('.sortable-item');
                if (item) startDrag(e, item);
                return;
            }
            el = el.parentNode;
        }
    };

    function getItems() {
        return Array.prototype.slice.call(list.querySelectorAll('.sortable-item'));
    }

    function startDrag(e, item) {
        dragItem = item;
        startY = e.clientY;

        var items = getItems();
        rects = [];
        for (var i = 0; i < items.length; i++) {
            var r = items[i].getBoundingClientRect();
            rects.push({ el: items[i], top: r.top, height: r.height });
        }

        dragItem.style.background = 'var(--bg-secondary)';
        dragItem.style.zIndex = '10';
        dragItem.style.boxShadow = '0 4px 16px rgba(0,0,0,0.3)';
        dragItem.style.position = 'relative';

        for (var i = 0; i < items.length; i++) {
            if (items[i] !== dragItem) {
                items[i].style.transition = 'transform 0.15s ease';
            }
        }

        document.onmousemove = onDrag;
        document.onmouseup = endDrag;
    }

    function onDrag(e) {
        if (!dragItem) return;
        e.preventDefault();

        var delta = e.clientY - startY;
        dragItem.style.transform = 'translateY(' + delta + 'px)';

        var dragIdx = -1;
        for (var i = 0; i < rects.length; i++) {
            if (rects[i].el === dragItem) { dragIdx = i; break; }
        }

        var dragCenter = rects[dragIdx].top + rects[dragIdx].height / 2 + delta;

        for (var i = 0; i < rects.length; i++) {
            if (i === dragIdx) continue;
            var center = rects[i].top + rects[i].height / 2;

            if (dragIdx < i && dragCenter > center) {
                rects[i].el.style.transform = 'translateY(-' + rects[dragIdx].height + 'px)';
            } else if (dragIdx > i && dragCenter < center) {
                rects[i].el.style.transform = 'translateY(' + rects[dragIdx].height + 'px)';
            } else {
                rects[i].el.style.transform = '';
            }
        }
    }

    function endDrag() {
        if (!dragItem) return;

        var delta = document.onmousemove ? (parseInt(dragItem.style.transform.replace(/[^-\d]/g,'')) || 0) : 0;
        var dragIdx = -1;
        for (var i = 0; i < rects.length; i++) {
            if (rects[i].el === dragItem) { dragIdx = i; break; }
        }
        var dragCenter = rects[dragIdx].top + rects[dragIdx].height / 2 + delta;

        var newIdx = dragIdx;
        for (var i = 0; i < rects.length; i++) {
            if (i === dragIdx) continue;
            var center = rects[i].top + rects[i].height / 2;
            if (dragIdx < i && dragCenter > center) newIdx = i;
            if (dragIdx > i && dragCenter < center && newIdx >= dragIdx) newIdx = i;
        }

        for (var i = 0; i < rects.length; i++) {
            rects[i].el.style.transform = '';
            rects[i].el.style.transition = '';
        }
        dragItem.style.background = '';
        dragItem.style.zIndex = '';
        dragItem.style.boxShadow = '';
        dragItem.style.position = '';

        var items = getItems();
        if (newIdx > dragIdx) {
            list.insertBefore(dragItem, items[newIdx].nextSibling);
        } else if (newIdx < dragIdx) {
            list.insertBefore(dragItem, items[newIdx]);
        }

        dragItem = null;
        rects = [];
        document.onmousemove = null;
        document.onmouseup = null;

        var ids = [];
        var all = list.querySelectorAll('.sortable-item');
        for (var i = 0; i < all.length; i++) ids.push(all[i].dataset.id);
        fetch('/admin/reorder', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({ order: ids })
        });
    }

    // Delete confirmation (replaces inline onsubmit)
    document.querySelectorAll('.delete-form').forEach(function(form) {
        form.addEventListener('submit', function(e) {
            if (!confirm('Delete this post?')) {
                e.preventDefault();
            }
        });
    });
})();
