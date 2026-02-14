// Theme Toggle
(function() {
    const html = document.documentElement;
    const stored = localStorage.getItem('theme');
    if (stored) {
        html.setAttribute('data-theme', stored);
    }

    document.querySelector('.theme-toggle')?.addEventListener('click', function() {
        const current = html.getAttribute('data-theme');
        const next = current === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', next);
        localStorage.setItem('theme', next);
    });
})();

// Search Overlay
(function() {
    const overlay = document.getElementById('searchOverlay');
    const input = document.getElementById('searchInput');
    const toggle = document.querySelector('.search-toggle');
    const close = document.getElementById('searchClose');

    if (!overlay || !toggle) return;

    toggle.addEventListener('click', function() {
        overlay.classList.add('active');
        setTimeout(() => input?.focus(), 100);
    });

    close?.addEventListener('click', function() {
        overlay.classList.remove('active');
    });

    overlay.addEventListener('click', function(e) {
        if (e.target === overlay) {
            overlay.classList.remove('active');
        }
    });

    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            overlay.classList.remove('active');
        }
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            overlay.classList.add('active');
            setTimeout(() => input?.focus(), 100);
        }
    });
})();

// Syntax Highlighting
hljs.highlightAll();

// --- SPA Navigation (Slide Transition) ---
(function() {
    const SLIDE_OUT_MS = 250;
    const SLIDE_IN_MS = 300;
    let lastUrl = location.href;
    let isNavigating = false;

    function isInternalLink(a) {
        if (!a || !a.href) return false;
        if (a.target === '_blank') return false;
        if (a.hasAttribute('download')) return false;
        if (a.pathname.startsWith('/admin')) return false;
        return a.origin === location.origin;
    }

    // Determine slide direction based on navigation type
    function getDirection(currentUrl, targetUrl) {
        // Pagination: older = slide left, newer = slide right
        const a = document.querySelector(`a[href="${new URL(targetUrl).pathname}"]`);
        if (a) {
            if (a.classList.contains('older')) return 'left';
            if (a.classList.contains('newer')) return 'right';
        }
        // Post detail: slide left (forward), back: slide right
        return 'left';
    }

    function swapContent(html, push, url, direction) {
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');

        const newTitle = doc.querySelector('title')?.textContent || document.title;
        const newHeader = doc.querySelector('.site-header, .post-header, .tag-header');
        const newMain = doc.querySelector('.main-content');

        if (!newMain) {
            location.href = url;
            return;
        }

        const header = document.querySelector('.site-header, .post-header, .tag-header');
        const main = document.querySelector('.main-content');
        const slideOut = direction === 'left' ? '-60px' : '60px';
        const slideIn = direction === 'left' ? '60px' : '-60px';

        // Slide out current content
        main.style.transition = `opacity ${SLIDE_OUT_MS}ms ease, transform ${SLIDE_OUT_MS}ms ease`;
        main.style.opacity = '0';
        main.style.transform = `translateX(${slideOut})`;
        if (header) {
            header.style.transition = `opacity ${SLIDE_OUT_MS}ms ease`;
            header.style.opacity = '0';
        }

        setTimeout(() => {
            // Swap title
            document.title = newTitle;

            // Swap header
            if (header && newHeader) {
                header.replaceWith(newHeader);
                newHeader.style.opacity = '1';
            } else if (!header && newHeader) {
                const nav = document.querySelector('.nav-header');
                if (nav) nav.after(newHeader);
                newHeader.style.opacity = '1';
            } else if (header && !newHeader) {
                header.remove();
            }

            // Prepare slide in: position off-screen from opposite side
            main.style.transition = 'none';
            main.style.transform = `translateX(${slideIn})`;
            main.style.opacity = '0';

            // Swap main content (use DOM methods instead of innerHTML to prevent DOM XSS)
            main.replaceChildren(...newMain.childNodes);

            // Force reflow
            void main.offsetHeight;

            // Slide in new content
            main.style.transition = `opacity ${SLIDE_IN_MS}ms ease, transform ${SLIDE_IN_MS}ms ease`;
            main.style.opacity = '1';
            main.style.transform = 'translateX(0)';

            // Re-run syntax highlighting
            main.querySelectorAll('pre code').forEach(block => {
                hljs.highlightElement(block);
            });

            // Push history
            if (push) {
                history.pushState({ direction }, '', url);
            }

            // Scroll to top
            window.scrollTo({ top: 0, behavior: 'instant' });

            setTimeout(() => {
                isNavigating = false;
            }, SLIDE_IN_MS);
        }, SLIDE_OUT_MS);
    }

    async function navigateTo(url, push, direction) {
        if (isNavigating) return;
        isNavigating = true;
        try {
            const resp = await fetch(url);
            if (!resp.ok) {
                location.href = url;
                return;
            }
            const html = await resp.text();
            swapContent(html, push, url, direction);
            lastUrl = url;
        } catch (e) {
            location.href = url;
        }
    }

    // Intercept clicks on internal links
    document.addEventListener('click', function(e) {
        const a = e.target.closest('a');
        if (!a) return;
        if (!isInternalLink(a)) return;
        if (e.ctrlKey || e.metaKey || e.shiftKey) return;

        e.preventDefault();
        const direction = getDirection(location.href, a.href);
        navigateTo(a.href, true, direction);
    });

    // Handle browser back/forward
    window.addEventListener('popstate', function() {
        navigateTo(location.href, false, 'right');
    });
})();
