// Убедимся, что ENVIRONMENT определен до использования
if (typeof window.ENVIRONMENT === 'undefined') {
    window.ENVIRONMENT = 'production';
}

document.addEventListener('DOMContentLoaded', () => {
    const app = document.getElementById('app');
    const loader = document.getElementById('loader');

    if (!app || !loader) {
        console.error('Не найден элемент #app или #loader');
        return;
    }

    let currentPage = 'home';
    let isNavigationInProgress = false;

    const csrfMetaTag = document.querySelector('meta[name="csrf_token"]');
    let csrfToken = csrfMetaTag ? csrfMetaTag.content : '';

    loadPage(currentPage);

    document.addEventListener('click', async (e) => {
        const pageBtn = e.target.closest('[data-page]');
        const logoutBtn = e.target.closest('.logout-btn');

        if (pageBtn && !isNavigationInProgress) {
            e.preventDefault();
            const targetPage = pageBtn.dataset.page;
            if (targetPage !== currentPage) {
                currentPage = targetPage;
                await loadPage(targetPage);
            }
        }

        if (logoutBtn) {
            e.preventDefault();
            await handleLogout();
        }
    });

    async function loadPage(page) {
        if (isNavigationInProgress) return;
        isNavigationInProgress = true;

        try {
            showLoader();

            const response = await fetch(`ajax.php?page=${encodeURIComponent(page)}&r=${Date.now()}`, {
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept': 'text/html',
                    'X-CSRF-Token': csrfToken
                }
            });

            if (!response.ok) {
                throw await handleErrorResponse(response);
            }

            const newToken = response.headers.get('X-CSRF-Token');
            if (newToken) updateCsrfToken(newToken);

            const content = await response.text();
            app.innerHTML = content;

        } catch (error) {
            console.error('Ошибка загрузки:', error);
            showError(error);
            if (error.isAuthError) await redirectToLogin();
        } finally {
            hideLoader();
            isNavigationInProgress = false;
        }
    }

    async function handleLogout() {
        if (isNavigationInProgress) return;
        isNavigationInProgress = true;

        try {
            showLoader();

            const response = await fetch('logout.php', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-CSRF-Token': csrfToken
                },
                body: `csrf_token=${encodeURIComponent(csrfToken)}`
            });

            if (!response.ok) {
                throw new Error('Ошибка при выходе');
            }

            window.location.href = 'login.php';

        } catch (error) {
            console.error('Ошибка выхода:', error);
            showError(error);
        } finally {
            hideLoader();
            isNavigationInProgress = false;
        }
    }

    async function handleErrorResponse(response) {
        const error = new Error();

        switch (response.status) {
            case 401:
                error.message = 'Требуется авторизация';
                error.isAuthError = true;
                break;
            case 403:
                error.message = 'Доступ запрещен';
                error.isAuthError = true;
                break;
            case 500:
                error.message = 'Ошибка сервера';
                break;
            default:
                error.message = `Ошибка загрузки: ${response.status}`;
        }

        try {
            const data = await response.json();
            if (data.error) error.message = data.error;
            if (data.details) error.details = data.details;
        } catch (e) {
            // Не JSON-ответ
        }

        return error;
    }

    function updateCsrfToken(newToken) {
        csrfToken = newToken;
        let meta = document.querySelector('meta[name="csrf_token"]');
        if (!meta) {
            meta = document.createElement('meta');
            meta.name = 'csrf_token';
            document.head.appendChild(meta);
        }
        meta.content = newToken;
    }

    function showError(error) {
        const errorHtml = `
            <div class="error">
                <h3>❌ ${error.message}</h3>
                ${ENVIRONMENT === 'development' && error.details ? `<pre>${JSON.stringify(error.details, null, 2)}</pre>` : ''}
                <button class="btn retry-btn">Повторить</button>
            </div>
        `;

        app.innerHTML = errorHtml;

        const retryBtn = app.querySelector('.retry-btn');
        if (retryBtn) {
            retryBtn.addEventListener('click', () => {
                loadPage(currentPage);
            });
        }
    }

    async function redirectToLogin() {
        sessionStorage.setItem('returnUrl', window.location.href);
        window.location.href = 'login.php';
    }

    function showLoader() {
        loader.style.display = 'flex';
        app.style.opacity = '0.5';
        app.style.pointerEvents = 'none';
    }

    function hideLoader() {
        loader.style.display = 'none';
        app.style.opacity = '1';
        app.style.pointerEvents = 'auto';
    }
});