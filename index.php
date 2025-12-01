<?php
ob_start();
require_once 'system/function.php';
require_once 'system/header.php';

if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

try {
    $user = getUser($mysqli);
    if (!$user || !isset($user['id'])) {
        throw new RuntimeException('Invalid user data');
    }
} catch (Exception $e) {
    error_log('User data error: ' . $e->getMessage());
    header('Location: error.php?code=user_data');
    exit;
}

$csrf_token = generateCsrfToken();
?>

<!-- Стили для лоадера и прогресс-бара с процентами -->
<style>
#loader {
    position: fixed;
    top:0; left:0;
    width:100%;
    height:100%;
    background:#1a1a1a;
    display:flex;
    justify-content:center;
    align-items:center;
    flex-direction:column;
    z-index:9999;
    transition: opacity 0.3s ease;
}

#loader.hidden {
    opacity:0;
    pointer-events:none;
}

.loader-spinner {
    width:50px;
    height:50px;
    border:6px solid #444;
    border-top:6px solid #ff4d4d;
    border-radius:50%;
    animation:spin 1s linear infinite;
    margin-bottom:15px;
}

@keyframes spin {0%{transform:rotate(0deg);}100%{transform:rotate(360deg);}}

.loader-bar-container {
    width:250px;
    height:12px;
    background:#333;
    border-radius:6px;
    overflow:hidden;
    margin-bottom:10px;
}

.loader-bar {
    height:100%;
    width:0;
    background:linear-gradient(90deg,#ff4d4d,#ffa500);
    transition:width 0.2s ease;
}

#loader-percent {
    color:#fff;
    font-weight:bold;
}
#app {opacity:0; transition:opacity 0.5s ease;}
</style>

<!-- Лоадер -->
<div id="loader">
    <div class="loader-spinner"></div>
    <div class="loader-bar-container">
        <div class="loader-bar" id="loader-bar"></div>
    </div>
    <div id="loader-percent">0%</div>
</div>


<!-- Основное содержимое -->
<div id="app" style="opacity: 1;margin-top: -10px;"></div>

<script>
window.APP_CONFIG = {
  csrfToken: '<?= $csrf_token ?>',
  userId: <?= (int)($user['id'] ?? 0) ?>,
  environment: '<?= ENVIRONMENT ?>',
  baseUrl: '<?= htmlspecialchars(getBaseUrl()) ?>'
};

document.addEventListener('DOMContentLoaded', () => {
    const loader = document.getElementById('loader');
    const bar = document.getElementById('loader-bar');
    const percent = document.getElementById('loader-percent');
    const app = document.getElementById('app');

    function showLoader() {
        loader.style.display = 'flex';
        bar.style.width = '0%';
        percent.textContent = '0%';
        app.style.opacity = '0.5';
        app.style.pointerEvents = 'none';
    }

    function hideLoader() {
        loader.style.display = 'none';
        app.style.opacity = 1;
        app.style.pointerEvents = 'auto';
    }

    async function loadPageWithProgress(page) {
        showLoader();

        try {
            const response = await fetch(`ajax.php?page=${encodeURIComponent(page)}&r=${Date.now()}`, {
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-Token': window.APP_CONFIG.csrfToken
                }
            });

            if (!response.ok) throw new Error(`Ошибка загрузки: ${response.status}`);

            const reader = response.body.getReader();
            const contentLength = +response.headers.get('Content-Length') || 0;
            let receivedLength = 0;
            let chunks = [];

            while(true){
                const {done, value} = await reader.read();
                if(done) break;
                chunks.push(value);
                receivedLength += value.length;

                // Прогресс в процентах
                let progress = contentLength ? Math.floor(receivedLength / contentLength * 100) : Math.min(percentFromChunks(chunks), 95);
                bar.style.width = progress + '%';
                percent.textContent = progress + '%';
            }

            const chunksAll = new Uint8Array(receivedLength);
            let position = 0;
            for(let chunk of chunks){
                chunksAll.set(chunk, position);
                position += chunk.length;
            }

            const html = new TextDecoder("utf-8").decode(chunksAll);
            app.innerHTML = html;

            // Достигли 100%
            bar.style.width = '100%';
            percent.textContent = '100%';

        } catch(e){
            console.error(e);
            app.innerHTML = `<div style="color:red">Ошибка загрузки: ${e.message}</div>`;
        } finally {
            setTimeout(hideLoader, 300); // плавно скрываем
        }
    }

    function percentFromChunks(chunks){
        // если нет Content-Length, приблизительно считаем прогресс
        const maxChunks = 10;
        let prog = Math.min(chunks.length/maxChunks*100, 95);
        return Math.floor(prog);
    }

    // Загружаем главную страницу деревни
    loadPageWithProgress('home');
});
</script>

<!-- Подключаем обычный main.js для дальнейших кликов и логики -->
<script src="main.js?v=<?= filemtime('main.js') ?>"></script>
