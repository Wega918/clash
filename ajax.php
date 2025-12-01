<?php
require_once 'system/function.php';

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Установка окружения (если не задано)
if (!defined('ENVIRONMENT')) {
    define('ENVIRONMENT', 'production');
}

// Проверка необходимых функций и переменных
if (!function_exists('isLoggedIn')) {
    die(json_encode(['error' => 'Функция isLoggedIn не определена']));
}
if (!function_exists('getUser')) {
    die(json_encode(['error' => 'Функция getUser не определена']));
}
if (!isset($mysqli)) {
    die(json_encode(['error' => '$mysqli не определена']));
}

// Безопасная инициализация сессии
$sessionParams = [
    'lifetime' => 86400,
    'path' => '/',
    'domain' => $_SERVER['HTTP_HOST'],
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'httponly' => true,
    'samesite' => 'Strict'
];

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params($sessionParams);
    session_start();
}

// Инициализация CSRF токена
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

try {
    // Проверка метода запроса и CSRF токена
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && !check_csrf($_POST['csrf_token'] ?? '')) {
        throw new RuntimeException('Недействительный CSRF токен', 403);
    }

    // Проверка авторизации
    if (!isLoggedIn()) {
        throw new RuntimeException('Требуется авторизация', 401);
    }

    // Получение данных пользователя
    $user = getUser($mysqli);
    if (empty($user['id'])) {
        throw new RuntimeException('Данные пользователя недействительны', 403);
    }

    // Подготовка данных
    $userData = [
        'login' => cleanString($user['login'] ?? 'Гость'),
        'gold' => toInt($user['gold'] ?? 0),
        'elixir' => toInt($user['elixir'] ?? 0),
        'townhall_lvl' => toInt($user['townhall_lvl'] ?? 1, 1, 20),
        'csrf_token' => $_SESSION['csrf_token']
    ];

    // Валидация страницы
    $allowedPages = ['home', 'buildings', 'army'];
    $page = $_GET['page'] ?? 'home';
    if (!in_array($page, $allowedPages)) {
        $page = 'home';
    }

    // Генерация контента
    $content = generatePageContent($page, $userData);

    // Отправка CSRF токена в заголовке
    header('X-CSRF-Token: ' . $_SESSION['csrf_token']);
    echo $content;

} catch (Throwable $e) {
    handleError($e, true); // Включаем AJAX-режим
}

/**
 * Генерирует HTML-содержимое страницы
 */
function generatePageContent(string $page, array $userData): string {
    ob_start();
    
	
	?>
<?
switch ($page) {
case 'home':
?>

  <!-- Центрированный контент -->
  <div class="page-wrapper">

<div class="village-map">
  <!-- Здания с обработчиками кликов -->
<div class="building" style="top: 16%;left: 65%;transform: rotate(0deg);" onclick="showBuildingModal('production')">
    <div class="building-label">Производство</div>
    <img src="/images/building/production.png" alt="Производство">
    <div class="building-shadow"></div>
  </div>

<div class="building" style="top: 5%;right: 63%;transform: rotate(0deg);" onclick="showBuildingModal('storage')">
    <div class="building-label">Хранилища</div>
    <img src="/images/building/storage.png" alt="Хранилища">
    <div class="building-shadow"></div>
  </div>

<div class="building" style="top: 41%;right: 54%;transform: rotate(0deg);" onclick="showBuildingModal('townhall')">
    <div class="building-label">Ратуша</div>
    <img src="https://support.supercell.com/images/icon_CoC_Account_v1.png?v=1669362208" alt="Ратуша">
    
  </div>

<div class="building mirror" style="top: 39.47%;left: 66%;transform: rotate(1deg);" onclick="showBuildingModal('barracks')">
    <div class="building-label">Казармы</div>
    <img src="/images/building/barracks.png" alt="Казармы">
  </div>

<div class="building mirror" style="top: 19%;left: 44%;transform: translateX(-50%) rotate(0deg);" onclick="showBuildingModal('defense')">
    <div class="building-label">Оборона</div>
    <img src="/images/building/defense.png" alt="Оборона">
    <div class="building-shadow"></div>
  </div>

<div class="building mirror" style="bottom: 25%;left: 75%;transform: rotate(0deg);" onclick="showBuildingModal('lab')">
    <div class="building-label">Лаборатория</div>
    <img src="/images/building/lab.png" alt="Лаборатория">
  </div>

<div class="building" style="bottom: 17%;left: 15%;transform: translateX(-50%) rotate(-1deg);" onclick="showBuildingModal('clan')">
    <div class="building-label">Клановая крепость</div>
    <img src="/images/building/clan.png" alt="Клановая крепость">
    <div class="building-shadow"></div>
  </div>
</div>


<!-- Модальные окна для каждого здания -->
<div id="production-modal" class="modal-overlay">
  <div class="modal-content">
    <button class="close-modal" onclick="hideModal('production-modal')">×</button>
    <h2>Производство</h2>
    <p>Здесь вы можете управлять производством ресурсов.</p>
    <p>Доступные улучшения:</p>
    <ul>
      <li>Золотой рудник (уровень 3)</li>
      <li>Эликсирный колодец (уровень 2)</li>
    </ul>
  </div>
</div>

<div id="storage-modal" class="modal-overlay">
  <div class="modal-content">
    <button class="close-modal" onclick="hideModal('storage-modal')">×</button>
    <h2>Хранилища</h2>
    <p>Здесь хранятся ваши ресурсы.</p>
    <p>Текущие запасы:</p>
    <ul>
      <li>Золото: <?= $userData['gold'] ?></li>
      <li>Эликсир: <?= $userData['elixir'] ?></li>
    </ul>
  </div>
</div>

<div id="townhall-modal" class="modal-overlay">
  <div class="modal-content">
    <button class="close-modal" onclick="hideModal('townhall-modal')">×</button>
    <h2>Ратуша</h2>
    <p>🏛 Ратуша: уровень <?= $userData['townhall_lvl'] ?></p>
    <p>Это главное здание вашей деревни. Улучшение ратуши открывает новые возможности.</p>
  </div>
</div>

<div id="barracks-modal" class="modal-overlay">
  <div class="modal-content">
    <button class="close-modal" onclick="hideModal('barracks-modal')">×</button>
    <h2>Казармы</h2>
    <p>Здесь вы тренируете войска.</p>
    <p>Доступные юниты:</p>
    <ul>
      <li>Воины (уровень 1)</li>
      <li>Лучники (уровень 1)</li>
    </ul>
  </div>
</div>

<div id="defense-modal" class="modal-overlay">
  <div class="modal-content">
    <button class="close-modal" onclick="hideModal('defense-modal')">×</button>
    <h2>Оборона</h2>
    <p>Здания защиты вашей деревни.</p>
    <p>Доступные защиты:</p>
    <ul>
      <li>Пушка (уровень 2)</li>
      <li>Арбалет (уровень 1)</li>
    </ul>
  </div>
</div>

<div id="lab-modal" class="modal-overlay">
  <div class="modal-content">
    <button class="close-modal" onclick="hideModal('lab-modal')">×</button>
    <h2>Лаборатория</h2>
    <p>Здесь вы улучшаете свои войска и заклинания.</p>
    <p>Доступные исследования:</p>
    <ul>
      <li>Улучшение воинов</li>
      <li>Улучшение лучников</li>
    </ul>
  </div>
</div>

<div id="clan-modal" class="modal-overlay">
  <div class="modal-content">
    <button class="close-modal" onclick="hideModal('clan-modal')">×</button>
    <h2>Клановая крепость</h2>
    <p>Здесь вы можете вступить в клан или создать свой.</p>
    <p>Текущий клан: Нет</p>
  </div>
</div>


</div>

<?php
            break;
    }

    return ob_get_clean();
}