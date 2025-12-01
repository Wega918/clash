<?php
// Включаем отображение ошибок (только для разработки)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
$start = microtime(true);

session_start(); // нужно до доступа к $_SESSION

header('Content-Type: text/html; charset=utf-8');
header('X-XSS-Protection: 1; mode=block'); // опционально, устарел
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN'); // или DENY если не планируешь iframe
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Cache-Control: no-cache, must-revalidate');
header('Expires: 0');
header('Pragma: no-cache');
header('Referrer-Policy: no-referrer-when-downgrade');


// Логирование для отладки (только в dev-среде)
if (defined('ENVIRONMENT') && ENVIRONMENT === 'development') {
    error_log("===== AJAX Request =====");
    error_log("Time: ".date('Y-m-d H:i:s'));
    error_log("GET: ".print_r($_GET, true));
    error_log("SESSION: ".print_r($_SESSION, true));
}

// Настройки безопасности
define('ENVIRONMENT', 'production'); // 'development' или 'production'
define('DB_HOST', 'localhost');
define('DB_USER', 'oksiv92_clash');
define('DB_PASS', 'jeJeQLj8QkkF1');
define('DB_NAME', 'oksiv92_clash');
define('MAX_LOGIN_ATTEMPTS', 5);
define('RESOURCE_UPDATE_INTERVAL', 5); // секунд

// Инициализация ошибок

ini_set('error_log', __DIR__ . '/../logs/php_errors.log');

// Подключение к БД с обработкой ошибок
try {
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($mysqli->connect_errno) {
        throw new RuntimeException('DB connection failed: ' . $mysqli->connect_error);
    }
    $mysqli->set_charset("utf8mb4");
} catch (Exception $e) {
    error_log('Database error: ' . $e->getMessage());
    http_response_code(500);
    die('System temporarily unavailable');
}


// ------------------ ФУНКЦИИ БЕЗОПАСНОСТИ ------------------

/**
 * Очистка и обрезка строки
 * @param string $str Входная строка
 * @param int $max_length Максимальная длина (по умолчанию 255)
 * @return string Очищенная строка
 */
function cleanString($str, $max_length = 255) {
    if (!is_string($str)) {
        return '';
    }
    
    $str = trim($str);
    $str = htmlspecialchars($str, ENT_QUOTES | ENT_HTML5, 'UTF-8', true);
    return mb_substr($str, 0, $max_length, 'UTF-8');
}

/**
 * Безопасное преобразование в целое число с проверкой диапазона
 * @param mixed $val Входное значение
 * @param int $min Минимальное значение
 * @param int $max Максимальное значение
 * @return int Проверенное целое число
 */
function toInt($val, $min = 0, $max = PHP_INT_MAX) {
    $options = [
        'options' => [
            'min_range' => $min,
            'max_range' => $max
        ],
        'flags' => FILTER_NULL_ON_FAILURE
    ];
    
    $result = filter_var($val, FILTER_VALIDATE_INT, $options);
    return $result !== null ? $result : 0;
}

/**
 * Проверка аутентификации пользователя
 * @return bool True если пользователь аутентифицирован
 */
function isLoggedIn() {
    return !empty($_SESSION['user_id']) && 
           !empty($_SESSION['user_ip']) && 
           !empty($_SESSION['user_agent']) &&
           $_SESSION['user_ip'] === $_SERVER['REMOTE_ADDR'] &&
           $_SESSION['user_agent'] === ($_SERVER['HTTP_USER_AGENT'] ?? '');
}

/**
 * Генерация CSRF токена
 * @return string Токен
 * @throws RuntimeException Если невозможно сгенерировать токен
 */
function generateCsrfToken() {
    if (empty($_SESSION['csrf_token'])) {
        try {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['csrf_token_time'] = time();
        } catch (Exception $e) {
            throw new RuntimeException('Ошибка генерации CSRF токена');
        }
    }
    return $_SESSION['csrf_token'];
}

/**
 * Валидация CSRF токена
 * @param string $token Токен для проверки
 * @param int $timeout Время жизни токена в секундах (по умолчанию 3600)
 * @return bool Результат проверки
 */
function validateCsrfToken($token, $timeout = 3600) {
    if (empty($_SESSION['csrf_token']) || 
        empty($_SESSION['csrf_token_time'])) {
        return false;
    }
    
    // Проверка времени жизни токена
    if (time() - $_SESSION['csrf_token_time'] > $timeout) {
        unset($_SESSION['csrf_token'], $_SESSION['csrf_token_time']);
        return false;
    }
    
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Генерация HTML-поля с CSRF токеном
 * @return string HTML-код input элемента
 */
function csrfInput() {
    $token = generateCsrfToken();
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token, ENT_QUOTES) . '">';
}

/**
 * Проверка CSRF токена в POST запросе
 * @throws RuntimeException Если токен недействителен
 */
function verifyCsrfPost() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $token = $_POST['csrf_token'] ?? '';
        if (!validateCsrfToken($token)) {
            throw new RuntimeException('Недействительный CSRF токен');
        }
    }
}

/**
 * Проверка CSRF токена для AJAX запросов
 * @throws RuntimeException Если токен недействителен
 */
function verifyCsrfAjax() {
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
        strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
        $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!validateCsrfToken($token)) {
            throw new RuntimeException('Недействительный CSRF токен (AJAX)');
        }
    }
}
// ------------------ ФУНКЦИИ ПОЛЬЗОВАТЕЛЯ ------------------
function getUser($mysqli) {
    // Проверка авторизации
if (!isLoggedIn()) {
    error_log('Unauthorized access attempt. IP: '.$_SERVER['REMOTE_ADDR']);

    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
        strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
        throw new RuntimeException('Требуется авторизация', 401);
    }

    header('Location: login.php');
    exit;
}

    static $cached_user = null;
    $user_id = (int)$_SESSION['user_id'];

// Проверка кэша (только если есть данные и ID совпадает)
if ($cached_user !== null && 
    isset($cached_user['id']) && 
    $cached_user['id'] === $user_id &&
    (time() - ($cached_user['last_cache_update'] ?? 0)) < RESOURCE_UPDATE_INTERVAL
) {
    return $cached_user;
}
    try {
        // Подготовка запроса
        $stmt = $mysqli->prepare("SELECT id, login, gold, elixir, townhall_lvl, last_update FROM users WHERE id = ?");
        if ($stmt === false) {
            throw new RuntimeException('Prepare failed: '.$mysqli->error);
        }

        // Привязка параметров
        if (!$stmt->bind_param("i", $user_id)) {
            throw new RuntimeException('Bind failed: '.$stmt->error);
        }

        // Выполнение запроса
        if (!$stmt->execute()) {
            throw new RuntimeException('Execute failed: '.$stmt->error);
        }

        // Получение результата
        $result = $stmt->get_result();
        if ($result === false) {
            throw new RuntimeException('Get result failed: '.$stmt->error);
        }

        $user = $result->fetch_assoc();
        $stmt->close();

        // Проверка наличия пользователя
        if (empty($user)) {
            error_log("User not found in DB. ID: $user_id, SESSION: ".json_encode($_SESSION));
            logout(); // Функция должна сделать редирект
        }

        // Проверка обязательных полей
        $required = ['id', 'login', 'gold', 'elixir', 'townhall_lvl', 'last_update'];
        foreach ($required as $field) {
            if (!array_key_exists($field, $user)) {
                throw new RuntimeException("Missing required field in user data: $field");
            }
        }

        // Обновление ресурсов
        $user = updateResources($user, $mysqli);
        $user['last_cache_update'] = time();
        $cached_user = $user;

        return $user;

    } catch (Exception $e) {
        error_log("Error in getUser(): ".$e->getMessage()."\nStack trace: ".$e->getTraceAsString());
        
        // Если есть валидные кэшированные данные - вернём их
        if ($cached_user !== null && isset($cached_user['id']) && $cached_user['id'] === $user_id) {
            return $cached_user;
        }

        // Для AJAX-запросов - выбрасываем исключение
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
            throw $e;
        }
        
        // Для обычных запросов - перенаправляем на страницу ошибки
        header('Location: error.php?code=user_data_error');
        exit;
    }
}

function updateResources($user, $mysqli) {
    $defaults = [
        'gold' => 0,
        'elixir' => 0,
        'townhall_lvl' => 1,
        'last_update' => time()
    ];
    $user = array_merge($defaults, $user);

    $now = time();
    if ($now <= $user['last_update']) return $user;

    $seconds = $now - $user['last_update'];
    $gold_gain = min(floor($seconds * 1), 1000000 - $user['gold']);
    $elixir_gain = min(floor($seconds * 0.5), 1000000 - $user['elixir']);

    $stmt = $mysqli->prepare("UPDATE users SET gold=gold+?, elixir=elixir+?, last_update=? WHERE id=?");
    $stmt->bind_param("iiii", $gold_gain, $elixir_gain, $now, $user['id']);
    $stmt->execute();
    $stmt->close();

    $user['gold'] += $gold_gain;
    $user['elixir'] += $elixir_gain;
    $user['last_update'] = $now;

    return $user;
}

function logout() {
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    session_destroy();
    header('Location: login.php');
    exit;
}

// ------------------ АУТЕНТИФИКАЦИЯ ------------------

function registerUser($mysqli, $login, $password) {
    if (strlen($password) < 8) {
        throw new InvalidArgumentException('Password too short');
    }

    $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    $stmt = $mysqli->prepare("INSERT INTO users (login, password) VALUES (?, ?)");
    $stmt->bind_param("ss", $login, $hash);
    return $stmt->execute();
}

function verifyLogin($mysqli, $login, $password) {
    static $attempts = [];
    $ip = $_SERVER['REMOTE_ADDR'];
    $key = md5($login.$ip);

    if (($attempts[$key] ?? 0) >= MAX_LOGIN_ATTEMPTS) {
        sleep(($attempts[$key] - MAX_LOGIN_ATTEMPTS + 1) * 2);
        throw new RuntimeException('Too many attempts');
    }

    $stmt = $mysqli->prepare("SELECT id, password FROM users WHERE login = ?");
    $stmt->bind_param("s", $login);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$user || !password_verify($password, $user['password'])) {
        $attempts[$key] = ($attempts[$key] ?? 0) + 1;
        throw new RuntimeException('Invalid credentials');
    }

    $_SESSION['user_id'] = $user['id'];
    $_SESSION['user_ip'] = $ip;
    session_regenerate_id(true);
    
    return true;
}

// ------------------ УТИЛИТЫ ------------------

function logError($message, $context = []) {
    $log = date('[Y-m-d H:i:s]') . ' ' . strip_tags($message);
    if ($context) {
        $log .= ' ' . json_encode($context);
    }
    file_put_contents(__DIR__.'/../logs/security.log', $log.PHP_EOL, FILE_APPEND);
}

function isPasswordStrong($password) {
    return preg_match('/^(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[^\w\d\s:])([^\s]){8,}$/', $password);
}

function generatePassword($length = 12) {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_-=+';
    $password = '';
    $max = strlen($chars) - 1;
    
    for ($i = 0; $i < $length; $i++) {
        $password .= $chars[random_int(0, $max)];
    }
    
    return $password;
}








// ------------------ ОБРАБОТКА ОШИБОК ------------------
/**
 * Логирование в файл
 * @param string $message Сообщение для логирования
 */
function logToFile(string $message) {
    $logFile = __DIR__ . '/../logs/system.log';
    $date = date('[Y-m-d H:i:s]');
    file_put_contents($logFile, "$date $message\n", FILE_APPEND);
}


/**
 * Универсальный обработчик ошибок
 * @param Throwable $e Исключение или ошибка
 * @param bool $isAjax Флаг AJAX-запроса
 */
function handleError(Throwable $e, bool $isAjax = false): void {
    $code = $e->getCode() ?: 500;
    http_response_code($code);

    $errorData = [
        'message' => $e->getMessage(),
        'code' => $code,
    ];

    if (defined('ENVIRONMENT') && ENVIRONMENT === 'development') {
        $errorData['file'] = $e->getFile();
        $errorData['line'] = $e->getLine();
        $errorData['trace'] = $e->getTrace();
    }

    if (function_exists('logToFile')) {
        logToFile("ERROR: " . json_encode($errorData));
    }

    if ($isAjax || (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest')) {
        header('Content-Type: application/json');
        die(json_encode(['error' => $errorData['message']]));
    }

    if ($code === 401) {
        header('Location: login.php');
        exit;
    }

    $message = (defined('ENVIRONMENT') && ENVIRONMENT === 'development')
        ? '<pre>' . print_r($errorData, true) . '</pre>'
        : 'Произошла ошибка. Пожалуйста, попробуйте позже.';

    die('<div class="error">' . $message . '</div>');
}


// ------------------ БЕЗОПАСНОСТЬ ------------------

/**
 * Проверка CSRF токена
 * @param string $token Токен для проверки
 * @return bool Результат проверки
 */
function check_csrf(string $token): bool {
    return isset($_SESSION['csrf_token']) && 
           hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Защита от брутфорса
 * @param string $login Логин пользователя
 * @return bool Превышено ли количество попыток
 */
function isBruteforceAttempt(string $login): bool {
    global $mysqli;
    
    $stmt = $mysqli->prepare("SELECT login_attempts, last_attempt FROM users WHERE login = ?");
    $stmt->bind_param("s", $login);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    
    return $result && 
           $result['login_attempts'] >= 5 && 
           time() - strtotime($result['last_attempt']) < 60;
}

/**
 * Логирование неудачной попытки входа
 * @param string $login Логин пользователя
 */
function logFailedLoginAttempt(string $login) {
    global $mysqli;
    
    $stmt = $mysqli->prepare("UPDATE users SET 
        login_attempts = IF(last_attempt < DATE_SUB(NOW(), INTERVAL 1 HOUR), 1, login_attempts + 1),
        last_attempt = NOW()
        WHERE login = ?");
    $stmt->bind_param("s", $login);
    $stmt->execute();
    $stmt->close();
}

/**
 * Сброс счетчика попыток входа
 * @param int $user_id ID пользователя
 */
function resetLoginAttempts(int $user_id) {
    global $mysqli;
    
    $stmt = $mysqli->prepare("UPDATE users SET login_attempts = 0 WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $stmt->close();
}

// ------------------ УТИЛИТЫ ------------------

/**
 * Получение базового URL сайта
 * @return string Базовый URL
 */
function getBaseUrl(): string {
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
    return $protocol . $_SERVER['HTTP_HOST'] . rtrim(dirname($_SERVER['PHP_SELF']), '/\\');
}

/**
 * Подтверждение действия (JS)
 * @param string $message Текст подтверждения
 * @return string JavaScript код
 */
function confirm(string $message): string {
    return 'onclick="return confirm(\'' . addslashes($message) . '\')"';
}
?>