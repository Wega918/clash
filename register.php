<?php
ob_start(); // Включаем буферизацию вывода
require_once 'system/function.php';
require_once 'system/header.php';
// Устанавливаем security-заголовки
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer-when-downgrade');

// Если пользователь уже авторизован - перенаправляем
if (isLoggedIn()) {
    header('Location: /');
    exit;
}

$error = '';
$formData = [
    'login' => '',
    'password' => '',
    'confirm' => ''
];

$turnstile_secret = '0x4AAAAAABgrOxFOs-yAgOChyDd1VllSHcg';
$turnstile_sitekey = '0x4AAAAAABgrOz68iJtS7HNQ';

// Обработка формы регистрации
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
       if (!check_csrf($_POST['csrf_token'] ?? '')) {
            throw new RuntimeException('Недействительный CSRF токен');
        }
        
        // Проверка капчи
        if (empty($_POST['cf-turnstile-response'])) {
            throw new RuntimeException('Пожалуйста, пройдите проверку капчи.');
        }
        
        $token = $_POST['cf-turnstile-response'];
        $remote_ip = $_SERVER['REMOTE_ADDR'];
        
        $response = file_get_contents("https://challenges.cloudflare.com/turnstile/v0/siteverify", false, stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-type: application/x-www-form-urlencoded\r\n",
                'content' => http_build_query([
                    'secret' => $turnstile_secret,
                    'response' => $token,
                    'remoteip' => $remote_ip,
                ]),
            ]
        ]));
        
        if (!$response) {
            throw new RuntimeException('Ошибка проверки капчи');
        }
        
        $result = json_decode($response, true);
        if (empty($result['success']) || $result['success'] !== true) {
            throw new RuntimeException('Неверная капча. Попробуйте снова.');
        }

        // Получение и очистка данных
        $formData['login'] = cleanString($_POST['login'] ?? '');
        $formData['password'] = $_POST['password'] ?? '';
        $formData['confirm'] = $_POST['confirm'] ?? '';

        // Валидация
        if (empty($formData['login']) || empty($formData['password']) || empty($formData['confirm'])) {
            throw new RuntimeException('Все поля обязательны для заполнения');
        }

        if (strlen($formData['login']) < 3 || strlen($formData['login']) > 20) {
            throw new RuntimeException('Логин должен быть от 3 до 20 символов');
        }

        if (!preg_match('/^[a-zA-Z0-9_]+$/', $formData['login'])) {
            throw new RuntimeException('Логин может содержать только латинские буквы, цифры и подчёркивание');
        }

        if (strlen($formData['password']) < 8) {
            throw new RuntimeException('Пароль должен быть не менее 8 символов');
        }

        if (!preg_match('/[A-Z]/', $formData['password']) || 
            !preg_match('/[0-9]/', $formData['password']) || 
            !preg_match('/[^a-zA-Z0-9]/', $formData['password'])) {
            throw new RuntimeException('Пароль должен содержать заглавные буквы, цифры и спецсимволы');
        }

        if ($formData['password'] !== $formData['confirm']) {
            throw new RuntimeException('Пароли не совпадают');
        }

        // Проверка существования пользователя
        $stmt = $mysqli->prepare("SELECT id FROM users WHERE login = ?");
        if (!$stmt) {
            throw new RuntimeException('Ошибка подготовки запроса');
        }
        
        $stmt->bind_param("s", $formData['login']);
        if (!$stmt->execute()) {
            throw new RuntimeException('Ошибка выполнения запроса');
        }
        
        $stmt->store_result();
        
        if ($stmt->num_rows > 0) {
            throw new RuntimeException('Этот логин уже занят');
        }
        $stmt->close();

        // Регистрация пользователя
        $hashed = password_hash($formData['password'], PASSWORD_BCRYPT, ['cost' => 12]);
        
        $stmt = $mysqli->prepare("INSERT INTO users (login, password, gold, elixir, townhall_lvl, last_update) VALUES (?, ?, 500, 200, 1, UNIX_TIMESTAMP())");
        if (!$stmt) {
            throw new RuntimeException('Ошибка подготовки запроса');
        }
        
        $stmt->bind_param("ss", $formData['login'], $hashed);
        
        if (!$stmt->execute()) {
            throw new RuntimeException('Ошибка регистрации пользователя');
        }

        // Автоматический вход после регистрации
        $_SESSION['user_id'] = $stmt->insert_id;
        $_SESSION['user_ip'] = $_SERVER['REMOTE_ADDR'];
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
        session_regenerate_id(true);
        
        $stmt->close();

        // Перенаправление на главную
        header('Location: /');
        exit;
        
    } catch (RuntimeException $e) {
        $error = $e->getMessage();
    }
}
?>
<style>
.page-glade {
    position: fixed;
    top: 0;
    left: 50%;
    transform: translateX(-50%);
    width: 100%;
    max-width: var(--map-width);
    height: 100vh;
    max-height: var(--map-height);
    display: flex;
    z-index: 999;
    align-content: center;
    justify-content: center;
    align-items: center;
    overflow-x: auto; /* горизонтальный скрол только при переполнении */
    overflow-y: auto; /* вертикальный скрол только при переполнении */
}
.page-glade {
    overflow: auto !important;              /* скролл только при переполнении */
    -webkit-overflow-scrolling: touch;      /* плавный скролл на iOS */
    overscroll-behavior: contain;           /* не прокидывать скролл наружу */
}

/* не даём flex-детям сжиматься, иначе переполнения не будет */
.page-glade > * {
    flex: 0 0 auto;
}

</style>




<body>
    <div class="login-container">
       
        <form class="login-form" method="POST" action="<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>" novalidate>
            <?= csrfInput() ?>
            
            <?php if ($error): ?>
                <div class="alert alert-danger" id="error-message">
                    <?= htmlspecialchars($error) ?>
                </div>
                <script>
                    document.getElementById('error-message').classList.add('shake');
                </script>
            <?php endif; ?>
            
            <div class="form-group">
                <label for="login">Логин</label>
                <input type="text" 
                       id="login" 
                       name="login" 
                       class="form-control" 
                       value="<?= htmlspecialchars($formData['login']) ?>" 
                       required
                       minlength="3"
                       maxlength="20"
                       pattern="[a-zA-Z0-9_]+"
                       title="Только латинские буквы, цифры и подчёркивание">
                <small class="form-text">От 3 до 20 символов (латинские буквы, цифры, _)</small>
            </div>
            
            <div class="form-group">
                <label for="password">Пароль</label>
                <input type="password" 
                       id="password" 
                       name="password" 
                       class="form-control" 
                       required
                       minlength="8"
                       oninput="updatePasswordStrength()">
                <div class="password-strength">
                    <div class="password-strength-fill" id="password-strength"></div>
                </div>
                <small class="form-text">Минимум 8 символов: заглавные, цифры, спецсимволы</small>
            </div>
            
            <div class="form-group">
                <label for="confirm">Подтверждение пароля</label>
                <input type="password" 
                       id="confirm" 
                       name="confirm" 
                       class="form-control" 
                       required
                       minlength="8">
            </div>
<center>
<div class="cf-turnstile" data-sitekey="<?= htmlspecialchars($turnstile_sitekey) ?>"></div>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</center>
            <button type="submit" class="btn">
                Зарегистрироваться
            </button>
            
            <div class="register-link">
                Уже есть аккаунт? <a href="login.php">Войти</a>
            </div>
        </form>
    </div>
    
    <script>
        // Функция оценки сложности пароля
        function updatePasswordStrength() {
            const password = document.getElementById('password').value;
            const strengthBar = document.getElementById('password-strength');
            let strength = 0;
            
            // Проверка длины
            if (password.length > 7) strength += 20;
            if (password.length > 11) strength += 20;
            
            // Проверка наличия разных типов символов
            if (/[A-Z]/.test(password)) strength += 20;
            if (/[0-9]/.test(password)) strength += 20;
            if (/[^a-zA-Z0-9]/.test(password)) strength += 20;
            
            // Обновление индикатора
            strengthBar.style.width = strength + '%';
            
            // Изменение цвета в зависимости от сложности
            if (strength < 40) {
                strengthBar.style.backgroundColor = '#ff5722';
            } else if (strength < 80) {
                strengthBar.style.backgroundColor = '#ffc107';
            } else {
                strengthBar.style.backgroundColor = '#4caf50';
            }
        }
        
        // Улучшение UX
        document.addEventListener('DOMContentLoaded', function() {
            // Фокус на поле логина при загрузке
            document.getElementById('login').focus();
            
            // Валидация формы
            document.querySelector('form').addEventListener('submit', function(e) {
                let valid = true;
                
                // Простая валидация на клиенте
                document.querySelectorAll('.form-control').forEach(function(input) {
                    if (!input.value.trim()) {
                        input.style.borderColor = '#e53935';
                        valid = false;
                    }
                });
                
                // Проверка совпадения паролей
                const password = document.getElementById('password').value;
                const confirm = document.getElementById('confirm').value;
                
                if (password !== confirm) {
                    document.getElementById('confirm').style.borderColor = '#e53935';
                    valid = false;
                }
                
                if (!valid) {
                    e.preventDefault();
                }
            });
            
            // Сброс цвета при вводе
            document.querySelectorAll('.form-control').forEach(function(input) {
                input.addEventListener('input', function() {
                    this.style.borderColor = '';
                });
            });
        });
    </script>
</body>
</html>