<!DOCTYPE html>
<html lang="ru" class="no-js">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="description" content="Clash Browser">
    <title>Clash Browser</title>
    <link rel="icon" href="favicon.ico" type="image/x-icon">
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<div class="page-glade">
    <?php if (isLoggedIn()): ?>
    <div class="main-frame-left"></div>
    <div class="main-frame-right"></div>
    <div class="game-ui" style="position: fixed;bottom: 94%;left: 1%;z-index: 9999;">
        <button id="btn-sound" title="Включить/выключить звук">🔇</button>
        <button id="btn-fullscreen" title="На весь экран">⛶</button>
        <button id="btn-settings" title="Настройки">⚙️</button>
    </div>

    <style>
    .game-ui button {
        background: rgba(0,0,0,0.6);
        color: white;
        border: none;
        font-size: 11px;
        padding: 8px;
        border-radius: 8px;
        cursor: pointer;
        transition: background 0.3s;
    }
    .game-ui button:hover {
        background: rgba(0,0,0,0.8);
    }
    </style>

    <script>
    document.addEventListener('DOMContentLoaded', async () => {
        const btnSound = document.getElementById('btn-sound');
        const btnFullscreen = document.getElementById('btn-fullscreen');
        const btnSettings = document.getElementById('btn-settings');

        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        let buffer = null;
        let source = null;
        const gainNode = audioCtx.createGain();
        let soundOn = localStorage.getItem('music-sound-on') || 'true';

        btnSound.textContent = soundOn === 'true' ? '🔊' : '🔇';

        const response = await fetch('home_music.mp3');
        const arrayBuffer = await response.arrayBuffer();
        buffer = await audioCtx.decodeAudioData(arrayBuffer);

        function play() {
            if (source) source.stop();
            source = audioCtx.createBufferSource();
            source.buffer = buffer;
            source.loop = true;
            gainNode.gain.value = soundOn === 'true' ? 0.3 : 0;
            source.connect(gainNode).connect(audioCtx.destination);
            source.start();
        }

        async function resumeCtx() {
            if (audioCtx.state === 'suspended') {
                await audioCtx.resume();
            }
        }

        async function init() {
            if (audioCtx.state === 'suspended') {
                const unlock = async () => {
                    await resumeCtx();
                    play();
                    document.body.removeEventListener('click', unlock);
                    document.body.removeEventListener('keydown', unlock);
                };
                document.body.addEventListener('click', unlock, { once: true });
                document.body.addEventListener('keydown', unlock, { once: true });
            } else {
                play();
            }
        }

        btnSound.addEventListener('click', () => {
            if (soundOn === 'true') {
                gainNode.gain.value = 0;
                soundOn = 'false';
                btnSound.textContent = '🔇';
            } else {
                gainNode.gain.value = 0.3;
                soundOn = 'true';
                btnSound.textContent = '🔊';
            }
            localStorage.setItem('music-sound-on', soundOn);
        });

        btnFullscreen.addEventListener('click', () => {
            if (!document.fullscreenElement) {
                document.documentElement.requestFullscreen();
            } else {
                document.exitFullscreen();
            }
        });

        btnSettings.addEventListener('click', () => {
            alert('Окно настроек (здесь можно сделать меню)');
        });

        let previousVolume = gainNode.gain.value;
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                previousVolume = gainNode.gain.value;
                gainNode.gain.value = 0;
            } else {
                if (soundOn === 'true') {
                    gainNode.gain.value = previousVolume || 0.3;
                }
            }
        });

        init();

    });
    </script>

    <div class="glade-board top"></div>

    <div class="balance-indicators">
        <div class="balance-row">
            <div class="balance gold">
                <div class="balance-bar" style="width: 70%;"></div>
                <div class="balance-text">12,300</div>
                <img src="/images/icons/gold.png" alt="Gold">
            </div>
            <div class="balance fuel">
                <div class="balance-bar" style="width: 40%;"></div>
                <div class="balance-text">9,500</div>
                <img src="/images/icons/fuel.png" alt="Fuel">
            </div>
        </div>
        <div class="balance-row">
            <div class="balance elixir">
                <div class="balance-bar" style="width: 55%;"></div>
                <div class="balance-text">6,000</div>
                <img src="/images/icons/elixir.png" alt="Elixir">
            </div>
            <div class="balance gems">
                <div class="balance-bar" style="width: 20%;"></div>
                <div class="balance-text">1,200</div>
                <img src="/images/icons/gems.png" alt="Gems">
            </div>
        </div>
    </div>

    <div class="glade-board bottom">
        <div class="player-left">
            <div class="level-box">
                <img src="/images/icons/xp_icon.png" alt="Уровень" class="level-icon">
                <span class="level-number">65</span>
            </div>
            <div class="level-progress">
                <div class="level-fill" style="width: 65%;"></div>
            </div>
        </div>
        <button class="battle-button">В БОЙ!</button>
        <div class="player-right">
            <div class="trophy-progress">
                <img src="/images/league/no_league.png" alt="Лига" class="league-icon">
                <span class="trophy-count" style="position: relative; z-index: 1;">1850</span>
            </div>
            <div class="trophy-box">
                <img src="/images/icons/trophy_icon.png" alt="Кубок" class="trophy-icon">
            </div>
        </div>
    </div>

    <div class="page-decorations">
        <img src="/images/diz/left-top.png" class="tree left-top" alt="">
    </div>
    <?php endif; ?>

    <script>
    function showBuildingModal(buildingType) {
        const modal = document.getElementById(buildingType + '-modal');
        if (!modal) {
            console.error('Модальное окно не найдено: ' + buildingType + '-modal');
            return;
        }
        modal.classList.add('active');
    }

    function hideModal(modalId) {
        const modal = document.getElementById(modalId);
        if (!modal) {
            console.error('Модальное окно не найдено: ' + modalId);
            return;
        }
        modal.classList.remove('active');
    }

    window.addEventListener('click', function(event) {
        if (event.target.classList.contains('modal-overlay')) {
            event.target.classList.remove('active');
        }
    });
    </script>
