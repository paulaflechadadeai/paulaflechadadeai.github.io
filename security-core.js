/**
 * SCAN-IAS SECURITY CORE v2.0
 * Sistema anti-clonación y verificación de integridad
 */

(function() {
    'use strict';
    
    // ============================================
    // CONFIGURACIÓN DE SEGURIDAD
    // ============================================
    const SECURITY_CONFIG = {
        // Dominios permitidos (ofuscados)
        _d: [
            atob('cGF1bGFmbGVjaGFkYWRlYWkuZ2l0aHViLmlv'), // paulaflechadadeai.github.io
            atob('bG9jYWxob3N0'), // localhost
            atob('MTI3LjAuMC4x')  // 127.0.0.1
        ],
        
        // Clave de verificación (derivada, no hardcodeada completa)
        _k: {
            p1: atob('cGF0'), // pat
            p2: atob('aXRv'), // ito
            p3: atob('MTIz')  // 123
        },
        
        // TTL de sesión (ms)
        sessionTTL: 30 * 60 * 1000, // 30 minutos
        
        // Máximo intentos fallidos
        maxAttempts: 3,
        
        // Delay exponencial entre intentos
        lockoutDelay: 5000
    };

    // ============================================
    // ESTADO DE SEGURIDAD
    // ============================================
    const SecurityState = {
        attempts: parseInt(sessionStorage.getItem('_sa') || '0'),
        locked: sessionStorage.getItem('_sl') === '1',
        sessionStart: parseInt(sessionStorage.getItem('_ss') || '0'),
        verified: false
    };

    // ============================================
    // FUNCIONES DE VERIFICACIÓN
    // ============================================

    /**
     * Verifica el dominio actual contra la whitelist
     */
    function verifyDomain() {
        const currentHost = window.location.hostname;
        const isValid = SECURITY_CONFIG._d.some(domain => {
            // Verificación flexible (subdominios, etc)
            return currentHost === domain || 
                   currentHost.endsWith('.' + domain) ||
                   currentHost.includes(domain);
        });
        
        if (!isValid) {
            triggerSecurityBreach('INVALID_DOMAIN', currentHost);
            return false;
        }
        
        console.log('[SCAN-IAS] Dominio verificado:', currentHost);
        return true;
    }

    /**
     * Verifica la integridad del código (anti-tampering básico)
     */
    function verifyIntegrity() {
        // Verificar que no estamos en un iframe (clickjacking)
        if (window.top !== window.self) {
            triggerSecurityBreach('IFRAME_DETECTED');
            return false;
        }
        
        // Verificar que no estamos en modo incógnito (opcional, paranoia)
        // Esto es difícil de detectar fiablemente, lo omitimos por ahora
        
        return true;
    }

    /**
     * Verifica la clave del editor con rate limiting
     */
    function verifyKey(inputKey) {
        if (SecurityState.locked) {
            const remaining = parseInt(sessionStorage.getItem('_sle') || '0') - Date.now();
            if (remaining > 0) {
                throw new Error(`Sistema bloqueado. Espera ${Math.ceil(remaining/1000)}s`);
            } else {
                // Desbloquear
                SecurityState.locked = false;
                SecurityState.attempts = 0;
                sessionStorage.removeItem('_sl');
                sessionStorage.removeItem('_sle');
            }
        }

        // Reconstruir clave esperada
        const expectedKey = SECURITY_CONFIG._k.p1 + SECURITY_CONFIG._k.p2 + SECURITY_CONFIG._k.p3;
        
        // Comparación segura (timing-safe aproximado)
        let match = true;
        if (inputKey.length !== expectedKey.length) match = false;
        
        for (let i = 0; i < Math.max(inputKey.length, expectedKey.length); i++) {
            if (inputKey[i] !== expectedKey[i]) match = false;
        }
        
        if (!match) {
            SecurityState.attempts++;
            sessionStorage.setItem('_sa', SecurityState.attempts.toString());
            
            if (SecurityState.attempts >= SECURITY_CONFIG.maxAttempts) {
                SecurityState.locked = true;
                const unlockTime = Date.now() + SECURITY_CONFIG.lockoutDelay;
                sessionStorage.setItem('_sl', '1');
                sessionStorage.setItem('_sle', unlockTime.toString());
                throw new Error('Sistema bloqueado por múltiples intentos fallidos');
            }
            
            throw new Error(`Clave incorrecta. Intentos restantes: ${SECURITY_CONFIG.maxAttempts - SecurityState.attempts}`);
        }
        
        // Éxito: resetear intentos y marcar sesión
        SecurityState.attempts = 0;
        SecurityState.verified = true;
        SecurityState.sessionStart = Date.now();
        sessionStorage.removeItem('_sa');
        sessionStorage.setItem('_ss', SecurityState.sessionStart.toString());
        sessionStorage.setItem('_sv', '1');
        
        return true;
    }

    /**
     * Verifica si la sesión sigue válida
     */
    function isSessionValid() {
        if (!sessionStorage.getItem('_sv')) return false;
        
        const start = parseInt(sessionStorage.getItem('_ss') || '0');
        const elapsed = Date.now() - start;
        
        return elapsed < SECURITY_CONFIG.sessionTTL;
    }

    /**
     * Activa modo de seguridad breach
     */
    function triggerSecurityBreach(type, details = '') {
        // Log silencioso (no revelar mucho al atacante)
        console.error('[SECURITY] Breach detectado:', type);
        
        // Enviar alerta silenciosa a tu analytics (opcional)
        if (typeof gtag !== 'undefined') {
            gtag('event', 'security_breach', {
                event_category: 'security',
                event_label: type,
                value: 1
            });
        }
        
        // Destruir datos sensibles en memoria
        wipeSensitiveData();
        
        // Mostrar pantalla de bloqueo
        renderLockScreen(type);
        
        // Prevenir cualquier ejecución posterior
        throw new Error('SECURITY_BREACH: ' + type);
    }

    /**
     * Limpia datos sensibles de memoria
     */
    function wipeSensitiveData() {
        // Limpiar variables globales potenciales
        if (window.PINATA_JWT) window.PINATA_JWT = null;
        if (window.CLAVE_EDITOR) window.CLAVE_EDITOR = null;
        
        // Forzar garbage collection (lo mejor que podemos hacer en JS)
        for (let i = 0; i < 1000; i++) {
            const tmp = new Array(1000).fill(0);
        }
    }

    /**
     * Renderiza pantalla de bloqueo
     */
    function renderLockScreen(reason) {
        document.documentElement.innerHTML = `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>ACCESO DENEGADO</title>
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body {
                        background: #000;
                        color: #0f0;
                        font-family: 'Courier New', monospace;
                        display: flex;
                        flex-direction: column;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        overflow: hidden;
                    }
                    .glitch {
                        font-size: 3em;
                        text-shadow: 2px 0 #f0f, -2px 0 #0ff;
                        animation: glitch 1s infinite;
                        margin-bottom: 20px;
                    }
                    @keyframes glitch {
                        0%, 100% { transform: translate(0); }
                        25% { transform: translate(-2px, 2px); }
                        50% { transform: translate(2px, -2px); }
                    }
                    .code {
                        color: #f00;
                        font-size: 0.8em;
                        margin-top: 20px;
                    }
                    .hexdump {
                        position: absolute;
                        bottom: 0;
                        left: 0;
                        right: 0;
                        font-size: 0.6em;
                        color: #333;
                        word-break: break-all;
                        padding: 10px;
                        opacity: 0.5;
                    }
                </style>
            </head>
            <body>
                <div class="glitch">⚠️ ACCESO DENEGADO ⚠️</div>
                <p>Sistema de seguridad scan-ias activado</p>
                <p class="code">CÓDIGO: ${btoa(reason).slice(0, 20)}...</p>
                <div class="hexdump">${generateHexDump()}</div>
                <script>
                    // Prevenir cualquier interacción
                    document.addEventListener('contextmenu', e => e.preventDefault());
                    document.addEventListener('keydown', e => {
                        if(e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.key === 'I')) {
                            e.preventDefault();
                        }
                    });
                <\/script>
            </body>
            </html>
        `;
        
        // Prevenir navegación
        window.history.pushState(null, '', window.location.href);
        window.onpopstate = function() {
            window.history.pushState(null, '', window.location.href);
        };
    }

    /**
     * Genera hexdump falso para efecto visual
     */
    function generateHexDump() {
        const chars = '0123456789ABCDEF';
        let dump = '';
        for (let i = 0; i < 500; i++) {
            dump += chars[Math.floor(Math.random() * 16)];
            if (i % 2 === 1) dump += ' ';
            if (i % 32 === 31) dump += '<br>';
        }
        return dump;
    }

    // ============================================
    // ANTI-DEBUGGING BÁSICO
    // ============================================
    
    function initAntiDebug() {
        // Detectar DevTools abierto
        const threshold = 160;
        let devtoolsOpen = false;
        
        setInterval(() => {
            const widthThreshold = window.outerWidth - window.innerWidth > threshold;
            const heightThreshold = window.outerHeight - window.innerHeight > threshold;
            
            if (widthThreshold || heightThreshold) {
                if (!devtoolsOpen) {
                    devtoolsOpen = true;
                    console.clear();
                    console.log('%c⚠️ Consola detectada', 'color: red; font-size: 20px;');
                    // No bloqueamos, solo advertimos, puede ser legítimo
                }
            } else {
                devtoolsOpen = false;
            }
        }, 1000);

        // Prevenir debugger statement
        setInterval(() => {
            const start = performance.now();
            debugger;
            const end = performance.now();
            if (end - start > 100) {
                triggerSecurityBreach('DEBUGGER_DETECTED');
            }
        }, 2000);
    }

    // ============================================
    // INICIALIZACIÓN
    // ============================================

    function init() {
        // Verificaciones inmediatas
        if (!verifyDomain()) return;
        if (!verifyIntegrity()) return;
        
        // Iniciar anti-debug en producción
        if (!window.location.hostname.includes('localhost')) {
            initAntiDebug();
        }
        
        // Exponer API segura
        window.ScaniasSecurity = {
            verifyKey: verifyKey,
            isSessionValid: isSessionValid,
            getSessionTime: () => {
                if (!isSessionValid()) return 0;
                return SECURITY_CONFIG.sessionTTL - (Date.now() - SecurityState.sessionStart);
            },
            logout: () => {
                sessionStorage.clear();
                SecurityState.verified = false;
                location.reload();
            },
            // Función para cambiar clave (requiere verificación previa)
            changeKey: (oldKey, newKey) => {
                if (!verifyKey(oldKey)) return false;
                // Aquí implementarías lógica para actualizar la clave
                // Por ahora solo retorna éxito simulado
                console.log('[SECURITY] Clave cambiada (simulado)');
                return true;
            }
        };

        console.log('%c🔒 scan-ias security core inicializado', 'color: #00ff00;');
    }

    // Ejecutar inmediatamente
    init();

})();
