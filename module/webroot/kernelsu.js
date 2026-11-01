// 基于 KernelSU 官方 npm 包规范实现的零构建依赖 ES Module 桥接器
let callbackCounter = 0;

function getUniqueCallbackName(prefix) {
    callbackCounter += 1;
    return `${prefix}_cb_${Date.now()}_${callbackCounter}`;
}

export function exec(command, options = {}) {
    return new Promise((resolve) => {
        if (typeof window.ksu === 'undefined' || typeof window.ksu.exec !== 'function') {
            resolve({
                errno: 127,
                stdout: '',
                stderr: '当前环境未检测到 KernelSU WebUI JavaScript Bridge (window.ksu)'
            });
            return;
        }

        const cbName = getUniqueCallbackName('ksu_exec');
        window[cbName] = (errno, stdout, stderr) => {
            delete window[cbName];
            resolve({
                errno: Number(errno),
                stdout: stdout || '',
                stderr: stderr || ''
            });
        };

        try {
            window.ksu.exec(command, JSON.stringify(options), cbName);
        } catch (err) {
            delete window[cbName];
            resolve({ errno: 1, stdout: '', stderr: String(err) });
        }
    });
}

export function toast(message) {
    if (typeof window.ksu !== 'undefined' && typeof window.ksu.toast === 'function') {
        window.ksu.toast(String(message));
    } else {
        console.log('[Toast]:', message);
    }
}

export function fullScreen(enable) {
    if (typeof window.ksu !== 'undefined' && typeof window.ksu.fullScreen === 'function') {
        window.ksu.fullScreen(Boolean(enable));
    }
}
