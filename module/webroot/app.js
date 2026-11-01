import { exec, toast } from './kernelsu.js';

constMOD_ID = 'cacerts_bind_manager';
const CTL_SCRIPT = `/data/adb/modules/${MOD_ID}/scripts/cert_ctl.sh`;

let allCerts = [];
let currentFilter = 'all';
let selectedCert = null;
let bindMountEnabled = true;

// Base64 编解码工具（支持 UTF-8）
function utf8ToBase64(str) {
    return btoa(unescape(encodeURIComponent(str)));
}

// 轻量级 MD5 实现（用于计算 OpenSSL subject_hash_old）
function md5Bytes(bytes) {
    function rotl(x, n) { return (x << n) | (x >>> (32 - n)); }
    const K = new Uint32Array(64);
    for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296);
    const S = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ];
    const origLen = bytes.length;
    const bitLen = origLen * 8;
    const padLen = ((56 - (origLen + 1) % 64) + 64) % 64;
    const buf = new Uint8Array(origLen + 1 + padLen + 8);
    buf.set(bytes);
    buf[origLen] = 0x80;
    const view = new DataView(buf.buffer);
    view.setUint32(buf.length - 8, bitLen >>> 0, true);
    view.setUint32(buf.length - 4, Math.floor(bitLen / 4294967296), true);

    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    for (let offset = 0; offset < buf.length; offset += 64) {
        let A = a0, B = b0, C = c0, D = d0;
        for (let i = 0; i < 64; i++) {
            let F, g;
            if (i < 16) { F = (B & C) | (~B & D); g = i; }
            else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
            else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
            else { F = C ^ (B | ~D); g = (7 * i) % 16; }
            const temp = D;
            D = C;
            C = B;
            const word = view.getUint32(offset + g * 4, true);
            B = (B + rotl((A + F + K[i] + word) >>> 0, S[i])) >>> 0;
            A = temp;
        }
        a0 = (a0 + A) >>> 0;
        b0 = (b0 + B) >>> 0;
        c0 = (c0 + C) >>> 0;
        d0 = (d0 + D) >>> 0;
    }
    return a0.toString(16).padStart(8, '0');
}

// 解析 ASN.1 节点辅助函数
function readAsn1Node(bytes, offset) {
    const start = offset;
    const tag = bytes[offset++];
    let len = bytes[offset++];
    if (len & 0x80) {
        const nBytes = len & 0x7f;
        len = 0;
        for (let i = 0; i < nBytes; i++) len = (len << 8) | bytes[offset++];
    }
    return {
        tag,
        headerLen: offset - start,
        contentOffset: offset,
        length: len,
        totalLen: (offset - start) + len,
        raw: bytes.subarray(start, offset + len),
        content: bytes.subarray(offset, offset + len)
    };
}

// 从 PEM 证书中解析 Subject / Issuer / 有效期 与 OpenSSL subject_hash_old
function parseX509Pem(pemText) {
    const info = { subject: '未知机构', issuer: '未知颁发者', expiry: '未知', oldHash: '' };
    const subjMatch = pemText.match(/Subject:\s*(.+)/i);
    const issuerMatch = pemText.match(/Issuer:\s*(.+)/i);
    const afterMatch = pemText.match(/Not After\s*:\s*(.+)/i);
    if (subjMatch) info.subject = subjMatch[1].trim();
    if (issuerMatch) info.issuer = issuerMatch[1].trim();
    if (afterMatch) info.expiry = afterMatch[1].trim();

    const b64Match = pemText.match(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/);
    if (!b64Match) return info;

    try {
        const binStr = atob(b64Match[1].replace(/\s+/g, ''));
        const der = new Uint8Array(binStr.length);
        for (let i = 0; i < binStr.length; i++) der[i] = binStr.charCodeAt(i);

        const certSeq = readAsn1Node(der, 0);
        const tbsCert = readAsn1Node(der, certSeq.contentOffset);
        let ptr = tbsCert.contentOffset;

        // 跳过可选的 version [0] 与 serialNumber
        if (der[ptr] === 0xa0) ptr += readAsn1Node(der, ptr).totalLen;
        ptr += readAsn1Node(der, ptr).totalLen; // serialNumber
        ptr += readAsn1Node(der, ptr).totalLen; // signature
        const issuerNode = readAsn1Node(der, ptr);
        ptr += issuerNode.totalLen;
        const validityNode = readAsn1Node(der, ptr);
        ptr += validityNode.totalLen;
        const subjectNode = readAsn1Node(der, ptr);

        // OpenSSL subject_hash_old 直接对 Subject Name 的完整 ASN.1 SEQUENCE (含 Tag+Len) 计算 MD5 前 4 字节小端序
        info.oldHash = md5Bytes(subjectNode.raw);

        // 提取可读文本字段作为后备展示
        const decodeReadable = (buf) => {
            const texts = [];
            for (let i = 0; i < buf.length - 2; i++) {
                if ((buf[i] === 0x0c || buf[i] === 0x13 || buf[i] === 0x16) && buf[i + 1] > 1 && buf[i + 1] < 80) {
                    const l = buf[i + 1];
                    if (i + 2 + l <= buf.length) {
                        const str = new TextDecoder().decode(buf.subarray(i + 2, i + 2 + l));
                        if (/^[\x20-\x7E\u4e00-\u9fa5]+$/.test(str)) texts.push(str);
                        i += 1 + l;
                    }
                }
            }
            return texts.join(' / ');
        };

        if (info.subject === '未知机构') info.subject = decodeReadable(subjectNode.content) || 'X.509 Certificate';
        if (info.issuer === '未知颁发者') info.issuer = decodeReadable(issuerNode.content) || info.subject;
        if (info.expiry === '未知') {
            const vNode1 = readAsn1Node(validityNode.content, 0);
            const vNode2 = readAsn1Node(validityNode.content, vNode1.totalLen);
            const rawDate = new TextDecoder().decode(vNode2.content);
            if (rawDate.length >= 12) {
                const yr = rawDate.length === 13 ? '20' + rawDate.slice(0, 2) : rawDate.slice(0, 4);
                const rest = rawDate.length === 13 ? rawDate.slice(2) : rawDate.slice(4);
                info.expiry = `${yr}-${rest.slice(0, 2)}-${rest.slice(2, 4)}`;
            }
        }
    } catch (e) {
        console.warn('X509 parse fallback:', e);
    }
    return info;
}

async function loadDashboard() {
    const statusRes = await exec(`sh "${CTL_SCRIPT}" status`);
    if (statusRes.errno !== 0) {
        toast(`读取模块状态失败: ${statusRes.stderr}`);
        return;
    }

    const kv = {};
    statusRes.stdout.split('\n').forEach((line) => {
        const idx = line.indexOf('=');
        if (idx > 0) kv[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    });

    bindMountEnabled = kv.BIND_MOUNT !== 'false';
    document.getElementById('toggleBindMount').checked = bindMountEnabled;
    document.getElementById('managerBadge').textContent = kv.ROOT_MANAGER || 'Root Environment';
    document.getElementById('statTargetDir').textContent = kv.TARGET_DIR || '--';
    document.getElementById('envSubtitle').textContent =
        kv.TARGET_DIR && kv.TARGET_DIR.includes('/apex')
            ? '已识别 Android 14+ Conscrypt APEX 证书目录'
            : '已识别传统 /system 系统证书目录';

    if (bindMountEnabled) {
        document.getElementById('mountModeTitle').textContent = '内置 Bind Mount 引擎 (运行中)';
        document.getElementById('mountModeDesc').textContent =
            `skip_mount: ${kv.SKIP_MOUNT === 'true' ? '已启用' : '未启用'} · 目录挂载状态: ${kv.DIR_MOUNTED === 'true' ? '已挂载' : '未挂载'}`;
        document.getElementById('statVerifyMethod').textContent = 'Inode 严格比对';
    } else {
        document.getElementById('mountModeTitle').textContent = '已交由 Root 管理器接管';
        document.getElementById('mountModeDesc').textContent =
            '已移除 skip_mount 并同步至模块 system 目录，重启后由管理器挂载';
        document.getElementById('statVerifyMethod').textContent = '文件大小比对 (Bytes)';
    }

    document.getElementById('statCounts').textContent =
        `${kv.TOTAL_ACTIVE || 0} / ${kv.TOTAL_CUSTOM || 0} / ${kv.TOTAL_DELETED || 0}`;

    await loadCertificates();
}

async function loadCertificates() {
    const listEl = document.getElementById('certList');
    listEl.innerHTML = '<div class="empty-state">正在读取并逐个比对证书 Inode / 大小...</div>';

    const res = await exec(`sh "${CTL_SCRIPT}" list_certs`);
    if (res.errno !== 0) {
        listEl.innerHTML = `<div class="empty-state">加载失败: ${res.stderr}</div>`;
        return;
    }

    allCerts = [];
    const lines = res.stdout.split('\n').filter((l) => l.startsWith('CERT_ITEM|'));
    for (const line of lines) {
        // CERT_ITEM|fname|type|installed|method|srcVal|dstVal|subjLine
        const parts = line.split('|');
        allCerts.push({
            fname: parts[1],
            type: parts[2], // stock | custom | modified | deleted
            installed: parts[3] === 'true',
            method: parts[4], // inode | size
            srcVal: parts[5],
            dstVal: parts[6],
            subjHint: parts.slice(7).join('|') || '点击查看并解析 X.509 证书详情'
        });
    }

    renderCertList();
}

function renderCertList() {
    const listEl = document.getElementById('certList');
    const keyword = document.getElementById('searchInput').value.trim().toLowerCase();

    const filtered = allCerts.filter((c) => {
        if (currentFilter === 'custom' && c.type !== 'custom' && c.type !== 'modified') return false;
        if (currentFilter === 'stock' && c.type !== 'stock') return false;
        if (currentFilter === 'deleted' && c.type !== 'deleted') return false;
        if (currentFilter === 'unmounted' && (c.type === 'deleted' || c.installed)) return false;
        if (keyword && !c.fname.toLowerCase().includes(keyword) && !c.subjHint.toLowerCase().includes(keyword)) {
            return false;
        }
        return true;
    });

    if (filtered.length === 0) {
        listEl.innerHTML = '<div class="empty-state">没有匹配的证书条目</div>';
        return;
    }

    const typeLabels = {
        stock: ['系统原厂', 'tag-stock'],
        custom: ['用户新增', 'tag-custom'],
        modified: ['已修改覆盖', 'tag-modified'],
        deleted: ['已屏蔽', 'tag-deleted']
    };

    listEl.innerHTML = filtered
        .map((c) => {
            const [tName, tClass] = typeLabels[c.type] || ['未知', 'tag-stock'];
            let verifyHtml = '';
            if (c.type === 'deleted') {
                verifyHtml = `<span class="verify-pill pill-muted">已卸载屏蔽</span>`;
            } else if (c.installed) {
                const label = c.method === 'inode' ? `Inode: ${c.dstVal} ✓` : `Size: ${c.dstVal}B ✓`;
                verifyHtml = `<span class="verify-pill pill-ok">${label}</span>`;
            } else {
                const label = c.method === 'inode' ? `Inode 不匹配` : `大小不匹配`;
                verifyHtml = `<span class="verify-pill pill-warn">⚠ ${label}</span>`;
            }

            return `
            <div class="cert-card" data-fname="${c.fname}">
                <div class="cert-main">
                    <div class="cert-title-row">
                        <span class="cert-hash mono">${c.fname}</span>
                        <span class="type-tag ${tClass}">${tName}</span>
                    </div>
                    <div class="cert-subj">${c.subjHint}</div>
                </div>
                ${verifyHtml}
            </div>`;
        })
        .join('');

    listEl.querySelectorAll('.cert-card').forEach((card) => {
        card.addEventListener('click', () => openCertDetail(card.dataset.fname));
    });
}

async function openCertDetail(fname) {
    selectedCert = allCerts.find((c) => c.fname === fname);
    if (!selectedCert) return;

    const modal = document.getElementById('detailModal');
    modal.classList.remove('hidden');
    document.getElementById('modalCertHash').textContent = fname;
    document.getElementById('detailPemTextarea').value = '正在读取证书原文...';

    const badge = document.getElementById('modalVerifyBadge');
    if (selectedCert.type === 'deleted') {
        badge.className = 'verify-pill pill-muted';
        badge.textContent = '已从挂载目录中屏蔽';
    } else if (selectedCert.installed) {
        badge.className = 'verify-pill pill-ok';
        badge.textContent = selectedCert.method === 'inode' ? '已安装 (Inode 校验一致)' : '已安装 (文件大小一致)';
    } else {
        badge.className = 'verify-pill pill-warn';
        badge.textContent = '未生效 (源与目标不匹配)';
    }

    const proofLabel =
        selectedCert.method === 'inode'
            ? `源 Inode: ${selectedCert.srcVal} / 目标 Inode: ${selectedCert.dstVal}`
            : `源大小: ${selectedCert.srcVal} B / 目标大小: ${selectedCert.dstVal} B`;
    document.getElementById('detailProof').textContent = proofLabel;

    // 控制恢复原厂按钮显隐
    const restoreBtn = document.getElementById('btnRestoreCert');
    if (selectedCert.type === 'modified' || selectedCert.type === 'deleted') {
        restoreBtn.classList.remove('hidden');
    } else {
        restoreBtn.classList.add('hidden');
    }

    const res = await exec(`sh "${CTL_SCRIPT}" get_cert "${fname}"`);
    const content = res.stdout || '';
    document.getElementById('detailPemTextarea').value = content;

    const parsed = parseX509Pem(content);
    document.getElementById('detailSubject').textContent = parsed.subject;
    document.getElementById('detailIssuer').textContent = parsed.issuer;
    document.getElementById('detailExpiry').textContent = parsed.expiry;
    selectedCert.subjHint = parsed.subject;
}

// 绑定事件监听
document.getElementById('btnRefresh').addEventListener('click', () => {
    toast('正在刷新证书挂载状态...');
    loadDashboard();
});

document.getElementById('btnRemount').addEventListener('click', async () => {
    const res = await exec(`sh "${CTL_SCRIPT}" remount`);
    if (res.errno === 0) {
        toast('已重新挂载并更新证书工作区');
        loadDashboard();
    } else {
        toast(`重载失败: ${res.stderr}`);
    }
});

document.getElementById('toggleBindMount').addEventListener('change', async (e) => {
    const enable = e.target.checked;
    const res = await exec(`sh "${CTL_SCRIPT}" set_bind_mode ${enable ? 'true' : 'false'}`);
    if (res.errno === 0) {
        toast(
            enable
                ? '已切换为内置 Bind Mount 模式并恢复 skip_mount'
                : '已关闭内置挂载，证书已同步至模块 system 目录交由管理器接管'
        );
        loadDashboard();
    } else {
        toast(`切换失败: ${res.stderr}`);
        e.target.checked = !enable;
    }
});

document.getElementById('searchInput').addEventListener('input', renderCertList);

document.getElementById('filterTabs').addEventListener('click', (e) => {
    const btn = e.target.closest('.tab');
    if (!btn) return;
    document.querySelectorAll('#filterTabs .tab').forEach((t) => t.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.filter;
    renderCertList();
});

document.getElementById('btnCloseDetail').addEventListener('click', () => {
    document.getElementById('detailModal').classList.add('hidden');
});

document.getElementById('btnSaveCert').addEventListener('click', async () => {
    if (!selectedCert) return;
    const newContent = document.getElementById('detailPemTextarea').value.trim();
    if (!newContent.includes('-----BEGIN CERTIFICATE-----')) {
        toast('证书内容必须包含有效的 -----BEGIN CERTIFICATE----- 块');
        return;
    }
    const b64 = utf8ToBase64(newContent + '\n');
    const res = await exec(`sh "${CTL_SCRIPT}" save_cert "${selectedCert.fname}" "${b64}"`);
    if (res.errno === 0) {
        toast(`已保存并挂载 ${selectedCert.fname}`);
        document.getElementById('detailModal').classList.add('hidden');
        loadDashboard();
    } else {
        toast(`保存失败: ${res.stderr}`);
    }
});

document.getElementById('btnDeleteCert').addEventListener('click', async () => {
    if (!selectedCert) return;
    const res = await exec(`sh "${CTL_SCRIPT}" delete_cert "${selectedCert.fname}"`);
    if (res.errno === 0) {
        toast(`已移除/屏蔽证书 ${selectedCert.fname}`);
        document.getElementById('detailModal').classList.add('hidden');
        loadDashboard();
    }
});

document.getElementById('btnRestoreCert').addEventListener('click', async () => {
    if (!selectedCert) return;
    const res = await exec(`sh "${CTL_SCRIPT}" restore_cert "${selectedCert.fname}"`);
    if (res.errno === 0) {
        toast(`已恢复原厂证书 ${selectedCert.fname}`);
        document.getElementById('detailModal').classList.add('hidden');
        loadDashboard();
    }
});

// 添加证书弹窗逻辑
document.getElementById('btnOpenAddModal').addEventListener('click', () => {
    document.getElementById('addHashInput').value = '';
    document.getElementById('addPemTextarea').value = '';
    document.getElementById('addModal').classList.remove('hidden');
});

document.getElementById('btnCloseAdd').addEventListener('click', () => {
    document.getElementById('addModal').classList.add('hidden');
});

document.getElementById('certFileInput').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const buf = await file.arrayBuffer();
    const bytes = new Uint8Array(buf);
    let text = new TextDecoder().decode(bytes);

    // 如果上传的是二进制 DER 格式证书，自动转换为标准 PEM 格式
    if (!text.includes('-----BEGIN CERTIFICATE-----')) {
        let bin = '';
        for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        const b64Lines = btoa(bin).match(/.{1,64}/g).join('\n');
        text = `-----BEGIN CERTIFICATE-----\n${b64Lines}\n-----END CERTIFICATE-----\n`;
    }

    document.getElementById('addPemTextarea').value = text;
    const parsed = parseX509Pem(text);
    if (/^[0-9a-f]{8}\.\d+$/i.test(file.name)) {
        document.getElementById('addHashInput').value = file.name.toLowerCase();
    } else if (parsed.oldHash) {
        document.getElementById('addHashInput').value = `${parsed.oldHash}.0`;
        toast(`已自动计算证书 Hash: ${parsed.oldHash}.0`);
    }
});

document.getElementById('addPemTextarea').addEventListener('input', (e) => {
    const parsed = parseX509Pem(e.target.value);
    const hashInput = document.getElementById('addHashInput');
    if (parsed.oldHash && !hashInput.value) {
        hashInput.value = `${parsed.oldHash}.0`;
    }
});

document.getElementById('btnConfirmAdd').addEventListener('click', async () => {
    let fname = document.getElementById('addHashInput').value.trim().toLowerCase();
    const pem = document.getElementById('addPemTextarea').value.trim();

    if (!pem.includes('-----BEGIN CERTIFICATE-----')) {
        toast('请提供有效的 PEM 证书内容');
        return;
    }
    if (!fname) {
        const parsed = parseX509Pem(pem);
        if (parsed.oldHash) fname = `${parsed.oldHash}.0`;
    }
    if (!/^[0-9a-f]{8}\.\d+$/.test(fname)) {
        toast('证书文件名格式必须为 8位十六进制Hash.0 (如 9a5ba575.0)');
        return;
    }

    const b64 = utf8ToBase64(pem + '\n');
    const res = await exec(`sh "${CTL_SCRIPT}" save_cert "${fname}" "${b64}"`);
    if (res.errno === 0) {
        toast(`成功安装并挂载证书 ${fname}`);
        document.getElementById('addModal').classList.add('hidden');
        loadDashboard();
    } else {
        toast(`添加失败: ${res.stderr}`);
    }
});

// 启动初始化
loadDashboard();
