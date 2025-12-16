const output = document.getElementById('output');
const viewer = document.getElementById('viewer');
const code = document.getElementById('code');
const toggleBtn = document.getElementById('toggleBtn');
const actionBtn = document.getElementById('actionBtn');
const copyBtn = document.getElementById('copyBtn');
const newBtn = document.getElementById('newBtn');
const statusElem = document.getElementById('status');

const ivLength = 12;
const tagLength = 128;
let isViewMode = false;

function enterEditMode() {
    output.style.display = 'block';
    viewer.style.display = 'none';
    toggleBtn.textContent = 'View';
    output.focus();
    isViewMode = false;
}

function enterViewMode() {
    if (!output.value.trim()) {
        enterEditMode();
        return;
    }
    code.className = 'hljs';
    delete code.dataset.highlighted;
    code.textContent = output.value;
    hljs.highlightElement(code);
    viewer.style.display = 'block';
    output.style.display = 'none';
    toggleBtn.textContent = 'Edit';
    isViewMode = true;
}

function base64Encode(buffer) {
    return new Uint8Array(buffer).toBase64();
}

function base64urlEncode(buffer) {
    return new Uint8Array(buffer).toBase64({ alphabet: 'base64url', omitPadding: true });
}

function base64Decode(str) {
    return Uint8Array.fromBase64(str);
}

function base64urlDecode(str) {
    return Uint8Array.fromBase64(str, { alphabet: 'base64url' });
}

async function compress(data) {
    const stream = new Blob([data]).stream().pipeThrough(new CompressionStream('gzip'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function decompress(compressed) {
    const stream = new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function encrypt(text, key) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const compressed = await compress(data);
    const iv = crypto.getRandomValues(new Uint8Array(ivLength));

    const ctBuffer = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength },
        key,
        compressed
    );

    return {
        iv: base64Encode(iv),
        ct: base64Encode(ctBuffer)
    };
}

async function decrypt(keyObj, ivStr, ctStr) {
    const iv = base64Decode(ivStr);
    const ct = base64Decode(ctStr);
    const decBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, tagLength },
        keyObj,
        ct
    );
    const decompressed = await decompress(new Uint8Array(decBuffer));
    return new TextDecoder().decode(decompressed);
}

async function createPaste() {
    const text = output.value.trim();
    if (!text) {
        showStatus('Empty paste', 'info');
        return;
    }
    if (!window.isSecureContext) {
        showStatus('Secure context required (HTTPS/localhost)', 'error');
        return;
    }
    if (new Blob([text]).size > 1024 * 1024) {
        showStatus('Plain text > 1MB', 'error');
        return;
    }

    actionBtn.disabled = true;
    actionBtn.textContent = 'Creating...';

    try {
        const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
        const [enc, keyBuffer] = await Promise.all([
            encrypt(text, key),
            crypto.subtle.exportKey('raw', key)
        ]);
        const keyB64 = base64urlEncode(keyBuffer);

        const res = await fetch('/paste', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({ data: enc.ct, iv: enc.iv }),
            credentials: 'include'
        });

        if (!res.ok) {
            throw new Error(res.status === 413 ? 'Paste too large' : 'Server error');
        }

        const { id } = await res.json();
        const newUrl = `/p/${id}#${keyB64}`;
        history.pushState(null, '', newUrl);
        await navigator.clipboard.writeText(location.origin + newUrl);
        showStatus('Paste created! URL copied to clipboard.', 'success');
        enterViewMode();
    } catch (e) {
        const msg = e.name === 'TypeError' && e.message.includes('clipboard')
            ? 'Paste created! Copy URL manually.'
            : `Error: ${e.message}`;
        showStatus(msg, 'error');
        console.warn('Operation failed:', e);
    } finally {
        actionBtn.disabled = false;
        actionBtn.textContent = 'Create Paste';
    }
}

function showStatus(msg, type = 'info') {
    statusElem.textContent = msg;
    statusElem.className = type;
    statusElem.classList.add('show');
    setTimeout(() => statusElem.classList.remove('show'), 5000);
}

async function copyToClipboard() {
    const text = output.value.trim();
    if (!text) {
        showStatus('Nothing to copy!', 'error');
        return;
    }
    try {
        await navigator.clipboard.writeText(text);
        showStatus('Copied to clipboard!', 'success');
    } catch (err) {
        showStatus('Copy failed! Try selecting and copying manually.', 'error');
        console.warn('Clipboard failed:', err);
    }
}

async function loadPaste() {
    output.value = '';
    if (location.pathname === '/') {
        return false;
    }
    const parts = location.pathname.split('/');
    if (parts.length < 3 || parts[1] !== 'p' || !parts[2]) return false;

    const id = parts[2];
    const hash = location.hash.slice(1);

    let respData;
    try {
        const res = await fetch(`/p/${id}`, {
            credentials: 'include',
            headers: { 'Accept': 'application/json' }
        });
        if (!res.ok) {
            showStatus('Paste not found or expired.', 'error');
            return false;
        }
        respData = await res.json();
    } catch (e) {
        showStatus('Network error loading paste.', 'error');
        return false;
    }

    let hasContent = false;
    let statusMsg = '';

    if (hash) {
        try {
            const keyBytes = base64urlDecode(hash);
            const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
            const plain = await decrypt(key, respData.iv, respData.data);
            output.value = plain;
            hasContent = true;
        } catch (e) {
            console.error('Key import or decryption failed:', e);
            statusMsg = 'Invalid key in URL or decryption failed.';
        }
    } else {
        statusMsg = 'Encrypted paste. Append #key to URL to view.';
    }

    if (statusMsg) showStatus(statusMsg, hash && statusMsg.includes('Invalid') ? 'error' : 'info');
    return hasContent;
}

window.addEventListener('load', () => {
    if (actionBtn) actionBtn.addEventListener('click', createPaste);
    if (copyBtn) copyBtn.addEventListener('click', copyToClipboard);
    if (newBtn) {
        newBtn.addEventListener('click', () => {
            output.value = '';
            statusElem.classList.remove('show');
            history.pushState(null, '', '/');
            enterEditMode();
        });
    }
    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => isViewMode ? enterEditMode() : enterViewMode());
    }

    document.addEventListener('keydown', e => {
        if (!isViewMode || e.ctrlKey || e.altKey || e.metaKey || e.shiftKey) return;
        const key = e.key.toLowerCase();
        if (key === 'e') { enterEditMode(); e.preventDefault(); }
        else if (key === 'c') { copyToClipboard(); e.preventDefault(); }
    });

    loadPaste().then(hasContent => hasContent ? enterViewMode() : enterEditMode());
});