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
let currentSequence = 0;

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
    const text = output.value;
    if (text.trim() === '') {
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
        const pasteUrl = `/#${id}:${keyB64}`;
        history.pushState(null, '', pasteUrl);
        const fullUrl = location.origin + pasteUrl;

        let copied = false;
        try {
            await navigator.clipboard.writeText(fullUrl);
            copied = true;
        } catch (e) {
            console.warn('Clipboard failed:', e);
        }

        showStatus(copied ? 'Paste created! URL copied to clipboard.' : 'Paste created! Copy URL manually.', copied ? 'success' : 'info');
        enterViewMode();
    } catch (e) {
        showStatus(e.message, 'error');
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
    const text = output.value;
    if (text.trim() === '') {
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

    const hash = location.hash.slice(1);
    if (!hash) {
        return false;
    }

    const colonIdx = hash.indexOf(':');
    if (colonIdx <= 0 || colonIdx === hash.length - 1) {
        showStatus('Invalid URL format. Expected #id:key', 'error');
        return false;
    }

    const id = hash.slice(0, colonIdx);
    const keyB64 = hash.slice(colonIdx + 1);

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

    try {
        const keyBytes = base64urlDecode(keyB64);
        const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
        const plain = await decrypt(key, respData.iv, respData.data);
        output.value = plain;
        return true;
    } catch (e) {
        showStatus('Decryption failed. Wrong or invalid key.', 'error');
        console.error('Decryption error:', e);
        return false;
    }
}

async function handleLocation() {
    currentSequence = ++currentSequence % (10 ** 9 + 7);
    const thisSequence = currentSequence;
    const loaded = await loadPaste();
    if (thisSequence !== currentSequence) {
        return;
    }
    if (loaded) {
        enterViewMode();
    } else {
        enterEditMode();
    }
}

window.addEventListener('load', () => {
    if (actionBtn) actionBtn.addEventListener('click', createPaste);
    if (copyBtn) copyBtn.addEventListener('click', copyToClipboard);
    if (newBtn) {
        newBtn.addEventListener('click', () => {
            statusElem.classList.remove('show');
            history.pushState(null, '', '/');
            handleLocation();
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

    handleLocation();
});
window.addEventListener('hashchange', handleLocation);
window.addEventListener('popstate', handleLocation);
