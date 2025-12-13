let currentKey = null;
let currentIv = null;

function base64urlEncode(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function compress(data) {
  if (!('CompressionStream' in window)) {
    throw new Error('Compression not supported in this browser');
  }
  const compressedStream = new CompressionStream('gzip');
  const writer = compressedStream.writable.getWriter();
  const reader = compressedStream.readable.getReader();
  writer.write(data);
  writer.close();
  const chunks = [];
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const totalLength = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

async function decompress(compressed) {
  if (!('DecompressionStream' in window)) {
    throw new Error('Decompression not supported in this browser');
  }
  const decompressedStream = new DecompressionStream('gzip');
  const writer = decompressedStream.writable.getWriter();
  const reader = decompressedStream.readable.getReader();
  writer.write(compressed);
  writer.close();
  const chunks = [];
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const totalLength = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

async function encrypt(text, key) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const compressed = await compress(data);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ctBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    key,
    compressed
  );
  const ct = new Uint8Array(ctBuffer);
  return {
    iv: base64urlEncode(iv.buffer),
    ct: base64urlEncode(ct.buffer)
  };
}

async function decrypt(keyObj, ivStr, ctStr) {
  const iv = base64urlDecode(ivStr);
  const ct = base64urlDecode(ctStr);
  const decBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    keyObj,
    ct
  );
  const compressed = new Uint8Array(decBuffer);
  const decompressed = await decompress(compressed);
  return new TextDecoder().decode(decompressed);
}

async function createPaste() {
  const text = document.getElementById('output').value;
  if (!text.trim()) {
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

  const button = document.getElementById('actionBtn');
  button.disabled = true;
  button.textContent = 'Creating...';

  try {
    const key = await crypto.subtle.generateKey(
        {name: 'AES-GCM', length: 256}, 
        true, 
        ['encrypt', 'decrypt']
    );
    const enc = await encrypt(text, key);
    const keyBuffer = await crypto.subtle.exportKey('raw', key);
    const keyB64 = base64urlEncode(keyBuffer);

    const res = await fetch('/paste', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'Accept': 'application/json'},
      body: JSON.stringify({data: enc.ct, iv: enc.iv}),
      credentials: 'include'
    });

    if (!res.ok) {
        if (res.status === 413) throw new Error('Paste too large');
        throw new Error('Server error');
    }

    const resp = await res.json();
    const id = resp.id;
    const newUrl = '/p/' + id + '#' + keyB64;
    
    // Update URL without reloading
    history.pushState(null, '', newUrl);
    
    try {
      await navigator.clipboard.writeText(window.location.origin + newUrl);
      showStatus('Paste created! URL copied to clipboard.', 'success');
    } catch (e) {
      showStatus('Paste created! Copy URL manually.', 'info');
      console.warn('Clipboard failed:', e);
    }
  } catch (e) {
    showStatus('Error: ' + e.message, 'error');
  } finally {
    button.disabled = false;
    button.textContent = 'Create Paste';
  }
}

function showStatus(msg, type) {
  const status = document.getElementById('status');
  status.textContent = msg;
  status.className = type; 
  status.classList.add('show');
  setTimeout(() => {
    status.classList.remove('show');
  }, 5000);
}

async function copyToClipboard() {
  const textarea = document.getElementById('output');
  const text = textarea.value.trim();
  if (!text) {
    showStatus('Nothing to copy!', 'error');
    return;
  }

  try {
    await navigator.clipboard.writeText(text);
    showStatus('Copied to clipboard!', 'success');
  } catch (err) {
    // Fallback for older browsers or denied permissions
    textarea.select();
    textarea.setSelectionRange(0, 99999); // For mobile
    document.execCommand('copy');
    showStatus('Copied (fallback method)!', 'success');
  }
}

async function loadPaste() {
  const path = window.location.pathname;
  if (path === '/') return;

  const parts = path.split('/');
  // Expected format: /p/{id}
  if (parts.length < 3 || parts[1] !== 'p') return;
  
  const id = parts[2];
  if (!id) return;

  const hash = window.location.hash.slice(1);
  let decryptError = false;
  let statusMsg = '';

  if (hash) {
    try {
      const keyBytes = base64urlDecode(hash);
      currentKey = await crypto.subtle.importKey(
          'raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']
      );
    } catch (e) {
      decryptError = true;
      console.error('Key import failed:', e);
      statusMsg = 'Invalid key in URL.';
    }
  } else {
    statusMsg = 'Encrypted paste. Append #key to URL to view.';
  }

  const res = await fetch('/p/' + id, {
    credentials: 'include',
    headers: {'Accept': 'application/json'}
  });

  if (!res.ok) {
    showStatus('Paste not found or expired.', 'error');
    return;
  }

  const respData = await res.json();
  
  if (currentKey && !decryptError) {
    try {
      const plain = await decrypt(currentKey, respData.iv, respData.data);
      document.getElementById('output').value = plain;
    } catch (e) {
      decryptError = true;
      console.error('Decryption failed:', e);
      statusMsg = 'Decryption failed: Invalid key.';
    }
  }

  if (statusMsg) {
    showStatus(statusMsg, decryptError ? 'error' : 'info');
  }
}

window.addEventListener('load', () => {
    const btn = document.getElementById('actionBtn');
    if(btn) {
        btn.addEventListener('click', createPaste);
    }
    const copyBtn = document.getElementById('copyBtn');
    if (copyBtn) {
        copyBtn.addEventListener('click', copyToClipboard);
    }
    loadPaste();
});