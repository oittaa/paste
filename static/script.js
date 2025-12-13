const ivLength = 12;
const tagLength = 128;
let currentKey = null;

function base64Encode(buffer) {
  return new Uint8Array(buffer).toBase64();
}

function base64urlEncode(buffer) {
  return base64Encode(buffer)
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64Decode(str) {
  return Uint8Array.fromBase64(str);
}

function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return base64Decode(str);
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
    { name: 'AES-GCM', iv, tagLength: tagLength },
    key,
    compressed
  );
  
  return {
    iv: base64Encode(iv.buffer),
    ct: base64Encode(ctBuffer)
  };
}

async function decrypt(keyObj, ivStr, ctStr) {
  const iv = base64Decode(ivStr);
  const ct = base64Decode(ctStr);
  const decBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: tagLength },
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
    
    await navigator.clipboard.writeText(window.location.origin + newUrl);
    showStatus('Paste created! URL copied to clipboard.', 'success');
  } catch (e) {
    let msg = 'Error: ' + e.message;
    if (e.name === 'TypeError' && e.message.includes('clipboard')) {
      msg = 'Paste created! Copy URL manually.';
      showStatus(msg, 'info');
    } else {
      showStatus(msg, 'error');
    }
    console.warn('Operation failed:', e);
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
    showStatus('Copy failed! Try selecting and copying manually.', 'error');
    console.warn('Clipboard failed:', err);
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
    const newBtn = document.getElementById('newBtn');
    if (newBtn) {
        newBtn.addEventListener('click', () => {
            document.getElementById('output').value = '';
            document.getElementById('output').focus();
            document.getElementById('status').classList.remove('show');
            currentKey = null;
            history.pushState(null, '', '/');
        });
    }
});