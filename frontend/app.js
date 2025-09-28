// Simple frontend that stores access token in-memory and uses fetch wrapper to auto-refresh
const API_BASE = 'http://localhost:5000/api'; // backend base
let accessToken = null; // in-memory storage

// Utility: set access token
function setAccessToken(token) {
  accessToken = token;
}

// fetch wrapper that auto-refreshes on 401 (one retry)
async function apiFetch(path, opts = {}) {
  const url = API_BASE + path;
  opts.credentials = 'include'; // important to send cookie (refresh token)
  opts.headers = opts.headers || {};
  if (accessToken) opts.headers['Authorization'] = 'Bearer ' + accessToken;
  // JSON default
  if (opts.body && typeof opts.body === 'object') {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(opts.body);
  }

  let res = await fetch(url, opts);
  if (res.status === 401) {
    // Try to refresh once
    const refreshed = await tryRefresh();
    if (!refreshed) {
      throw new Error('Unauthorized and refresh failed');
    }
    // update header and retry original request
    if (accessToken) opts.headers['Authorization'] = 'Bearer ' + accessToken;
    res = await fetch(url, opts);
  }
  return res;
}

async function tryRefresh() {
  try {
    const res = await fetch(API_BASE + '/auth/refresh', {
      method: 'POST',
      credentials: 'include'
    });
    if (!res.ok) return false;
    const data = await res.json();
    setAccessToken(data.accessToken);
    return true;
  } catch (e) {
    console.error('Refresh failed', e);
    return false;
  }
}

// DOM
const usernameEl = document.getElementById('username');
const passwordEl = document.getElementById('password');
const loginBtn = document.getElementById('loginBtn');
const registerBtn = document.getElementById('registerBtn');
const fetchBtn = document.getElementById('fetchProtected');
const logoutBtn = document.getElementById('logoutBtn');
const output = document.getElementById('output');

loginBtn.addEventListener('click', async () => {
  const username = usernameEl.value.trim();
  const password = passwordEl.value.trim();
  try {
    const res = await apiFetch('/auth/login', { method: 'POST', body: { username, password } });
    if (!res.ok) {
      output.textContent = 'Login failed: ' + (await res.text());
      return;
    }
    const data = await res.json();
    setAccessToken(data.accessToken);
    output.textContent = 'Logged in, access token obtained (in memory).';
  } catch (e) {
    output.textContent = 'Login error: ' + e.message;
  }
});

registerBtn.addEventListener('click', async () => {
  const username = usernameEl.value.trim();
  const password = passwordEl.value.trim();
  try {
    const res = await apiFetch('/auth/register', { method: 'POST', body: { username, password } });
    const txt = await res.text();
    output.textContent = (res.ok ? 'Registered: ' : 'Register failed: ') + txt;
  } catch (e) {
    output.textContent = 'Register error: ' + e.message;
  }
});

fetchBtn.addEventListener('click', async () => {
  try {
    const res = await apiFetch('/user/me', { method: 'GET' });
    if (!res.ok) {
      output.textContent = 'Fetch failed: ' + (await res.text());
      return;
    }
    const data = await res.json();
    output.textContent = JSON.stringify(data, null, 2);
  } catch (e) {
    output.textContent = 'Error: ' + e.message;
  }
});

logoutBtn.addEventListener('click', async () => {
  try {
    const res = await apiFetch('/auth/logout', { method: 'POST' });
    if (res.ok) {
      setAccessToken(null);
      output.textContent = 'Logged out';
    } else {
      output.textContent = 'Logout failed';
    }
  } catch (e) {
    output.textContent = 'Logout error: ' + e.message;
  }
});
