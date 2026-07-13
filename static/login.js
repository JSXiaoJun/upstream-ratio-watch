const form = document.getElementById('loginForm');
const usernameInput = document.getElementById('loginUsername');
const passwordInput = document.getElementById('loginPassword');
const submitButton = document.getElementById('loginSubmit');
const message = document.getElementById('loginMessage');

function nextPath() {
  const value = new URLSearchParams(window.location.search).get('next') || '/';
  return value.startsWith('/') && !value.startsWith('//') ? value : '/';
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.message || `HTTP ${response.status}`);
  return body;
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  if (!username || !password) {
    message.textContent = '请输入用户名和密码';
    message.classList.add('error');
    return;
  }

  submitButton.disabled = true;
  submitButton.textContent = '登录中...';
  message.textContent = '';
  message.classList.remove('error');
  try {
    await request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    window.location.replace(nextPath());
  } catch (error) {
    message.textContent = error.message;
    message.classList.add('error');
    submitButton.disabled = false;
    submitButton.textContent = '登录';
    passwordInput.select();
  }
});

request('/api/auth/status')
  .then((status) => {
    if (status.authenticated) window.location.replace(nextPath());
  })
  .catch(() => {});
