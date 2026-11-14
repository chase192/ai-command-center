const login = document.querySelector('#login');
const workspace = document.querySelector('#workspace');
const status = document.querySelector('#status');
async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { 'content-type': 'application/json' } });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}
function show(authenticated) { login.hidden = authenticated; workspace.hidden = !authenticated; }
api('/api/session').then(data => show(data.authenticated)).catch(() => show(false));
document.querySelector('#loginForm').addEventListener('submit', async event => {
  event.preventDefault(); status.textContent = 'Signing in…';
  try {
    await api('/api/login', { method: 'POST', body: JSON.stringify({ password: document.querySelector('#password').value }) });
    document.querySelector('#password').value = ''; show(true); status.textContent = '';
  } catch (error) { status.textContent = error.message; }
});
document.querySelector('#logout').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST' }); show(false); status.textContent = 'Signed out'; }
  catch (error) { status.textContent = error.message; }
});
document.querySelector('#askForm').addEventListener('submit', async event => {
  event.preventDefault(); const button = document.querySelector('#askButton');
  button.disabled = true; status.textContent = 'Consulting models…';
  document.querySelector('#combined').textContent = 'Working…';
  document.querySelector('#answers').replaceChildren();
  try {
    const data = await api('/api/ask', { method: 'POST', body: JSON.stringify({ prompt: document.querySelector('#prompt').value }) });
    document.querySelector('#combined').textContent = data.combined;
    for (const [name, result] of Object.entries(data.answers)) {
      const section = document.createElement('section'); section.className = 'answer';
      const heading = document.createElement('h3'); heading.textContent = name;
      const body = document.createElement('pre'); body.textContent = result.text || result.error;
      section.append(heading, body); document.querySelector('#answers').append(section);
    }
    status.textContent = 'Complete';
  } catch (error) { document.querySelector('#combined').textContent = ''; status.textContent = error.message; }
  finally { button.disabled = false; }
});
