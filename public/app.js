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
  document.querySelector('#reviews').replaceChildren();
  document.querySelector('#sources').replaceChildren();
  document.querySelector('#sourcesSection').hidden = true;
  document.querySelector('#reviewsSection').hidden = true;
  try {
    const data = await api('/api/ask', { method: 'POST', body: JSON.stringify({ prompt: document.querySelector('#prompt').value, mode: document.querySelector('#mode').value }) });
    document.querySelector('#combined').textContent = data.combined;
    if (data.sources?.length) {
      document.querySelector('#sourcesSection').hidden = false;
      for (const source of data.sources) {
        const p = document.createElement('p');
        const a = document.createElement('a'); a.href = source.url; a.textContent = source.title || source.url;
        a.target = '_blank'; a.rel = 'noopener noreferrer';
        p.append(a); document.querySelector('#sources').append(p);
      }
    }
    for (const [name, result] of Object.entries(data.answers)) {
      const section = document.createElement('section'); section.className = 'answer';
      const heading = document.createElement('h3'); heading.textContent = name;
      const body = document.createElement('pre'); body.textContent = result.text || result.error;
      section.append(heading, body); document.querySelector('#answers').append(section);
    }
    if (data.reviews) {
      document.querySelector('#reviewsSection').hidden = false;
      for (const [name, review] of Object.entries(data.reviews)) {
        const section = document.createElement('section'); section.className = 'answer';
        const heading = document.createElement('h3'); heading.textContent = name;
        const body = document.createElement('pre'); body.textContent = review.text || review.error || review.skipped || 'No review returned';
        section.append(heading, body); document.querySelector('#reviews').append(section);
      }
    }
    status.textContent = 'Complete (' + (data.mode || 'fast') + ' mode)';
  } catch (error) { document.querySelector('#combined').textContent = ''; status.textContent = error.message; }
  finally { button.disabled = false; }
});
