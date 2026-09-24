// Fill in branding, the real origin in code samples, and the live status pill.
(function () {
  document.querySelectorAll('[data-year]').forEach((el) => (el.textContent = new Date().getFullYear()));
  document.querySelectorAll('[data-origin]').forEach((el) => (el.textContent = location.origin));

  fetch('/api/site')
    .then((r) => r.json())
    .then(({ name }) => {
      if (!name) return;
      document.querySelectorAll('[data-site-name]').forEach((el) => (el.textContent = name));
      document.title = `${name} — Script Whitelisting`;
    })
    .catch(() => {});

  const dot = document.querySelector('[data-status-dot]');
  const text = document.querySelector('[data-status-text]');
  fetch('/healthz')
    .then((r) => (r.ok ? r.json() : Promise.reject()))
    .then(() => {
      dot.classList.add('up');
      text.textContent = 'All systems operational';
    })
    .catch(() => {
      dot.classList.add('down');
      text.textContent = 'Service unreachable';
    });
})();
