const form = document.querySelector('form');
const btn = document.querySelector('.btn-check');

if (form && btn) {
    form.addEventListener('submit', () => {
        btn.textContent = '🔍 Checking...';
        btn.disabled = true;
    });
}