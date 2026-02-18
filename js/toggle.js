function toggleForms(target) {
    const regForm = document.getElementById('register-form');
    if (regForm) {
        regForm.style.display = (target === 'register') ? 'block' : 'none';
    }
}