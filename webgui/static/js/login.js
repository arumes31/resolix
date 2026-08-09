(function () {
    var saved = localStorage.getItem('theme');
    var preferred = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    var theme = saved || preferred;
    document.documentElement.setAttribute('data-theme', theme);
})();
