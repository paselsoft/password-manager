// Configurazione della web app.
// dropboxAppKey: la "App key" dell'app creata su https://www.dropbox.com/developers/apps
// (non è un segreto: con il flusso PKCE non serve l'App secret).
// Se resta vuota, l'app la chiede al primo avvio e la ricorda nel browser.
window.PM_CONFIG = {
  dropboxAppKey: '',
};
