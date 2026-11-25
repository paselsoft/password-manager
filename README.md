# Cassaforte: gestore di password personale

Web app per le tue password, usabile da qualunque browser (iMac, Linux, PC dell'ufficio,
iPhone, iPad) senza installare nulla. I dati stanno in **un file KeePass (`.kdbx`) su
Dropbox** e vengono cifrati e decifrati **solo sul dispositivo**: né Dropbox né il sito che
ospita l'app vedono mai le password in chiaro.

Il formato è quello standard di KeePass, quindi lo stesso file si apre anche con
**KeePassXC** (Windows, Linux, macOS) e **KeePassium** o **Strongbox** (iPhone e iPad). Se un
giorno non vuoi più usare questa app, non perdi nulla.

```
 browser (iMac / Linux / Windows / iPhone / iPad)
   └─ Cassaforte: decifra in locale (Argon2id + AES/ChaCha20, formato KDBX 4)
        └─ Dropbox API ──► Dropbox/App/<nome app>/Password.kdbx   (sempre cifrato)
```

## Cosa fa (versione 0.1)

- Collegamento a Dropbox con OAuth PKCE: nessun server e nessun segreto. L'app può
  accedere **solo** alla propria cartella `Dropbox/App/<nome app>/` (in inglese `Apps`).
- Sblocco con password principale ed eventuale **key file** (che può essere ricordato
  sul dispositivo come secondo fattore, come la "Secret Key" di 1Password).
- Ricerca istantanea (anche senza accenti e su più parole), filtro per gruppo, cestino.
- **Codici 2FA (TOTP)** generati nell'app, compatibili con KeePassXC, KeePassium e KeePass.
- Copia di utente, password e codici con **svuotamento automatico degli appunti**.
- Creazione e modifica delle voci: generatore di password, campi personalizzati
  (anche protetti), tag, gruppi, **allegati** (utile per i 7 allegati di 1Password).
- **Sincronizzazione sicura**: prima di salvare controlla che il file su Dropbox non sia
  cambiato. Se è stato modificato altrove (un altro dispositivo, KeePassXC), **unisce le
  modifiche** invece di sovrascriverle.
- **Funziona offline**: usa l'ultima copia cifrata salvata sul dispositivo; le modifiche
  fatte offline restano in attesa (cifrate) e partono al ritorno della rete.
- **Blocco automatico** dopo inattività (configurabile), e se vuoi anche quando l'app va in
  secondo piano.
- Aggiornamento con un clic dei file vecchi (KDBX 3.1 / AES-KDF) a **KDBX 4 + Argon2id**.
- Si installa sulla schermata Home di iPhone e iPad come un'app (PWA), con tema chiaro e scuro.

Limiti di questa versione: niente compilazione automatica nei siti e nelle app (sull'iPhone
è riservata alle app native: si copia e incolla), niente estensione per il browser, e
nessun audit di sicurezza indipendente (vedi "Sicurezza" più sotto).

## Messa in funzione (una volta sola, circa 15 minuti)

### 1. Crea l'app su Dropbox

1. Vai su <https://www.dropbox.com/developers/apps> e scegli **Create app**.
2. **Scoped access**, poi **App folder** (l'app vedrà solo la propria cartella).
3. Dai un nome unico, ad esempio `Cassaforte-tuonome`. Su Dropbox comparirà la cartella
   `App/Cassaforte-tuonome/`.
4. Scheda **Permissions**: attiva `files.metadata.read`, `files.content.read` e
   `files.content.write`, poi premi **Submit**.
5. Scheda **Settings**:
   - in **OAuth 2, Redirect URIs** aggiungi l'indirizzo esatto dell'app, ad esempio
     `https://paselsoft.github.io/password-manager/` (con la `/` finale). Per le prove in
     locale aggiungi anche `http://localhost:8080/`;
   - **Allow public clients (Implicit Grant & PKCE)**: lascia **Allow**;
   - copia la **App key**. Non è un segreto; l'*App secret* invece non serve e non va
     usato da nessuna parte.

L'app può restare in stato "Development": per l'uso personale non serve chiedere a Dropbox
il passaggio in produzione.

### 2. Pubblica il sito su GitHub Pages

1. Facoltativo: inserisci la App key in `webapp/config.js` (`dropboxAppKey: '...'`),
   così non dovrai digitarla su ogni dispositivo.
2. Sul repository GitHub: **Settings, Pages, Build and deployment, Source: GitHub Actions**.
3. Pubblica il contenuto su un branch `main` (il workflow `.github/workflows/pages.yml`
   esegue i test e pubblica `webapp/` a ogni push su `main`). In alternativa avvialo a mano
   da **Actions, Pubblica web app, Run workflow**.
4. L'indirizzo sarà `https://<utente>.github.io/password-manager/`: deve coincidere con il
   Redirect URI impostato su Dropbox.

Va bene anche qualsiasi altro hosting statico HTTPS (Cloudflare Pages, Netlify…): basta
pubblicare la cartella `webapp/` così com'è, senza passaggi di build.

### 3. Primo avvio

1. Apri l'indirizzo, inserisci la App key (se non è in `config.js`) e premi **Collega Dropbox**.
2. Scegli il file `.kdbx`, oppure **Carica un .kdbx dal dispositivo**, oppure **Crea nuovo
   database**. Per portare dentro le password di 1Password segui
   [docs/MIGRAZIONE-1PASSWORD.md](docs/MIGRAZIONE-1PASSWORD.md).
3. Se compare l'avviso "protezione datata", premi **Aggiorna ora**.

### iPhone e iPad

Apri l'indirizzo in Safari, poi Condividi, **Aggiungi alla schermata Home**. L'app installata
ha un suo spazio separato da Safari, quindi va collegata a Dropbox una volta anche lì. Se
dopo l'autorizzazione Dropbox non torna all'app, usa **Collega con codice** (sotto il
pulsante principale): autorizzi, copi il codice e lo incolli nell'app.

### iMac con High Sierra

Usa la versione più recente di Firefox ESR disponibile per macOS 10.13: Chrome e Safari su
High Sierra non ricevono più aggiornamenti di sicurezza, e anche il supporto di Firefox per
High Sierra è a fine vita. Un browser senza aggiornamenti è il punto debole di qualsiasi
gestore di password su quella macchina.

### PC dell'ufficio (Windows 10)

Basta il browser, nessuna installazione. Imposta un blocco automatico breve (1-2 minuti)
dalle impostazioni e **non** spuntare "Ricorda il key file" su un computer condiviso.

## Uso insieme a KeePassXC e KeePassium

- **KeePassXC** (Linux, Windows): apri il file dalla cartella Dropbox sincronizzata
  (`Dropbox/App/<nome app>/Password.kdbx`). KeePassXC si accorge dei cambiamenti fatti
  dall'app web e li ricarica.
- **KeePassium** (iPhone, iPad): apri il file da app File, Dropbox. In più hai la
  compilazione automatica di iOS (la versione gratuita gestisce un database).
- Se due dispositivi modificano il file nello stesso momento, Cassaforte unisce le modifiche.
  KeePassXC fa lo stesso quando ricarica. Evita però di tenere il file aperto con
  modifiche non salvate su più programmi a lungo.

## Sicurezza: cosa protegge e cosa no

- **Protegge da**: furto o fuga del file da Dropbox (senza password e key file è
  inutilizzabile; Argon2id rende lenti i tentativi), accesso di Dropbox ai dati, perdita
  del telefono (blocco automatico, nessun dato in chiaro salvato sul dispositivo).
- **Il punto delicato di ogni web app**: il codice arriva dal sito a ogni apertura. Se
  qualcuno prendesse il controllo del tuo account GitHub potrebbe pubblicare una versione
  modificata. Quindi: **attiva la verifica in due passaggi su GitHub e su Dropbox** e usa
  una password principale lunga (frase di 5-6 parole).
- Un dispositivo compromesso (virus, estensioni malevole del browser) può leggere ciò che
  vedi. Vale per qualsiasi gestore di password.
- Il codice di crittografia non è scritto da zero: il formato KDBX è gestito da `kdbxweb`
  (la libreria di KeeWeb) e Argon2 da `hash-wasm`. L'app però non ha avuto un audit
  indipendente.
- **Fai backup**: Dropbox conserva le versioni precedenti dei file (cronologia versioni).
  Tieni comunque, ogni tanto, una copia del `.kdbx` su una chiavetta, e un foglio con la
  password principale in un posto sicuro.

## Sviluppo e test

Requisiti: Node.js 18+ (per i test). L'app in sé non ha passaggi di build.

```bash
npm install
```

```bash
npm run serve
```

Apre l'app su `http://localhost:8080/` (localhost conta come contesto sicuro, quindi
WebCrypto e service worker funzionano).

```bash
npm test
```

I test coprono TOTP (vettori ufficiali RFC 6238), generatore, lettura e scrittura KDBX,
unione di modifiche concorrenti e compatibilità reale con `keepassxc-cli` (se installato).
Nel browser, con Playwright e un Dropbox simulato, verificano sblocco, ricerca, modifica,
conflitti, lavoro offline, cestino e aggiornamento della protezione.

`npm run vendor` ricopia in `webapp/vendor/` le librerie (`kdbxweb`, `hash-wasm`) dopo un
aggiornamento delle dipendenze.

### Struttura

| Percorso | Contenuto |
|---|---|
| `webapp/` | la web app pubblicata (HTML, CSS, JS, librerie, service worker) |
| `webapp/js/vault.js` | apertura, ricerca, modifica e unione dei database KDBX |
| `webapp/js/dropbox.js` | OAuth PKCE e API Dropbox (download e upload con controllo di revisione) |
| `webapp/js/totp.js`, `generator.js` | codici 2FA e generatore di password |
| `webapp/js/store.js` | IndexedDB: copia cifrata offline, modifiche in attesa, key file |
| `webapp/js/app.js` | interfaccia |
| `onepif_tool.py` | verifica e conversione dell'export di 1Password 7 ([guida](docs/MIGRAZIONE-1PASSWORD.md)) |
| `tests/` | test Python (strumento di migrazione) e Node/Playwright (web app) |
