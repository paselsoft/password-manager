# Migrazione da 1Password 7: verifica e conversione dell'export `.1pif`

`onepif_tool.py` legge l'export `.1pif` di 1Password 7 e fa tre cose:

1. **verifica**: conta gli elementi per tipo, controlla i TOTP (2FA), segnala doppioni,
   password riutilizzate o deboli, login senza URL e il cestino. Il report **non** contiene
   password, segreti o note.
2. **converti**: crea in un colpo solo i file di import per entrambe le strade:
   - `bitwarden_import.json`: Bitwarden, Vaultwarden (e anche KeePassXC 2.8+);
   - `keepass_import.xml`: KeePassXC tramite `keepassxc-cli import`, che produce un `.kdbx`
     apribile poi da KeePassium o Strongbox su iPhone e iPad.
3. **confronta**: dopo l'import, confronta l'originale con un export del nuovo gestore
   (titolo + utente + password + presenza del TOTP, per ogni elemento).

Basta Python 3.6 o successivo, solo libreria standard. Lo script è stato provato con
KeePassXC 2.7.6 (import reale, generazione dei codici TOTP, export e confronto).

## Cosa viene convertito

| 1Password 7 | Bitwarden | KeePassXC (.kdbx) |
|---|---|---|
| Login, Password | Login (URL multipli) | Voce: URL aggiuntivi come `KP2A_URL_n` |
| TOTP | campo TOTP (il primo valido; gli altri diventano campi nascosti) | attributo `otp` (otpauth://) |
| Campi personalizzati / sezioni | campi personalizzati (nascosti se "concealed") | attributi (protetti se "concealed") |
| Storico password | `passwordHistory` | cronologia della voce |
| Carta di credito | Carta | voce con attributi (numero e CVV protetti) |
| Identità | Identità | voce con attributi |
| Nota sicura | Nota sicura | voce nel gruppo "Note sicure" |
| Server, Database, Email, Router… | Login se c'è utente/password/TOTP, altrimenti Nota | voce |
| Cartelle (anche annidate) | cartelle `Padre/Figlio` | gruppi |
| Tag, Preferiti | campo "Tag 1Password", preferito | Tag (+ "Preferito") |
| Cestino | escluso (opzione `--includi-cestino`) | escluso |
| **Allegati** | **non presenti nel .1pif: vanno salvati e ricaricati a mano** | idem |

## Procedura

### 0. Preparazione (su iMac High Sierra)

- Python 3: il Python di sistema di High Sierra è il 2.7 e **non va bene**. Installa
  il pacchetto "macOS 64-bit universal2 installer" da python.org, scegliendo una versione
  che indichi compatibilità con macOS 10.13 (lo dice la nota accanto al download).
- Crea una cartella **locale e non sincronizzata** (non iCloud Drive, Dropbox, OneDrive), ad esempio:

```bash
mkdir -m 700 ~/migrazione-1p
```

- Copia `onepif_tool.py` in quella cartella.

### 1. Ripristino ed export da 1Password 7

1. 1Password 7, Preferenze, Avanzate: abilita le casseforti locali.
2. File, Ripristina: scegli il backup `.1p4_zip` (954 elementi, 5 cartelle, 7 allegati).
3. **Salva a mano i 7 allegati** in `~/migrazione-1p/allegati/` (apri l'elemento, clic
   destro sull'allegato, Salva). Annotati a quale elemento appartiene ciascuno.
4. Per **ogni** cassaforte: selezionala, poi File, Esporta, Tutti gli elementi, formato
   "1Password Interchange File (.1pif)", e salva in `~/migrazione-1p/`, dando al file il nome
   della cassaforte (es. `Personale.1pif`).

### 2. Verifica

```bash
cd ~/migrazione-1p
```

```bash
python3 onepif_tool.py verifica Personale.1pif --atteso 954 --report report.md
```

Con più casseforti passale tutte insieme (`Personale.1pif Lavoro.1pif …`). Il controllo
`--atteso` confronta il totale (cestino compreso, cartelle escluse) con i 954 elementi
dichiarati dal backup. Leggi il report: se vuoi, elimina doppioni e voci inutili in 1Password 7,
poi esporta di nuovo.

### 3. Conversione

```bash
python3 onepif_tool.py converti *.1pif --atteso 954 --out ~/migrazione-1p/out
```

Con più casseforti, il nome della cassaforte diventa la cartella o il gruppo di primo livello
(`--senza-cassaforte` per evitarlo).

### 4a. Import in Bitwarden o Vaultwarden

Web Vault, Strumenti, Importa dati, formato **"Bitwarden (json)"**, file `out/bitwarden_import.json`.
Poi ricarica i 7 allegati (Premium) oppure conservali altrove.

### 4b. Import in KeePassXC

```bash
keepassxc-cli import -p out/keepass_import.xml ~/Passwords.kdbx
```

Su Mac il comando si trova dentro l'app: `/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli`.
Su Linux e Windows è installato insieme a KeePassXC. Scegli una password principale robusta
quando la chiede. Gli allegati si aggiungono dalla scheda "Avanzate" della voce.
In alternativa, KeePassXC 2.8+ importa direttamente `bitwarden_import.json`
(Database, Importa, Bitwarden).

### 5. Verifica dopo l'import

Esporta dal nuovo gestore e confronta:

- **Bitwarden**: Strumenti, Esporta cassaforte, formato `.json` (**non** "json crittografato").
- **KeePassXC**: esporta in XML con il comando qui sotto.

```bash
keepassxc-cli export -f xml ~/Passwords.kdbx > verifica.xml
```

```bash
python3 onepif_tool.py confronta *.1pif --con verifica.xml
```

L'esito deve essere `TUTTO CORRISPONDE`; se non lo è, controlla gli elementi elencati.
Prova anche a mano 3 o 4 TOTP, confrontando il codice con quello di 1Password 7.

### 6. Pulizia (importante)

I `.1pif`, i file in `out/` e gli export di verifica contengono **tutte le password in chiaro**.

```bash
rm -rf ~/migrazione-1p/*.1pif ~/migrazione-1p/out ~/migrazione-1p/verifica.* ~/migrazione-1p/report.md
```

Svuota poi il Cestino del Mac. Tieni da parte, in un posto sicuro, il backup
`.1p4_zip` originale (è cifrato) finché non sei certo della migrazione.

## Test

```bash
python3 -m unittest discover -s tests -v
```

`tests/fixtures/esempio.1pif` contiene solo dati inventati. Se `keepassxc-cli` è installato,
i test fanno anche un import reale in KeePassXC e controllano la generazione del codice TOTP.
