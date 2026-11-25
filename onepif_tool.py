#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
onepif_tool.py - Verifica e conversione degli export 1Password 7 (.1pif).

Sottocomandi:
  verifica  INPUT... [--atteso N]             analizza l'export e stampa un report
  converti  INPUT... --out DIR [--formato F]  report + file per Bitwarden e/o KeePassXC
  confronta ORIGINALE.1pif... --con FILE       confronta l'originale con un export
                                               del nuovo gestore (verifica post-import)

INPUT e' un file .1pif oppure la cartella-pacchetto .1pif creata da 1Password 7
per Mac (che contiene data.1pif). Si possono passare piu' casseforti insieme.

Requisiti: Python 3.6 o successivo, solo libreria standard (nessuna dipendenza).
Il report non contiene mai password, segreti TOTP o contenuto delle note.
"""

import argparse
import base64
import binascii
import collections
import datetime
import hashlib
import json
import os
import re
import stat
import sys
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, quote, parse_qs

VERSION = "1.0"

SEPARATOR_RE = re.compile(r"^\*\*\*[0-9A-Za-z-]+\*\*\*\s*$", re.M)

TYPE_LABELS = {
    "webforms.WebForm": "Login",
    "passwords.Password": "Password",
    "securenotes.SecureNote": "Nota sicura",
    "wallet.financial.CreditCard": "Carta di credito",
    "wallet.financial.BankAccountUS": "Conto bancario",
    "identities.Identity": "Identita'",
    "wallet.computer.License": "Licenza software",
    "wallet.computer.Database": "Database",
    "wallet.computer.UnixServer": "Server",
    "wallet.computer.Router": "Router / Wi-Fi",
    "wallet.onlineservices.Email.v2": "Account email",
    "wallet.onlineservices.GenericAccount": "Account generico",
    "wallet.government.Passport": "Passaporto",
    "wallet.government.DriversLicense": "Patente",
    "wallet.government.SsnUS": "Codice fiscale / SSN",
    "wallet.membership.Membership": "Tessera",
    "wallet.membership.RewardProgram": "Programma fedelta'",
    "wallet.financial.CryptoWallet": "Crypto wallet",
    "system.folder.Regular": "(cartella)",
    "system.folder.SavedSearch": "(ricerca salvata)",
}

USERNAME_KEYS = ("username", "pop_username", "smtp_username", "login")
PASSWORD_KEYS = ("password", "pop_password", "wireless_password", "smtp_password")
URL_KEYS = ("url", "website", "hostname", "server", "pop_server", "publisher_website")

# Tipi di campo dei form web che non portano informazioni utili
WEBFORM_SKIP_TYPES = ("B", "C", "R", "I")

CC_BRANDS = {
    "visa": "Visa", "mc": "Mastercard", "mastercard": "Mastercard",
    "amex": "Amex", "american express": "Amex", "discover": "Discover",
    "diners": "Diners Club", "dinersclub": "Diners Club", "jcb": "JCB",
    "maestro": "Maestro", "unionpay": "UnionPay", "rupay": "RuPay",
}

CLOUD_HINTS = ("dropbox", "icloud", "mobile documents", "onedrive",
               "google drive", "googledrive", "box sync", "pcloud", "mega")

B32_RE = re.compile(r"^[A-Z2-7]+=*$")


# --------------------------------------------------------------------------
# Lettura del file .1pif
# --------------------------------------------------------------------------

def resolve_input(path):
    """Restituisce (percorso data.1pif, nome cassaforte)."""
    path = os.path.abspath(os.path.expanduser(path))
    if os.path.isdir(path):
        candidate = os.path.join(path, "data.1pif")
        if not os.path.isfile(candidate):
            raise SystemExit("ERRORE: nella cartella %s non c'e' data.1pif" % path)
        name = os.path.basename(path.rstrip(os.sep))
        return candidate, re.sub(r"\.1pif$", "", name, flags=re.I)
    if not os.path.isfile(path):
        raise SystemExit("ERRORE: file non trovato: %s" % path)
    base = os.path.basename(path)
    if base.lower() == "data.1pif":
        parent = os.path.basename(os.path.dirname(path))
        return path, re.sub(r"\.1pif$", "", parent, flags=re.I) or "Cassaforte"
    return path, re.sub(r"\.1pif$", "", base, flags=re.I)


def read_1pif(path):
    """Legge un file .1pif e restituisce (lista record JSON, lista errori)."""
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        text = fh.read()
    records, errors = [], []
    chunks = [c.strip() for c in SEPARATOR_RE.split(text)]
    for idx, chunk in enumerate(c for c in chunks if c):
        try:
            records.append(json.loads(chunk))
        except ValueError as exc:
            errors.append("record #%d non e' JSON valido (%s)" % (idx + 1, exc))
    return records, errors


# --------------------------------------------------------------------------
# Normalizzazione in un modello intermedio
# --------------------------------------------------------------------------

def ts_to_iso(ts, date_only=False):
    try:
        dt = datetime.datetime.fromtimestamp(int(ts), datetime.timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return ""
    if date_only:
        return dt.strftime("%Y-%m-%d")
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def fmt_value(kind, value):
    if value is None:
        return ""
    if kind == "date":
        return ts_to_iso(value, date_only=True) or str(value)
    if kind == "monthYear":
        s = str(value)
        if re.match(r"^\d{6}$", s):
            return "%s/%s" % (s[4:], s[:4])
        return s
    if kind == "address" and isinstance(value, dict):
        parts = [value.get(k) for k in ("street", "zip", "city", "state", "region", "country")]
        return ", ".join(str(p) for p in parts if p)
    if isinstance(value, bool):
        return "si" if value else "no"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value).strip() if isinstance(value, str) else str(value)


def is_totp_field(name, value):
    return (name or "").upper().startswith("TOTP_") or value.lower().startswith("otpauth://")


def totp_problem(value):
    """None se il TOTP sembra valido, altrimenti descrizione del problema."""
    v = value.strip()
    if v.lower().startswith("otpauth://"):
        try:
            qs = parse_qs(urlparse(v).query)
        except ValueError:
            return "URI otpauth non valido"
        secret = (qs.get("secret") or [""])[0]
        if not secret:
            return "URI otpauth senza parametro secret"
        v = secret
    v = v.replace(" ", "").upper()
    if not v or not B32_RE.match(v):
        return "segreto non in Base32"
    try:
        base64.b32decode(v + "=" * (-len(v) % 8))
    except (binascii.Error, ValueError):
        return "segreto Base32 non decodificabile"
    return None


def totp_uri(value, title, account):
    """Restituisce sempre un URI otpauth:// (KeePassXC/Bitwarden lo accettano)."""
    v = value.strip()
    if v.lower().startswith("otpauth://"):
        return v
    secret = v.replace(" ", "").upper()
    label = quote(title or "1Password", safe="")
    if account:
        label += ":" + quote(account, safe="@")
    return "otpauth://totp/%s?secret=%s&period=30&digits=6&issuer=%s" % (
        label, secret, quote(title or "1Password", safe=""))


def dedupe(seq):
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


class Item(object):
    def __init__(self):
        self.uuid = ""
        self.vault = ""
        self.type_name = ""
        self.title = ""
        self.kind = "note"   # login | note | card | identity
        self.urls = []
        self.username = ""
        self.password = ""
        self.totp = []       # lista di (etichetta, valore)
        self.notes = ""
        self.fields = []     # lista di dict: n, label, value, hidden, raw, k
        self.folder_path = []
        self.tags = []
        self.favorite = False
        self.created = ""
        self.updated = ""
        self.updated_ts = 0
        self.trashed = False
        self.history = []    # lista di (password, iso time)
        self.card = {}
        self.identity = {}

    def take(self, names):
        """Estrae (e rimuove dai campi) il primo campo con nome in names."""
        for i, f in enumerate(self.fields):
            if f["n"] in names:
                return self.fields.pop(i)
        return None


def build_folders(records):
    folders = {}
    for r in records:
        if r.get("typeName") == "system.folder.Regular":
            folders[r.get("uuid")] = (r.get("title") or "Senza nome", r.get("folderUuid"))

    def path_of(fuuid):
        path, seen = [], set()
        while fuuid and fuuid in folders and fuuid not in seen:
            seen.add(fuuid)
            name, parent = folders[fuuid]
            path.insert(0, name.replace("/", "-"))
            fuuid = parent
        return path
    return folders, path_of


def normalize(record, vault, path_of):
    it = Item()
    sc = record.get("secureContents") or {}
    oc = record.get("openContents") or {}
    it.uuid = record.get("uuid") or ""
    it.vault = vault
    it.type_name = record.get("typeName") or "?"
    it.title = (record.get("title") or "").strip()
    it.trashed = bool(record.get("trashed"))
    it.favorite = record.get("faveIndex") is not None
    it.created = ts_to_iso(record.get("createdAt"))
    it.updated = ts_to_iso(record.get("updatedAt"))
    try:
        it.updated_ts = int(record.get("updatedAt") or 0)
    except (TypeError, ValueError):
        it.updated_ts = 0
    it.folder_path = path_of(record.get("folderUuid"))
    it.tags = [t for t in (oc.get("tags") or []) if isinstance(t, str)]
    it.notes = sc.get("notesPlain") or ""

    urls = [record.get("location") or ""]
    for u in sc.get("URLs") or []:
        if isinstance(u, dict):
            urls.append(u.get("url") or "")
    if sc.get("URL"):
        urls.append(sc.get("URL"))

    # Campi dei form web (Login)
    username = password = ""
    for f in sc.get("fields") or []:
        if not isinstance(f, dict):
            continue
        val = fmt_value(None, f.get("value"))
        des = f.get("designation")
        if des == "username" and not username:
            username = val
        elif des == "password" and not password:
            password = val
        elif val and f.get("type") not in WEBFORM_SKIP_TYPES:
            it.fields.append({"n": "form:" + (f.get("name") or ""),
                              "label": "Campo form " + (f.get("name") or f.get("id") or ""),
                              "value": val, "hidden": f.get("type") == "P",
                              "raw": f.get("value"), "k": "string"})
    if not password and sc.get("password"):
        password = fmt_value(None, sc.get("password"))

    # Sezioni (tutti i tipi di elemento)
    for sec in sc.get("sections") or []:
        if not isinstance(sec, dict):
            continue
        sec_title = (sec.get("title") or "").strip()
        for f in sec.get("fields") or []:
            if not isinstance(f, dict):
                continue
            k = f.get("k") or "string"
            n = f.get("n") or ""
            val = fmt_value(k, f.get("v"))
            if val == "":
                continue
            label = (f.get("t") or n or "Campo").strip()
            if is_totp_field(n, val):
                it.totp.append((label, val))
                continue
            if sec_title and sec_title.lower() not in label.lower():
                label = "%s - %s" % (sec_title, label)
            it.fields.append({"n": n, "label": label, "value": val,
                              "hidden": k == "concealed", "raw": f.get("v"), "k": k})

    # Campi "noti" dei tipi generici (server, database, email, router...)
    if not username:
        f = it.take(USERNAME_KEYS)
        username = f["value"] if f else ""
    if not password:
        f = it.take(PASSWORD_KEYS)
        password = f["value"] if f else ""
    f = it.take(URL_KEYS) if it.type_name not in ("webforms.WebForm",) else None
    if f:
        urls.append(f["value"])
    it.urls = dedupe(u.strip() for u in urls if isinstance(u, str))
    it.username, it.password = username, password

    for h in sc.get("passwordHistory") or []:
        if isinstance(h, dict) and h.get("value"):
            it.history.append((str(h.get("value")), ts_to_iso(h.get("time"))))

    # Il primo TOTP valido diventa quello principale
    it.totp.sort(key=lambda t: totp_problem(t[1]) is not None)

    # Tipo di destinazione
    tn = it.type_name
    if tn == "wallet.financial.CreditCard":
        it.kind = "card"
        for key, names in (("cardholder", ("cardholder",)), ("cctype", ("type", "cctype")),
                           ("ccnum", ("ccnum",)), ("cvv", ("cvv",)), ("expiry", ("expiry",))):
            f = it.take(names)
            if f:
                it.card[key] = f
    elif tn == "identities.Identity":
        it.kind = "identity"
        for key in ("firstname", "initial", "lastname", "company", "email", "defphone",
                    "cellphone", "address", "username"):
            f = it.take((key,))
            if f:
                it.identity[key] = f
        if it.username and "username" not in it.identity:
            it.identity["username"] = {"value": it.username}
            it.username = ""
    elif tn in ("webforms.WebForm", "passwords.Password"):
        it.kind = "login"
    elif it.username or it.password or it.totp:
        it.kind = "login"
    else:
        it.kind = "note"
    return it


def load_all(inputs, include_trash):
    """Legge tutte le casseforti. Restituisce (items, stats)."""
    items = []
    stats = {"vaults": [], "parse_errors": [], "types": collections.Counter(),
             "folders": 0, "saved_searches": 0, "trashed": 0, "records": 0}
    for raw in inputs:
        path, vault = resolve_input(raw)
        records, errors = read_1pif(path)
        stats["vaults"].append((vault, path, len(records)))
        stats["parse_errors"].extend("%s: %s" % (vault, e) for e in errors)
        stats["records"] += len(records)
        _, path_of = build_folders(records)
        for r in records:
            tn = r.get("typeName") or "?"
            stats["types"][tn] += 1
            if tn == "system.folder.Regular":
                stats["folders"] += 1
                continue
            if tn.startswith("system.folder."):
                stats["saved_searches"] += 1
                continue
            if tn.startswith("system."):
                continue
            it = normalize(r, vault, path_of)
            if it.trashed:
                stats["trashed"] += 1
                if not include_trash:
                    continue
            items.append(it)
    return items, stats


# --------------------------------------------------------------------------
# Report di verifica
# --------------------------------------------------------------------------

def host_of(url):
    u = url if "://" in url else "http://" + url
    try:
        h = (urlparse(u).hostname or "").lower()
    except ValueError:
        return ""
    return h[4:] if h.startswith("www.") else h


def label_of(it):
    t = it.title or "(senza titolo)"
    where = "/".join([it.vault] + it.folder_path)
    return "%s  [%s]" % (t, where)


def build_report(items, stats, expected=None, include_trash=False, max_list=40):
    out = []
    w = out.append
    now = datetime.datetime.now(datetime.timezone.utc)
    w("# Report verifica export 1Password (.1pif)")
    w("")
    w("Generato: %s - onepif_tool %s" % (now.strftime("%Y-%m-%d %H:%M UTC"), VERSION))
    w("Il report NON contiene password, segreti TOTP o note. Contiene pero' i titoli degli")
    w("elementi: trattalo comunque come documento riservato.")
    w("")

    # 1. Lettura
    w("## 1. Lettura dei file")
    w("")
    for vault, path, n in stats["vaults"]:
        w("- Cassaforte **%s**: %d record (%s)" % (vault, n, path))
    if stats["parse_errors"]:
        w("- **ERRORI DI LETTURA (%d)**:" % len(stats["parse_errors"]))
        for e in stats["parse_errors"][:max_list]:
            w("  - %s" % e)
    else:
        w("- Nessun errore di lettura.")
    w("")

    # 2. Conteggi
    real_types = {k: v for k, v in stats["types"].items() if not k.startswith("system.")}
    total_items = sum(real_types.values())
    w("## 2. Conteggi")
    w("")
    w("| Tipo 1Password | Etichetta | N. |")
    w("|---|---|---:|")
    for tn, n in sorted(real_types.items(), key=lambda x: -x[1]):
        w("| `%s` | %s | %d |" % (tn, TYPE_LABELS.get(tn, "altro"), n))
    w("| | **Totale elementi** | **%d** |" % total_items)
    w("")
    w("- Cartelle: %d - Ricerche salvate (ignorate): %d" % (stats["folders"], stats["saved_searches"]))
    w("- Elementi nel cestino: %d (%s)" % (
        stats["trashed"], "INCLUSI nella conversione" if include_trash else "esclusi dalla conversione"))
    w("- Elementi che verranno convertiti: **%d**" % len(items))
    if expected is not None:
        if expected == total_items:
            w("- Controllo atteso: **OK** (%d elementi come indicato dal backup)" % expected)
        else:
            w("- Controllo atteso: **ATTENZIONE** - attesi %d, trovati %d (differenza %+d). "
              "Hai esportato tutte le casseforti? Il conteggio del backup puo' includere "
              "il cestino o elementi di sistema." % (expected, total_items, total_items - expected))
    w("")

    by_kind = collections.Counter(it.kind for it in items)
    w("Destinazione nel nuovo gestore: login %d, note %d, carte %d, identita' %d." % (
        by_kind["login"], by_kind["note"], by_kind["card"], by_kind["identity"]))
    w("")

    def listing(title, rows, note=None):
        w("### %s (%d)" % (title, len(rows)))
        w("")
        if note:
            w(note)
            w("")
        for r in rows[:max_list]:
            w("- %s" % r)
        if len(rows) > max_list:
            w("- ... e altri %d" % (len(rows) - max_list))
        if not rows:
            w("- nessuno")
        w("")

    # 3. TOTP
    w("## 3. Autenticazione a due fattori (TOTP)")
    w("")
    with_totp = [it for it in items if it.totp]
    bad_totp, multi_totp, non_login_totp = [], [], []
    for it in with_totp:
        for lab, val in it.totp:
            p = totp_problem(val)
            if p:
                bad_totp.append("%s - campo \"%s\": %s" % (label_of(it), lab, p))
        if len(it.totp) > 1:
            multi_totp.append("%s - %d codici" % (label_of(it), len(it.totp)))
        if it.type_name not in ("webforms.WebForm", "passwords.Password"):
            non_login_totp.append("%s (%s)" % (label_of(it), TYPE_LABELS.get(it.type_name, it.type_name)))
    w("- Elementi con TOTP: **%d**" % len(with_totp))
    w("")
    listing("TOTP non validi", bad_totp,
            "Questi codici probabilmente non funzioneranno dopo l'import: verificali a mano "
            "(e tieni pronti i codici di recupero del sito).")
    listing("Elementi con piu' di un TOTP", multi_totp,
            "Bitwarden supporta un solo TOTP per login: il primo va nel campo TOTP, gli altri "
            "diventano campi nascosti (senza generazione del codice).")
    listing("TOTP su elementi che non sono Login", non_login_totp,
            "Verranno convertiti come Login, altrimenti il codice non sarebbe generato.")

    # 4. Qualita' dei dati
    w("## 4. Qualita' dei dati")
    w("")
    logins = [it for it in items if it.kind == "login"]
    listing("Login senza password", [label_of(it) for it in logins if not it.password and not it.totp])
    listing("Login senza URL", [label_of(it) for it in logins if not it.urls],
            "Senza URL l'autocompilazione nel nuovo gestore non funziona.")
    listing("Elementi senza titolo", [label_of(it) for it in items if not it.title])

    groups = collections.defaultdict(list)
    for it in logins:
        hosts = dedupe(host_of(u) for u in it.urls) or [""]
        key = (hosts[0], it.username.lower())
        if key[0] or key[1]:
            groups[key].append(it)
    dups = []
    for (h, u), its in sorted(groups.items()):
        if len(its) > 1:
            same_pw = len(set(x.password for x in its)) == 1
            dups.append("%s / %s -> %d elementi%s: %s" % (
                h or "(nessun sito)", u or "(nessun utente)", len(its),
                " (password IDENTICA: probabile doppione)" if same_pw else " (password diverse)",
                "; ".join(x.title or "?" for x in its)))
    listing("Possibili doppioni (stesso sito + stesso utente)", dups,
            "Prima dell'import puoi eliminarli in 1Password 7, oppure dopo nel nuovo gestore.")

    pw_groups = collections.defaultdict(list)
    for it in logins:
        if it.password:
            pw_groups[hashlib.sha256(it.password.encode("utf-8")).hexdigest()].append(it)
    reused = []
    for its in pw_groups.values():
        hosts = set(dedupe(host_of(u) for x in its for u in x.urls[:1]))
        if len(its) > 1 and len(hosts) > 1:
            reused.append("%d elementi: %s" % (len(its), "; ".join(sorted(x.title or "?" for x in its))))
    reused.sort(key=lambda s: -int(s.split()[0]))
    listing("Password riutilizzate su siti diversi", reused)

    weak = [label_of(it) for it in logins if it.password and len(it.password) < 8]
    listing("Password corte (meno di 8 caratteri)", weak)

    five_years = (now - datetime.timedelta(days=5 * 365)).timestamp()
    old = [it for it in logins if it.password and 0 < it.updated_ts < five_years]
    w("- Login non modificati da oltre 5 anni: %d (da rivedere con calma dopo la migrazione)" % len(old))
    w("- Elementi con campi personalizzati/sezioni: %d" % sum(1 for it in items if it.fields))
    w("- Elementi con storico password: %d" % sum(1 for it in items if it.history))
    w("- Elementi con tag: %d - Preferiti: %d" % (
        sum(1 for it in items if it.tags), sum(1 for it in items if it.favorite)))
    w("")

    # 5. Promemoria
    w("## 5. Cose che il .1pif NON contiene")
    w("")
    w("- **Allegati**: il formato .1pif non li esporta. Salva a mano i 7 allegati da 1Password 7")
    w("  (apri l'elemento, clic destro sull'allegato, Salva) e ricaricali nel nuovo gestore.")
    w("- **Passkey**: 1Password 7 non le gestisce; se ne hai create con 1Password 8, vanno ricreate.")
    w("- **Ricerche salvate**: ignorate.")
    w("")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# Esportazione Bitwarden (JSON non cifrato, importabile anche da Vaultwarden
# e da KeePassXC 2.8+)
# --------------------------------------------------------------------------

def bw_field(name, value, hidden=False):
    return {"name": name, "value": value, "type": 1 if hidden else 0, "linkedId": None}


def to_bitwarden(items, vault_prefix):
    folders, folder_ids, bw_items = [], {}, []
    for it in items:
        parts = ([it.vault] if vault_prefix else []) + it.folder_path
        folder_name = "/".join(parts)
        fid = None
        if folder_name:
            if folder_name not in folder_ids:
                folder_ids[folder_name] = str(uuid.uuid4())
                folders.append({"id": folder_ids[folder_name], "name": folder_name})
            fid = folder_ids[folder_name]

        fields = [bw_field(f["label"], f["value"], f["hidden"]) for f in it.fields]
        if it.tags:
            fields.append(bw_field("Tag 1Password", ", ".join(it.tags)))
        entry = {
            "id": str(uuid.uuid4()),
            "organizationId": None,
            "folderId": fid,
            "type": 2,
            "reprompt": 0,
            "name": it.title or "(senza titolo)",
            "notes": it.notes or None,
            "favorite": it.favorite,
            "fields": fields,
            "collectionIds": None,
            "creationDate": it.created or None,
            "revisionDate": it.updated or None,
        }
        if it.history:
            entry["passwordHistory"] = [{"lastUsedDate": t or it.updated or None, "password": p}
                                        for p, t in it.history]

        if it.kind == "login":
            entry["type"] = 1
            first_totp = it.totp[0][1] if it.totp else None
            for lab, val in it.totp[1:]:
                fields.append(bw_field("TOTP - " + lab, val, True))
            entry["login"] = {
                "uris": [{"match": None, "uri": u} for u in it.urls],
                "username": it.username or None,
                "password": it.password or None,
                "totp": first_totp,
            }
        elif it.kind == "card":
            entry["type"] = 3
            c = it.card
            exp = str((c.get("expiry") or {}).get("raw") or "")
            brand_raw = (c.get("cctype") or {}).get("value", "")
            entry["card"] = {
                "cardholderName": (c.get("cardholder") or {}).get("value"),
                "brand": CC_BRANDS.get(brand_raw.lower(), brand_raw or None),
                "number": (c.get("ccnum") or {}).get("value"),
                "expMonth": str(int(exp[4:6])) if re.match(r"^\d{6}$", exp) else None,
                "expYear": exp[:4] if re.match(r"^\d{6}$", exp) else None,
                "code": (c.get("cvv") or {}).get("value"),
            }
            if brand_raw and brand_raw.lower() not in CC_BRANDS:
                fields.append(bw_field("Circuito", brand_raw))
            for lab, val in it.totp:
                fields.append(bw_field("TOTP - " + lab, val, True))
        elif it.kind == "identity":
            entry["type"] = 4
            d = it.identity
            g = lambda k: (d.get(k) or {}).get("value")
            addr = (d.get("address") or {}).get("raw")
            addr = addr if isinstance(addr, dict) else {}
            entry["identity"] = {
                "title": None, "firstName": g("firstname"), "middleName": g("initial"),
                "lastName": g("lastname"), "company": g("company"), "email": g("email"),
                "phone": g("defphone") or g("cellphone"), "username": g("username"),
                "address1": addr.get("street") or (g("address") if not addr else None),
                "address2": None, "address3": None,
                "city": addr.get("city"), "state": addr.get("state") or addr.get("region"),
                "postalCode": addr.get("zip"), "country": addr.get("country"),
                "ssn": None, "passportNumber": None, "licenseNumber": None,
            }
            if g("cellphone") and g("defphone"):
                fields.append(bw_field("Cellulare", g("cellphone")))
            for lab, val in it.totp:
                fields.append(bw_field("TOTP - " + lab, val, True))
        else:
            entry["secureNote"] = {"type": 0}
        bw_items.append(entry)
    return {"encrypted": False, "folders": folders, "items": bw_items}


# --------------------------------------------------------------------------
# Esportazione KeePass 2 XML (per: keepassxc-cli import FILE.xml NUOVO.kdbx)
# --------------------------------------------------------------------------

def kp_uuid(src):
    s = re.sub(r"[^0-9A-Fa-f]", "", src or "")
    raw = bytes.fromhex(s) if len(s) == 32 else uuid.uuid4().bytes
    return base64.b64encode(raw).decode("ascii")


def kp_string(entry, key, value, protect=False):
    s = ET.SubElement(entry, "String")
    ET.SubElement(s, "Key").text = key
    v = ET.SubElement(s, "Value")
    v.text = value or ""
    if protect:
        v.set("ProtectInMemory", "True")


def kp_times(parent, created, updated):
    t = ET.SubElement(parent, "Times")
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ET.SubElement(t, "CreationTime").text = created or now
    ET.SubElement(t, "LastModificationTime").text = updated or created or now
    ET.SubElement(t, "LastAccessTime").text = updated or created or now
    ET.SubElement(t, "ExpiryTime").text = updated or created or now
    ET.SubElement(t, "Expires").text = "False"
    ET.SubElement(t, "UsageCount").text = "0"
    ET.SubElement(t, "LocationChanged").text = updated or created or now


def kp_group(parent, name):
    g = ET.SubElement(parent, "Group")
    ET.SubElement(g, "UUID").text = kp_uuid(None)
    ET.SubElement(g, "Name").text = name
    kp_times(g, None, None)
    ET.SubElement(g, "IsExpanded").text = "True"
    return g


def unique_key(used, key):
    base, n = key, 2
    reserved = ("title", "username", "password", "url", "notes", "otp")
    while key.lower() in used or key.lower() in reserved:
        key = "%s (%d)" % (base, n)
        n += 1
    used.add(key.lower())
    return key


def to_keepass_xml(items, vault_groups, db_name="Migrazione da 1Password"):
    root_el = ET.Element("KeePassFile")
    meta = ET.SubElement(root_el, "Meta")
    ET.SubElement(meta, "Generator").text = "onepif_tool %s" % VERSION
    ET.SubElement(meta, "DatabaseName").text = db_name
    root = ET.SubElement(root_el, "Root")
    top = kp_group(root, "Root")
    groups = {(): top}

    def group_for(path):
        path = tuple(path)
        if path not in groups:
            parent = group_for(path[:-1])
            groups[path] = kp_group(parent, path[-1])
        return groups[path]

    for it in items:
        path = ([it.vault] if vault_groups else []) + it.folder_path
        if it.kind == "card":
            path = path or ["Carte"]
        elif it.kind == "identity":
            path = path or ["Identita'"]
        elif it.kind == "note" and not path:
            path = ["Note sicure"]
        g = group_for(path)
        e = ET.SubElement(g, "Entry")
        ET.SubElement(e, "UUID").text = kp_uuid(it.uuid)
        tags = list(it.tags) + (["Preferito"] if it.favorite else [])
        if tags:
            ET.SubElement(e, "Tags").text = ";".join(t.replace(";", ",") for t in tags)
        kp_times(e, it.created, it.updated)

        used = set()
        username = it.username
        if it.kind == "identity":
            username = (it.identity.get("username") or {}).get("value") or ""
        kp_string(e, "Title", it.title or "(senza titolo)")
        kp_string(e, "UserName", username)
        kp_string(e, "Password", it.password, protect=True)
        kp_string(e, "URL", it.urls[0] if it.urls else "")
        kp_string(e, "Notes", it.notes)
        for i, u in enumerate(it.urls[1:], 1):
            kp_string(e, unique_key(used, "KP2A_URL_%d" % i), u)
        if it.totp:
            lab, val = it.totp[0]
            kp_string(e, "otp", totp_uri(val, it.title, it.username), protect=True)
            for lab, val in it.totp[1:]:
                kp_string(e, unique_key(used, "TOTP " + lab), val, protect=True)
        card_labels = {"cardholder": "Titolare", "cctype": "Circuito", "ccnum": "Numero carta",
                       "cvv": "CVV", "expiry": "Scadenza"}
        for key, f in it.card.items():
            kp_string(e, unique_key(used, card_labels.get(key, key)), f["value"],
                      protect=key in ("ccnum", "cvv"))
        id_labels = {"firstname": "Nome", "initial": "Iniziale", "lastname": "Cognome",
                     "company": "Azienda", "email": "Email", "defphone": "Telefono",
                     "cellphone": "Cellulare", "address": "Indirizzo"}
        for key, f in it.identity.items():
            if key != "username":
                kp_string(e, unique_key(used, id_labels.get(key, key)), f["value"])
        for f in it.fields:
            kp_string(e, unique_key(used, f["label"]), f["value"], protect=f["hidden"])

        if it.history:
            h = ET.SubElement(e, "History")
            for pw, t in it.history:
                he = ET.SubElement(h, "Entry")
                ET.SubElement(he, "UUID").text = kp_uuid(it.uuid)
                kp_times(he, it.created, t or it.created)
                kp_string(he, "Title", it.title or "(senza titolo)")
                kp_string(he, "UserName", username)
                kp_string(he, "Password", pw, protect=True)
                kp_string(he, "URL", it.urls[0] if it.urls else "")
    indent_xml(root_el)
    return '<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n' + \
        ET.tostring(root_el, encoding="unicode") + "\n"


def indent_xml(elem, level=0):
    pad = "\n" + "\t" * level
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = pad + "\t"
        for child in elem:
            indent_xml(child, level + 1)
        if not child.tail or not child.tail.strip():
            child.tail = pad
    if level and (not elem.tail or not elem.tail.strip()):
        elem.tail = pad


# --------------------------------------------------------------------------
# Confronto post-import
# --------------------------------------------------------------------------

def fingerprint(title, username, password, has_totp):
    return (title.strip().lower(), (username or "").strip().lower(),
            hashlib.sha256((password or "").encode("utf-8")).hexdigest()[:16], bool(has_totp))


def fp_from_items(items):
    return collections.Counter(fingerprint(it.title or "(senza titolo)",
                                           it.username if it.kind != "identity" else "",
                                           it.password, it.totp) for it in items)


def fp_from_bitwarden(path):
    with open(path, "r", encoding="utf-8-sig") as fh:
        data = json.load(fh)
    if data.get("encrypted"):
        raise SystemExit("ERRORE: l'export Bitwarden e' cifrato: esporta in formato .json NON cifrato.")
    c = collections.Counter()
    for i in data.get("items", []):
        login = i.get("login") or {}
        c[fingerprint(i.get("name") or "", login.get("username"), login.get("password"),
                      login.get("totp"))] += 1
    return c


def fp_from_keepass_xml(path):
    tree = ET.parse(path)
    c = collections.Counter()
    root = tree.getroot().find("Root")
    # le voci dentro <History> non vanno contate
    hist = set(id(e) for h in root.iter("History") for e in h.findall("Entry"))
    recycle = None
    meta = tree.getroot().find("Meta")
    if meta is not None and meta.findtext("RecycleBinUUID"):
        recycle = meta.findtext("RecycleBinUUID")

    def walk(group, in_bin):
        in_bin = in_bin or (recycle is not None and group.findtext("UUID") == recycle)
        for e in group.findall("Entry"):
            if id(e) in hist or in_bin:
                continue
            s = {x.findtext("Key"): (x.findtext("Value") or "") for x in e.findall("String")}
            c[fingerprint(s.get("Title", ""), s.get("UserName"), s.get("Password"),
                          s.get("otp") or s.get("TOTP Seed"))] += 1
        for g in group.findall("Group"):
            walk(g, in_bin)
    for g in root.findall("Group"):
        walk(g, False)
    return c


def compare(items, other_path):
    if other_path.lower().endswith(".json"):
        other = fp_from_bitwarden(other_path)
    elif other_path.lower().endswith(".xml"):
        other = fp_from_keepass_xml(other_path)
    else:
        raise SystemExit("ERRORE: --con deve essere un export Bitwarden .json (non cifrato) "
                         "o un export KeePassXC .xml (keepassxc-cli export --format xml)")
    mine = fp_from_items(items)
    missing = mine - other
    extra = other - mine
    lines = ["# Confronto originale 1Password vs %s" % os.path.basename(other_path), "",
             "- Elementi originali: %d" % sum(mine.values()),
             "- Elementi nel nuovo gestore: %d" % sum(other.values()),
             "- Corrispondenze esatte (titolo + utente + password + presenza TOTP): %d" %
             sum((mine & other).values()), ""]
    lines.append("## Presenti nell'originale ma non trovati identici (%d)" % sum(missing.values()))
    lines.append("")
    for (t, u, _, tot), n in sorted(missing.items()):
        lines.append("- %s / %s%s%s" % (t or "?", u or "-", " [TOTP]" if tot else "",
                                         " x%d" % n if n > 1 else ""))
    lines.append("")
    lines.append("## Presenti solo nel nuovo gestore (%d)" % sum(extra.values()))
    lines.append("")
    for (t, u, _, tot), n in sorted(extra.items()):
        lines.append("- %s / %s%s%s" % (t or "?", u or "-", " [TOTP]" if tot else "",
                                         " x%d" % n if n > 1 else ""))
    lines.append("")
    lines.append("Un elemento compare in entrambe le liste quando e' stato importato ma con "
                 "password, utente o TOTP diversi: controllalo a mano.")
    ok = not missing and not extra
    lines.append("")
    lines.append("**ESITO: %s**" % ("TUTTO CORRISPONDE" if ok else "CI SONO DIFFERENZE"))
    return "\n".join(lines) + "\n", ok


# --------------------------------------------------------------------------
# Scrittura sicura dei file
# --------------------------------------------------------------------------

def warn_if_cloud(path):
    low = os.path.abspath(path).lower()
    for hint in CLOUD_HINTS:
        if hint in low:
            sys.stderr.write("ATTENZIONE: %s sembra una cartella sincronizzata nel cloud (%s).\n"
                             "I file prodotti contengono password IN CHIARO: usa una cartella "
                             "locale non sincronizzata.\n" % (path, hint))
            return True
    return False


def write_private(path, text):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(description="Verifica e conversione export 1Password 7 (.1pif)")
    sub = p.add_subparsers(dest="cmd")

    def common(sp):
        sp.add_argument("input", nargs="+", help="file .1pif o cartella .1pif (una per cassaforte)")
        sp.add_argument("--includi-cestino", action="store_true",
                        help="includi gli elementi nel cestino (default: esclusi)")
        sp.add_argument("--atteso", type=int, default=None,
                        help="numero di elementi atteso (es. 954) per il controllo di completezza")

    sv = sub.add_parser("verifica", help="analizza l'export e stampa il report")
    common(sv)
    sv.add_argument("--report", help="salva il report anche in questo file .md")

    sc = sub.add_parser("converti", help="report + file di import per il nuovo gestore")
    common(sc)
    sc.add_argument("--out", required=True, help="cartella di destinazione (locale, NON nel cloud)")
    sc.add_argument("--formato", choices=("bitwarden", "keepass", "entrambi"), default="entrambi")
    sc.add_argument("--senza-cassaforte", action="store_true",
                    help="non usare il nome della cassaforte come cartella/gruppo di primo livello")

    scmp = sub.add_parser("confronta", help="verifica post-import contro un export del nuovo gestore")
    common(scmp)
    scmp.add_argument("--con", required=True, help="export Bitwarden .json o KeePassXC .xml")

    args = p.parse_args(argv)
    if not args.cmd:
        p.print_help()
        return 2

    items, stats = load_all(args.input, args.includi_cestino)

    if args.cmd == "confronta":
        text, ok = compare(items, args.con)
        sys.stdout.write(text)
        return 0 if ok else 1

    report = build_report(items, stats, args.atteso, args.includi_cestino)

    if args.cmd == "verifica":
        sys.stdout.write(report)
        if args.report:
            write_private(args.report, report)
        return 1 if stats["parse_errors"] else 0

    out = os.path.abspath(os.path.expanduser(args.out))
    warn_if_cloud(out)
    if not os.path.isdir(out):
        os.makedirs(out, mode=0o700)
    vault_prefix = len(stats["vaults"]) > 1 and not args.senza_cassaforte
    written = [os.path.join(out, "report_verifica.md")]
    write_private(written[0], report)
    if args.formato in ("bitwarden", "entrambi"):
        bw = to_bitwarden(items, vault_prefix)
        path = os.path.join(out, "bitwarden_import.json")
        write_private(path, json.dumps(bw, ensure_ascii=False, indent=2) + "\n")
        written.append(path)
    if args.formato in ("keepass", "entrambi"):
        path = os.path.join(out, "keepass_import.xml")
        write_private(path, to_keepass_xml(items, vault_prefix))
        written.append(path)

    sys.stdout.write(report)
    sys.stdout.write("\nFile creati (permessi 600, CONTENGONO PASSWORD IN CHIARO):\n")
    for w in written:
        sys.stdout.write("  %s\n" % w)
    sys.stdout.write("Cancellali appena terminato e verificato l'import.\n")
    return 1 if stats["parse_errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
