# -*- coding: utf-8 -*-
"""Test di onepif_tool.py sul file di esempio tests/fixtures/esempio.1pif (dati inventati).

Esecuzione:  python3 -m unittest discover -s tests -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import onepif_tool as t  # noqa: E402

FIXTURE = os.path.join(HERE, "fixtures", "esempio.1pif")
PASSWORD_IN_FIXTURE = ("Segreta-123!", "Nas-Pass-99", "Vecchia-1", "JBSWY3DPEHPK3PXP", "4111111111111111")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.items, self.stats = t.load_all([FIXTURE], include_trash=False)
        self.by_title = {it.title: it for it in self.items}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestLettura(Base):
    def test_conteggi(self):
        self.assertEqual(self.stats["records"], 12)
        self.assertEqual(self.stats["folders"], 2)
        self.assertEqual(self.stats["saved_searches"], 1)
        self.assertEqual(self.stats["trashed"], 1)
        self.assertEqual(len(self.items), 8)
        self.assertEqual(self.stats["parse_errors"], [])

    def test_cestino_incluso(self):
        items, _ = t.load_all([FIXTURE], include_trash=True)
        self.assertEqual(len(items), 9)

    def test_cartella_pacchetto_mac(self):
        pkg = os.path.join(self.tmp, "Personale.1pif")
        os.mkdir(pkg)
        shutil.copy(FIXTURE, os.path.join(pkg, "data.1pif"))
        items, stats = t.load_all([pkg], include_trash=False)
        self.assertEqual(len(items), 8)
        self.assertEqual(stats["vaults"][0][0], "Personale")

    def test_login(self):
        it = self.by_title["Esempio Mail"]
        self.assertEqual(it.kind, "login")
        self.assertEqual(it.username, "mario@example.com")
        self.assertEqual(it.password, "Segreta-123!")
        self.assertEqual(it.folder_path, ["Lavoro"])
        self.assertEqual(len(it.urls), 2)
        self.assertEqual(len(it.totp), 1)
        self.assertTrue(it.favorite)
        self.assertEqual(it.history[0][0], "Vecchia-1")
        labels = [f["label"] for f in it.fields]
        self.assertIn("Sicurezza - Domanda segreta", labels)
        self.assertNotIn("Campo form remember", labels)  # checkbox ignorata

    def test_totp_valido_per_primo(self):
        it = self.by_title["Forum"]
        self.assertIsNone(t.totp_problem(it.totp[0][1]))
        self.assertIsNotNone(t.totp_problem(it.totp[1][1]))

    def test_tipi_generici(self):
        nas = self.by_title["NAS"]
        self.assertEqual((nas.kind, nas.username, nas.password), ("login", "admin", "Nas-Pass-99"))
        self.assertEqual(nas.urls, ["https://nas.local:5001"])
        self.assertEqual(self.by_title["Visa Banca"].kind, "card")
        self.assertEqual(self.by_title["Visa Banca"].folder_path, ["Lavoro", "Banche"])
        self.assertEqual(self.by_title["Mario Rossi"].kind, "identity")
        self.assertEqual(self.by_title["Codici recupero"].kind, "note")


class TestReport(Base):
    def test_report_senza_segreti(self):
        rep = t.build_report(self.items, self.stats, expected=9)
        for secret in PASSWORD_IN_FIXTURE + ("nota di prova", "gatto"):
            self.assertNotIn(secret, rep)
        self.assertIn("Controllo atteso: **OK**", rep)
        self.assertIn("TOTP non validi (1)", rep)
        self.assertIn("probabile doppione", rep)
        self.assertIn("Password riutilizzate su siti diversi (1)", rep)


class TestBitwarden(Base):
    def test_struttura(self):
        bw = t.to_bitwarden(self.items, vault_prefix=False)
        json.dumps(bw)
        self.assertFalse(bw["encrypted"])
        names = {f["name"] for f in bw["folders"]}
        self.assertEqual(names, {"Lavoro", "Lavoro/Banche"})
        items = {i["name"]: i for i in bw["items"]}
        mail = items["Esempio Mail"]
        self.assertEqual(mail["type"], 1)
        self.assertTrue(mail["login"]["totp"].startswith("otpauth://"))
        self.assertEqual(mail["passwordHistory"][0]["password"], "Vecchia-1")
        card = items["Visa Banca"]["card"]
        self.assertEqual((card["brand"], card["expMonth"], card["expYear"]), ("Visa", "12", "2028"))
        ident = items["Mario Rossi"]["identity"]
        self.assertEqual((ident["firstName"], ident["city"], ident["postalCode"]), ("Mario", "Torino", "10100"))
        self.assertEqual(items["Codici recupero"]["type"], 2)
        forum = items["Forum"]
        self.assertEqual(forum["login"]["totp"], "JBSWY3DPEHPK3PXP")
        self.assertTrue(any(f["type"] == 1 and f["name"].startswith("TOTP") for f in forum["fields"]))

    def test_round_trip(self):
        path = os.path.join(self.tmp, "bw.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(t.to_bitwarden(self.items, False), fh)
        _, ok = t.compare(self.items, path)
        self.assertTrue(ok)

    def test_confronto_rileva_differenze(self):
        bw = t.to_bitwarden(self.items, False)
        bw["items"] = [i for i in bw["items"] if i["name"] != "NAS"]
        bw["items"][0]["login"]["password"] = "cambiata"
        path = os.path.join(self.tmp, "bw.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(bw, fh)
        text, ok = t.compare(self.items, path)
        self.assertFalse(ok)
        self.assertIn("nas / admin", text)


class TestKeePass(Base):
    def test_xml_valido(self):
        xml = t.to_keepass_xml(self.items, vault_groups=True)
        root = ET.fromstring(xml.split("\n", 1)[1])
        entries = [e for e in root.iter("Entry")]
        self.assertEqual(len(entries), 9)  # 8 elementi + 1 voce di storico
        path = os.path.join(self.tmp, "kp.xml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(xml)
        _, ok = t.compare(self.items, path)
        self.assertTrue(ok)

    @unittest.skipUnless(shutil.which("keepassxc-cli"), "keepassxc-cli non installato")
    def test_import_reale_keepassxc(self):
        xml_path = os.path.join(self.tmp, "kp.xml")
        db = os.path.join(self.tmp, "test.kdbx")
        exp = os.path.join(self.tmp, "export.xml")
        with open(xml_path, "w", encoding="utf-8") as fh:
            fh.write(t.to_keepass_xml(self.items, vault_groups=False))
        pw = "prova123\n"
        subprocess.run(["keepassxc-cli", "import", "-p", xml_path, db], input=pw * 2,
                       universal_newlines=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        res = subprocess.run(["keepassxc-cli", "show", "-t", db, "Lavoro/Esempio Mail"], input=pw,
                             universal_newlines=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertRegex(res.stdout.strip(), r"^\d{6}$")
        res = subprocess.run(["keepassxc-cli", "export", "-f", "xml", db], input=pw,
                             universal_newlines=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with open(exp, "w", encoding="utf-8") as fh:
            fh.write(res.stdout)
        _, ok = t.compare(self.items, exp)
        self.assertTrue(ok)


class TestCli(Base):
    def test_converti(self):
        out = os.path.join(self.tmp, "out")
        rc = t.main(["converti", FIXTURE, "--out", out, "--atteso", "9"])
        self.assertEqual(rc, 0)
        for name in ("report_verifica.md", "bitwarden_import.json", "keepass_import.xml"):
            p = os.path.join(out, name)
            self.assertTrue(os.path.isfile(p))
            if os.name == "posix":
                self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
