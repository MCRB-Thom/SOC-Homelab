"""Tests hors ligne des règles de réglage de soclab_rules.xml.

Usage : python configs/wazuh/rules/test_soclab_rules.py configs/wazuh/rules/soclab_rules.xml
Rejoue des chemins réels (relevés dans les alertes) contre les expressions pcre2 des règles,
avec les antislashs doublés comme dans les champs eventchannel de Wazuh. Le module re de
Python suffit pour les constructions utilisées ici (classes, groupes, quantificateurs).
"""
import re, sys, xml.etree.ElementTree as ET
B = "\\"
src = open(sys.argv[1], encoding="utf-8").read()
root = ET.fromstring("<r>" + src.split("-->", 1)[1] + "</r>")
rules = {r.get("id"): {f.get("name"): f.text for f in r.findall("field")} for r in root.iter("rule")}
d = lambda s: s.replace(B, B * 2)   # Wazuh double les antislashs des champs eventchannel
P32 = r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
P64 = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
tests = [
 ("100110", True,  P64, r"C:\Users\j.martin\AppData\Local\Temp\__PSScriptPolicyTest_5okk3jef.uw0.ps1"),
 ("100110", True,  P64, r"C:\Users\Administrateur\AppData\Local\Temp\2\__PSScriptPolicyTest_ab12cd34.ef5.ps1"),
 ("100110", True,  P32, r"C:\Windows\SystemTemp\__PSScriptPolicyTest_ab12cd34.ef5.ps1"),
 ("100110", True,  P32, r"C:\Windows\Temp\__PSScriptPolicyTest_ab12cd34.ef5.ps1"),
 ("100110", True,  r"C:\Program Files\PowerShell\7\pwsh.exe", r"C:\Windows\Temp\__PSScriptPolicyTest_abcd1234.x1y.ps1"),
 ("100110", False, P64, r"C:\Users\j.martin\AppData\Local\Temp\payload.ps1"),
 ("100110", False, P64, r"C:\Users\j.martin\AppData\Local\MyTemp\__PSScriptPolicyTest_ab12cd34.ef5.ps1"),
 ("100110", False, r"C:\Users\j.martin\Downloads\evil.exe", r"C:\Users\j.martin\AppData\Local\Temp\__PSScriptPolicyTest_5okk3jef.uw0.ps1"),
 ("100110", False, r"C:\Windows\System32\sdiagnhost.exe", r"C:\Windows\Temp\__PSScriptPolicyTest_ab12cd34.ef5.ps1"),
 ("100111", True,  r"C:\Users\Administrateur\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe", r"C:\Users\Administrateur\AppData\Local\Microsoft\OneDrive\26.183.0920.0005\CollectSyncLogs.bat"),
 ("100111", True,  r"C:\Users\j.martin\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe", r"C:\Users\j.martin\AppData\Local\Microsoft\OneDrive\26.183.0920.0005\images\darkTheme\fre_done.js"),
 ("100111", False, r"C:\Users\j.martin\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe", r"C:\Users\j.martin\AppData\Local\Temp\run.ps1"),
 ("100111", False, r"C:\Users\j.martin\Downloads\OneDriveSetup.exe", r"C:\Users\j.martin\AppData\Local\Microsoft\OneDrive\26.183.0920.0005\x.js"),
]
ok = True
for rid, expect, img, tgt in tests:
    f = rules[rid]
    got = bool(re.search(f["win.eventdata.image"], d(img))) and bool(re.search(f["win.eventdata.targetFilename"], d(tgt)))
    ok &= got == expect
    print(("OK " if got == expect else "KO ") + rid, "attendu", "ignoré" if expect else "alerte", "|",
          B.join(img.split(B)[-2:]), "->", B.join(tgt.split(B)[-3:]))
# Règles de gravité Suricata : valeur de alert.metadata.signature_severity -> règle attendue (None = 86601, niveau 3)
SEV = [
 ("Informational", None),                # cas réel : alerte 2100498 du 18/10 (capture s04-wazuh-suricata-detail-1.png)
 ('["Informational"]', None),
 ("Major", "100201"),
 ('["Major"]', "100201"),
 ("Critical", "100200"),
 ('["Critical"]', "100200"),
 ("Minor", "100202"),
 ("", None),                             # règle sans métadonnée ET
 ("Majority", None),                     # piège : mot qui contient "Major"
]
order = ["100200", "100201", "100202"]   # ordre de déclaration dans soclab_rules.xml
for val, expect in SEV:
    got = next((rid for rid in order if re.search(rules[rid]["alert.metadata.signature_severity"], val)), None)
    ok &= got == expect
    print(("OK " if got == expect else "KO ") + "gravité", repr(val), "->", got or "86601 (niveau 3)")
print("TOUS LES TESTS PASSENT" if ok else "ECHEC")
