# Configuration Sysmon

| Élément | Valeur |
|---|---|
| Source | [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular), release `configs-082cba578667` (2026-09-18) |
| Fichier | `sysmonconfig-15.21.xml` (configuration par défaut équilibrée, pour Sysmon v15.x, schéma 4.91) |
| SHA-256 | `f115aac5770dae468e5cfb48c58a8b6e37588208a31f1b746812c534577a244b` (vérifié contre `SHA256SUMS` de la release) |
| Licence | MIT, voir [LICENSE-sysmon-modular.md](LICENSE-sysmon-modular.md) |
| Déployé sur | `dc01`, `ws01` |

Choix de sysmon-modular plutôt que la configuration SwiftOnSecurity : règles
organisées par type d'événement et annotées avec les techniques MITRE ATT&CK
(champ `RuleName`), ce qui facilite la mesure de couverture des semaines 5-6.

Le fichier est conservé tel que publié. Toute modification locale sera faite
dans un fichier séparé et documentée ici.
