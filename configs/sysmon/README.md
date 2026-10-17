# Configuration Sysmon

| Élément | Valeur |
|---|---|
| Source | [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular), release `configs-082cba578667` (2026-09-18) |
| Fichier | `sysmonconfig-15.21.xml` (configuration par défaut équilibrée, pour Sysmon v15.x, schéma 4.91) |
| SHA-256 | `f115aac5770dae468e5cfb48c58a8b6e37588208a31f1b746812c534577a244b` (vérifié contre `SHA256SUMS` de la release) |
| Licence | MIT, voir [LICENSE-sysmon-modular.md](LICENSE-sysmon-modular.md) |
| Déployé sur | `dc01`, `ws01` (version `-lab` à partir de la S3, voir plus bas) |

Choix de sysmon-modular plutôt que la configuration SwiftOnSecurity : règles
organisées par type d'événement et annotées avec les techniques MITRE ATT&CK
(champ `RuleName`), ce qui facilite la mesure de couverture des semaines 5-6.

Le fichier est conservé tel que publié. Toute modification locale sera faite
dans un fichier séparé et documentée ici.

> **Empreinte** : la copie versionnée ne redonne plus `f115aac5...` (fins de
> ligne normalisées par Git via `* text=auto`). La vérification d'intégrité
> fait foi au moment du téléchargement (S2) ; à refaire contre la release si
> besoin.

## Modifications locales (`sysmonconfig-15.21-lab.xml`)

Configuration réellement déployée à partir de la S3 : le fichier publié, plus
les ajouts ci-dessous. Fichier versionné sans conversion des fins de ligne
(`.gitattributes`), SHA-256
`63bcb62d2d1933f02f0a2f5c4cba9b59db81ead33a26a332fdf2241227e36694`.

| Ajout | Raison | Preuve |
|---|---|---|
| Événement 1 : `OriginalFileName is nltestrk.exe` (T1018) | Le nom d'origine de `nltest.exe` est `nltestrk.exe`. Le fichier publié ne le couvre qu'avec `/domain_trusts` (et vise `nltestk.exe`, probable coquille) : `nltest /dclist` n'était jamais journalisé. | [s03-03](../../docs/preuves/s03/s03-03-chaine-detection.txt) |
