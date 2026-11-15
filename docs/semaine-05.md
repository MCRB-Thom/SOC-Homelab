# Semaine 5 — tests offensifs depuis `attacker` et couverture ATT&CK (10 → 14 nov. 2026)

> Statut : **en cours** (phase S5-S6). Trois techniques exécutées depuis le
> conteneur `attacker` et mesurées des deux côtés (poste et réseau). La matrice
> de couverture ATT&CK (section 4) est le livrable de la phase ; elle se
> complétera avec les activités Atomic Red Team de la S6.

**Objectif** : générer des attaques réelles depuis le conteneur `attacker`
contre le domaine, et mesurer pour chacune ce que voit le lab (poste via
Sysmon/journaux Windows, réseau via Suricata) et ce que Wazuh en fait vraiment
une alerte — c'est-à-dire séparer *visibilité* et *détection*.

**Résultat** : trois techniques ATT&CK jouées et mesurées. Un **balayage de
ports** que les règles ET Open ne relèvent pas, corrigé par une règle Suricata
locale. Une **force brute SMB** vue intégralement côté contrôleur de domaine
mais dont la corrélation Wazuh n'existe qu'au-delà d'un seuil. Un
**Kerberoasting** invisible pour le SIEM côté poste, rattrapé uniquement par la
sonde réseau. Chaque cas donne une ligne de matrice et, quand il le fallait, une
règle locale ou un angle mort documenté.

| # | Étape | Preuves |
|---|---|---|
| 1 | Balayage de ports (`nmap`) : non détecté par ET Open, règle Suricata locale `sid 1000001` | [s05-01](preuves/s05/s05-01-scan-initial.txt), [s05-02](preuves/s05/s05-02-regle-scan-deploiement.txt) |
| 2 | Re-test du balayage après règle locale : alerte niveau 10 | [s05-03](preuves/s05/s05-03-retest-scan.txt), [capture](screenshots/s05-wazuh-scan-niveau10.png) |
| 3 | Force brute SMB sur `j.martin` : visibilité DC, seuil de corrélation Wazuh | [s05-04](preuves/s05/s05-04-bruteforce-smb.txt) |
| 4 | Kerberoasting de `svc_sql` : angle mort endpoint, détection réseau | [s05-05](preuves/s05/s05-05-kerberoasting.txt), [capture](screenshots/s05-wazuh-kerberoasting-suricata.png) |

---

## 1. Balayage de ports (T1046) — un angle mort d'ET Open, comblé par une règle locale

Un balayage `nmap -sS` depuis `attacker` (10.10.10.66) vers `ws01`
(10.10.10.30) ne déclenchait aucune alerte de balayage : les règles ET Open ne
couvrent pas le scan SYN lui-même. Seule une sonde annexe remontait — la
signature RDP de `nmap` (ET 2036252, niveau 7) — et seulement parce que le port
3389 était ouvert. L'activité de reconnaissance principale passait donc
inaperçue.

Une **règle Suricata locale** (`sid:1000001`) a été ajoutée : elle compte les
paquets SYN par source et lève une alerte au-delà de 30 SYN en 60 secondes
(`threshold: type both, track by_src`), avec `signature_severity Major`.

```
alert tcp any any -> $HOME_NET any (msg:"SOCLAB SCAN Balayage de ports TCP ...";
  flow:to_server; flags:S; threshold:type both,track by_src,count 30,seconds 60;
  classtype:attempted-recon; metadata:signature_severity Major; sid:1000001; rev:1;)
```

La règle est déposée dans `/etc/suricata/rules/local.rules` — **hors** de
`/var/lib/suricata/rules`, que `suricata-update` réécrit — et référencée
explicitement dans `suricata.yaml`. Copie versionnée dans
[`configs/suricata/local.rules`](../configs/suricata/local.rules), vérifiée par
SHA-256 au déploiement.

**Re-test** : les ~100 SYN du balayage produisent **une seule** alerte Wazuh
(`threshold both` : au plus une par source et par minute), niveau 10 via la
règle locale 100201 (lecture de `signature_severity Major`), de 10.10.10.66
vers 10.10.10.30. Délai paquet → alerte : ~1,5 s.

Le choix du seuil (30 SYN / 60 s) est un compromis : assez haut pour ne pas
réagir à une poignée de connexions légitimes, assez bas pour attraper un
`--top-ports 100`. Un attaquant qui ralentit volontairement son scan
(un port toutes les trois secondes) resterait sous le seuil — angle mort
assumé, documenté comme tel.

## 2. Force brute SMB (T1110) — tout voir au DC, ne détecter qu'au-dessus d'un seuil

Force brute d'authentification contre `j.martin` via SMB depuis `attacker`.
Note de méthode : `hydra` a été écarté, son module SMB parlant **SMBv1**
(refusé par le contrôleur de domaine moderne : *invalid reply from target*). Une
boucle `smbclient` (SMBv2/3) l'a remplacé.

**Visibilité (DC)** : totale. Pour cinq mauvais mots de passe suivis du bon, le
journal Security de `dc01` enregistre exactement **5 × 4625** (échecs) et
**1 × 4624** (succès).

**Détection (Wazuh)** : partielle, et c'est l'enseignement. Chaque échec remonte
en règle 60122 (« Logon Failure », niveau 5), mais la règle de corrélation
force brute — **60204** « Multiple Windows Logon Failures », niveau 10 —
**n'existe qu'au-delà de 8 échecs rapprochés**. Vérifié par deux passages :

| Tentatives échouées | Règle 60122 (niveau 5) | Règle 60204 (niveau 10, corrélation) |
|---|---|---|
| 5 | 5 alertes | aucune |
| 10 | 10 alertes | **1 alerte** |

Une force brute courte (sous 8), ou étalée dans le temps pour casser la fenêtre
de corrélation, génère donc des alertes isolées de niveau 5 noyées dans le
bruit, sans jamais l'alerte agrégée qui attire l'œil de l'analyste. Le seuil est
un paramètre de détection à part entière, pas une constante : le connaître,
c'est connaître la façon de passer dessous.

## 3. Kerberoasting (T1558.003) — invisible au SIEM côté poste, vu seulement par le réseau

Mise en place : un compte de service `svc_sql` porteur d'un SPN
(`MSSQL/sql01.soclab.internal:1433`). Depuis `attacker`, avec les simples
identifiants de `j.martin` (utilisateur standard, le compte « compromis »),
Impacket `GetUserSPNs` demande le ticket de service de `svc_sql` et en extrait
un hash **`$krb5tgs$23$`**. Le `23` est le type de chiffrement **RC4-HMAC**
(etype `0x17`), demandé volontairement parce qu'il se casse hors ligne
(hashcat `-m 13100`) bien plus vite qu'AES. Aucune élévation de privilège n'est
requise : tout utilisateur du domaine peut réclamer le ticket de n'importe quel
compte à SPN.

Mesure des deux côtés :

| Source | Ce qui est enregistré | Alerte Wazuh |
|---|---|---|
| **Poste** — `dc01`, journal Security | 1 × événement **4769** pour `svc_sql`, `Ticket Encryption Type 0x17` | **aucune** — le ruleset par défaut ne relève pas le 4769 |
| **Réseau** — Suricata | ticket RC4 sur le fil (réponse TGS du KDC) | ✅ **86601**, niveau 3 — *SURICATA Kerberos 5 weak encryption parameters* (×2) |

Horodatage cohérent : 4769 au DC à 18:09:21, alerte Suricata à 18:09:25, sens
`10.10.10.20 → 10.10.10.66` (la réponse du contrôleur de domaine renvoyant le
ticket chiffré en RC4 à l'attaquant).

**C'est l'angle mort le plus net de la semaine.** L'attaque est *visible*
partout — le DC l'a journalisée, la sonde l'a vue — mais *détectée* seulement
par le réseau, et à un niveau faible (3). Côté poste, le SIEM reste muet : le
4769 est si fréquent en fonctionnement normal qu'aucune règle générique ne le
relève. Ce qui fait le signal ici, c'est le **contraste** : dans ce lab, Server
2022 et Windows 11 négocient en AES, donc une demande Kerberos en RC4 est
anormale. Sur un vrai parc hébergeant de vieux clients RC4, ce contraste
disparaît et le signal réseau se noie à son tour — d'où l'intérêt d'une règle
endpoint ciblée (4769 + etype `0x17` + compte à SPN), piste d'amélioration
notée.

## 4. Matrice de couverture ATT&CK

Pour chaque technique jouée depuis `attacker`, ce que voient les deux points
d'observation et ce que Wazuh en fait une alerte exploitable. « Visible » =
une source l'enregistre ; « Détecté » = Wazuh lève une alerte de niveau utile.

| Technique ATT&CK | Visible (poste) | Visible (réseau) | Détecté par Wazuh | Angle mort | Preuve |
|---|---|---|---|---|---|
| **T1046** Network Service Discovery (balayage de ports) | partiel (journaux Windows) | ✅ (après règle locale) | ✅ 100201, niveau 10 (règle Suricata locale `sid 1000001`) | ET Open ne couvre pas le scan SYN ; scan lent sous le seuil | [s05-02](preuves/s05/s05-02-regle-scan-deploiement.txt), [s05-03](preuves/s05/s05-03-retest-scan.txt) |
| **T1110** Brute Force (SMB) | ✅ 4625 / 4624 (DC) | — (auth locale au DC) | ⚠️ 60122 niveau 5 par échec ; corrélation 60204 niveau 10 seulement à ≥ 8 échecs | force brute courte ou étalée : pas de corrélation | [s05-04](preuves/s05/s05-04-bruteforce-smb.txt) |
| **T1558.003** Kerberoasting | ✅ 4769 RC4 (DC) | ✅ ticket RC4 (Suricata) | ⚠️ réseau seul : 86601 niveau 3 ; **rien côté poste** | 4769 non relevé par défaut ; signal RC4 noyé si clients RC4 légitimes | [s05-05](preuves/s05/s05-05-kerberoasting.txt) |

Pour mémoire, les techniques de reconnaissance de la S3 (T1018 `nltest`,
T1087 énumération de comptes) figurent dans la
[matrice de visibilité de la S4](semaine-04.md#7-matrice-de-visibilité--activité--détecté-par-quoi) ;
elles sont vues côté poste (Sysmon) et relevées par les règles 100100 / 92031.

**Lecture d'ensemble** :

- **Visible n'est pas détecté.** Les trois attaques laissent une trace
  exploitable quelque part ; une seule (le balayage, après ajout d'une règle)
  produit d'emblée une alerte de niveau élevé. La force brute dépend d'un seuil,
  le Kerberoasting d'une sonde réseau à bas niveau.
- **Poste et réseau se complètent.** La force brute ne se voit qu'au poste (DC),
  le Kerberoasting n'est *détecté* qu'au réseau. Retirer l'une des deux sources
  créerait un trou franc dans la couverture.
- **Les seuils et les niveaux sont des décisions de détection.** Seuil de 8 pour
  la corrélation force brute, niveau 3 pour l'alerte Kerberos : deux réglages qui
  déterminent si l'analyste voit l'attaque. Les mesurer, c'est mesurer la vraie
  couverture, pas la couverture affichée.

## Limites connues

- **Microsoft Defender actif** sur `ws01` et `dc01` : il peut bloquer ou altérer
  certaines techniques de la S6 (Atomic Red Team). Son effet sera mesuré
  explicitement plutôt que contourné.
- **Hashes Kerberos non reproduits dans le dépôt** : le `$krb5tgs$` complet est
  cassable hors ligne ; les preuves le tronquent.
- **Mots de passe de test en clair** sur le conteneur `attacker` pendant les
  tests (listes de force brute) : supprimés après usage, jamais versionnés.

## Suite (semaine 6)

Jouer une série Atomic Red Team ciblée sur `ws01` (techniques de Defense
Evasion et de Persistence), mesurer l'effet de Defender, et ajouter les lignes
correspondantes à la matrice de couverture. Prototyper la règle endpoint
Kerberoasting (4769 + etype `0x17` sur comptes à SPN) pour combler l'angle mort
identifié en section 3.
