# Semaine 3 — Reprise, passage sur SSD et chaîne de détection (16 → 18 oct. 2026)

**Objectif** : valider la chaîne complète Sysmon → agent → règle Wazuh → alerte
sur une activité de test, après avoir levé le goulot disque du lab.

**Résultat** : lab repris après un changement de PC d'administration,
VM du projet déplacées sur SSD (démarrage de l'indexer 274 s → 19 s). Premier
test de la chaîne de détection : Sysmon voit 5 commandes de reconnaissance sur
6, Wazuh n'en alerte explicitement que 2, en niveau 3, pendant qu'un faux
positif de niveau 15 passe devant. L'angle mort `nltest` a été expliqué (défaut
de la config sysmon-modular) et fermé : règle Sysmon locale + règle Wazuh 100100
de niveau 8. Bruit PowerShell et OneDrive filtré par deux règles de niveau 0,
vérifiées en conditions réelles (26 fichiers créés, 0 alerte).

| # | Étape | Preuves |
|---|---|---|
| 1 | Reprise et état initial du lab | [s03-01](preuves/s03/s03-01-etat-initial.txt) |
| 2 | Ajout d'un SSD et migration des VM | [s03-02](preuves/s03/s03-02-ssd.txt), [capture](screenshots/s03-proxmox-disques-ssd.png) |
| 3 | Test de la chaîne de détection sur `ws01` | [s03-03](preuves/s03/s03-03-chaine-detection.txt), [capture](screenshots/s03-wazuh-discovery-92031.png), [rafale](screenshots/s03-wazuh-rafale-92200.png) |
| 4 | Angle mort `nltest` : cause, règle Sysmon locale, règle Wazuh 100100 | [s03-03](preuves/s03/s03-03-chaine-detection.txt) (2ᵉ partie), [liste](screenshots/s03-wazuh-regle-100100-liste.png), [détail](screenshots/s03-wazuh-regle-100100-detail.png) |
| 5 | Réglage du bruit : règles 100110 (PSScriptPolicyTest) et 100111 (OneDrive) | [s03-04](preuves/s03/s03-04-reglage-bruit.txt) |

---

## 1. Reprise et état initial

Le PC d'administration a changé : le dépôt a été recloné depuis GitHub. Le lab
tourne sur Proxmox et n'a pas bougé : `wazuh`, `dc01` et `ws01` en marche,
snapshots `s01-base` et `s02-domaine` présents, agents `ws01` (001) et
`dc01` (002) actifs, Suricata toujours arrêté (prévu jusqu'en S4).

La RAM de la VM Wazuh a été portée de 5 à 6 Go ; le budget RAM de l'hôte passe
à ~14 Go sur 16 ([architecture](architecture.md#4-budget-ram-hôte-16-go)).

**Constat** : au redémarrage de Wazuh (pour appliquer la RAM), avec `dc01` et
`ws01` en marche, `wazuh-indexer` a mis **274 s** à démarrer contre 59 s en S1,
avec un load de 10,76 sur 2 vCPU. Le CPU n'était pas en cause : les processus
attendaient le disque. Le délai systemd de 600 s posé en S1 a évité l'échec.

## 2. Passage sur SSD

**Diagnostic** : le disque de l'hôte est un SSHD 2,5" à 5400 tr/min
(`ST500LX012`). Plusieurs VM qui lisent et écrivent de petits blocs en même
temps produisent des accès aléatoires, ce qu'un disque mécanique gère très mal.
C'est le goulot du lab depuis la S1 (IO delay 40 à 80 %).

**Choix du matériel** : la carte mère (MSI H310M PRO-VDH PLUS) n'a pas de slot
M.2, mais a des ports SATA libres. SSD SATA Kingston A400 480 Go (TLC) :
largement suffisant pour les ~150 Go provisionnés des 3 VM du projet. Le gain
attendu porte sur les accès aléatoires, pas sur le débit séquentiel : le NVMe
n'aurait rien changé de notable ici.

**Mise en place** :

- Disque désigné par `/dev/disk/by-id/...` (stable) plutôt que `/dev/sdb`, et
  vérifié non monté avant effacement.
- Stockage lvm-thin `ssd` (pool sur 95 % du VG, marge pour les métadonnées) :
  les snapshots restent possibles.
- `qm disk move` des 6 disques (système, EFI, TPM), VM éteintes : le disque TPM
  ne se déplace pas à chaud, et l'arrêt garantit la cohérence du contrôleur de
  domaine.
- Pas de `vzdump` : le stockage `local` est sur le même disque physique que
  `local-lvm`, il n'apporterait aucune protection de plus. Le point de retour
  est le disque d'origine, conservé par `qm disk move` (`unusedN`) avec ses
  snapshots.
- `fstrim` dans Wazuh : 5,6 Gio de blocs libérés, recopiés par la migration,
  rendus au pool.

**Résultat** :

| Mesure | SSHD | SSD | Gain |
|---|---|---|---|
| Démarrage de l'indexer, Wazuh seul | 58,6 s (S1) | 16,6 s | ×3,5 |
| Démarrage de l'indexer, Windows en marche | 274 s | 19,4 s | ×14 |
| Démarrage du manager, Wazuh seul | 37,9 s (S1) | 18,5 s | ×2 |
| Load average au démarrage | 10,76 | 3,16 | |

Le délai systemd de 600 s n'est plus qu'un garde-fou. Le snapshot `s03-ssd` des
3 VM sert de nouveau point de retour ; le gel/dégel VSS de `dc01`, qui dépassait
le délai de l'agent QEMU en S1, passe désormais sans erreur. Enseignement : sur ce
lab, la RAM et le CPU étaient dimensionnés correctement ; c'est le stockage qui
dégradait tout, et l'écart grandit avec le nombre de VM actives.

## 3. Test de la chaîne de détection

**Scénario** : sur `ws01`, l'utilisateur standard `j.martin` (le compte
« compromis » des scénarios à venir) lance une reconnaissance bénigne mais
typique d'un attaquant qui vient d'obtenir un accès : identité, comptes et
groupes du domaine, contrôleurs de domaine, tâche planifiée créée puis
supprimée.

**Méthode** : comparer, pour chaque commande, ce que Sysmon a journalisé sur
le poste (événement 1, création de processus, lu dans le journal local) et ce
que Wazuh a transformé en alerte (fichier d'alertes du manager).

| Commande | ATT&CK | Vue par Sysmon | Alerte Wazuh |
|---|---|---|---|
| `whoami /all` | T1033 | ✅ | ❌ aucune |
| `net user /domain` | T1087.002 | ✅ | ✅ 92039, niveau 3 |
| `net group "Domain Admins" /domain` | T1069.002 | ✅ | ✅ 92031, niveau 3 |
| `nltest /dclist:soclab.internal` | T1018 | ❌ | ❌ aucune |
| `schtasks /create` | T1053.005 | ✅ | ⚠️ indirecte : 92154, niveau 4 |
| `schtasks /delete` | T1053.005 | ✅ | ⚠️ indirecte : 92154, niveau 4 |

**Analyse** :

- **La chaîne fonctionne** : événement Sysmon → agent → règle Wazuh → alerte
  enrichie (technique MITRE, ligne de commande) en environ 2 s.
- **Couverture partielle** : 2 commandes sur 6 alertées explicitement. Les
  tâches planifiées ne sont repérées qu'au chargement de `taskschd.dll` : l'alerte
  existe, mais ne dit pas quelle tâche a été créée. `whoami` est journalisé mais
  aucune règle ne le relève.
- **Angle mort** : `nltest.exe` a bien tourné (il a affiché le contrôleur de
  domaine), mais Sysmon n'a aucun événement de création de processus pour lui.
  Cause et correction en section 4.
- **Gravité inversée** : toute la reconnaissance sort en niveau 3-4, invisible
  pour un analyste qui filtre à partir du niveau 7. Dans la même fenêtre,
  l'alerte la plus grave (92213, **niveau 15**, le maximum) est un faux positif :
  le fichier `__PSScriptPolicyTest_*.ps1` que PowerShell crée dans `Temp` à
  chaque lancement.
- **Bruit** : les 2 170 alertes 92200 « Scripting file created » de la journée
  viennent toutes de la mise à jour de OneDrive (`OneDriveSetup.exe`), une fois
  par profil utilisateur. Ce sont les deux rafales visibles dans le dashboard.
- **Détail de terrain** : `net group "Domain Admins"` échoue sur un AD en
  français (« Admins du domaine »), mais l'alerte se déclenche quand même :
  Wazuh détecte la tentative, pas son succès.

## 4. Angle mort `nltest` : cause et correction

**Cause** : la configuration sysmon-modular n'enregistre une création de
processus que si elle correspond à une règle d'inclusion, et identifie les
programmes par leur nom d'origine (`OriginalFileName`), pas par le nom du
fichier. Celui de `nltest.exe` est `nltestrk.exe`. Les règles publiées visent
`nltest.exe`, `nltestk.exe` (probable coquille) et `nltestrk.exe` **seulement
avec** `/domain_trusts`. Vérification : `nltest /domain_trusts` journalisé,
`nltest /dclist` non.

**Correction en deux couches** :

| Couche | Fichier | Effet |
|---|---|---|
| Collecte (Sysmon) | [`sysmonconfig-15.21-lab.xml`](../configs/sysmon/README.md#modifications-locales-sysmonconfig-1521-labxml) | règle `OriginalFileName is nltestrk.exe` (T1018) ; fichier publié conservé à part |
| Détection (Wazuh) | [`soclab_rules.xml`](../configs/wazuh/rules/soclab_rules.xml) | règle 100100, niveau 8, T1018 + T1482, utilisateur et ligne de commande dans la description |

Déploiement contrôlé : empreinte SHA-256 vérifiée avant chargement sur
`ws01` et `dc01` (ce dernier par PowerShell à distance depuis `ws01`), et
config Wazuh validée par `wazuh-analysisd -t` avant redémarrage du manager.

**Résultat** : `nltest /dclist` et `nltest /domain_trusts` produisent chacun une
alerte de niveau 8, au-dessus du bruit de reconnaissance (niveau 3-4). Délai
mesuré entre l'événement Sysmon (`systemTime` 13:28:53 UTC) et l'alerte
(15:28:56 heure locale) : environ 3 s.

| Commande | Avant | Après |
|---|---|---|
| `nltest /dclist` | ni journalisé, ni alerté | journalisé (T1018) + alerte 100100 niveau 8 |
| `nltest /domain_trusts` | journalisé (T1482), pas d'alerte | alerte 100100 niveau 8 |

**Enseignement** : une configuration communautaire réputée n'est pas une
garantie de couverture. Il faut tester chaque technique qu'on prétend couvrir,
au niveau de la collecte (l'événement existe-t-il ?) puis de la détection
(une règle le relève-t-elle ?).

## 5. Réglage du bruit

**Objectif** : faire taire les deux sources de faux positifs identifiées en
section 3, sans aveugler la détection. Principe : règles Wazuh enfants de
niveau 0 (aucune alerte), limitées à un couple précis « programme + fichier
créé ».

**Mesurer avant de régler** : le diagnostic a changé deux fois la règle
avant son déploiement.

- Le fichier `__PSScriptPolicyTest_*.ps1` déclenche **trois** règles selon le
  contexte : 92201 et 92205 (niveau 9), 92213 (niveau 15), et pas seulement 92213.
- 20 alertes sur 24 viennent d'un **PowerShell 32 bits lancé par
  `AUTORITE NT\Système`** (probablement l'agent Wazuh, 32 bits, pour ses
  modules : à confirmer), qui écrit dans `C:\Windows\SystemTemp`. Les sessions
  RDP écrivent dans `Temp\1`, `Temp\2`. La première expression ne couvrait
  aucun de ces dossiers : elle n'aurait filtré que 11 alertes sur 24.
- Les 1 085 alertes OneDrive du 17/10 sont l'installation de OneDrive dans le
  nouveau profil `SOCLAB\Administrateur`.

| Règle | Filtre | Reste détecté |
|---|---|---|
| 100110 | `powershell.exe` / `pwsh.exe` crée `__PSScriptPolicyTest_xxxxxxxx.xxx.ps1` dans `Temp`, `Temp\<n>` ou `SystemTemp` (sur 92200, 92201, 92205, 92213) | tout autre script dans `Temp` ; ce nom créé par un autre programme (dont `sdiagnhost.exe`, laissé volontairement) |
| 100111 | `OneDriveSetup.exe` (chemin exact du profil) dépose des fichiers dans le dossier de version de OneDrive (sur 92200) | un `OneDriveSetup.exe` situé ailleurs ; des fichiers hors du dossier de version |

**Tests hors ligne** : [test_soclab_rules.py](../configs/wazuh/rules/test_soclab_rules.py)
rejoue 13 chemins réels ou piégés (faux `OneDriveSetup.exe`, autre script dans
`Temp`, autre programme) contre les expressions des règles, avec les antislashs
doublés des champs eventchannel. À relancer à chaque modification.

**Déploiement** : un premier essai a copié le mauvais fichier ; la chaîne
« empreinte → `wazuh-analysisd -t` → redémarrage » a empêché le redémarrage,
mais l'empreinte était contrôlée trop tard (fichier invalide déjà en place).
Procédure corrigée : `sha256sum -c` **avant** toute installation, copie de
sauvegarde, validation, puis redémarrage.

**Vérification** (preuve en trois points) :

| Contrôle | Résultat |
|---|---|
| Alertes PSScriptPolicyTest avant le déploiement (17/10, 0 h → 16 h 13) | 24, dont 4 de niveau 15 |
| Fichiers `__PSScriptPolicyTest` créés le 18/10 entre 0 h 02 et 0 h 11 (Sysmon, `ws01`) | 26 (14 `.ps1`, 12 `.psm1`) |
| Alertes de l'agent `ws01` sur la même période | 184 (agent actif) |
| Alertes PSScriptPolicyTest après le déploiement | **0** |

Les événements existent et arrivent au manager : c'est la règle 100110 qui
les écarte. Les `.psm1` ne déclenchaient aucune règle par défaut. L'effet de
100111 (OneDrive) se confirmera à la prochaine mise à jour de OneDrive.

**Enseignement** : un réglage se prouve par trois mesures (le bruit avant,
l'événement source toujours présent, l'absence d'alerte après), pas par la
seule disparition des alertes, qui peut aussi venir d'un agent muet.

Ces constats alimentent directement la suite : réglage du bruit (OneDrive,
`__PSScriptPolicyTest`), règles locales pour les angles morts, et matrice de
couverture ATT&CK des semaines 5-6.

## Limites connues

- Test unique, sur un seul poste : les résultats de couverture sont indicatifs.
- Règle 100110 limitée aux `.ps1` ; les `.psm1` du même mécanisme ne déclenchent
  aujourd'hui aucune règle, à revoir si cela change. Parent du PowerShell 32 bits
  système non confirmé.
- Règle 100111 : un faux `OneDriveSetup.exe` placé exactement dans le dossier de
  OneDrive du profil passerait (dossier modifiable par l'utilisateur).
- Le fichier d'alertes est archivé à minuit (`logs/alerts/AAAA/Mois/`) ; une
  ligne de l'archive du 16/10 était illisible (JSON tronqué).

- Les disques d'origine (`unusedN` sur `local-lvm`) et leurs snapshots occupent
  encore de la place sur le SSHD : à supprimer une fois le SSD validé et un
  nouveau snapshot pris.
- Un seul SSD, sans redondance : une panne du SSD fait perdre le lab (hors
  disques d'origine tant qu'ils sont conservés).
- SSD de récupération : SMART `PASSED` mais **21 % d'usure** déjà consommée
  ([capture](screenshots/s03-proxmox-disques-ssd.png)). À surveiller ; des
  sauvegardes hors de l'hôte deviennent souhaitables.
