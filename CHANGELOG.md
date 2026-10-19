# Journal des modifications

Format : une entrée par session de travail, la plus récente en haut.
Chaque entrée indique ce qui a changé dans le lab, pourquoi, et la preuve
(`docs/preuves/`, `docs/screenshots/`).

## 2026-10-18 → 20 — Semaine 4 (en cours) : Suricata sur le lab, conteneur attaquant, gravité des alertes

### Fait
- Mode hub de `vmbr1` vérifié : la VM Wazuh voit le trafic `ws01` ↔ `dc01`, réponses ARP unicast comprises, 0 paquet perdu (`docs/preuves/s04/s04-01-etat-initial.txt`).
- Suricata reconfiguré sur le lab : `HOME_NET` 10.10.10.0/24, capture sur `enp6s19` au lieu du LAN, règles ET Open mises à jour (53 195 actives), drop-in systemd qui coupe GRO/GSO/TSO avant chaque démarrage (`configs/suricata/suricata.service.d/override.conf`, `s04-02`).
- Suricata démarré et activé au boot : +572 Mo de RAM sur la VM Wazuh (1,6 Gio restants), aucune perte de paquets ; redémarrage automatique vérifié (`s04-03`).
- Chaîne trafic → Suricata → Wazuh validée en ~5 s (règle 2100498 via httpbin.org, `testmynids.org` n'existant plus) (`s04-04`).
- Conteneur LXC `attacker` (130) : Debian 12, non privilégié, 10.10.10.66 sur `vmbr1`, disque sur le SSD, Nmap 7.93 et Hydra 9.4, snapshot `s04-base` (`s04-05`).
- Règles Wazuh locales 100200-100202 : niveau des alertes Suricata selon la gravité Emerging Threats (Critical 12, Major 10, Minor 7, Informational inchangé à 3), vérifiées par `wazuh-logtest` sur l'alerte réelle (`s04-06`).

### Constat
- Bruit `SURICATA STREAM` disparu : 1 alerte en 2 jours (coupure des connexions d'agents au redémarrage du manager), contre ~22 000/jour en S2.
- Wazuh ramenait toute alerte Suricata au niveau 3 (règle 86601), et `alert.severity` seule est trop grossière : le test `uid=0(root)` vaut 2 mais ET le classe « Informational ».
- Les alertes Suricata sont rattachées à la sonde (agent `WAZUH`), pas à la machine visée : corrélation par IP nécessaire avec Sysmon.
- `eve.json` : ~20 Mo/jour (tous les flux et le DNS, pas seulement les alertes) ; conservation à vérifier.

## 2026-10-16 → 18 — Semaine 3 : reprise, SSD, test de détection, angle mort nltest, réglage du bruit

### Fait
- Changement de PC d'administration : dépôt recloné depuis GitHub. Le lab (Proxmox) n'a pas bougé : 109, 120 et 121 en marche, snapshots `s01-base` et `s02-domaine` présents, agents `ws01` et `dc01` actifs (`docs/preuves/s03/s03-01-etat-initial.txt`).
- RAM de la VM Wazuh portée de 5 à 6 Go (redémarrage de la VM 109 seule) : `docs/architecture.md` mis à jour, budget RAM à ~14 Go, marge ~2 Go.
- SSD Kingston A400 480 Go ajouté sur un port SATA libre (pas de slot M.2 sur la carte mère) : stockage lvm-thin `ssd`, disques de 109, 120 et 121 déplacés VM éteintes. Les disques d'origine restent en `unusedN` sur `local-lvm`, avec leurs snapshots, comme point de retour. `fstrim` dans Wazuh : 5,6 Gio rendus au pool (`docs/preuves/s03/s03-02-ssd.txt`).
- Résultat : indexer Wazuh démarré en 16,6 s seul (58,6 s en S1) et en 19,4 s avec les Windows en marche (274 s avant), load 3,16 au lieu de 10,76.
- Snapshot `s03-ssd` de 109, 120 et 121 : point de retour sur SSD. Le gel/dégel VSS de `dc01` (en échec de délai en S1) passe sans erreur.
- Test de la chaîne de détection sur `ws01` (reconnaissance par `j.martin`) : Sysmon journalise 5 commandes sur 6, Wazuh en alerte 2 explicitement (92039, 92031, niveau 3) et 2 indirectement (92154, `taskschd.dll`) (`docs/preuves/s03/s03-03-chaine-detection.txt`).
- Angle mort `nltest` corrigé. Cause : le nom d'origine de `nltest.exe` est `nltestrk.exe`, que sysmon-modular 15.21 ne couvre qu'avec `/domain_trusts`. Ajout de `configs/sysmon/sysmonconfig-15.21-lab.xml` (règle `nltestrk.exe`, T1018), déployé sur `ws01` et `dc01` après contrôle SHA-256, et de la règle Wazuh locale 100100 niveau 8 (`configs/wazuh/rules/soclab_rules.xml`). `nltest /dclist` et `/domain_trusts` sont maintenant alertés.
- `.gitattributes` : config Sysmon du lab versionnée sans conversion de fins de ligne ; XML Wazuh forcés en LF.
- Réglage du bruit : règles Wazuh locales de niveau 0 100110 (fichier `__PSScriptPolicyTest` de PowerShell, sur 92200/92201/92205/92213) et 100111 (mise à jour de OneDrive, sur 92200), testées hors ligne (`configs/wazuh/rules/test_soclab_rules.py`, 13 cas). Vérifié : 26 fichiers créés le 18/10, agent actif, 0 alerte (24 la veille, dont 4 de niveau 15) (`docs/preuves/s03/s03-04-reglage-bruit.txt`).
- Procédure de déploiement des règles : `sha256sum -c` avant installation, sauvegarde, `wazuh-analysisd -t`, puis redémarrage (un premier essai avec le mauvais fichier a été bloqué par la validation).

### Constat
- `whoami` journalisé par Sysmon mais sans alerte Wazuh : angle mort restant.
- La copie versionnée de `sysmonconfig-15.21.xml` ne redonne plus l'empreinte publiée (fins de ligne normalisées par Git).
- Faux positifs identifiés puis filtrés (ci-dessus) : `__PSScriptPolicyTest` (24 alertes/jour, niveaux 9 à 15, dont 20 venant d'un PowerShell 32 bits lancé par le système, probablement l'agent Wazuh) et mises à jour de OneDrive (1 085 alertes par profil).
- Avant le SSD, redémarrage de Wazuh avec `dc01` et `ws01` déjà en marche : `wazuh-indexer` met 274 s à démarrer (contre 59 s en S1), avec un load de 10,76 sur 2 vCPU (attente disque). Le délai de 600 s tient. Cause : le SSHD ; résolu par le passage sur SSD (ci-dessus).

## 2026-10-11 — Semaine 2 : domaine AD, Sysmon, agents Wazuh

### Fait
- Bruit Wazuh identifié : ~22 000 alertes/jour `SURICATA STREAM` venant d'un Suricata hérité qui capturait le LAN. Suricata arrêté jusqu'à la semaine 4 ; 3 agents hérités supprimés.
- Forêt `soclab.internal` (dc01), OU `Lab/Utilisateurs` et `Lab/Postes`, utilisateur standard `j.martin`, `ws01` joint au domaine.
- GPO `LAB - Mises a jour manuelles` liée à `OU=Lab` ; Windows Search désactivé sur `ws01`.
- Sysmon v15.22 + sysmon-modular 15.21 (SHA-256 vérifié) sur `dc01` et `ws01` (`configs/sysmon/`).
- Agents Wazuh 4.14.6 (signature vérifiée) sur `dc01` et `ws01`, groupe `windows` avec collecte du canal Sysmon (`configs/wazuh/shared/windows/agent.conf`).
- Snapshot `s02-domaine` (109, 120, 121).

### Limites
- Enrôlement des agents sans mot de passe (lab isolé uniquement).

## 2026-10-10 — Semaine 1 : ws01

### Fait
- VM `ws01` (121) : Windows 11 Professionnel, 2 vCPU, 4 Go (ballooning, min 2 Go), 64 Go, TPM 2.0, sur `vmbr1`.
- Compte local `labadmin`, pilotes VirtIO + agent QEMU, IP 10.10.10.30/24, RDP activé.
- Isolation vérifiée depuis `dc01` et `ws01` : Internet OK, ni Wazuh (192.168.1.40) ni la box joignables depuis le lab.
- Test de charge (109 + 120 + 121 allumées) : 4,6 Gio de RAM disponibles, aucun swap → **budget RAM validé**.
- Corrigé : `wazuh-indexer` tué au boot à froid (délai de 180 s dépassé à cause du disque SSHD). Drop-in `TimeoutStartSec=600` pour l'indexer, manager démarré `After=wazuh-indexer.service`. Validé par un arrêt/démarrage à froid : indexer en 59 s, manager en 38 s, les 3 services `active`.
- Corrigé : disque thin de Wazuh à 99 % alors que le système de fichiers était à 56 %. `discard=on` sur `scsi0` + `fstrim` + `fstrim.timer` → 56 %, environ 16 Go rendus au thin pool (60 % → 55 %).

- Snapshots `s01-base` de 109, 120 et 121 : point de retour du lab de base (fin de semaine 1).

### Constat
- Snapshot de `dc01` : le dégel VSS (`guest-fsfreeze-thaw`) a dépassé le délai de l'agent QEMU (disque lent). Le snapshot est créé ; état du système de fichiers à vérifier (`qm guest cmd 120 fsfreeze-status`).
- Disque de l'hôte = SSHD 2,5" 5400 tr/min (`ST500LX012`) : IO delay de 40 à 80 % au premier démarrage de Windows. C'est le vrai goulot du lab, avant la RAM. Piste S2 : calmer les Windows (mises à jour en pause, indexation coupée) et éviter les démarrages simultanés.

## 2026-10-09 — Semaine 1 : dc01

### Fait
- VM `dc01` (120) : Windows Server 2022 Standard Evaluation **Core**, 2 vCPU, 2 Go, 40 Go, sur `vmbr1`.
- Pilotes VirtIO + agent QEMU installés, IP 10.10.10.20/24, RDP activé (NLA), accès Internet via NAT vérifié.
- Accès d'administration avec copier-coller : RDP à travers un tunnel SSH par l'hôte Proxmox (`ssh -L 3390:10.10.10.20:3389`).

## 2026-10-08 — Semaine 1 : snapshot

### Fait
- ISO Debian démontée de la VM 109 (`ide2`).
- Snapshot `pre-lab-v2` de la VM 109 (point de retour avant toute modification).
- Sauvegarde de `/etc/network/interfaces` de l'hôte dans `/root/interfaces.bak-2026-10-08`.

- Bridge lab `vmbr1` (10.10.10.1/24) créé sur l'hôte, NAT vers `vmbr0` actif, accès lab → LAN bloqué. Appliqué via SSH/VPN avec un retour arrière automatique (`systemd-run --on-active=5min`) en filet de sécurité.

- VM Wazuh : 2ᵉ carte `enp6s19` sur `vmbr1` en 10.10.10.10/24 (sans passerelle), RAM 8 → 5 Go. Heap indexer déjà à 2 Go.
- Corrigé : `wazuh-manager` en échec au boot (`timeout`, pas d'OOM). Drop-in systemd `TimeoutStartSec=300` (`configs/wazuh/`). Validé par un reboot : les 3 services sont `active`.

- ISO déjà présentes sur `local` : Windows Server 2022 (fr-fr), Windows 11 (fr-fr, build 26300), `virtio-win.iso` (capture `s01-proxmox-isos.png`).

### Constat
- VM Wazuh à 5 Go : ~1,1 Go disponible et un peu de swap après boot. Passer à 6 Go si le swap grimpe avec les agents ou Suricata.
- Thin pool `pve/data` surprovisionné (572 Gio virtuels pour un pool plus petit). À surveiller avec `lvs` avant d'ajouter `dc01` et `ws01`.

## 2026-10-07 — Semaine 1 : préparation

### Ajouté
- `README.md` : présentation du projet, architecture cible, feuille de route.
- `docs/architecture.md` : schéma de l'état actuel et de la cible, plan IP, budget RAM pour 16 Go.
- `docs/semaine-01.md` : compte rendu technique de la semaine (procédure, résultats, enseignements).
- `configs/proxmox/vmbr1.interfaces` : bridge du lab isolé avec NAT.

### Modifié
- `PREREQUIS.md` : GPU réel (RTX 4050 Laptop, 6 Go) ; Wazuh tourne sur Proxmox, plus en Docker sur le PC.
- `docker-compose.yml` : le service `soc-bridge` (commenté) pointe vers l'indexer Wazuh sur Proxmox.

### Décisions
- Lab isolé sur `vmbr1` (10.10.10.0/24), NAT vers Internet, pas d'accès au LAN.
- Suricata sur la VM Wazuh (2ᵉ interface) grâce à `bridge-ageing 0`, pour économiser une VM.
- Attaquant en LXC plutôt qu'en VM Kali (RAM limitée à 16 Go).
- DC en Windows Server 2022 Core (2 Go).

### Inventaire Proxmox
- PVE 9.2.21, 15 Gio RAM, `local-lvm` en lvm-thin (172 Go libres), un seul bridge `vmbr0` (192.168.1.150/24).
- Seule la VM 109 (Wazuh, Debian 12, 2 vCPU, 8 Go, disque sur `local-lvm`) fait partie du projet ; les autres VM sont d'anciens projets, hors périmètre.
