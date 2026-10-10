# Journal des modifications

Format : une entrée par session de travail, la plus récente en haut.
Chaque entrée indique ce qui a changé dans le lab, pourquoi, et la preuve
(`docs/preuves/`, `docs/screenshots/`).

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
