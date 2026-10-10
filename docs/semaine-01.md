# Semaine 1 — Préparation du lab (7 → 10 oct. 2026)

**Objectif** : poser les fondations du lab (réseau isolé, VM Windows, Wazuh
remis en état) et un point de retour propre avant d'ajouter la télémétrie.

**Résultat** : réseau lab `vmbr1` isolé et NATé, VM `dc01` (Server 2022 Core)
et `ws01` (Windows 11 Pro) installées, VM Wazuh à deux interfaces, budget RAM
validé en charge, snapshots `s01-base` sur les trois VM.

| # | Étape | Preuves |
|---|---|---|
| 1 | Inventaire de l'hôte Proxmox | [s01-01](preuves/s01/s01-01-inventaire.txt) |
| 2 | Snapshot de la VM Wazuh avant modification | [s01-02](preuves/s01/s01-02-snapshot.txt), [capture](screenshots/s01-wazuh-snapshot-pre-lab-v2.png) |
| 3 | Bridge lab `vmbr1` + NAT + isolation du LAN | [s01-03](preuves/s01/s01-03-vmbr1.txt), [capture](screenshots/s01-proxmox-reseau.png) |
| 4 | VM Wazuh : interface lab, RAM, stabilité au démarrage | [s01-04](preuves/s01/s01-04-wazuh-avant.txt) → [s01-07](preuves/s01/s01-07-wazuh-manager-fix.txt), [s01-13](preuves/s01/s01-13-wazuh-indexer-timeout.txt), [s01-14](preuves/s01/s01-14-wazuh-boot-ok.txt), [dashboard](screenshots/s01-wazuh-dashboard.png) |
| 5 | ISO | [capture](screenshots/s01-proxmox-isos.png) |
| 6 | VM `dc01` | [s01-08](preuves/s01/s01-08-dc01.txt), [captures](screenshots/s01-dc01-hardware.png) |
| 7 | VM `ws01` + test d'isolation | [s01-09](preuves/s01/s01-09-ws01-creation.txt), [s01-10](preuves/s01/s01-10-ws01.txt), [capture](screenshots/s01-isolation-lab-vers-lan.png) |
| 8 | Test de charge + correction du thin provisioning | [s01-11](preuves/s01/s01-11-test-charge.txt), [s01-12](preuves/s01/s01-12-wazuh-discard.txt), [capture](screenshots/s01-proxmox-ram-charge.png) |
| 9 | Snapshots `s01-base` | [s01-15](preuves/s01/s01-15-snapshots-s01-base.txt), [capture](screenshots/s01-wazuh-snapshots.png) |

---

## 1. Inventaire

Proxmox VE 9.2.21, i5-9400F (6 cœurs), 15 Gio de RAM, un seul bridge `vmbr0`
(hôte en 192.168.1.150/24). Stockage `local-lvm` en lvm-thin, donc snapshots
possibles. Seule la VM 109 (Wazuh, Debian 12) fait partie du projet ; les
autres VM de l'hôte sont d'anciens projets, laissées éteintes.

## 2. Point de retour

```bash
qm set 109 --ide2 none,media=cdrom          # ISO d'installation encore montée
qm snapshot 109 pre-lab-v2 --description "Avant projet SOC v2"
cp /etc/network/interfaces /root/interfaces.bak-2026-10-08
```

Les avertissements LVM signalent un thin pool surprovisionné (somme des disques
virtuels > taille du pool). Ce n'est pas bloquant tant que l'occupation réelle
reste sous ~80 % ; elle se suit avec :

```bash
lvs -o lv_name,lv_size,data_percent pve/data
```

## 3. Réseau lab `vmbr1`

Bloc ajouté à `/etc/network/interfaces` de l'hôte
([copie versionnée](../configs/proxmox/vmbr1.interfaces)) :

```
auto vmbr1
iface vmbr1 inet static
    address 10.10.10.1/24
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    bridge-ageing 0
    post-up   echo 1 > /proc/sys/net/ipv4/ip_forward
    post-up   iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o vmbr0 -j MASQUERADE
    post-up   iptables -I FORWARD -i vmbr1 -d 192.168.1.0/24 -j DROP
    post-down iptables -t nat -D POSTROUTING -s 10.10.10.0/24 -o vmbr0 -j MASQUERADE
    post-down iptables -D FORWARD -i vmbr1 -d 192.168.1.0/24 -j DROP
```

- `bridge-ageing 0` : le bridge inonde toutes les trames sur tous ses ports
  (comportement de hub), ce qui permettra à Suricata sur la VM Wazuh de voir
  tout le trafic du lab sans port mirroring.
- NAT vers `vmbr0` pour l'accès Internet du lab ; la règle `FORWARD DROP`
  empêche le lab d'atteindre le LAN.

Le changement a été appliqué à distance (VPN + SSH). Pour ne pas perdre
l'accès en cas d'erreur, un retour arrière automatique a été armé avant
`ifreload`, puis annulé une fois la connexion vérifiée :

```bash
systemd-run --on-active=5min --unit=net-rollback sh -c 'cp /root/interfaces.bak-2026-10-08 /etc/network/interfaces && ifreload -a'
ifquery -a                      # contrôle de syntaxe
ifreload -a
systemctl stop net-rollback.timer
```

## 4. VM Wazuh (109)

**Interface lab et RAM** :

```bash
# hôte
qm set 109 --net1 virtio,bridge=vmbr1,firewall=0 --memory 5120
```

```
# VM : /etc/network/interfaces.d/lab — pas de passerelle sur cette interface
auto enp6s19
iface enp6s19 inet static
    address 10.10.10.10/24
```

La route par défaut reste sur l'interface LAN (`enp6s18`, 192.168.1.40). La
heap de l'indexer était déjà limitée à 2 Go (`/etc/wazuh-indexer/jvm.options`).

**Stabilité au démarrage** : sur ce matériel (2 vCPU, disque SSHD lent),
`wazuh-manager` puis `wazuh-indexer` dépassaient leur délai de démarrage
systemd et étaient marqués `failed` (`Result: timeout`, aucune trace d'OOM).
Correctif par drop-ins systemd ([configs/wazuh/](../configs/wazuh/)) :

| Service | Réglage |
|---|---|
| `wazuh-indexer` | `TimeoutStartSec=600` |
| `wazuh-manager` | `TimeoutStartSec=300`, `After=wazuh-indexer.service` |

Validé par un arrêt/démarrage à froid : indexer prêt en 59 s, manager en 38 s,
les trois services `active`.

## 5. ISO

Sur `local` : Windows Server 2022 (fr-fr, évaluation), Windows 11 (fr-fr,
build 26300), `virtio-win.iso` 0.1.285.

## 6. VM `dc01` (120) — Windows Server 2022 Core

```bash
qm create 120 --name dc01 --ostype win11 --machine q35 --bios ovmf \
  --efidisk0 local-lvm:1,efitype=4m,pre-enrolled-keys=1 \
  --cpu host --cores 2 --memory 2048 --balloon 0 \
  --scsihw virtio-scsi-single --scsi0 local-lvm:40,iothread=1,discard=on \
  --net0 virtio,bridge=vmbr1,firewall=0 \
  --ide2 local:iso/SERVER_WINSERV2022_x64FRE_fr-fr.iso,media=cdrom \
  --ide0 local:iso/virtio-win.iso,media=cdrom \
  --boot 'order=ide2;scsi0' --agent enabled=1
```

- Édition « Standard Evaluation » sans expérience de bureau (Core, 2 Go).
- Pilote de stockage chargé pendant l'installation : `vioscsi\2k22\amd64`.
- Post-installation : pilotes VirtIO (`virtio-win-gt-x64.msi`) **avant** toute
  configuration réseau (sans eux la carte n'existe pas), agent QEMU, puis via
  `sconfig` : IP 10.10.10.20/24, passerelle 10.10.10.1, DNS 1.1.1.1, Bureau à
  distance (NLA), renommage.

**Accès d'administration** : le lab n'étant pas routé depuis le LAN, l'accès
RDP passe par un tunnel SSH via l'hôte Proxmox, seule machine présente sur
les deux réseaux :

```bash
ssh -L 3390:10.10.10.20:3389 root@192.168.1.150   # puis RDP vers localhost:3390
```

Remarque : ISO en français, donc groupes AD localisés (« Admins du domaine »),
à prendre en compte dans les tests Atomic Red Team.

## 7. VM `ws01` (121) — Windows 11 Pro

Mêmes paramètres que `dc01`, plus TPM 2.0, 4 Go avec ballooning (min 2 Go) et
64 Go de disque :

```bash
qm create 121 --name ws01 --ostype win11 --machine q35 --bios ovmf \
  --efidisk0 local-lvm:1,efitype=4m,pre-enrolled-keys=1 \
  --tpmstate0 local-lvm:1,version=v2.0 \
  --cpu host --cores 2 --memory 4096 --balloon 2048 \
  --scsihw virtio-scsi-single --scsi0 local-lvm:64,iothread=1,discard=on \
  --net0 virtio,bridge=vmbr1,firewall=0 \
  --ide2 local:iso/Windows11_Client_x64_fr-fr_26300_9457.iso,media=cdrom \
  --ide0 local:iso/virtio-win.iso,media=cdrom \
  --boot 'order=ide2;scsi0' --agent enabled=1
```

- Édition Pro (l'édition Famille ne peut pas rejoindre un domaine), compte
  local `labadmin` créé sans compte Microsoft (`start ms-cxh:localonly`).
- Pilote de stockage : `vioscsi\w11\amd64`. Post-installation identique à
  `dc01` : IP 10.10.10.30/24, RDP (règle `RemoteDesktop-UserMode-In-TCP`).

**Test d'isolation**, depuis `dc01` et `ws01` :

| Test | Résultat |
|---|---|
| `Test-NetConnection 1.1.1.1 -Port 443` | ✅ `True` (Internet via NAT) |
| `Test-NetConnection 192.168.1.40 -Port 22` | ✅ `False` (LAN inaccessible) |

## 8. Test de charge et stockage

Wazuh, `dc01` et `ws01` allumées ~15 min : **4,6 Gio disponibles sur l'hôte,
aucun swap**. Le budget RAM tient (critère : ≥ 1,5 Gio).

Le goulot est le **disque** : l'hôte n'a qu'un SSHD 2,5" 5400 tr/min
(`ST500LX012`), avec un IO delay de 40 à 80 % pendant le premier démarrage de
Windows 11.

Le même contrôle a révélé un disque Wazuh occupé à 99 % côté thin pool pour
seulement 56 % dans la VM : les blocs libérés n'étaient jamais rendus faute de
`discard`. Correctif :

```bash
# hôte (arrêt/démarrage à froid nécessaire)
qm set 109 --scsi0 local-lvm:vm-109-disk-0,cache=writeback,iothread=1,discard=on
# VM
fstrim -av
systemctl enable --now fstrim.timer
```

Résultat : disque Wazuh 99 % → 56 %, thin pool 60 % → 55 % (~16 Go rendus).

## 9. Point de retour de fin de semaine

```bash
for id in 109 120 121; do qm snapshot $id s01-base --description "Fin semaine 1 - lab de base"; done
```

Sur `dc01`, le dégel VSS (`guest-fsfreeze-thaw`) a dépassé le délai de l'agent
QEMU, conséquence probable du disque lent ; le snapshot est bien créé.

## Enseignements

- Sur un hyperviseur à disque mécanique, les délais de démarrage par défaut des
  services Java (OpenSearch) sont trop courts : prévoir des drop-ins systemd.
- Le thin provisioning sans `discard` donne une image fausse de l'occupation
  réelle : `discard=on` + `fstrim` dès la création des VM.
- Modifier le réseau d'un hôte distant : toujours armer un retour arrière
  automatique avant d'appliquer.

## Suite (semaine 2)

Promotion de `dc01` en contrôleur de domaine `soclab.internal`, jonction de
`ws01`, déploiement de Sysmon et des agents Wazuh.

État initial du dashboard Wazuh à reprendre : trois agents déconnectés hérités
d'anciens projets, à supprimer, et environ 22 000 alertes de bas niveau
(0 à 6) en 24 h générées par le manager lui-même, bruit à analyser avant de
mesurer quoi que ce soit.
