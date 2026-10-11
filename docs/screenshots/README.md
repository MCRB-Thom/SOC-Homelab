# Captures

Captures d'interfaces graphiques (Proxmox, dashboard Wazuh, Windows). Les
sorties de commandes sont en texte dans [`../preuves/`](../preuves/).

Nommage : `sNN-<sujet>.png`.

## Semaine 1

| Fichier | Contenu |
|---|---|
| `s01-wazuh-snapshot-pre-lab-v2.png` | Snapshot de la VM Wazuh avant toute modification |
| `s01-proxmox-reseau.png` | Réseau de l'hôte : `vmbr0` (LAN) et `vmbr1` (lab) |
| `s01-wazuh-dashboard.png` | Dashboard Wazuh opérationnel (état initial, avant les agents du lab) |
| `s01-proxmox-isos.png` | ISO disponibles sur le stockage `local` |
| `s01-dc01-sconfig.png` | `dc01` installé (Server 2022 Core, `sconfig`) |
| `s01-dc01-hardware.png` | Matériel virtuel de `dc01` |
| `s01-isolation-lab-vers-lan.png` | Test d'isolation : le lab ne joint pas le LAN |
| `s01-proxmox-ram-charge.png` | Résumé de l'hôte avec les trois VM allumées |
| `s01-wazuh-snapshots.png` | Snapshots `pre-lab-v2` et `s01-base` de la VM Wazuh |

## Semaine 2

| Fichier | Contenu |
|---|---|
| `s02-dc01-domaine.png` | Domaine `soclab.internal` opérationnel (AD DS, DNS, Netlogon) |
| `s02-ws01-domaine.png` | Session d'un utilisateur du domaine sur `ws01` |
