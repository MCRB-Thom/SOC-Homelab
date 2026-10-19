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

## Semaine 3

| Fichier | Contenu |
|---|---|
| `s03-proxmox-disques-ssd.png` | Disques de l'hôte : SSHD d'origine (`sda`) et SSD Kingston A400 (`sdb`, LVM) |
| `s03-wazuh-ws01-derniere-heure.png` | Alertes de `ws01` sur une heure : deux rafales (~23:27 et ~23:39) : mises à jour OneDrive des profils labadmin et j.martin |
| `s03-wazuh-rafale-92200.png` | Détail de la rafale de 23:39 : ~1 000 alertes 92200 « Scripting file created » en ~20 s, toutes dues à `OneDriveSetup.exe` |
| `s03-wazuh-discovery-92031.png` | Règle 92031 « Discovery activity executed » sur `ws01` (24 h) : 2 alertes pendant le test de 23:37 |
| `s03-wazuh-regle-100100-liste.png` | Règle locale 100100 : 2 alertes de niveau 8 pour `nltest /dclist` et `/domain_trusts` |
| `s03-wazuh-regle-100100-detail.png` | Détail d'une alerte 100100 : MITRE T1018 + T1482 (tactique Discovery), groupes `soclab`, événement Sysmon d'origine (`full_log`) |

## Semaine 4

| Fichier | Contenu |
|---|---|
| `s04-wazuh-suricata-24h.png` | Alertes Suricata dans Wazuh sur 24 h : une seule (le test `uid=0(root)`), plus de bruit `SURICATA STREAM` ; rattachée à l'agent `WAZUH` (la sonde), pas à `ws01` |
| `s04-wazuh-suricata-detail-1.png` | Détail de l'alerte 2100498 : `alert.severity` 2 (classe « Potentially Bad Traffic ») mais `signature_severity` ET « Informational » |
| `s04-wazuh-suricata-detail-2.png` | Suite : capture sur `enp6s19`, httpbin (44.210.74.85:80) → `ws01`, ramenée par Wazuh à la règle 86601 niveau 3 |
