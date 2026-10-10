# Architecture

## 1. État actuel (avant le projet)

Inventaire du 2026-10-07 : Proxmox VE 9.2.21 (noyau 7.0.14-20-pve), 15 Gio
de RAM + 8 Gio de swap. Un seul bridge `vmbr0` (sur `enp2s0`), hôte en
`192.168.1.150/24`, passerelle `192.168.1.1`. Stockage `local` (dir, 72 Go
libres) et `local-lvm` (**lvm-thin**, 172 Go libres → snapshots possibles).

```mermaid
flowchart LR
    subgraph LAN["LAN 192.168.1.0/24 (vmbr0)"]
        PC["PC portable<br/>Win11 — RTX 4050 6 Go<br/>Docker: Ollama (llama3.1:8b)<br/>soc-bridge (Python + SQLite + Streamlit)"]
        subgraph PVE["Proxmox 192.168.1.150 — i5-9400F, 16 Go"]
            WZ["VM 109 Wazuh all-in-one<br/>Debian 12, 2 vCPU, 8 Go<br/>192.168.1.40"]
        end
    end
    PC -- "HTTPS 9200 (indexer)" --> WZ
```

| VMID | Nom | OS | vCPU | RAM | Disque | Réseau |
|---|---|---|---|---|---|---|
| 109 | Wazuh | Debian 12 (q35, CPU host) | 2 | 8 Go → **5 Go** | 42 Go `local-lvm` | `net0` virtio sur `vmbr0` (firewall=1) |

Les autres VM de l'hôte sont d'anciens projets, hors périmètre ; elles restent
éteintes pendant le lab.

## 2. Architecture cible (fin de semaine 4)

```mermaid
flowchart TB
    subgraph LAN["LAN 192.168.1.0/24 — vmbr0"]
        PC["PC portable<br/>Ollama + soc-bridge"]
        BOX["Box / routeur<br/>192.168.1.1"]
    end

    subgraph HOST["Hôte Proxmox"]
        NAT["vmbr1 10.10.10.1<br/>NAT → vmbr0<br/>lab → LAN bloqué"]
    end

    subgraph LAB["Lab isolé 10.10.10.0/24 — vmbr1 (bridge-ageing 0 = hub)"]
        WZ["wazuh (109)<br/>net0 enp6s18: 192.168.1.40 (LAN)<br/>net1 enp6s19: 10.10.10.10 (lab + capture Suricata)"]
        DC["dc01 — 10.10.10.20<br/>AD DS + DNS<br/>Sysmon + agent Wazuh"]
        WS["ws01 — 10.10.10.30<br/>Win11 joint au domaine<br/>Sysmon + agent Wazuh + Atomic Red Team"]
        ATK["attacker (LXC) — 10.10.10.66<br/>Nmap, Hydra, Impacket"]
    end

    PC -- "9200 indexer / 443 dashboard" --> WZ
    DC -- "1514-1515/tcp" --> WZ
    WS -- "1514-1515/tcp" --> WZ
    ATK -. "scans, brute force, Kerberoasting" .-> DC
    ATK -.-> WS
    LAB --> NAT --> BOX
```

### Choix d'architecture

- **Réseau lab isolé (`vmbr1`)** : les attaques et Atomic Red Team restent
  dans le lab. Le lab sort sur Internet via NAT de l'hôte (mises à jour,
  téléchargements) mais **ne peut pas joindre le LAN** (règle `FORWARD DROP`).
- **Wazuh à deux pattes** : une interface LAN pour que le PC accède au
  dashboard/indexer, une interface lab pour les agents. Aucun routage entre
  les deux sur la VM (`net.ipv4.ip_forward=0`).
- **`bridge-ageing 0` sur `vmbr1`** : le bridge oublie immédiatement les
  adresses MAC et inonde toutes les trames sur tous les ports, comme un hub.
  L'interface lab de la VM Wazuh voit donc tout le trafic du lab → Suricata
  peut tourner sur la VM Wazuh, sans VM ni port mirroring dédiés.
- **Attaquant en LXC** : environ 512 Mo au lieu de 2 à 4 Go pour une VM Kali.
- **LLM hors Proxmox** : le PC portable fait l'inférence (6 Go de VRAM). Pour
  l'évaluation (S7–S8), les alertes sont exportées en JSONL ; pas besoin que le
  PC soit connecté au lab en permanence.

## 3. Plan d'adressage

| Hôte | Interface | IP | Passerelle | DNS |
|---|---|---|---|---|
| Hôte Proxmox | vmbr0 | 192.168.1.150 | 192.168.1.1 | box |
| Hôte Proxmox | vmbr1 | 10.10.10.1/24 | — | — |
| wazuh | enp6s18 (vmbr0) | 192.168.1.40 | 192.168.1.1 | box |
| wazuh | enp6s19 (vmbr1) | 10.10.10.10/24 | aucune | — |
| dc01 | vmbr1 | 10.10.10.20/24 | 10.10.10.1 | 127.0.0.1 (redirecteur 1.1.1.1) |
| ws01 | vmbr1 | 10.10.10.30/24 | 10.10.10.1 | 10.10.10.20 |
| attacker | vmbr1 | 10.10.10.66/24 | 10.10.10.1 | 10.10.10.20 |

Domaine AD : `soclab.internal` (NetBIOS `SOCLAB`). `.internal` est réservé à
l'usage privé et évite les conflits mDNS de `.local`.

## 4. Budget RAM (hôte 16 Go)

| Élément | RAM | vCPU | Notes |
|---|---|---|---|
| Hôte Proxmox | ~1,5 Go | — | KSM actif (partage des pages entre les 2 Windows) |
| wazuh (+ Suricata) | 5 Go | 2 | heap indexer limitée à 2 Go (`jvm.options`) |
| dc01 (Server 2022 Core) | 2 Go | 2 | pas d'interface graphique |
| ws01 (Win11) | 4 Go max / 2 Go min | 2 | ballooning ; 4 Go requis à l'installation |
| attacker (LXC Debian 12) | 512 Mo | 1 | |
| **Total** | **~13 Go** | 7 / 6 cœurs | marge ~3 Go |
