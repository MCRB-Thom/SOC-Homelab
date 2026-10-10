# Configurations versionnées

Chaque fichier ici est la copie exacte de ce qui est déployé dans le lab.
Toute modification passe par ce dossier et est notée dans le CHANGELOG.

| Dossier | Contenu | Semaine |
|---|---|---|
| `proxmox/` | Réseau de l'hôte (`vmbr1`, NAT) | S1 |
| `sysmon/` | Config Sysmon (sysmon-modular ou SwiftOnSecurity) + version | S2–S3 |
| `wazuh/` | Drop-ins systemd indexer/manager (S1), `ossec.conf`, règles et décodeurs locaux | S1–S4 |
| `suricata/` | `suricata.yaml` (extraits utiles), règles locales | S4 |

Aucun mot de passe, clé d'enregistrement d'agent ni certificat n'est versionné ici.
