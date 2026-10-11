# Semaine 2 — Domaine AD, Sysmon et agents Wazuh (10 → 11 oct. 2026)

**Objectif** : construire le domaine Active Directory, déployer la télémétrie
endpoint (Sysmon) et la raccorder à Wazuh, sur une base d'alertes propre.

**Résultat** : forêt `soclab.internal` opérationnelle, `ws01` joint au domaine,
GPO de lab appliquée, Sysmon v15.22 sur `dc01` et `ws01`, agents Wazuh actifs
avec collecte du canal Sysmon. Le bruit hérité (22 000 alertes/jour) a été
identifié et neutralisé.

| # | Étape | Preuves |
|---|---|---|
| 1 | État initial de Wazuh et origine du bruit | [s02-01](preuves/s02/s02-01-wazuh-etat-initial.txt), [s02-05](preuves/s02/s02-05-wazuh-nettoyage.txt), [s02-06](preuves/s02/s02-06-suricata-existant.txt) |
| 2 | Promotion de `dc01` en contrôleur de domaine | [s02-02](preuves/s02/s02-02-dc01-promotion.txt), [capture](screenshots/s02-dc01-domaine.png) |
| 3 | Structure AD, utilisateur standard, jonction de `ws01` | [s02-03](preuves/s02/s02-03-ws01-jonction.txt), [capture](screenshots/s02-ws01-domaine.png) |
| 4 | GPO de lab et allègement des E/S | [s02-04](preuves/s02/s02-04-gpo-lab.txt) |
| 5 | Arrêt de Suricata, snapshot `s02-domaine` | [s02-07](preuves/s02/s02-07-suricata-arret-snapshot.txt) |
| 6 | Sysmon sur `dc01` et `ws01` | [s02-08](preuves/s02/s02-08-sysmon-dc01.txt), [s02-09](preuves/s02/s02-09-sysmon-ws01.txt) |
| 7 | Agents Wazuh et collecte Sysmon | [s02-10](preuves/s02/s02-10-agent-ws01.txt), [s02-11](preuves/s02/s02-11-agents-wazuh.txt) |

---

## 1. Base d'alertes propre

**Constat** : le dashboard affichait 3 agents déconnectés et ~22 000 alertes de
bas niveau en 24 h, sans aucun agent actif.

**Analyse** (comptage des règles déclenchées dans les fichiers d'alertes) :

| Source | Volume | Nature |
|---|---|---|
| Suricata — `SURICATA STREAM` (out of window, invalid ack) | ~22 100 / jour | anomalies de flux TCP, pas des attaques |
| Règle 12 « System user successfully logged to the system » | 11 | connexions d'administration légitimes (faux positifs) |
| PAM / sshd | ~15 | sessions d'administration |

Une instance Suricata 7.0.10 héritée d'un ancien projet tournait sur la VM
Wazuh et capturait l'interface **LAN** (`enp6s18`) : trafic domestique hors
périmètre, et bruit typique d'une capture sur l'interface d'une VM.

**Actions** :
- suppression des trois agents hérités (`manage_agents -r`) ;
- Suricata arrêté et désactivé jusqu'à sa reconfiguration sur l'interface lab
  (semaine 4) ;
- les faux positifs de niveau 12 sont conservés comme cas d'étude pour
  l'évaluation du classifieur LLM.

## 2. Forêt Active Directory

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName soclab.internal -DomainNetbiosName SOCLAB -InstallDns `
  -SafeModeAdministratorPassword (Read-Host -AsSecureString "Mot de passe DSRM") -Force
```

Contrôles : services NTDS, DNS et Netlogon actifs, niveau fonctionnel
`Windows2016Domain`, résolution interne (`soclab.internal` → 10.10.10.20) et
externe via le redirecteur 1.1.1.1.

## 3. Structure, comptes et jonction

```
soclab.internal
└── OU=Lab                       ← GPO "LAB - Mises a jour manuelles"
    ├── OU=Utilisateurs          ← j.martin (utilisateur standard)
    └── OU=Postes                ← ws01
```

- `j.martin` représente un employé sans privilèges : c'est le compte
  « compromis » des scénarios d'attaque des semaines 5-6.
- Jonction de `ws01` : DNS pointé sur le contrôleur de domaine, puis
  `Add-Computer -OUPath "OU=Postes,OU=Lab,..."`.
- Accès RDP de `j.martin` : ajout au groupe local « Utilisateurs du Bureau à
  distance » par son SID (`S-1-5-32-555`), indépendant de la langue du système.
- Canal sécurisé vérifié (`nltest /sc_verify` → `NERR_Success`).

## 4. GPO de lab

| GPO | Paramètre | Raison |
|---|---|---|
| `LAB - Mises a jour manuelles` | `NoAutoUpdate = 1` | disque lent ; pas de mise à jour pendant un test, pour la reproductibilité |

Le service d'indexation Windows Search est également désactivé sur `ws01`.
Microsoft Defender reste actif : son effet sur les attaques sera mesuré.

## 5. Sysmon

Configuration [sysmon-modular](../configs/sysmon/README.md) `sysmonconfig-15.21.xml`,
figée sur la release `configs-082cba578667` et vérifiée par SHA-256 avant
installation :

```powershell
if ((Get-FileHash "$d\sysmonconfig.xml").Hash -ne "F115AAC5...244B") { <# arrêt #> }
else { & "$d\Sysmon64.exe" -accepteula -i "$d\sysmonconfig.xml" }
```

Sysmon v15.22 actif sur les deux machines. Chaque événement porte le
`RuleName` de la règle qui l'a capturé (`technique_id=T1053,...`). Cette
étiquette indique ce que la règle surveille, pas qu'une attaque a eu lieu :
distinction importante pour le triage.

## 6. Agents Wazuh

- Agent 4.14.6 (même version que le manager), signature Authenticode du paquet
  vérifiée avant installation (`Valid - CN="Wazuh, Inc"`).
- Enrôlement dans le groupe `windows`, dont la configuration centralisée
  ([agent.conf](../configs/wazuh/shared/windows/agent.conf)) ajoute le canal
  `Microsoft-Windows-Sysmon/Operational`, non collecté par défaut.
- Résultat : `ws01` (001) et `dc01` (002) actifs, premiers événements Sysmon
  présents dans les alertes. Modules FIM et SCA (benchmark CIS Windows 11)
  actifs par défaut.

## Limites connues

- **Enrôlement sans mot de passe** : `wazuh-authd` accepte tout nouvel agent.
  Acceptable dans un réseau de lab isolé ; à durcir (mot de passe
  d'enrôlement) avant tout usage hors lab.
- Le snapshot `s02-domaine` précède l'arrêt de Suricata : une restauration le
  réactiverait.

## Suite (semaine 3)

Vérifier dans le dashboard le mapping ATT&CK des événements Sysmon, générer
une activité de test simple sur `ws01` et contrôler la chaîne complète
(Sysmon → agent → règle Wazuh → alerte).
