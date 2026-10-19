# Semaine 4 — Suricata sur le lab, conteneur attaquant, gravité des alertes (18 → 20 oct. 2026)

> Statut : **en cours**. Le livrable « activité → détecté par quoi » (section 7) reste à produire.

**Objectif** : ajouter la détection réseau (Suricata, règles ET Open) à la chaîne
Wazuh, sur le trafic du lab, et préparer une machine attaquante pour les tests.

**Résultat** : Suricata, hérité de la S2 où il capturait le LAN domestique et
produisait ~22 000 alertes `SURICATA STREAM` par jour, a été reconfiguré pour
le lab : interface de capture, `HOME_NET`, règles ET à jour, et délestages
matériels (GRO/GSO/TSO) coupés à chaque démarrage. Bruit `STREAM` : **1 alerte
en 2 jours**, expliquée. Chaîne trafic → Suricata → Wazuh validée en ~5 s. Le
conteneur `attacker` (LXC, 512 Mo) est en place. Wazuh ramenait toute alerte
Suricata au niveau 3 : trois règles locales lui donnent désormais le niveau
correspondant à la gravité évaluée par Emerging Threats. Conservation des
journaux vérifiée : aucun risque de saturation sur la durée du projet.

| # | Étape | Preuves |
|---|---|---|
| 1 | État initial, vérification du mode hub de `vmbr1` | [s04-01](preuves/s04/s04-01-etat-initial.txt) |
| 2 | Reconfiguration de Suricata (interface, `HOME_NET`, règles, drop-in systemd) | [s04-02](preuves/s04/s04-02-reconfiguration-suricata.txt) |
| 3 | Démarrage, impact RAM, redémarrage automatique | [s04-03](preuves/s04/s04-03-demarrage-suricata.txt) |
| 4 | Test de bout en bout trafic → Suricata → Wazuh | [s04-04](preuves/s04/s04-04-test-bout-en-bout.txt), [24 h](screenshots/s04-wazuh-suricata-24h.png), [détail 1](screenshots/s04-wazuh-suricata-detail-1.png), [détail 2](screenshots/s04-wazuh-suricata-detail-2.png) |
| 5 | Conteneur attaquant `attacker` (130) | [s04-05](preuves/s04/s04-05-conteneur-attaquant.txt) |
| 6 | Gravité des alertes Suricata : règles 100200-100202 | [s04-06](preuves/s04/s04-06-gravite-suricata.txt) |
| 7 | Conservation des journaux (Suricata, indexer) | [s04-07](preuves/s04/s04-07-conservation-journaux.txt) |

---

## 1. État initial et mode hub

Suricata 7.0.10 était arrêté et désactivé depuis la S2, avec une configuration
héritée inadaptée : capture sur `enp6s18` (LAN) et `HOME_NET` = 192.168.1.0/24.
Règles ET datant du 8 juillet.

Toute l'architecture repose sur `bridge-ageing 0` sur `vmbr1` : le bridge
n'apprend aucune adresse MAC et diffuse chaque trame sur tous ses ports, comme
un hub. **Test** : pendant un `ping` de `ws01` vers `dc01`, `tcpdump` sur
l'interface lab de la VM Wazuh capture les échanges ICMP **et les réponses ARP
unicast** entre deux machines qui ne la concernent pas, sans perte. Suricata
verra donc le trafic est-ouest du lab.

> **En entreprise**, on n'utilise pas de hub (diffuser tout le trafic partout
> coûte en bande passante et en confidentialité). La sonde reçoit une copie du
> trafic par **port mirroring** (SPAN, configuré sur le commutateur) ou par un
> **TAP** réseau (boîtier passif inséré sur le lien, qui ne perd rien même sous
> charge). Le mode hub est ici un raccourci de lab, sans équivalent en production.

## 2. Reconfiguration de Suricata

Avant toute modification : copie de `suricata.yaml` et snapshot Proxmox
`s04-avant` de la VM 109.

**Comment le service démarre** : l'unité systemd lance Suricata en mode
`--af-packet` et lit l'interface dans `suricata.yaml`. Le fichier
`/etc/default/suricata` (mode `nfqueue`, `eth0`) n'est référencé par aucune
`EnvironmentFile` : il est ignoré. Le modifier n'aurait rien changé.

| Changement | Avant | Après |
|---|---|---|
| `HOME_NET` | `[192.168.1.0/24]` (LAN) | `[10.10.10.0/24]` (lab) |
| Interface `af-packet` | `enp6s18` (LAN) | `enp6s19` (lab) |
| Règles ET Open | 8 juillet | 18 octobre : 69 151 règles, 53 195 actives (`suricata-update`, testé par `suricata -T`) |
| GRO / GSO / TSO sur `enp6s19` | activés | coupés à chaque démarrage (drop-in systemd) |

**Pourquoi couper GRO/GSO/TSO** : ces délestages font fusionner les paquets
par la carte réseau (ici virtio) avant qu'ils n'atteignent la capture. Suricata
voit alors des « paquets » plus gros que ce qui a circulé sur le fil, et son
moteur de suivi des flux TCP les juge anormaux : c'est la cause probable des
~22 000 alertes `SURICATA STREAM` par jour de la S2.

**Drop-in systemd** : petit fichier placé dans `suricata.service.d/` qui
complète l'unité du paquet sans la modifier (une mise à jour du paquet ne
l'écrase pas). Ici, une ligne `ExecStartPre=/usr/sbin/ethtool -K enp6s19 gro
off gso off tso off` exécutée avant chaque lancement de Suricata
([override.conf](../configs/suricata/suricata.service.d/override.conf),
déployé après contrôle SHA-256).

## 3. Démarrage et impact

| Mesure | Avant | Après (~6 min) |
|---|---|---|
| RAM utilisée (VM Wazuh, 6 Go) | 3 716 Mo | 4 288 Mo (**+572 Mo**) |
| RAM disponible | 2 208 Mo | 1 636 Mo |
| RSS de Suricata | | 550 Mo |
| Load average | 0,00 | 0,07 |
| Paquets capturés / perdus | | 1 248 / 0 |

Suricata est activé au démarrage. **Redémarrage de la VM le 19/10** : Suricata
repart 4 s après le système, 53 195 règles chargées sans échec, et
GRO/GSO/TSO sont de nouveau coupés : le réglage tient.

**Bruit** : 2 alertes Suricata en 2 jours (18/10 15 h 20 → 19/10 23 h 47) :
le test de la section 4, et un seul `SURICATA STREAM suspected RST injection`
du manager Wazuh (port 1514) vers `dc01` au moment du redémarrage (connexions
d'agents coupées dont Suricata n'avait pas vu l'ouverture). Faux positif
expliqué, contre ~22 000 par jour en S2.

## 4. Test de bout en bout

Le site de test habituel des IDS (`testmynids.org`) n'existe plus
(NXDOMAIN, y compris chez Cloudflare). Même réponse reproduite par
`httpbin.org/base64/...`, qui renvoie le texte `uid=0(root) gid=0(root)
groups=0(root)` : la signature d'une commande `id` exécutée en root sur un
serveur compromis.

| Étape | Heure |
|---|---|
| Requête depuis `ws01` | 23:35:01 |
| Alerte Suricata 2100498 (`eve.json`) | 23:35:04 |
| Alerte Wazuh 86601 | 23:35:06 |

**Constats** ([captures](screenshots/README.md#semaine-4)) :

- L'alerte est rattachée à l'**agent `WAZUH`** (la sonde), pas à `ws01` : pour
  relier une alerte réseau à l'activité d'un poste (Sysmon), il faut corréler
  par adresse IP.
- **Toute alerte Suricata sort au niveau 3** (règle Wazuh 86601), le niveau du
  bruit : une attaque réseau sérieuse passerait inaperçue d'un analyste qui
  filtre à partir du niveau 7.
- Deux notions de gravité coexistent dans l'alerte : `alert.severity` (1 à 3,
  priorité de la **classe** de règle) et `metadata.signature_severity`
  (évaluation d'Emerging Threats **règle par règle**). Ici : 2 et
  « Informational ».

## 5. Conteneur attaquant

| Paramètre | Valeur |
|---|---|
| Type | LXC **non privilégié** (root du conteneur ≠ root de l'hôte) |
| Système | Debian 12 (modèle `debian-12-standard_12.12-1`) |
| Ressources | 1 vCPU, 512 Mo + 512 Mo de swap, 8 Go sur le SSD |
| Réseau | `vmbr1`, 10.10.10.66/24, DNS `dc01` |
| Démarrage avec l'hôte | non (`onboot 0`) : allumé seulement pendant les tests |
| Outils | Nmap 7.93, Hydra 9.4, curl, dig, smbclient (Impacket en S5-S6) |
| Point de retour | snapshot `s04-base` |

Avec les 4 machines du lab allumées, l'hôte garde 3,1 Gio de RAM disponibles :
le choix du LXC plutôt qu'une VM Kali (2 à 4 Go) tient le budget.

## 6. Gravité des alertes Suricata

**Choix** : s'appuyer sur `metadata.signature_severity` d'Emerging Threats
plutôt que sur `alert.severity`. Ce dernier est trop grossier : le test
`uid=0(root)`, classé « Informational » par ET, vaut 2 et serait remonté au
rang d'incident.

| Gravité ET | Règle Wazuh | Niveau |
|---|---|---|
| Critical | 100200 | 12 |
| Major | 100201 | 10 |
| Minor | 100202 | 7 |
| Informational, ou pas de métadonnée ET | 86601 (inchangée) | 3 |

Les trois règles sont des **enfants** de 86601
([soclab_rules.xml](../configs/wazuh/rules/soclab_rules.xml)) : elles ne
s'évaluent que sur une alerte Suricata déjà reconnue. Le champ est une liste
dans `eve.json` : l'expression `\bMajor\b` trouve le mot avec ou sans crochets,
mais pas `Majority`.

**Vérification** :

- Hors ligne : 9 cas ajoutés à
  [test_soclab_rules.py](../configs/wazuh/rules/test_soclab_rules.py) (22 au
  total, les 13 de la S3 passent toujours).
- Sur le manager : `wazuh-logtest` rejoue l'**alerte réelle** du 18/10 et trois
  copies où seule la gravité change. Les quatre donnent la règle et le niveau
  attendus ; l'alerte réelle reste au niveau 3. La description porte
  maintenant la source et la destination, ce qui compense en partie le
  rattachement à l'agent `WAZUH`.

Le premier essai de `wazuh-logtest` n'a rien affiché (lancé trop tôt après le
redémarrage, erreurs masquées par `2>/dev/null`) ; le deuxième a pris une
vieille alerte de juillet dans les archives. Le ciblage par horodatage a
réglé le problème : **toujours vérifier que l'on teste bien l'événement visé**.

## 7. Activité → détecté par quoi (à venir)

Livrable de la feuille de route pour cette semaine : pour chaque activité
générée depuis `attacker` ou `ws01`, indiquer quelle source la voit (Suricata,
Sysmon, journal Windows du contrôleur de domaine) et quelle règle Wazuh
l'alerte, à quel niveau. Il complète le tableau de la S3 (côté poste) par le
côté réseau, et prépare la matrice de couverture ATT&CK des semaines 5-6.

## 8. Conservation des journaux

| Données | Volume | Conservation | Verdict |
|---|---|---|---|
| Suricata (`eve.json`, `stats.log`) | ~32 Mo/j brut, 72 Mo sur disque | logrotate du paquet : hebdomadaire, 14 rotations compressées (~14 semaines, < 1 Go) | suffisant |
| Archives Wazuh (`logall`) | 116 Ko | désactivées | rien ne s'accumule |
| Fichiers d'alertes Wazuh | 224 Mo | archivés chaque nuit, jamais supprimés | à surveiller sur la durée |
| Indexer Wazuh (dashboard) | 103 Mo, 8 à 14 Mo par jour de lab | **aucune suppression** (index journaliers depuis le 31/01) | ~5,5 Go/an au pire, pour 18 Go libres |

**Décision** : pas de politique de suppression dans le lab. La capacité le
permet, et l'historique complet sert les comparaisons avant/après. En
production, on fixerait une durée de conservation (par exemple 90 jours en
ligne puis archivage froid) par une politique ISM de l'indexer, selon les
exigences légales et internes.

Observation : la journée la plus lourde (08/10, 67 021 alertes, avant le réglage
du bruit) ne pèse que 14 Mo. Le coût disque suit le contenu des alertes plus
que leur nombre.

## Limites connues

- **Mode hub** : propre au lab (voir section 1). En production : port mirroring
  ou TAP.
- **Sonde sur la VM Wazuh** : la détection réseau partage la RAM du SIEM
  (marge ramenée à 1,6 Gio) ; une panne de la VM coupe les deux.
- **Avertissement AF_PACKET** : `tpacket-v3` recommandé pour la capture passive,
  non encore activé (performance, sans effet visible au débit du lab).
- **Alertes rattachées à la sonde** : corrélation poste ↔ réseau par IP
  uniquement.
- Règles 100200-100202 : une alerte Suricata de priorité 1 **sans**
  métadonnée ET (règles internes de Suricata) reste au niveau 3.
- `stats.log` (compteurs toutes les 8 s) pèse plus que les alertes : intervalle
  à espacer si la place devient un sujet.
- Le snapshot `s04-avant` de la VM 109 date d'avant la reconfiguration :
  revenir dessus annulerait tout le travail Suricata.
