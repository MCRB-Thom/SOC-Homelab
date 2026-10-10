# Pont Wazuh → Ollama

Récupère les alertes depuis l'**indexer Wazuh** (port 9200 ; l'API du manager
sur le port 55000 n'expose plus les alertes dans les versions récentes), les
fait classifier par un modèle local via Ollama, et stocke le résultat dans
SQLite. Un dashboard Streamlit (`dashboard.py`) permet de les consulter.

## Installation

```bash
cd soc-bridge
python3 -m venv venv
source venv/bin/activate   # venv\Scripts\activate sous PowerShell
pip install -r requirements.txt
cp .env.example .env       # URL de l'indexer et mot de passe à renseigner
```

Le compte utilisé est l'utilisateur `admin` de l'indexer (généré par
`wazuh-passwords-tool.sh -a`, le même que pour le dashboard), et non le compte
API `wazuh` du manager.

## Utilisation

```bash
python bridge.py           # une passe
python bridge.py --loop    # en continu (Ctrl+C pour arrêter)
streamlit run dashboard.py # visualisation
```

Consultation directe :

```bash
sqlite3 data/soc_bridge.db "SELECT alert_timestamp, rule_level, severity, summary FROM classifications ORDER BY id DESC LIMIT 10;"
```

## Réglages (`.env`)

| Variable | Rôle |
|---|---|
| `MIN_ALERT_LEVEL` | Niveau Wazuh minimum traité (7 = moyen et plus) |
| `ALERTS_PER_BATCH` | Nombre maximum d'alertes par passage |
| `POLL_INTERVAL_SECONDS` | Intervalle de polling en mode `--loop` |
| `OLLAMA_MODEL` | Modèle utilisé (déjà téléchargé dans Ollama) |

## Comportements connus

- **Certificat auto-signé** : l'indexer utilise un certificat auto-signé et la
  vérification TLS est désactivée (`verify=False`). Acceptable en lab
  uniquement.
- **`ConnectionRefused` sur le port 9200** : l'URL de `.env` n'est pas
  joignable (`curl -k https://<IP>:9200`) ou un pare-feu bloque le port.
- **Réponse du modèle non JSON** : l'alerte est enregistrée avec
  `severity: unknown` au lieu de faire planter le script. Une fréquence élevée
  indique un prompt à durcir (la température est déjà à 0.1).

## Évolutions prévues

- Conteneurisation (Dockerfile + service dans `docker-compose.yml`).
- Exemples few-shot tirés des scénarios du lab (scan Nmap, brute force…).
- Évaluation quantitative du classifieur (semaines 7-8 du projet).
