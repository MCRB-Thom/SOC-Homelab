#!/usr/bin/env python3
"""
Pont Wazuh -> Ollama
Récupère les alertes depuis l'Indexer Wazuh (OpenSearch, port 9200),
les fait classifier par un modèle local via Ollama, et stocke le résultat
dans une base SQLite locale.

Usage:
    python bridge.py            # une seule passe
    python bridge.py --loop     # tourne en continu (poll toutes les N secondes)
"""

import argparse
import json
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth

from config import (
    WAZUH_INDEXER_URL,
    WAZUH_INDEXER_USER,
    WAZUH_INDEXER_PASSWORD,
    OLLAMA_URL,
    OLLAMA_MODEL,
    MIN_ALERT_LEVEL,
    POLL_INTERVAL_SECONDS,
    DB_PATH,
    ALERTS_PER_BATCH,
)

# désactive les warnings liés au certificat auto-signé de l'indexer
requests.packages.urllib3.disable_warnings()


# --------------------------------------------------------------------------
# Base SQLite
# --------------------------------------------------------------------------

def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS classifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT UNIQUE,
            alert_timestamp TEXT,
            rule_id TEXT,
            rule_level INTEGER,
            rule_description TEXT,
            agent_name TEXT,
            severity TEXT,
            summary TEXT,
            recommended_action TEXT,
            raw_llm_response TEXT,
            processed_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS checkpoint (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            last_timestamp TEXT
        )
        """
    )
    conn.commit()
    return conn


def get_last_checkpoint(conn: sqlite3.Connection) -> str | None:
    row = conn.execute("SELECT last_timestamp FROM checkpoint WHERE id = 1").fetchone()
    return row[0] if row else None


def set_checkpoint(conn: sqlite3.Connection, timestamp: str) -> None:
    conn.execute(
        """
        INSERT INTO checkpoint (id, last_timestamp) VALUES (1, ?)
        ON CONFLICT(id) DO UPDATE SET last_timestamp = excluded.last_timestamp
        """,
        (timestamp,),
    )
    conn.commit()


def already_processed(conn: sqlite3.Connection, alert_id: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM classifications WHERE alert_id = ?", (alert_id,)
    ).fetchone()
    return row is not None


def save_classification(conn: sqlite3.Connection, alert: dict, result: dict, raw: str) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO classifications (
            alert_id, alert_timestamp, rule_id, rule_level, rule_description,
            agent_name, severity, summary, recommended_action,
            raw_llm_response, processed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert["_id"],
            alert["_source"].get("timestamp"),
            str(alert["_source"].get("rule", {}).get("id")),
            alert["_source"].get("rule", {}).get("level"),
            alert["_source"].get("rule", {}).get("description"),
            alert["_source"].get("agent", {}).get("name"),
            result.get("severity"),
            result.get("summary"),
            result.get("recommended_action"),
            raw,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()


# --------------------------------------------------------------------------
# Wazuh Indexer
# --------------------------------------------------------------------------

def fetch_alerts(since_timestamp: str | None, min_level: int, size: int) -> list[dict]:
    """Interroge l'Indexer Wazuh pour récupérer les nouvelles alertes."""
    url = f"{WAZUH_INDEXER_URL}/wazuh-alerts-*/_search"

    must_clauses = [{"range": {"rule.level": {"gte": min_level}}}]
    if since_timestamp:
        must_clauses.append({"range": {"timestamp": {"gt": since_timestamp}}})

    query = {
        "size": size,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {"bool": {"must": must_clauses}},
    }

    resp = requests.post(
        url,
        auth=HTTPBasicAuth(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
        json=query,
        verify=False,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("hits", {}).get("hits", [])


# --------------------------------------------------------------------------
# Ollama
# --------------------------------------------------------------------------

CLASSIFICATION_PROMPT = """Tu es un analyste SOC senior. Voici une alerte de sécurité Wazuh, avec son
contexte MITRE ATT&CK et des métadonnées d'occurrence extraites pour toi.

Grille de sévérité à appliquer (dans l'ordre, la première condition qui matche s'applique) :
- "critical" : compromission confirmée (succès d'authentification après échecs, exécution de code,
  élévation de privilèges réussie, exfiltration constatée)
- "high" : technique MITRE de type Initial Access / Credential Access / Lateral Movement avec une
  fréquence élevée (frequency >= 8) OU une source déjà connue comme malveillante OU un compte
  sensible ciblé (root, admin, service account)
- "medium" : tentative détectée mais non aboutie, technique MITRE présente mais fréquence modérée
  (frequency < 8), ou activité suspecte sans confirmation d'intention malveillante
- "low" : bruit opérationnel (changement de config, installation de paquet, alertes de conformité
  CIS/benchmark) sans lien avec une technique MITRE ATT&CK

Réponds UNIQUEMENT avec un objet JSON valide (rien d'autre, pas de texte avant ou après),
avec exactement ces champs :

{{
  "severity": "low" | "medium" | "high" | "critical",
  "summary": "résumé en une phrase claire de ce qui s'est passé",
  "recommended_action": "action recommandée en une phrase, concrète et actionnable (ex: bloquer l'IP source, vérifier les connexions réussies de cet utilisateur, patcher le paquet, ignorer si conforme)"
}}

Contexte MITRE ATT&CK : {mitre_context}
Fréquence de l'alerte (nombre d'occurrences ayant déclenché la règle) : {frequency}
IP source : {src_ip}
Compte ciblé : {target_user}

Alerte Wazuh complète (JSON) :
{alert_json}
"""


def classify_alert(alert_source: dict) -> tuple[dict, str]:
    """Envoie l'alerte à Ollama et retourne (dict parsé, texte brut)."""
    rule = alert_source.get("rule", {})
    data = alert_source.get("data", {})
    mitre = rule.get("mitre", {})

    if mitre.get("technique") or mitre.get("tactic"):
        mitre_context = (
            f"tactique(s)={mitre.get('tactic', [])}, "
            f"technique(s)={mitre.get('technique', [])}, "
            f"id(s)={mitre.get('id', [])}"
        )
    else:
        mitre_context = "aucune technique MITRE associée à cette règle"

    prompt = CLASSIFICATION_PROMPT.format(
        mitre_context=mitre_context,
        frequency=rule.get("frequency", "non spécifiée"),
        src_ip=data.get("srcip", "non spécifiée"),
        target_user=data.get("dstuser") or data.get("uid") or "non spécifié",
        alert_json=json.dumps(alert_source, ensure_ascii=False, indent=2),
    )

    resp = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1},
        },
        timeout=120,
    )
    resp.raise_for_status()
    raw_text = resp.json().get("response", "")

    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        parsed = {
            "severity": "unknown",
            "summary": "Échec du parsing JSON de la réponse du modèle",
            "recommended_action": "Vérifier manuellement l'alerte",
        }

    return parsed, raw_text


# --------------------------------------------------------------------------
# Boucle principale
# --------------------------------------------------------------------------

def run_once(conn: sqlite3.Connection) -> int:
    last_ts = get_last_checkpoint(conn)
    alerts = fetch_alerts(last_ts, MIN_ALERT_LEVEL, ALERTS_PER_BATCH)

    if not alerts:
        print("Aucune nouvelle alerte.")
        return 0

    print(f"{len(alerts)} nouvelle(s) alerte(s) à traiter...")
    newest_ts = last_ts

    for alert in alerts:
        alert_id = alert["_id"]
        source = alert["_source"]

        if already_processed(conn, alert_id):
            continue

        rule = source.get("rule", {})
        print(f"  -> [{rule.get('level')}] {rule.get('description')} (agent: {source.get('agent', {}).get('name')})")

        try:
            result, raw = classify_alert(source)
        except requests.RequestException as e:
            print(f"     Erreur Ollama: {e}", file=sys.stderr)
            continue

        save_classification(conn, alert, result, raw)
        print(f"     -> Sévérité: {result.get('severity')} | {result.get('summary')}")

        ts = source.get("timestamp")
        if ts and (newest_ts is None or ts > newest_ts):
            newest_ts = ts

    if newest_ts:
        set_checkpoint(conn, newest_ts)

    return len(alerts)


def main():
    parser = argparse.ArgumentParser(description="Pont Wazuh -> Ollama")
    parser.add_argument("--loop", action="store_true", help="Tourne en continu")
    args = parser.parse_args()

    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = init_db(DB_PATH)

    if args.loop:
        print(f"Démarrage en boucle (intervalle: {POLL_INTERVAL_SECONDS}s). Ctrl+C pour arrêter.")
        try:
            while True:
                run_once(conn)
                time.sleep(POLL_INTERVAL_SECONDS)
        except KeyboardInterrupt:
            print("\nArrêt demandé.")
    else:
        run_once(conn)

    conn.close()


if __name__ == "__main__":
    main()
