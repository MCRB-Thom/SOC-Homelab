"""Configuration du pont Wazuh -> Ollama, chargée depuis .env"""

import os

from dotenv import load_dotenv

load_dotenv()

# --- Wazuh Indexer (port 9200, PAS l'API manager 55000) ---
WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://<IP_VM_WAZUH>:9200")
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "")

# --- Ollama ---
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

# --- Filtrage des alertes ---
MIN_ALERT_LEVEL = int(os.getenv("MIN_ALERT_LEVEL", "7"))
ALERTS_PER_BATCH = int(os.getenv("ALERTS_PER_BATCH", "20"))

# --- Boucle ---
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "60"))

# --- Stockage ---
DB_PATH = os.getenv("DB_PATH", "./data/soc_bridge.db")
