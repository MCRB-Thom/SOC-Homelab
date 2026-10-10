# Poste d'inférence — Ollama sur GPU (RTX 4050 Laptop, 6 Go)

Mise en place du PC portable qui exécute le LLM et `soc-bridge`. Wazuh et le
reste du lab tournent sur Proxmox : voir [docs/architecture.md](docs/architecture.md).

## 1. Pilote NVIDIA (côté Windows uniquement)

- Pilote NVIDIA récent installé **depuis Windows** (Game Ready ou Studio).
- Aucun CUDA Toolkit ni `cuda-drivers` dans la distribution WSL2 : NVIDIA
  expose le pilote Windows dans WSL2 via `/usr/lib/wsl/lib/`, et un pilote
  installé dans WSL2 casse ce pont.
- Contrôle (PowerShell) : `nvidia-smi` doit lister la RTX 4050 Laptop GPU.

## 2. WSL2

```powershell
wsl --install
wsl --set-default-version 2
wsl --install -d Ubuntu-24.04
```

Contrôle depuis WSL2 : `nvidia-smi` répond sans rien installer de plus
(c'est le pilote Windows qui répond).

## 3. Docker Desktop

- Moteur WSL 2 activé (**Settings > General**).
- Intégration WSL activée pour la distribution (**Settings > Resources > WSL Integration**).

## 4. NVIDIA Container Toolkit (dans la distribution WSL2)

```bash
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
  | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg

curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
  | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
  | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list

sudo apt-get update
sudo apt-get install -y nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=docker
```

Docker Desktop doit ensuite être complètement redémarré (quitté depuis la
barre des tâches).

## 5. Validation GPU dans Docker

```bash
docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi
```

L'erreur `could not select device driver "nvidia"` indique que l'étape 4 n'a
pas été prise en compte (redémarrage de Docker Desktop manquant).

## 6. Ollama

```bash
docker compose up -d ollama
docker exec -it ollama nvidia-smi        # le GPU doit être visible dans le conteneur
docker exec -it ollama ollama pull llama3.1:8b
docker exec -it ollama ollama run llama3.1:8b "dis bonjour"
```

`nvidia-smi` sur l'hôte ne prouve pas qu'Ollama voit le GPU : seul le contrôle
dans le conteneur compte.

## 7. Accès à Wazuh

Le PC joint l'indexer Wazuh par l'interface LAN de la VM :

```powershell
curl.exe -k -u admin https://192.168.1.40:9200
```

L'URL est renseignée dans `soc-bridge/.env` (`WAZUH_INDEXER_URL`).

## Contraintes matérielles

- VRAM (6 Go) : un modèle 7-8B en Q4 tient (llama3.1:8b ≈ 4,9 Go,
  qwen2.5:7b ≈ 4,7 Go, mistral:7b ≈ 4,1 Go), un seul chargé à la fois, avec un
  contexte modéré (`num_ctx` 4096). Les modèles 13B et plus ne tiennent pas.
- Disque : environ 15 Go pour trois modèles et l'image Ollama.
