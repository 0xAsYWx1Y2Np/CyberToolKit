# Cribble Setup

## 🧱 1. Prepare your VM | Ubuntu Server `172.16.106.129` / `srv01ubuntu`

### Update system & install dependencies

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl apt-transport-https ca-certificates gnupg
```

### Install Docker Engine per official instruction

```bash
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository \
  "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose
sudo usermod -aG docker $USER
```

> **🚨 Important**  
> Log out & back in so Docker group permissions apply.

---

## 🚀 2. Define Docker‑Compose for Leader + Worker

Create a directory, `~/cribl-docker`, then inside `docker-compose.yml`:

```yaml
version: '3.8'
services:
  leader:
    image: cribl/cribl:latest
    environment:
      - CRIBL_DIST_MODE=leader
      - CRIBL_DIST_LEADER_URL=tcp://criblmaster@0.0.0.0:4200
      - CRIBL_VOLUME_DIR=/opt/cribl/config
    ports:
      - "19000:9000"
    volumes:
      - ./config:/opt/cribl/config

  worker:
    image: cribl/cribl:latest
    depends_on:
      - leader
    environment:
      - CRIBL_DIST_MODE=worker
      - CRIBL_DIST_LEADER_URL=tcp://criblmaster@leader:4200
      - CRIBL_VOLUME_DIR=/opt/cribl/config
    ports:
      - "29000:9000"
    volumes:
      - ./config:/opt/cribl/config
```

- Latest stable image from Docker Hub
- Both containers share config via `./config`
- Expose `leader UI` on `port 19000`, `worker UI` on `port 29000`

---

## ⚙️ 3. Launch and Connect

From `~/cribl-docker`:

```bash
docker-compose up -d --scale worker=1
```

> `--scale worker=1` ensures one worker; increase as needed

### Monitor

```bash
docker ps
```

> You should see **two** Cribl containers with ports mapped

---

## ✅ 4. Validate & Tune

### Visit

- **Leader UI**
  - `http://<VM‑IP>:19000`

- **Worker UI**
  - `http://<VM‑IP>:29000`

- Ensure worker shows as connected under `Cluster` > `Nodes`

### Performance considerations

- Use `CRIBL_VOLUME_DIR` on **fast disk (SSD)**
- Allocate enough **RAM** & **CPU**; if leader crashes, thresholds likely exceeded

---

## 🔧 5. Running as Non‑Root (Optional)