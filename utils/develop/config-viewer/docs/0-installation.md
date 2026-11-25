# Installation (macOS, Windows)

The config viewer runs in **Docker**. Docker is the only thing to install yourself; the viewer and everything it
needs come as Docker images. When Docker works, one command installs and starts the viewer (step 3).

| | macOS | Windows |
|---|---|---|
| 1. Docker | Docker Desktop **or** Colima + Docker CLI | WSL 2 + Docker Desktop **or** WSL 2 + Docker Engine in Ubuntu |
| 2. Check | `docker version`, `docker compose version` in the Terminal | the same in the **Ubuntu** window (WSL) |
| 3. Viewer | `curl … install-viewer.sh \| bash` in the Terminal | the same in the **Ubuntu** window (WSL) |

**Which Docker?** Docker Desktop is the easiest way (an app with a window, updates itself). It is free for personal
use, education, non-commercial open source and small companies (fewer than 250 employees **and** less than
USD 10 million annual revenue); a larger company needs a paid Docker subscription per user - see the
[Docker Desktop license agreement](https://docs.docker.com/subscription/desktop-license/). Without Docker Desktop:
the Docker command line with a free engine - Colima on macOS, Docker Engine in WSL on Windows (below).

---

## macOS

Apple silicon (M1 …) and Intel both work; the images exist for both.

### A) Docker Desktop

1. Download: <https://docs.docker.com/desktop/setup/install/mac-install/> - choose **Apple silicon** or **Intel**
   (Apple menu → About This Mac → Chip / Processor).
2. Open the `.dmg`, drag **Docker** to **Applications**, start Docker from Applications.
3. Accept the terms, sign in or skip, wait until the whale in the menu bar says **Docker Desktop is running**.
4. Memory: Docker Desktop → Settings → Resources - large configurations: **8 GB** memory or more, then
   **Apply & restart**.
5. Docker Desktop must be running whenever the viewer runs (Settings → General → **Start Docker Desktop when you sign
   in** starts it with the Mac).

### B) Without Docker Desktop: Colima + Docker CLI

Colima runs the Docker engine in a small Linux VM; the `docker` command is the normal Docker CLI. Needs
[Homebrew](https://brew.sh) (install it first if `brew` is missing:
`/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`).

```bash
# Docker CLI, Compose and Colima
brew install colima docker docker-compose

# make "docker compose" find the Compose plugin of Homebrew
mkdir -p ~/.docker/cli-plugins
ln -sfn "$(brew --prefix)/opt/docker-compose/bin/docker-compose" ~/.docker/cli-plugins/docker-compose

# start the engine (CPU, memory in GB, disk in GB) - large configurations: 8 GB memory or more
colima start --cpu 4 --memory 8 --disk 60

# optional: start Colima with the Mac
brew services start colima
```

Colima must be running whenever the viewer runs (`colima status`; after a restart of the Mac without
`brew services`: `colima start`). Change memory later: `colima stop` then `colima start --memory 12`.

---

## Windows

The viewer runs in **WSL 2** (Windows Subsystem for Linux) with Ubuntu - with Docker Desktop and without. All commands
of step 2 and 3 are typed in the **Ubuntu** window, not in PowerShell. Windows 10 (version 2004 or newer) or
Windows 11; virtualisation switched on in the BIOS / UEFI (most computers have it on).

### WSL 2 with Ubuntu (both ways)

1. **PowerShell as administrator** (Start → type *PowerShell* → right click → *Run as administrator*):

   ```powershell
   wsl --install -d Ubuntu
   ```

2. Restart Windows when asked. Ubuntu opens and asks for a **user name and password** (for Linux, not your Windows
   password - remember it, `sudo` asks for it).
3. Check in PowerShell: `wsl -l -v` shows **Ubuntu** with **VERSION 2**. Already installed before: `wsl --update`,
   and for an old distribution `wsl --set-version Ubuntu 2`.
4. The Ubuntu window: Start → **Ubuntu** (or Windows Terminal → Ubuntu).

### A) Docker Desktop

1. Download: <https://docs.docker.com/desktop/setup/install/windows-install/> and run the installer; keep
   **Use WSL 2 instead of Hyper-V** switched on. Sign out / restart when asked.
2. Start Docker Desktop, accept the terms, wait for **Docker Desktop is running**.
3. Docker Desktop → Settings → Resources → **WSL integration**: switch on **Ubuntu**, **Apply & restart**.
4. Memory: with WSL 2 Docker Desktop takes the memory of WSL - large configurations: give WSL **8 GB** or more in
   `%UserProfile%\.wslconfig`:

   ```ini
   [wsl2]
   memory=8GB
   ```

   then `wsl --shutdown` in PowerShell and start Ubuntu again.
5. Docker Desktop must be running whenever the viewer runs (Settings → General → **Start Docker Desktop when you sign
   in**).

### B) Without Docker Desktop: Docker Engine in Ubuntu (WSL)

The Docker engine runs inside Ubuntu, started by systemd. In the **Ubuntu** window:

```bash
# 1. systemd in WSL (Ubuntu of "wsl --install" has it on already - check: ps -p 1 -o comm= says "systemd")
printf '[boot]\nsystemd=true\n' | sudo tee /etc/wsl.conf
```

Then in **PowerShell**: `wsl --shutdown`, and open Ubuntu again.

```bash
# 2. Docker Engine, CLI and Compose from the Docker repository (https://docs.docker.com/engine/install/ubuntu/)
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 3. start Docker with Ubuntu, and use it without sudo
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

Close the Ubuntu window and open it again (the group `docker` counts from the next login). Memory: as in A) step 4
(`%UserProfile%\.wslconfig`).

---

## 2. Check Docker

In the Terminal (macOS) or the Ubuntu window (Windows):

```bash
docker version            # shows "Client" and "Server" - no "Cannot connect to the Docker daemon"
docker compose version    # shows "Docker Compose version v2…"
docker run --rm hello-world
```

| Message | Cause |
|---|---|
| `Cannot connect to the Docker daemon` | Docker Desktop / Colima is not running; WSL without Desktop: `sudo systemctl start docker` |
| `permission denied … docker.sock` | WSL without Desktop: the group `docker` is missing - `sudo usermod -aG docker $USER`, open Ubuntu again |
| `'compose' is not a docker command` | macOS with Colima: the link of step B is missing; WSL: `docker-compose-plugin` is missing |
| `docker: command not found` in Ubuntu | Windows with Docker Desktop: WSL integration for Ubuntu is off (A step 3) |

## 3. Install and start the viewer

```bash
curl -fsSL https://raw.githubusercontent.com/swaschkut/pan-os-php/alpha/utils/develop/config-viewer/install-viewer.sh | bash
```

It makes the folder `panosphp-viewer` in the current folder, downloads the images and starts the viewer; the first
time it asks: only this computer, or HTTPS for several users. Then open the address it shows (only this computer:
<http://127.0.0.1:8080/>) - on Windows in the normal Windows browser - and create the administrator with the one-time
code (see [First steps](1-first-steps.md)).

- **Windows:** run it in the Ubuntu window in the Linux home folder (`cd ~` first), not under `/mnt/c/…`.
- Next time: `cd panosphp-viewer && ./panosphp-viewer start | stop | status | help`.
- Update: the same `curl … | bash` again - settings, plug-ins and data stay.
- Another channel: `curl … | PANOSPHP_CHANNEL=beta bash`.
- No internet at the computer: the air-gap bundle (one file with the images) - Docker must be installed there as
  above.

---

**Checked:** macOS with Docker Desktop (2026-11-20). **Not checked yet:** macOS with Colima, Windows (WSL 2 with
Docker Desktop and with Docker Engine), HTTPS for several users on Windows (other computers reach WSL only through
Windows: firewall / port forwarding, or `networkingMode=mirrored` in `.wslconfig`).
