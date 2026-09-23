# Deploying PRAHARI for the SIH demo

There are two deployments, because live packet capture and serverless hosting
are mutually exclusive and pretending otherwise would be dishonest. Pick the one
that fits how you are presenting.

| | Live sensor | Static viewer |
|---|---|---|
| **Where** | a Linux server / VM you control | Vercel, Netlify, GitHub Pages |
| **Does** | taps a real NIC, detects live traffic in real time | replays scenarios, shows measured results |
| **Needs** | root (CAP_NET_RAW), a persistent process | nothing — it is static files + one serverless function |
| **Best for** | the live demo you drive on stage | the link you hand the jury to open later |
| **Third-party deps** | none | none |

Both run the **same detection engine**. Neither needs a package index — the
engine is pure CPython.

---

## A. Live sensor on a cloud VM (the real-time demo)

Any small Linux VM works — a ₹400/month VPS, a cloud free-tier box, a laptop.

### Production install with systemd (real server, real traffic)

This is the deployment for a box that watches **real network traffic** on a real
interface, continuously, and restarts itself if it ever crashes or the server
reboots. On a span/mirror port or a tap it analyses live production traffic; the
attack buttons are only for a self-contained demo.

```bash
git clone https://github.com/Pulkitkh/AI_Riders && cd AI_Riders
sudo bash deploy/install.sh eth0        # the interface to monitor
```

That script:
- creates a dedicated unprivileged `prahari` user,
- installs the code under `/opt/prahari` (nothing to `pip install`),
- registers a systemd service that runs the sensor granted **only** `CAP_NET_RAW`
  — the least privilege the read-only posture implies — bound to `127.0.0.1:8000`,
- enables it on boot and starts it.

```bash
systemctl status prahari        # is it running?
journalctl -u prahari -f        # follow the live log
```

Then put TLS and a public port in front of it. Either:

```bash
# nginx + free Let's Encrypt certificate
sudo cp deploy/nginx.conf /etc/nginx/sites-available/prahari
sudo ln -s /etc/nginx/sites-available/prahari /etc/nginx/sites-enabled/
sudo certbot --nginx -d prahari.example.org
sudo nginx -t && sudo systemctl reload nginx
```

or, simpler, Caddy (automatic HTTPS, one file — `deploy/Caddyfile`):

```bash
sudo caddy run --config deploy/Caddyfile
```

The one thing a proxy must get right is the **Server-Sent-Events stream**: buffering
off, long read timeout. Both configs already set this, so alerts reach the browser
the moment the engine raises them instead of arriving in clumps.

> **To monitor real traffic**, the interface must actually see it: on a physical
> host, a switch **SPAN/mirror port** or a network **TAP** feeding the sensor NIC;
> on a cloud VM, a traffic-mirroring session (AWS VPC Traffic Mirroring, Azure vTAP,
> GCP Packet Mirroring) pointed at the sensor. That is exactly the passive-tap
> topology the problem statement assumes — the sensor receives a copy and can
> transmit nothing back.

---

### Quick demo with Docker (one command)

```bash
git clone https://github.com/Pulkitkh/AI_Riders && cd AI_Riders
docker compose up --build
```

`docker-compose.yml` uses host networking and grants `NET_RAW`, so the sensor
taps the host's real interfaces. Open `http://<vm-ip>:8000`, set the interface
if it is not `eth0` (edit `IFACE` in the compose file), press **Start sensor**.

### Without Docker

```bash
git clone https://github.com/Pulkitkh/AI_Riders && cd AI_Riders
python3 --version                 # 3.10+; nothing else to install
sudo python3 -m web.server --live --iface eth0 --port 8000
```

If you would rather not run the whole server as root, grant just the capture
capability to the interpreter instead:

```bash
sudo setcap cap_net_raw+ep $(readlink -f $(which python3))
python3 -m web.server --live --iface eth0 --port 8000
```

### Demonstrating with attacks

Real production traffic is mostly benign, which does not make a lively demo. The
**attack buttons** in the Live tab craft genuine attack packets on the loopback
interface — a spoofed-source SYN flood, a port scan, C2 beaconing, DNS
tunnelling, exfiltration — and the sensor detects them exactly as it would
attacker traffic on the tap. To watch it on loopback rather than the main NIC,
start with `--iface lo`.

> Firing the buttons is real packet injection on 127.0.0.0/8, which needs
> `NET_RAW` too. If capture works, injection works.

### Exposing it to the jury

- **Same network:** just share `http://<vm-ip>:8000`.
- **Over the internet:** put it behind a tunnel — `cloudflared tunnel --url
  http://localhost:8000` or `ngrok http 8000` — and share the HTTPS URL. SSE
  streams fine through both.
- Keep it running: the Docker service restarts unless stopped; under systemd,
  a one-line unit running the `web.server --live` command is enough.

---

## B. Static viewer on Vercel (the shareable link)

```bash
npm i -g vercel
vercel            # from the repo root; accept the defaults
vercel --prod
```

`vercel.json` builds the precomputed datasets (`python3 web/build.py`), serves
`web/public` as static files, and routes `/api/*` to one serverless function
(`api/index.py`) that runs the stateless endpoints — scenario analysis, the
read-only self-test, one-way-visibility measurement, the ledger tamper demo,
and metrics. All of it is the real engine; none of it needs a raw socket.

The **Live sensor** tab detects that the live endpoints are absent and explains
that live capture runs on the deployed server, pointing the visitor at Replay
instead. That is the honest boundary: a serverless function cannot sniff a NIC,
so the hosted link is read-only by construction.

Netlify and GitHub Pages work the same way for the static half; only the live
sensor needs a real host.

### Fully offline / air-gapped

The whole thing is one folder with no dependencies, so it also runs from a USB
stick on a machine with no internet:

```bash
python3 -m web.server --port 8000       # replay + viewer, no root
sudo python3 -m web.server --live --iface lo --port 8000   # + live sensor
```

---

## What each tab needs

| Tab | Live sensor | Static viewer |
|---|---|---|
| Live sensor | real-time capture | explains it runs on the server |
| Replay scenarios | live engine call | precomputed JSON / serverless |
| One-way visibility | live measurement | precomputed JSON |
| Measured results | eval outputs | precomputed JSON |
| Tamper-evident ledger | live build + verify | serverless function |
| Read-only proof | live AST scan | precomputed JSON / serverless |

## Sizing note

The serverless function bundle is a few hundred kilobytes — the whole `prahari`
package plus `web`, no dependencies — so it is nowhere near Vercel's 250 MB
limit, and the cold start is just the interpreter. This is the same property
that lets the sensor install on an air-gapped appliance: there is nothing to
download.
