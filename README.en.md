# Netkido — a private network for all your company's sites

[Español](README.md) · **English**

Netkido joins offices, shops and warehouses into one encrypted private network. Install the server
on a machine with a public IP and run **one command** on a Linux box at each site: within a couple
of minutes every site's LAN can reach the others, with no inbound ports at the sites and no changes
to the ISP router (works behind dynamic IPs and CG-NAT).

This repository is the **open edition** (AGPL-3.0 licence): the server and the site agent, for one
organisation, managed from the command line.

> **Rather not run a server?** At **[netkido.tech](https://netkido.tech)** you get Netkido as a
> service: we run the hub and you manage your sites from a web dashboard, with alerts, diagnostics
> and security built in. **Try it free with up to two sites**, installing nothing but the agent at
> each site.

## Open edition vs Netkido at netkido.tech

| | Open edition (this repository) | [Netkido at netkido.tech](https://netkido.tech) |
|---|:---:|:---:|
| WireGuard tunnels, BGP EVPN and hub isolation | ✅ | ✅ |
| One-time site installer and self-updating agent | ✅ | ✅ |
| Server (hub) | You install and maintain it | **We run it**, with backups and updates |
| Site management | `netkido` command on the server | **Web dashboard**, in English and Spanish |
| Site status | `netkido site list` | **Live:** latency, traffic, last contact and event history |
| Alerts | — | **By email** when a site stops responding |
| Diagnostics | SSH into each site | **From the dashboard:** tunnel, routes, MTU and agent log, without logging into the site |
| Team | Whoever has root on the server | **Users with roles** (admin or read-only) and two-factor authentication |
| Organisations | One | **Several, isolated from each other** (ideal for integrators managing clients) |
| Intrusion detection and prevention (Suricata) | — | ✅ on paid plans |
| OpenWrt router sites | — | ✅ on paid plans |
| Bandwidth per site | — | Depends on the plan |
| Support | Community ([Discussions](https://github.com/netkido/netkido/discussions)) | **By email**, priority and with a service-level agreement depending on the plan |

👉 **[Create your free account at netkido.tech](https://netkido.tech/en/)** and connect your first
two sites today. When you need more sites or more bandwidth, [tell us what you need](https://netkido.tech/en/#contact)
and we'll upgrade your account without reinstalling anything.

## How it works

```
 Site A (192.168.10.0/24)                                   Site B (192.168.20.0/24)
 PC ── nklan ─ agent ── WireGuard ──▶  server (hub)  ◀── WireGuard ── agent ─ nklan ── PC
                        VXLAN + BGP EVPN (FRR)  route reflector
```

- **WireGuard tunnels** from each site to the server; the sites start the connection.
- **BGP EVPN routing** (FRR): the server is the *route reflector* and each site announces its LAN.
  The server only accepts each site's own LAN from it, so a compromised site cannot hijack another
  site's traffic.
- **Isolation on the server** with nftables: only network traffic passes between sites; from the
  tunnels, only ping and BGP from registered sites are accepted.
- **Site agent** (`node/netkido-agent.py`, dependency-free Python): builds the site's network
  (WireGuard, VRF, VXLAN, LAN bridge, DHCP, FRR), keeps it running and updates itself.
- **Server:** it is the hub (WireGuard + BGP EVPN) and also runs an HTTPS service, `netkido serve`,
  to install and manage the sites: it serves the one-time installer, enrols each site and hands it
  its configuration (HMAC-signed requests). There is no web dashboard: sites are managed with the
  `netkido` command. The HTTPS certificate (Let's Encrypt) is for that service, on the domain you
  set at install time (`DOMAIN`).
- **All traffic between the sites and the hub runs inside WireGuard**, BGP sessions included
  (between tunnel IPs in 100.64.0.0/16); the BGP TCP MD5 password is an extra layer.

More detail in the [wiki](https://github.com/netkido/netkido/wiki/Arquitectura) (in Spanish).

## Requirements

- **Server:** Debian 12/13 or Ubuntu 22.04/24.04 with a public IP, a DNS name pointing to it, and
  80/TCP, 443/TCP and 51820/UDP open.
- **Sites:** a Linux box acting as the router of its LAN (mini PC or SBC, ideally with two network
  ports): Debian 12/13, Ubuntu 22.04/24.04, Armbian or 64-bit Raspberry Pi OS. See the
  [tested hardware](https://github.com/netkido/netkido/wiki/Equipos-probados).

## Installation

On the server:

```bash
git clone https://github.com/netkido/netkido.git
cd netkido
sudo DOMAIN=vpn.example.com EMAIL=admin@example.com ./server/install.sh
```

Optional variables: `WG_PORT` (default `51820`), `DNS` (DNS servers handed out by the sites'
DHCP, default `1.1.1.1,9.9.9.9`), `FIREWALL=no` (leave the server firewall alone) and
`CERT=existing` (use a certificate already in `/etc/letsencrypt/live/DOMAIN`).

Add a site (name, router IP on its LAN with prefix, LAN ports):

```bash
sudo netkido site add "Madrid office" 192.168.10.1/24 --ports eth1
```

The command prints the site installer, single-use and valid for 24 hours. Run it as root on that
site's machine (`?lang=en` gives you English messages):

```bash
curl -fsSL "https://vpn.example.com/install/<link>?lang=en" | sudo bash
```

## Usage

| To… | |
|---|---|
| List sites and their status | `sudo netkido site list` · `sudo netkido status` |
| Change the LAN ports or the LAN | `sudo netkido site ports <site> eth1,eth2` · `sudo netkido site lan <site> 192.168.11.1/24` |
| DHCP on the LAN | `sudo netkido site dhcp <site> on\|off` |
| Reinstall a site | `sudo netkido site link <site>` (new link) |
| Take a site off the network | `sudo netkido site disable <site>` · `enable` · `remove` |
| Logs | server: `journalctl -u netkido` · site: `journalctl -u netkido-agent` |

Changes reach the sites in under a minute. `netkido --help` and `netkido site --help` list every
command.

## Using it for your company or your clients?

If you manage several companies, want someone else to keep an eye on the network, or want
intrusion detection without building it yourself, **[take a look at netkido.tech](https://netkido.tech/en/)**:
it's the same engine as this repository, with the server, the dashboard and support taken care of.
Already running the open edition and want to move your sites to the service?
[Get in touch](https://netkido.tech/en/#contact) and we'll help you migrate.

## Development

```bash
python3 -m unittest discover -s tests -v
```

Contributions are welcome: read [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue,
follow [SECURITY.md](SECURITY.md). Questions and ideas go to
[Discussions](https://github.com/netkido/netkido/discussions) (English or Spanish).

## Licence

[GNU AGPL-3.0](LICENSE). If you offer a modified Netkido as a service to others, you must publish
the source code of your changes. "Netkido" is a trademark: you may use the name to refer to the
project, but not for derivative products.
