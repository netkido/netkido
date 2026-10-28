# Netkido — red privada entre las sedes de tu empresa

*[English below](#english)*

Netkido une oficinas, tiendas y almacenes en una sola red privada cifrada. Instalas el servidor en
una máquina con IP pública y ejecutas **un comando** en un equipo Linux de cada sede: en un par de
minutos las redes locales de todas las sedes se ven entre sí, sin abrir puertos en las sedes ni
tocar el router del operador (funciona con IP dinámica y CG-NAT).

Esta es la **edición abierta** (licencia AGPL-3.0): el servidor y el agente de las sedes, para una
organización. La edición comercial añade el panel web, varias organizaciones aisladas entre sí,
planes, límites de ancho de banda, detección y bloqueo de intrusiones y sedes con OpenWrt.

## Cómo funciona

```
 Sede A (192.168.10.0/24)                                   Sede B (192.168.20.0/24)
 PC ── nklan ─ agente ── WireGuard ──▶  servidor (hub)  ◀── WireGuard ── agente ─ nklan ── PC
                         VXLAN + BGP EVPN (FRR)  route reflector
```

- **Túneles WireGuard** de cada sede al servidor; las sedes inician la conexión.
- **Rutas con BGP EVPN** (FRR): el servidor hace de *route reflector* y cada sede anuncia su LAN.
  El servidor solo acepta de cada sede su propia LAN: una sede comprometida no puede desviar el
  tráfico de otra.
- **Aislamiento en el servidor** con nftables: entre sedes solo pasa el tráfico de la red; del
  túnel solo se aceptan ping y BGP de sedes registradas.
- **Agente de sede** (`node/netkido-agent.py`, Python sin dependencias): monta la red de la sede
  (WireGuard, VRF, VXLAN, puente de la LAN, DHCP, FRR), la mantiene y se actualiza solo.
- **Servidor:** hace de hub (WireGuard + BGP EVPN) y tiene además un servicio HTTPS,
  `netkido serve`, para instalar y gestionar las sedes: sirve el instalador de un solo uso, inscribe
  cada sede y le entrega su configuración (peticiones firmadas con HMAC). No hay panel web: las sedes
  se gestionan con el comando `netkido`. El certificado HTTPS (Let's Encrypt) es para ese servicio,
  con el dominio que indicas al instalar (`DOMAIN`).
- **Todo el tráfico entre las sedes y el hub va dentro de WireGuard**, también las sesiones BGP
  (entre las IP de túnel 100.64.0.0/16); la contraseña TCP MD5 de BGP es una protección adicional.

## Requisitos

- **Servidor:** Debian 12/13 o Ubuntu 22.04/24.04 con IP pública, un nombre DNS que apunte a ella y
  abiertos 80/TCP, 443/TCP y 51820/UDP.
- **Sedes:** un equipo Linux que haga de router de su LAN (mini PC o placa SBC, mejor con dos
  puertos de red): Debian 12/13, Ubuntu 22.04/24.04, Armbian o Raspberry Pi OS de 64 bits.

## Instalación

En el servidor:

```bash
git clone https://github.com/netkido/netkido.git
cd netkido
sudo DOMAIN=vpn.example.com EMAIL=admin@example.com ./server/install.sh
```

Da de alta una sede (nombre, IP del router en su LAN y prefijo, puertos de la LAN):

```bash
sudo netkido site add "Oficina Madrid" 192.168.10.1/24 --ports eth1
```

El comando muestra el instalador de la sede. Ejecútalo como root en el equipo de esa sede:

```bash
curl -fsSL https://vpn.example.com/install/<enlace> | sudo bash
```

## Uso

| Para… | |
|---|---|
| Ver las sedes y su estado | `sudo netkido site list` · `sudo netkido status` |
| Cambiar los puertos o la LAN | `sudo netkido site ports <sede> eth1,eth2` · `sudo netkido site lan <sede> 192.168.11.1/24` |
| DHCP en la LAN | `sudo netkido site dhcp <sede> on\|off` |
| Reinstalar una sede | `sudo netkido site link <sede>` (enlace nuevo) |
| Sacar una sede de la red | `sudo netkido site disable <sede>` · `enable` · `remove` |
| Logs | servidor: `journalctl -u netkido` · sede: `journalctl -u netkido-agent` |

Los cambios llegan a las sedes en menos de un minuto.

## Desarrollo

```bash
python3 -m unittest discover -s tests -v
```

Las contribuciones son bienvenidas: lee [CONTRIBUTING.md](CONTRIBUTING.md). Para avisar de un
fallo de seguridad, sigue [SECURITY.md](SECURITY.md).

## Licencia

[GNU AGPL-3.0](LICENSE). Si ofreces Netkido modificado como servicio a terceros, tienes que
publicar el código de tus cambios. «Netkido» es una marca: puedes usar el nombre para referirte al
proyecto, pero no para productos derivados.

---

## English

Netkido joins offices, shops and warehouses into one encrypted private network. Install the server
on a machine with a public IP and run **one command** on a Linux box at each site: within minutes
every site's LAN can reach the others — no inbound ports at the sites, works behind dynamic IPs and
CG-NAT.

This is the **open edition** (AGPL-3.0): the server and the site agent, for one organisation. The
commercial edition adds the web dashboard, multiple isolated organisations, plans, bandwidth
limits, intrusion detection and prevention, and OpenWrt sites.

**How it works:** WireGuard tunnels from each site to the server — all traffic, BGP included, runs
inside them; BGP EVPN routes (FRR) with the server as route reflector, accepting from each site only
its own LAN; nftables isolation on the server; a dependency-free Python agent at each site; and an
HTTPS service on the server (`netkido serve`, Let's Encrypt certificate for `DOMAIN`) that serves
the one-time installer and the signed (HMAC) agent API. There is no web dashboard: sites are
managed with the `netkido` command.

**Install:**

```bash
sudo DOMAIN=vpn.example.com EMAIL=admin@example.com ./server/install.sh
sudo netkido site add "Madrid office" 192.168.10.1/24 --ports eth1
# then, on the site's machine, as root (add ?lang=en for English messages):
curl -fsSL https://vpn.example.com/install/<link> | sudo bash
```

Requirements, usage and development notes are in the Spanish section above (`netkido --help`
lists every command). Licensed under the [GNU AGPL-3.0](LICENSE).
