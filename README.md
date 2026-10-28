# Netkido — red privada entre las sedes de tu empresa

**Español** · [English](README.en.md)

Netkido une oficinas, tiendas y almacenes en una sola red privada cifrada. Instalas el servidor en
una máquina con IP pública y ejecutas **un comando** en un equipo Linux de cada sede: en un par de
minutos las redes locales de todas las sedes se ven entre sí, sin abrir puertos en las sedes ni
tocar el router del operador (funciona con IP dinámica y CG-NAT).

Este repositorio es la **edición abierta** (licencia AGPL-3.0): el servidor y el agente de las
sedes, para una organización, gestionados desde la línea de comandos.

> **¿Prefieres no mantener un servidor?** En **[netkido.tech](https://netkido.tech)** tienes Netkido
> como servicio: nosotros mantenemos el hub y tú gestionas tus sedes desde un panel web, con avisos,
> diagnóstico y seguridad incluidos. **Puedes probarlo gratis con hasta dos sedes**, sin instalar
> nada más que el agente en cada sede.

## Edición abierta y Netkido en netkido.tech

| | Edición abierta (este repositorio) | [Netkido en netkido.tech](https://netkido.tech) |
|---|:---:|:---:|
| Túneles WireGuard, BGP EVPN y aislamiento en el hub | ✅ | ✅ |
| Instalador de sede de un solo uso y agente que se actualiza solo | ✅ | ✅ |
| Servidor (hub) | Lo instalas y mantienes tú | **Lo mantenemos nosotros**, con copias de seguridad y actualizaciones |
| Gestión de las sedes | Comando `netkido` en el servidor | **Panel web**, en español e inglés |
| Estado de cada sede | `netkido site list` | **En vivo:** latencia, tráfico, último contacto e historial de eventos |
| Avisos | — | **Por correo** cuando una sede deja de responder |
| Diagnóstico | Por SSH en cada sede | **Desde el panel:** túnel, rutas, MTU y log del agente, sin entrar en la sede |
| Equipo | Quien tenga root en el servidor | **Usuarios con permisos** (administrador o solo lectura) y doble factor |
| Organizaciones | Una | **Varias, aisladas entre sí** (ideal para integradores que gestionan clientes) |
| Detección y bloqueo de intrusiones (Suricata) | — | ✅ en los planes de pago |
| Sedes con routers OpenWrt | — | ✅ en los planes de pago |
| Ancho de banda por sede | — | Según el plan |
| Soporte | Comunidad ([Discussions](https://github.com/netkido/netkido/discussions)) | **Por correo**, prioritario y con acuerdo de nivel de servicio según el plan |

👉 **[Crea tu cuenta gratis en netkido.tech](https://netkido.tech)** y conecta tus dos primeras
sedes hoy. Cuando necesites más sedes o más ancho de banda, [cuéntanos qué necesitas](https://netkido.tech/#contacto)
y lo ampliamos sin reinstalar nada.

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

Más detalle en la [wiki](https://github.com/netkido/netkido/wiki/Arquitectura).

## Requisitos

- **Servidor:** Debian 12/13 o Ubuntu 22.04/24.04 con IP pública, un nombre DNS que apunte a ella y
  abiertos 80/TCP, 443/TCP y 51820/UDP.
- **Sedes:** un equipo Linux que haga de router de su LAN (mini PC o placa SBC, mejor con dos
  puertos de red): Debian 12/13, Ubuntu 22.04/24.04, Armbian o Raspberry Pi OS de 64 bits. Mira los
  [equipos probados](https://github.com/netkido/netkido/wiki/Equipos-probados).

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

Guía completa: [Instalación del servidor](https://github.com/netkido/netkido/wiki/Instalación-del-servidor)
y [Alta de sedes](https://github.com/netkido/netkido/wiki/Alta-de-sedes).

## Uso

| Para… | |
|---|---|
| Ver las sedes y su estado | `sudo netkido site list` · `sudo netkido status` |
| Cambiar los puertos o la LAN | `sudo netkido site ports <sede> eth1,eth2` · `sudo netkido site lan <sede> 192.168.11.1/24` |
| DHCP en la LAN | `sudo netkido site dhcp <sede> on\|off` |
| Reinstalar una sede | `sudo netkido site link <sede>` (enlace nuevo) |
| Sacar una sede de la red | `sudo netkido site disable <sede>` · `enable` · `remove` |
| Logs | servidor: `journalctl -u netkido` · sede: `journalctl -u netkido-agent` |

Los cambios llegan a las sedes en menos de un minuto. Todos los comandos, en
[Comando netkido](https://github.com/netkido/netkido/wiki/Comando-netkido); si algo falla, en
[Solución de problemas](https://github.com/netkido/netkido/wiki/Solución-de-problemas).

## ¿Lo usas en tu empresa o para tus clientes?

Si gestionas varias empresas, necesitas que alguien vigile la red por ti o quieres detección de
intrusiones sin montar nada, **[echa un vistazo a netkido.tech](https://netkido.tech)**: es el mismo
motor que este repositorio, con el servidor, el panel y el soporte a nuestro cargo. Y si ya usas la
edición abierta y quieres pasar tus sedes al servicio, [escríbenos](https://netkido.tech/#contacto)
y te ayudamos a migrar.

## Desarrollo

```bash
python3 -m unittest discover -s tests -v
```

Las contribuciones son bienvenidas: lee [CONTRIBUTING.md](CONTRIBUTING.md). Para avisar de un
fallo de seguridad, sigue [SECURITY.md](SECURITY.md). Las preguntas y las ideas, en
[Discussions](https://github.com/netkido/netkido/discussions).

## Licencia

[GNU AGPL-3.0](LICENSE). Si ofreces Netkido modificado como servicio a terceros, tienes que
publicar el código de tus cambios. «Netkido» es una marca: puedes usar el nombre para referirte al
proyecto, pero no para productos derivados.
