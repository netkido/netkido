#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Netkido (edición abierta) — instalación del servidor: hub WireGuard + BGP EVPN y un servicio HTTPS
# (netkido serve) para instalar y gestionar las sedes.
#
#   sudo DOMAIN=vpn.example.com EMAIL=admin@example.com ./server/install.sh
#
# Debian 12/13 o Ubuntu 22.04/24.04 con IP pública. Antes: un registro DNS A de DOMAIN que apunte al
# servidor y, en el cortafuegos del proveedor, abiertos 80/TCP (certificado), 443/TCP (API e
# instalador) y WG_PORT/UDP (túneles, 51820 por defecto).
#
# Instala:
#   * el hub: WireGuard (wg0, 100.64.0.1/16), FRR con BGP EVPN y nftables, aplicados por
#     netkido-hub-apply. Todo el tráfico de las sedes, también BGP, va dentro de WireGuard.
#   * el servicio HTTPS «netkido serve» (puerto 443): sirve el instalador de un solo uso, inscribe
#     las sedes y les entrega su configuración. Su certificado (Let's Encrypt) es para DOMAIN, que
#     es también el nombre con el que las sedes encuentran el hub. No hay panel web: las sedes se
#     gestionan con el comando «netkido».
# Es idempotente: se puede volver a ejecutar para actualizar.
#
# Variables: DOMAIN y EMAIL (obligatorias), WG_PORT=51820, DNS=1.1.1.1,9.9.9.9 (para las LAN de
# las sedes), FIREWALL=yes (no: no se toca el cortafuegos), CERT=letsencrypt (existing: ya hay
# certificado en /etc/letsencrypt/live/DOMAIN).
set -euo pipefail

DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
WG_PORT="${WG_PORT:-51820}"
DNS="${DNS:-1.1.1.1,9.9.9.9}"
FIREWALL="${FIREWALL:-yes}"
CERT="${CERT:-letsencrypt}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; SRC="$(dirname "$HERE")"

log() { echo -e "\e[1;34m[netkido]\e[0m $*"; }
die() { echo -e "\e[1;31m[netkido] ERROR:\e[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "ejecútalo como root (sudo)"
[[ -n "$DOMAIN" && "$DOMAIN" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "indica el dominio: DOMAIN=vpn.example.com"
[[ "$CERT" == existing || -n "$EMAIL" ]] || die "indica un email para Let's Encrypt: EMAIL=admin@example.com"
[[ "$WG_PORT" =~ ^[0-9]{1,5}$ ]] && (( WG_PORT > 0 && WG_PORT < 65536 )) || die "WG_PORT no válido"
for f in hub/netkido-hub-apply server/netkido server/messages.json node/netkido-agent.py node/install.sh; do
  [[ -f "$SRC/$f" ]] || die "falta $f (ejecuta el script desde el repositorio completo)"
done
. /etc/os-release
case "${ID}:${VERSION_ID:-}" in
  debian:12|ubuntu:22.04|ubuntu:24.04) FRR_REPO="${FRR_REPO:-frr-8}" ;;
  debian:13) FRR_REPO="${FRR_REPO:-frr-10}" ;;
  *) die "sistema no soportado: ${PRETTY_NAME:-?} (Debian 12/13, Ubuntu 22.04 o 24.04)" ;;
esac
CODENAME="${VERSION_CODENAME:-}"

log "Paquetes"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl gnupg wireguard-tools nftables python3 iproute2 sudo certbot >/dev/null
if ! [[ -f /etc/apt/sources.list.d/frr.list ]]; then
  curl -fsSL https://deb.frrouting.org/frr/keys.gpg -o /usr/share/keyrings/frrouting.gpg
  echo "deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouting.org/frr ${CODENAME} ${FRR_REPO}" \
    > /etc/apt/sources.list.d/frr.list
  apt-get update -qq
fi
apt-get install -y -qq frr frr-pythontools >/dev/null

log "Kernel"
cat > /etc/sysctl.d/90-netkido-hub.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF
sysctl -q --system

log "Usuario y ficheros"
id netkido &>/dev/null || useradd --system --home-dir /var/lib/netkido --shell /usr/sbin/nologin netkido
install -d -m 0755 /etc/netkido /usr/local/lib/netkido
install -d -m 0750 -o netkido -g netkido /var/lib/netkido
install -d -m 0750 -o root -g netkido /etc/netkido/tls
install -d -m 0700 /var/lib/netkido-hub
install -m 0755 "$SRC/hub/netkido-hub-apply" /usr/local/sbin/netkido-hub-apply
install -m 0755 "$SRC/server/netkido" /usr/local/sbin/netkido
install -m 0644 "$SRC/node/netkido-agent.py" "$SRC/node/install.sh" "$SRC/server/messages.json" /usr/local/lib/netkido/
if [[ ! -s /etc/netkido/wg0.key ]]; then
  (umask 077; wg genkey > /etc/netkido/wg0.key)
  log "clave nueva del hub generada"
fi
chmod 600 /etc/netkido/wg0.key
cat > /etc/netkido/hub.conf <<EOF
# netkido-hub-apply — ajustes locales del hub
WG_LISTEN_PORT=${WG_PORT}
WG_MTU=1420
EOF
# El servicio (usuario netkido) solo puede pasar el estado del hub por la entrada estándar.
cat > /etc/sudoers.d/netkido <<'EOF'
netkido ALL=(root) NOPASSWD: /usr/local/sbin/netkido-hub-apply ""
EOF
chmod 440 /etc/sudoers.d/netkido
visudo -cf /etc/sudoers.d/netkido >/dev/null || die "sudoers no válido"

log "FRR"
sed -i 's/^bgpd=no/bgpd=yes/' /etc/frr/daemons
systemctl enable frr >/dev/null 2>&1
systemctl restart frr   # apt lo arranca con bgpd=no: hay que reiniciarlo para que lea «daemons»

log "WireGuard (wg0, 100.64.0.1/16, puerto ${WG_PORT}/udp)"
if [[ ! -f /etc/wireguard/wg0.conf ]]; then
  (umask 077; cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 100.64.0.1/16
MTU = 1420
Table = off
ListenPort = ${WG_PORT}
PrivateKey = $(cat /etc/netkido/wg0.key)
EOF
)
fi
systemctl enable --now wg-quick@wg0 >/dev/null

if [[ "$FIREWALL" == yes ]]; then
  log "Cortafuegos (entrada: SSH, 80, 443 y ${WG_PORT}/udp)"
  SSH_PORT="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2; exit}')"; SSH_PORT="${SSH_PORT:-22}"
  cat > /etc/netkido/firewall.nft <<EOF
# Netkido — cortafuegos de entrada del servidor (lo escribe server/install.sh)
table inet netkido_fw
delete table inet netkido_fw
table inet netkido_fw {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    iifname "wg0" accept comment "lo filtra netkido-hub-apply (tabla netkido_iso)"
    icmp type { echo-request, destination-unreachable, time-exceeded } accept
    meta l4proto ipv6-icmp accept
    tcp dport ${SSH_PORT} ct state new limit rate 20/minute burst 20 packets accept
    tcp dport { 80, 443 } accept
    udp dport ${WG_PORT} accept
  }
}
EOF
  cat > /etc/systemd/system/netkido-firewall.service <<'EOF'
[Unit]
Description=Netkido: cortafuegos de entrada del servidor
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/netkido/firewall.nft
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now netkido-firewall >/dev/null
fi

log "Certificado TLS (${DOMAIN})"
cat > /etc/netkido/cert-deploy.sh <<EOF
#!/bin/sh
# Copia el certificado para el servicio netkido y lo reinicia (certbot --deploy-hook).
install -m 0640 -o root -g netkido /etc/letsencrypt/live/${DOMAIN}/fullchain.pem /etc/netkido/tls/fullchain.pem
install -m 0640 -o root -g netkido /etc/letsencrypt/live/${DOMAIN}/privkey.pem /etc/netkido/tls/privkey.pem
systemctl try-restart netkido.service
EOF
chmod 0755 /etc/netkido/cert-deploy.sh
if [[ "$CERT" != existing ]] && [[ ! -d "/etc/letsencrypt/live/${DOMAIN}" ]]; then
  certbot certonly --standalone -n --agree-tos -m "$EMAIL" -d "$DOMAIN" \
    --deploy-hook /etc/netkido/cert-deploy.sh >/dev/null \
    || die "no se pudo obtener el certificado: comprueba que ${DOMAIN} apunta a este servidor y que el puerto 80 está abierto"
fi
[[ -d "/etc/letsencrypt/live/${DOMAIN}" ]] || die "no hay certificado en /etc/letsencrypt/live/${DOMAIN}"
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
ln -sf /etc/netkido/cert-deploy.sh /etc/letsencrypt/renewal-hooks/deploy/netkido
/etc/netkido/cert-deploy.sh

log "Servicio netkido (API de las sedes e instalador, https://${DOMAIN})"
/usr/local/sbin/netkido init --domain "$DOMAIN" --wg-port "$WG_PORT" --dns "$DNS" >/dev/null
chown netkido:netkido /var/lib/netkido/state.json
cat > /etc/systemd/system/netkido.service <<'EOF'
[Unit]
Description=Netkido: API de las sedes e instalador
After=network-online.target wg-quick@wg0.service frr.service
Wants=network-online.target

[Service]
User=netkido
Group=netkido
ExecStart=/usr/local/sbin/netkido serve
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
PrivateTmp=yes
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/netkido-hub-restore.service <<'EOF'
[Unit]
Description=Netkido: reaplicar el estado del hub al arrancar
After=network-online.target nftables.service wg-quick@wg0.service frr.service
Wants=network-online.target
Requires=wg-quick@wg0.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/netkido apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable netkido-hub-restore >/dev/null
systemctl enable netkido >/dev/null
systemctl restart netkido
/usr/local/sbin/netkido apply >/dev/null || true

for _ in $(seq 1 20); do curl -fsS -m 3 "https://${DOMAIN}/up" >/dev/null 2>&1 && break; sleep 1; done
if curl -fsS -m 5 "https://${DOMAIN}/up" >/dev/null 2>&1; then
  log "https://${DOMAIN} responde"
else
  echo -e "\e[1;33m[netkido] AVISO:\e[0m https://${DOMAIN} no responde todavía: journalctl -u netkido -n 50" >&2
fi

cat <<EOF

 Servidor listo. Da de alta la primera sede:

   sudo netkido site add "Oficina Madrid" 192.168.10.1/24 --ports eth1

 y ejecuta en el equipo de esa sede el comando que te muestra. Más:  netkido --help
EOF
