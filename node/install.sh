#!/usr/bin/env bash
# Netkido — instalador de sede / site installer «@@SITE_NAME@@»
#
#   curl -fsSL @@PORTAL_URL@@/install/<token> | sudo bash
#
# Debian 12 / 13 (también Armbian y Raspberry Pi OS), Ubuntu 22.04 / 24.04 (amd64 / arm64).
# ES: el enlace es de un solo uso; al inscribirse, el portal registra la clave
#     pública de WireGuard de esta máquina y le entrega el secreto del agente.
# EN: the link works once; on enrolment the portal records this machine's
#     WireGuard public key and hands the agent its secret.
set -euo pipefail

PORTAL="@@PORTAL_URL@@"
TOKEN="@@INSTALL_TOKEN@@"
LIB=/usr/local/lib/netkido
NK_LANG="@@LANG@@"

# Mensajes / messages (es|en): los rellena el portal / filled in by the portal.
@@MESSAGES@@

# Todo va dentro de main(), que se llama en la última línea: si la descarga llega cortada,
# bash no ejecuta nada a medias. / Everything runs from main(), called on the last line, so a
# truncated download never runs half a script.
main() {
log()  { echo -e "\e[1;34m[netkido]\e[0m $*"; }
warn() { echo -e "\e[1;33m[netkido] ${M_WARNING}:\e[0m $*" >&2; }
die()  { echo -e "\e[1;31m[netkido] ERROR:\e[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "$M_NEED_ROOT"
[[ -r /etc/os-release ]] || die "$M_UNKNOWN_OS"
. /etc/os-release
# Rama de FRR del repositorio oficial: la 8 donde existe; Debian 13 (trixie) solo tiene la 10.
case "${ID}:${VERSION_ID:-}" in
  debian:12|ubuntu:22.04|ubuntu:24.04) FRR_REPO="${NETKIDO_FRR_REPO:-frr-8}" ;;
  debian:13) FRR_REPO="${NETKIDO_FRR_REPO:-frr-10}" ;;
  *) die "$(printf "$M_UNSUPPORTED" "${PRETTY_NAME:-?}")";;
esac
CODENAME="${VERSION_CODENAME:-$(lsb_release -sc 2>/dev/null || true)}"
[[ -n "$CODENAME" ]] || die "$(printf "$M_UNSUPPORTED" "${PRETTY_NAME:-?}")"
command -v systemctl >/dev/null || die "$M_NEED_SYSTEMD"

log "$(printf "$M_INSTALLING" "@@SITE_NAME@@" "$(hostname)" "${PRETTY_NAME}")"

log "$M_PACKAGES"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates gnupg iproute2 iputils-ping \
  wireguard-tools nftables python3 dnsmasq-base >/dev/null
if ! [[ -f /etc/apt/sources.list.d/frr.list ]]; then
  curl -fsSL https://deb.frrouting.org/frr/keys.gpg -o /usr/share/keyrings/frrouting.gpg
  echo "deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouting.org/frr ${CODENAME} ${FRR_REPO}" \
    > /etc/apt/sources.list.d/frr.list
  apt-get update -qq
fi
apt-get install -y -qq frr frr-pythontools >/dev/null
sed -i 's/^bgpd=no/bgpd=yes/' /etc/frr/daemons
modprobe wireguard 2>/dev/null || true
modprobe vrf 2>/dev/null || true
modprobe vxlan 2>/dev/null || true

log "$M_AGENT"
install -d -m 0755 "$LIB"
install -d -m 0700 /etc/netkido /var/lib/netkido
install -d -m 0750 /var/log/netkido
tmp="$(mktemp)"; hdr="$(mktemp)"
trap 'rm -f "$tmp" "$hdr"' EXIT
curl -fsSL -D "$hdr" "${PORTAL}/install/${TOKEN}/agent" -o "$tmp" || die "$M_DOWNLOAD_FAILED"
want="$(awk -F': ' 'tolower($1)=="x-netkido-agent-sha256"{print $2}' "$hdr" | tr -d '\r')"
have="$(sha256sum "$tmp" | awk '{print $1}')"
[[ -n "$want" && "$want" == "$have" ]] || die "$M_SHA_FAILED"
python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$tmp" || die "$M_PYTHON_FAILED"
install -m 0755 "$tmp" "$LIB/netkido-agent.py"
ln -sf "$LIB/netkido-agent.py" /usr/local/sbin/netkido-agent

cat > /etc/systemd/system/netkido-agent.service <<EOF
[Unit]
Description=${M_UNIT_AGENT}
After=network-online.target frr.service
Wants=network-online.target frr.service

[Service]
Type=simple
# Al arrancar, primero se rehace la red con la última configuración conocida.
ExecStartPre=-/usr/local/sbin/netkido-agent apply --cached
ExecStart=/usr/local/sbin/netkido-agent run
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/netkido-dhcp.service <<EOF
[Unit]
Description=${M_UNIT_DHCP}
After=netkido-agent.service
ConditionPathExists=/etc/netkido/dnsmasq-lan.conf

[Service]
ExecStart=/usr/sbin/dnsmasq -k --conf-file=/etc/netkido/dnsmasq-lan.conf --pid-file=
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

log "$M_ENROLL"
# apt arranca FRR al instalarlo con bgpd=no: hay que reiniciarlo para que lea «daemons» y arranque bgpd.
systemctl enable frr >/dev/null 2>&1
systemctl restart frr
/usr/local/sbin/netkido-agent enroll --portal "$PORTAL" --token "$TOKEN" --lang "$NK_LANG" \
  || die "$M_ENROLL_FAILED"
systemctl enable --now netkido-agent >/dev/null

log "$M_TUNNEL"
ok=""
for _ in $(seq 1 20); do
  if ping -c1 -W1 100.64.0.1 >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
[[ -n "$ok" ]] && log "$M_TUNNEL_OK" || warn "$M_TUNNEL_WAIT"

echo
/usr/local/sbin/netkido-agent status
echo
log "$M_INTERFACES"
ip -br link | grep -vE '^(lo|nk|TENANT-)' | sed 's/^/    /'
printf "\n%s\n" "$M_DONE"
}

main "$@"
