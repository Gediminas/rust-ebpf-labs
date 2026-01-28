#!/usr/bin/env bash
# 
set -euo pipefail
[[ -n "${DEBUG:-}" ]] && set -x

SECONDS=0  # Reset the SECONDS variable

#####################################
cat <<EOF
-------------------------------------------------------------------------
* Server
--------
KERNEL: $(uname -r)
USER: $(whoami)
------------------------
EOF
#####################################

export DEBIAN_FRONTEND=noninteractive

apt-get -y -q --no-install-recommends install \
    wireguard \
    wireguard-tools \
    tcpdump \
    curl \
    vim \
    > /dev/null

sysctl -w net.ipv4.ip_forward=1

# FIXME
wg-quick down wg0 || true
rm -rf /etc/wireguard/wg0.conf

if [[ ! -f /etc/wireguard/wg0.conf ]] ; then
    echo  --------
    echo "Adding Server Wireguard config wg0"

    # [Interface]
    # Address = 10.5.0.1/16
    # Address = fd00::1/112
    # ListenPort = 51820
    # PrivateKey = cOmmSJBi5IJ2Uh1AZsNZjmnEiGsr4MHpNUlAi1xUrmE=
    # PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    # PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

    cat << EOF > /etc/wireguard/wg0.conf
[Interface]
  ListenPort = 51820
  Address = 10.5.0.1/16
  Address = fd00::1/112
  PrivateKey = cOmmSJBi5IJ2Uh1AZsNZjmnEiGsr4MHpNUlAi1xUrmE=
        #pub = csmoelQgK1QvyE5+XmZnXaPNt/zCgk84BG6BwfcmOFE=
  PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
  PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
  PublicKey = C6qtaptmuYQLUM5z0FXjR3ECBL85I1eYeMBlcbu5BDY=
      #priv = CD2dqWTG5PltmCZdT0KfbaJdArriOndMibTw2/CLK2w=
  AllowedIPs = 10.5.0.2/32
  Endpoint = 192.168.211.101:51820
EOF

    wg-quick up wg0
fi

# BASEDIR=/vagrant
# SYNCDIR=/vagrant/sync
# GOLANG_IMAGE=golang:1.23-bookworm
# SECONDS=0  # Reset the SECONDS variable

# usermod -a -G systemd-journal vagrant

# (cd $SYNCDIR/server_root && cp -rf --parents * /)

# set +u
# source /etc/bash.bashrc
# set -u

# export LC_ALL=en_US.UTF-8
# export LANG=en_US.UTF-8
# export DEBUG=yes
# LOGDIR="/var/log/build"


# mkdir -p "$LOGDIR"
# echo "Starting setup (out will be printed when all jobs finishes)..."

# [[ -z "${SKIP_NLX_DKMS_BUILD:-}" ]] && {
#     set -e
#     trap "echo 'build has failed!'" ERR

#     echo "Setting up NordLynx DKMS..."
#     cd "$BASEDIR/nlx-dkms" || exit
#     make build
#     make -C src module-debug
#     sudo rmmod nordlynx &> /dev/null || echo "No nordlynx module to remove"
#     make -C src install
# } 2>&1 | sed 's/^/NLX-DKMS: /' > "${LOGDIR}/nlx-dkms.log" &

# [[ -z "${SKIP_NLX_TOOLS_BUILD:-}" ]] && {
#     set -e
#     trap "echo 'build has failed!'" ERR

#     echo "Setting up NordLynx Tools..."
#     cd "$BASEDIR/nlx-tools" || exit
#     make nordlynx-tools-dir
#     make -C nordlynx-tools/src
#     make -C nordlynx-tools/src install
# } 2>&1 | sed 's/^/NLX-TOOLS: /' > "${LOGDIR}/nlx-tools.log" &

# [[ -z "${SKIP_NLX_RADIUS_BUILD:-}" ]] && {
#     set -e
#     trap "echo 'build has failed!'" ERR

#     echo "Setting up NordLynx Radius..."
#     cd "$BASEDIR/nlx-radius" || exit
#     cargo install --locked --path . --root /usr --force
#     chown vagrant -R .   # Fix Rust build files ownership
# } 2>&1 | sed 's/^/NLX-RADIUS: /' > "${LOGDIR}/nlx-radius.log" &

# [[ -z "${SKIP_NLX_PQ_BUILD:-}" ]] && {
#     set -e
#     trap "echo 'build has failed!'" ERR

#     echo "Setting up Nordlynx PQ-UPGRADER..."
#     cd "$BASEDIR/nlx-pq" || exit
#     sudo docker pull "$GOLANG_IMAGE"   # Add golang image to build in container
#     ci/build.sh docker
#     sudo apt-get install -y ./dist/nordlynx-pq-upgrader_*_amd64.deb
# } 2>&1 | sed 's/^/NLX-PQ: /' > "${LOGDIR}/nlx-pq.log" &

# [[ -z "${SKIP_NLX_EBPF:-}" ]] && {
#     set -e
#     trap "echo 'build has failed!'" ERR

#     echo "Setting up Nordlynx eBPF..."
#     cd "$BASEDIR/nlx-ebpf" || exit
#     ci/build_on_docker.sh
#     sudo apt-get install -y ./nordlynx-ebpf*_amd64.deb
# } 2>&1 | sed 's/^/NLX-EBPF: /' > "${LOGDIR}/nlx-ebpf.log" &

# wait< <(jobs -p)
# echo "Waiting for build jobs to finish..."

# sleep .1
# cat ${LOGDIR}/*.log
# if grep -q ": build has failed!" ${LOGDIR}/*.log; then
#     grep -B 10 ": build has failed!" ${LOGDIR}/*.log
#     exit 1
# fi

# echo "Setting up services..."
# systemctl daemon-reload
# up nlx-quick@nlx0
# up nlx-radius
# up fakefm.service
# up pq-upgrader

echo "GREAT SUCCESS!!! Setup took ${SECONDS}s"
