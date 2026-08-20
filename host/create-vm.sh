#!/bin/bash
set -euo pipefail
NAME=avbox-bootstrap
POOL=default
OS_VOL=avbox-bootstrap-os.qcow2
DATA_VOL=avbox-bootstrap-preservation.qcow2
ISO=/home/pgo/Downloads/debian-13.6.0-amd64-netinst.iso
ROOT=$(cd "$(dirname "$0")/.." && pwd)
STATE="$ROOT/.state"

if virsh -c qemu:///system dominfo "$NAME" >/dev/null 2>&1; then
  echo "$NAME already exists; refusing to modify it" >&2; exit 1
fi
for vol in "$OS_VOL" "$DATA_VOL"; do
  if virsh -c qemu:///system vol-info --pool "$POOL" "$vol" >/dev/null 2>&1; then
    echo "$vol already exists; refusing to modify it" >&2; exit 1
  fi
done
test -r "$ISO" || { echo "Missing readable Debian ISO: $ISO" >&2; exit 1; }
mkdir -p "$STATE"
chmod 0700 "$STATE"
PASSWORD=$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)
HASH=$(openssl passwd -6 "$PASSWORD")
sed "s|@PASSWORD_HASH@|$HASH|" "$ROOT/installer/preseed.cfg.in" > "$STATE/preseed.cfg"
printf '%s\n' "$PASSWORD" > "$STATE/console-password"
chmod 0600 "$STATE/console-password" "$STATE/preseed.cfg"

PAYLOAD="$STATE/iso-tree/payload"
mkdir -p "$PAYLOAD/usr/local/lib/avbox-bootstrap" "$PAYLOAD/usr/local/bin" "$PAYLOAD/etc/avbox-bootstrap" "$PAYLOAD/usr/local/sbin" "$PAYLOAD/etc/systemd/system"
install -m 0755 "$ROOT/bin/avbox-bootstrap.py" "$PAYLOAD/usr/local/lib/avbox-bootstrap/"
for cmd in acquire verify inventory export-for-rab; do install -m 0755 "$ROOT/bin/$cmd" "$PAYLOAD/usr/local/bin/$cmd"; done
install -m 0444 "$ROOT/config/acquisition.yaml" "$PAYLOAD/etc/avbox-bootstrap/acquisition.yaml"
install -m 0755 "$ROOT/installer/payload/usr/local/sbin/avbox-bootstrap-init" "$PAYLOAD/usr/local/sbin/"
install -m 0444 "$ROOT/installer/payload/etc/systemd/system/avbox-bootstrap-init.service" "$PAYLOAD/etc/systemd/system/"
xorriso -as mkisofs -quiet -o "$STATE/bootstrap-config.iso" "$STATE/iso-tree"
chmod 0711 "$STATE"
chmod 0644 "$STATE/bootstrap-config.iso"

virsh -c qemu:///system vol-create-as "$POOL" "$OS_VOL" 32G --allocation 0 --format qcow2
virsh -c qemu:///system vol-create-as "$POOL" "$DATA_VOL" 32G --allocation 0 --format qcow2
virt-install --connect qemu:///system \
  --name "$NAME" --memory 2048 --vcpus 1 --cpu qemu64 \
  --osinfo debian13 --virt-type kvm --noautoconsole \
  --disk "vol=$POOL/$OS_VOL,bus=virtio,discard=unmap" \
  --disk "vol=$POOL/$DATA_VOL,bus=virtio,discard=unmap" \
  --disk "path=$STATE/bootstrap-config.iso,device=cdrom,readonly=on" \
  --network network=default,model=virtio \
  --graphics none --video none --sound none \
  --channel unix,target_type=virtio,name=org.qemu.guest_agent.0 \
  --location "$ISO" --initrd-inject "$STATE/preseed.cfg" \
  --extra-args 'auto=true priority=critical preseed/file=/preseed.cfg console=ttyS0,115200n8 serial'
echo "Installation started. Console password is stored in $STATE/console-password"
