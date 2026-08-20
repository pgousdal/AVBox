#!/bin/bash
set -euo pipefail

DOMAIN=${AVBOX_DOMAIN:-avbox-bootstrap}
URI=${LIBVIRT_DEFAULT_URI:-qemu:///system}

if (($# == 0)); then
  echo "usage: $0 command [argument ...]" >&2
  exit 64
fi

path=$1
shift
if (($#)); then
  args=$(printf '%s\n' "$@" | jq -R . | jq -s .)
else
  args='[]'
fi
request=$(jq -nc --arg path "$path" --argjson args "$args" '
  {execute:"guest-exec", arguments:{path:$path, arg:$args, "capture-output":true}}')
reply=$(virsh -c "$URI" qemu-agent-command "$DOMAIN" "$request")
pid=$(jq -er '.return.pid' <<<"$reply")

while :; do
  status=$(virsh -c "$URI" qemu-agent-command "$DOMAIN" \
    "{\"execute\":\"guest-exec-status\",\"arguments\":{\"pid\":$pid}}")
  jq -e '.return.exited == true' >/dev/null <<<"$status" && break
  sleep 1
done

jq -r '.return["out-data"] // "" | @base64d' <<<"$status"
jq -r '.return["err-data"] // "" | @base64d' <<<"$status" >&2
exit "$(jq -r '.return.exitcode // 1' <<<"$status")"
