#!/bin/sh
set -eu
for path in /var/lib/avbox/staging /var/lib/avbox/quarantine; do
  options=$(findmnt -no OPTIONS --target "$path")
  for required in nodev nosuid noexec; do
    case ",$options," in *,$required,*) ;; *) echo "$path lacks $required" >&2; exit 1;; esac
  done
done
