#!/bin/bash
set -euo pipefail
URI=qemu:///system
virsh -c "$URI" dominfo avbox-bootstrap
virsh -c "$URI" domblklist avbox-bootstrap --details
virsh -c "$URI" domiflist avbox-bootstrap
virsh -c "$URI" domifaddr avbox-bootstrap --source agent || virsh -c "$URI" domifaddr avbox-bootstrap --source lease

