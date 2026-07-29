# scripts/lib/mainline_r6_env.sh
#
# Shared M-r6 xiaomi-lmi release environment defaults and repo-root discovery.
# Source this file; do not execute it. Every consumer sees the same four
# release defaults, so the bundle builder (scripts/47) and the progress
# loop (scripts/68) can never silently disagree about which directory is
# built versus audited.
#
# Environment overrides always win; the values below are only defaults.

lmi_repo=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)

lmi_default_out_dir=${OUT_DIR:-/tmp/lmi-copydown-r6-bootmem-20260624}
lmi_default_export_dir=${PMOS_EXPORT_DIR:-/tmp/postmarketOS-export}
lmi_default_bundle_dir=${LMI_RELEASE_BUNDLE_DIR:-/tmp/lmi-release-r6-bootmem-20260624}
lmi_default_release_tag=${LMI_RELEASE_TAG:-r6-bootmem}
