#!/system/bin/sh
MODDIR=${0%/*}
sh "$MODDIR/scripts/cert_ctl.sh" unmount_all >/dev/null 2>&1
rm -rf "$MODDIR"
