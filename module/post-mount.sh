#!/system/bin/sh
MODDIR=${0%/*}

# 在元模块和其他模块挂载完成后执行，防止被其他模块的目录级挂载覆盖
sh "$MODDIR/scripts/cert_ctl.sh" boot_mount >> "$MODDIR/config/mount.log" 2>&1
