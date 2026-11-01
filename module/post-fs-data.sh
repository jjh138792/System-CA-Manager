#!/system/bin/sh
MODDIR=${0%/*}

# 如果运行在 KernelSU / SukiSU 或 APatch 下，跳过 post-fs-data 阶段，等待 post-mount 阶段挂载
if [ "$KSU" = "true" ] || [ "$APATCH" = "true" ] || [ -d "/data/adb/ksu" ] || [ -d "/data/adb/ap" ]; then
    exit 0
fi

# Magisk 没有 post-mount 阶段，在此处直接执行挂载
sh "$MODDIR/scripts/cert_ctl.sh" boot_mount >> "$MODDIR/config/mount.log" 2>&1
