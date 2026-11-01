#!/system/bin/sh
SKIPUNZIP=0

ui_print "- 正在初始化 System CA CertBind Manager..."

# 创建持久化数据目录与工作目录
mkdir -p "$MODPATH/config"
mkdir -p "$MODPATH/custom_certs"
mkdir -p "$MODPATH/stock_backup"
mkdir -p "$MODPATH/work_certs"

# 默认开启内置 bind mount，并打上 skip_mount 防止管理器重复挂载
if [ ! -f "$MODPATH/config/settings.conf" ]; then
    echo "BIND_MOUNT=true" > "$MODPATH/config/settings.conf"
fi
touch "$MODPATH/skip_mount"
touch "$MODPATH/config/deleted.list"

# 赋予脚本执行权限（注意：按照 KSU 官方规范，不要手动修改 webroot 的 SELinux 上下文）
set_perm_recursive "$MODPATH/scripts" 0 0 0755 0755
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
set_perm "$MODPATH/post-mount.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755

ui_print "- 已默认启用内置 Bind Mount 并添加 skip_mount 标签"
ui_print "- 安装完成，重启后即可在 KernelSU / APatch WebUI 中管理证书！"
