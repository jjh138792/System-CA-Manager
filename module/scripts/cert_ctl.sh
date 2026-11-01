#!/system/bin/sh
# System CA CertBind Manager - Core Backend Script

SCRIPT_DIR=${0%/*}
MODDIR=$(cd "$SCRIPT_DIR/.." && pwd)
CONF_DIR="$MODDIR/config"
CONF_FILE="$CONF_DIR/settings.conf"
DELETED_LIST="$CONF_DIR/deleted.list"
CUSTOM_DIR="$MODDIR/custom_certs"
STOCK_DIR="$MODDIR/stock_backup"
WORK_DIR="$MODDIR/work_certs"
SYS_MOD_CACERTS="$MODDIR/system/etc/security/cacerts"

# 引入 BusyBox 环境，确保 stat / awk / sed / nsenter / chcon 等命令完备
for bb in /data/adb/ksu/bin/busybox /data/adb/ap/bin/busybox /data/adb/magisk/busybox; do
    if [ -x "$bb" ]; then
        export PATH="$(dirname "$bb"):$PATH"
        break
    fi
done

mkdir -p "$CONF_DIR" "$CUSTOM_DIR" "$STOCK_DIR" "$WORK_DIR"
[ -f "$CONF_FILE" ] || echo "BIND_MOUNT=true" > "$CONF_FILE"
[ -f "$DELETED_LIST" ] || touch "$DELETED_LIST"

# 读取配置
get_bind_mode() {
    grep -q "^BIND_MOUNT=false" "$CONF_FILE" 2>/dev/null && echo "false" || echo "true"
}

# 自动检测 Android 系统证书路径（兼容旧版 /system 与 Android 14+ /apex）
detect_target_dir() {
    if [ -d "/apex/com.android.conscrypt/cacerts" ]; then
        echo "/apex/com.android.conscrypt/cacerts"
    else
        echo "/system/etc/security/cacerts"
    fi
}

# 检测当前 Root 管理器类型
detect_root_manager() {
    if [ "$KSU" = "true" ] || [ -d "/data/adb/ksu" ]; then
        echo "KernelSU / SukiSU (post-mount)"
    elif [ "$APATCH" = "true" ] || [ -d "/data/adb/ap" ]; then
        echo "APatch (post-mount)"
    else
        echo "Magisk (post-fs-data)"
    fi
}

# 首次启动或备份为空时，备份原厂系统证书（仅在未挂载覆盖前执行）
ensure_stock_backup() {
    TARGET_DIR=$(detect_target_dir)
    WORK_DEV_INO=$(stat -c "%d:%i" "$WORK_DIR" 2>/dev/null)
    TARGET_DEV_INO=$(stat -c "%d:%i" "$TARGET_DIR" 2>/dev/null)

    # 如果目标目录尚未被我们的 WORK_DIR 挂载，且备份目录为空，则备份原厂证书
    if [ "$WORK_DEV_INO" != "$TARGET_DEV_INO" ]; then
        if [ -z "$(ls -A "$STOCK_DIR" 2>/dev/null)" ]; then
            cp -pf "$TARGET_DIR"/*.0 "$STOCK_DIR"/ 2>/dev/null
            # 记录原厂目录 SELinux 上下文
            ORIG_CTX=$(ls -Zd "$TARGET_DIR" 2>/dev/null | awk '{print $1}')
            [ -n "$ORIG_CTX" ] && echo "$ORIG_CTX" > "$CONF_DIR/selinux_context"
        fi
    fi
}

# 构建合并工作区（使用硬链接 ln -f 保持 Inode 与源文件绝对一致）
rebuild_work_dir() {
    ensure_stock_backup
    rm -rf "$WORK_DIR"/* 2>/dev/null

    # 1. 硬链接未被屏蔽的原厂证书
    for cert in "$STOCK_DIR"/*.0; do
        [ -f "$cert" ] || continue
        fname=$(basename "$cert")
        if ! grep -qxF "$fname" "$DELETED_LIST" 2>/dev/null; then
            ln -f "$cert" "$WORK_DIR/$fname" 2>/dev/null || cp -pf "$cert" "$WORK_DIR/$fname"
        fi
    done

    # 2. 硬链接用户新增或修改的证书（同名自动覆盖原厂证书）
    for cert in "$CUSTOM_DIR"/*.0; do
        [ -f "$cert" ] || continue
        fname=$(basename "$cert")
        ln -f "$cert" "$WORK_DIR/$fname" 2>/dev/null || cp -pf "$cert" "$WORK_DIR/$fname"
    done

    # 3. 修正权限与 SELinux 安全上下文
    chown -R 0:0 "$WORK_DIR" 2>/dev/null
    chmod 755 "$WORK_DIR" 2>/dev/null
    chmod 644 "$WORK_DIR"/*.0 2>/dev/null

    TARGET_DIR=$(detect_target_dir)
    SAVED_CTX=$(cat "$CONF_DIR/selinux_context" 2>/dev/null)
    if [ -z "$SAVED_CTX" ]; then
        SAVED_CTX=$(ls -Zd "$TARGET_DIR" 2>/dev/null | awk '{print $1}')
    fi
    [ -z "$SAVED_CTX" ] && SAVED_CTX="u:object_r:system_file:s0"
    chcon -R "$SAVED_CTX" "$WORK_DIR" 2>/dev/null
}

# 在全局命名空间及 Zygote 命名空间执行挂载
do_bind_mount() {
    TARGET_DIR=$(detect_target_dir)
    rebuild_work_dir

    # 确保打上 skip_mount 标签并清理 system 目录防止冲突
    touch "$MODDIR/skip_mount"
    rm -rf "$MODDIR/system" 2>/dev/null

    WORK_DEV_INO=$(stat -c "%d:%i" "$WORK_DIR" 2>/dev/null)
    TARGET_DEV_INO=$(stat -c "%d:%i" "$TARGET_DIR" 2>/dev/null)

    if [ "$WORK_DEV_INO" != "$TARGET_DEV_INO" ]; then
        mount --bind "$WORK_DIR" "$TARGET_DIR"
    fi

    # 如果是 Android 14+ (/apex)，同时将工作区 bind mount 到 /system/etc/security/cacerts 兼容旧应用
    if [ "$TARGET_DIR" = "/apex/com.android.conscrypt/cacerts" ] && [ -d "/system/etc/security/cacerts" ]; then
        SYS_DEV_INO=$(stat -c "%d:%i" "/system/etc/security/cacerts" 2>/dev/null)
        if [ "$WORK_DEV_INO" != "$SYS_DEV_INO" ]; then
            mount --bind "$WORK_DIR" "/system/etc/security/cacerts" 2>/dev/null
        fi
    fi

    # Android 14+ Zygote 命名空间挂载传播补丁（使运行中或新孵化的 App 立即感知 /apex 证书变化）
    for zp in $(pidof zygote zygote64 2>/dev/null); do
        Z_INO=$(nsenter -t "$zp" -m -- stat -c "%d:%i" "$TARGET_DIR" 2>/dev/null)
        if [ -n "$Z_INO" ] && [ "$Z_INO" != "$WORK_DEV_INO" ]; then
            nsenter -t "$zp" -m -- mount --bind "$WORK_DIR" "$TARGET_DIR" 2>/dev/null
        fi
    done
}

# 卸载当前的 bind mount
do_unmount() {
    TARGET_DIR=$(detect_target_dir)
    WORK_DEV_INO=$(stat -c "%d:%i" "$WORK_DIR" 2>/dev/null)

    for zp in $(pidof zygote zygote64 2>/dev/null); do
        Z_INO=$(nsenter -t "$zp" -m -- stat -c "%d:%i" "$TARGET_DIR" 2>/dev/null)
        [ "$Z_INO" = "$WORK_DEV_INO" ] && nsenter -t "$zp" -m -- umount -l "$TARGET_DIR" 2>/dev/null
    done

    if [ "$(stat -c "%d:%i" "/system/etc/security/cacerts" 2>/dev/null)" = "$WORK_DEV_INO" ]; then
        umount -l "/system/etc/security/cacerts" 2>/dev/null
    fi
    if [ "$(stat -c "%d:%i" "$TARGET_DIR" 2>/dev/null)" = "$WORK_DEV_INO" ]; then
        umount -l "$TARGET_DIR" 2>/dev/null
    fi
}

# 同步到 $MODDIR/system/etc/security/cacerts（当关闭 bind mount 交由管理器挂载时使用）
sync_to_manager_dir() {
    rebuild_work_dir
    rm -f "$MODDIR/skip_mount"
    rm -rf "$SYS_MOD_CACERTS"
    mkdir -p "$SYS_MOD_CACERTS"
    cp -pf "$WORK_DIR"/*.0 "$SYS_MOD_CACERTS"/ 2>/dev/null
    chown -R 0:0 "$MODDIR/system" 2>/dev/null
    chmod -R 755 "$MODDIR/system" 2>/dev/null
    chmod 644 "$SYS_MOD_CACERTS"/*.0 2>/dev/null
}

# 确保在 PID 1 (init) 全局挂载命名空间执行
run_in_global_ns() {
    SELF_NS=$(readlink /proc/self/ns/mnt 2>/dev/null)
    INIT_NS=$(readlink /proc/1/ns/mnt 2>/dev/null)
    if [ -n "$SELF_NS" ] && [ -n "$INIT_NS" ] && [ "$SELF_NS" != "$INIT_NS" ]; then
        nsenter -t 1 -m -- sh "$0" "$@"
        exit $?
    fi
}

# 校验单个证书是否真正生效
# 返回格式: INSTALLED_BOOL|METHOD|SRC_VAL|DST_VAL
verify_cert_status() {
    fname="$1"
    BIND_MODE=$(get_bind_mode)
    TARGET_DIR=$(detect_target_dir)
    DST_FILE="$TARGET_DIR/$fname"

    if [ "$BIND_MODE" = "true" ]; then
        # 内置 Bind Mount 模式：对比源文件与目标系统文件的 Inode
        SRC_FILE="$WORK_DIR/$fname"
        SRC_INO=$(stat -c "%i" "$SRC_FILE" 2>/dev/null || echo "0")
        DST_INO=$(stat -c "%i" "$DST_FILE" 2>/dev/null || echo "-1")
        if [ "$SRC_INO" != "0" ] && [ "$SRC_INO" = "$DST_INO" ]; then
            echo "true|inode|$SRC_INO|$DST_INO"
        else
            echo "false|inode|$SRC_INO|$DST_INO"
        fi
    else
        # 交由管理器模式：退化为对比文件大小 (Bytes)
        SRC_FILE="$SYS_MOD_CACERTS/$fname"
        [ -f "$SRC_FILE" ] || SRC_FILE="$WORK_DIR/$fname"
        SRC_SIZE=$(stat -c "%s" "$SRC_FILE" 2>/dev/null || echo "0")
        DST_SIZE=$(stat -c "%s" "$DST_FILE" 2>/dev/null || echo "-1")
        if [ "$SRC_SIZE" != "0" ] && [ "$SRC_SIZE" = "$DST_SIZE" ]; then
            echo "true|size|$SRC_SIZE|$DST_SIZE"
        else
            echo "false|size|$SRC_SIZE|$DST_SIZE"
        fi
    fi
}

case "$1" in
    boot_mount)
        ensure_stock_backup
        if [ "$(get_bind_mode)" = "true" ]; then
            do_bind_mount
        else
            sync_to_manager_dir
        fi
        ;;

    status)
        ensure_stock_backup
        TARGET_DIR=$(detect_target_dir)
        BIND_MODE=$(get_bind_mode)
        MGR=$(detect_root_manager)
        SKIP_EXISTS="false"
        [ -f "$MODDIR/skip_mount" ] && SKIP_EXISTS="true"
        WORK_DEV_INO=$(stat -c "%d:%i" "$WORK_DIR" 2>/dev/null)
        TARGET_DEV_INO=$(stat -c "%d:%i" "$TARGET_DIR" 2>/dev/null)
        DIR_MOUNTED="false"
        [ "$WORK_DEV_INO" = "$TARGET_DEV_INO" ] && DIR_MOUNTED="true"

        echo "TARGET_DIR=$TARGET_DIR"
        echo "BIND_MOUNT=$BIND_MODE"
        echo "SKIP_MOUNT=$SKIP_EXISTS"
        echo "DIR_MOUNTED=$DIR_MOUNTED"
        echo "ROOT_MANAGER=$MGR"
        echo "TOTAL_ACTIVE=$(ls -1 "$WORK_DIR"/*.0 2>/dev/null | wc -l | tr -d ' ')"
        echo "TOTAL_CUSTOM=$(ls -1 "$CUSTOM_DIR"/*.0 2>/dev/null | wc -l | tr -d ' ')"
        echo "TOTAL_DELETED=$(grep -c '.0$' "$DELETED_LIST" 2>/dev/null || echo 0)"
        ;;

    list_certs)
        ensure_stock_backup
        [ -z "$(ls -A "$WORK_DIR" 2>/dev/null)" ] && rebuild_work_dir
        # 汇总所有已知证书文件名（原厂 + 自定义）
        ALL_FILES=$( (ls -1 "$STOCK_DIR"/*.0 "$CUSTOM_DIR"/*.0 2>/dev/null) | xargs -n 1 basename 2>/dev/null | sort -u )
        for fname in $ALL_FILES; do
            [ -z "$fname" ] && continue
            IS_STOCK="false"
            IS_CUSTOM="false"
            IS_DELETED="false"
            [ -f "$STOCK_DIR/$fname" ] && IS_STOCK="true"
            [ -f "$CUSTOM_DIR/$fname" ] && IS_CUSTOM="true"
            grep -qxF "$fname" "$DELETED_LIST" 2>/dev/null && IS_DELETED="true"

            if [ "$IS_CUSTOM" = "true" ] && [ "$IS_STOCK" = "true" ]; then
                TYPE="modified"
                READ_FILE="$CUSTOM_DIR/$fname"
            elif [ "$IS_CUSTOM" = "true" ]; then
                TYPE="custom"
                READ_FILE="$CUSTOM_DIR/$fname"
            elif [ "$IS_DELETED" = "true" ]; then
                TYPE="deleted"
                READ_FILE="$STOCK_DIR/$fname"
            else
                TYPE="stock"
                READ_FILE="$STOCK_DIR/$fname"
            fi

            VERIFY_INFO=$(verify_cert_status "$fname")
            # 提取证书文本摘要或交由前端解析 PEM
            SUBJ_LINE=$(grep -m 1 "Subject:" "$READ_FILE" 2>/dev/null | sed 's/^[[:space:]]*//')
            echo "CERT_ITEM|$fname|$TYPE|$VERIFY_INFO|$SUBJ_LINE"
        done
        ;;

    get_cert)
        fname="$2"
        if [ -f "$CUSTOM_DIR/$fname" ]; then
            cat "$CUSTOM_DIR/$fname"
        elif [ -f "$STOCK_DIR/$fname" ]; then
            cat "$STOCK_DIR/$fname"
        else
            TARGET_DIR=$(detect_target_dir)
            cat "$TARGET_DIR/$fname" 2>/dev/null
        fi
        ;;

    save_cert)
        # save_cert <filename.0> <base64_content>
        run_in_global_ns "$@"
        fname="$2"
        b64_data="$3"
        if [ -z "$fname" ] || [ -z "$b64_data" ]; then
            echo "ERR: Missing parameters"
            exit 1
        fi
        echo "$b64_data" | base64 -d > "$CUSTOM_DIR/$fname"
        chmod 644 "$CUSTOM_DIR/$fname"
        # 如果该证书此前在屏蔽列表中，移除屏蔽标记
        sed -i "/^${fname}$/d" "$DELETED_LIST" 2>/dev/null
        if [ "$(get_bind_mode)" = "true" ]; then
            do_bind_mount
        else
            sync_to_manager_dir
        fi
        echo "OK"
        ;;

    delete_cert)
        # delete_cert <filename.0>
        run_in_global_ns "$@"
        fname="$2"
        rm -f "$CUSTOM_DIR/$fname" 2>/dev/null
        if [ -f "$STOCK_DIR/$fname" ]; then
            if ! grep -qxF "$fname" "$DELETED_LIST" 2>/dev/null; then
                echo "$fname" >> "$DELETED_LIST"
            fi
        fi
        if [ "$(get_bind_mode)" = "true" ]; then
            do_bind_mount
        else
            sync_to_manager_dir
        fi
        echo "OK"
        ;;

    restore_cert)
        # 恢复被修改或被屏蔽的原厂证书
        run_in_global_ns "$@"
        fname="$2"
        rm -f "$CUSTOM_DIR/$fname" 2>/dev/null
        sed -i "/^${fname}$/d" "$DELETED_LIST" 2>/dev/null
        if [ "$(get_bind_mode)" = "true" ]; then
            do_bind_mount
        else
            sync_to_manager_dir
        fi
        echo "OK"
        ;;

    set_bind_mode)
        # set_bind_mode <true|false>
        run_in_global_ns "$@"
        mode="$2"
        if [ "$mode" = "false" ]; then
            echo "BIND_MOUNT=false" > "$CONF_FILE"
            do_unmount
            sync_to_manager_dir
            echo "MODE_MANAGER"
        else
            echo "BIND_MOUNT=true" > "$CONF_FILE"
            do_bind_mount
            echo "MODE_BIND"
        fi
        ;;

    remount)
        run_in_global_ns "$@"
        if [ "$(get_bind_mode)" = "true" ]; then
            do_unmount
            do_bind_mount
            echo "REMOUNT_OK"
        else
            sync_to_manager_dir
            echo "SYNC_OK"
        fi
        ;;

    unmount_all)
        run_in_global_ns "$@"
        do_unmount
        ;;
esac
