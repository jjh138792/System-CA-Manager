# System-CA-Manager
这款名为 System CA Manager (cacerts_bind_manager) 的模块采用纯内置 bind mount 引擎设计，不依赖任何 KSU 元模块，支持从 Android 7 到 Android 14+（自动识别 /system 与 /apex 证书路径）的全版本适配，并配备完整的 Material You 风格 KernelSU WebUI 管理面板。
## 一、 模块目录结构与核心机制
```text
cacerts_bind_manager/
├── module.prop           # 模块基础信息
├── customize.sh          # 安装初始化脚本（创建工作区、默认打上 skip_mount 标签）
├── post-fs-data.sh       # Magisk 专用挂载入口（识别到 KSU/APatch 自动退出）
├── post-mount.sh         # KernelSU / SukiSU / APatch 专用挂载入口（在元模块之后执行）
├── uninstall.sh          # 卸载还原脚本
├── scripts/
│   └── cert_ctl.sh       # 核心证书管理与挂载后端（负责挂载、Inode/Size 校验、增删改查）
└── webroot/
    ├── index.html        # KSU WebUI 主页面
    ├── style.css         # 现代深浅色自适应样式表（支持 KSU 沉浸式 Insets）
    ├── kernelsu.js       # 基于官方文档封装的 KSU WebUI 异步通信桥
    └── app.js            # 前端控制器（内置纯 JS X.509 解析器与 OpenSSL 旧版 Hash 算法）
```
## 核心设计亮点：
1. 分阶段精准挂载：post-fs-data.sh 会检测 $KSU 与 $APATCH 环境变量，仅在 Magisk 环境下执行挂载；在 KernelSU / SukiSU / APatch 下交由 post-mount.sh 执行，确保排在元模块和其他模块的目录级挂载之后。  
2. 双模式切换与 skip_mount 联动：
   * 内置 Bind Mount 模式（默认）：自动在模块根目录创建 skip_mount 标记并清空 $MODDIR/system，防止管理器二次挂载；同时将合并后的工作目录 $MODDIR/work_certs 通过 mount --bind 挂载到系统证书目录（并在 Android 14+ 下自动向 zygote / zygote64 挂载命名空间注入，解决 /apex 私有挂载传播问题）。
   * Root 管理器接管模式：在 WebUI 关闭内置 bind mount 后，自动移除 skip_mount，并将证书同步至 $MODDIR/system/etc/security/cacerts 交由管理器挂载。
3. 双维度主动安装校验：
   * 开启内置 Bind Mount 时：由于 mount --bind 与硬链接不会改变源文件 Inode，脚本直接对比模块源证书（$MODDIR/work_certs/<hash>.0）与系统目标证书（$TARGET_DIR/<hash>.0）的 Inode 编号（stat -c "%i"）。若被其他模块覆盖或挂载失败，Inode 会立即不一致并告警。
   * 关闭内置 Bind Mount（交由管理器）时：由于 OverlayFS / Magic Mount 可能会重写虚拟 Inode，自动退化为对比模块文件与目标文件的 文件大小（stat -c "%s"）
## 作者说
这是我的第一个root模块可能还有很多问题，非常欢迎大家Issue)PR
协议：GPL 3.0
