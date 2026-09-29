HexHound 完整离线安装包（Windows x64）

包含桌面程序及 Python 依赖、WebView2、Chromium 浏览器、WSL 安装器，
以及从空白 Ubuntu Base 构建的独立 HexHound-Tools 工具环境。
工具：nmap、sqlmap、nikto、whatweb、gobuster、ffuf、nuclei、curl、Python 3；
附 nuclei 3.3.7、模板 v10.1.5 和基础目录词表。

要求：Windows 10 2004（19041）及以上 / Windows 11 x64；建议预留 8 GB。
Linux 工具需要 BIOS/UEFI 开启 CPU 虚拟化，启用 Windows 组件需要管理员权限。
安装末尾运行工具环境配置；如提示重启，请重启后从开始菜单运行
“HexHound - Finish runtime setup”。不修改已有 WSL 分发版或默认分发版。
Windows 组件存储损坏时，系统修复可能仍需要 Windows 安装介质或联网。

桌面启动无需 Python。模型服务需要自行填写 API Key，并能访问服务商网络。
离线安装不意味着云模型可以离线调用。
本包不含个人 API Key、.env、个人设置、历史报告或工程目录。
原电脑中已保存的设置仍可能被程序读取，不代表安装包携带这些设置。

卸载会删除应用文件；为防误删，用户设置、报告和 HexHound-Tools 分发版保留。
工具配置日志：%LOCALAPPDATA%\HexHound\runtime-setup.log
第三方许可证随各组件保留；Linux 包许可证位于 /usr/share/doc。
请仅对自己拥有或明确获授权的目标使用安全评估功能。
