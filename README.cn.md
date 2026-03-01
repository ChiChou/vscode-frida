![Icon](icon.png)

# 将 Frida 集成到 VSCode

**非官方** Frida VSCode 工作台 [![](https://img.shields.io/visual-studio-marketplace/v/CodeColorist.vscode-frida?color=%230af&label=install&logo=visual-studio-code&logoColor=%230ac&style=plastic)](https://marketplace.visualstudio.com/items?itemName=CodeColorist.vscode-frida)

## 前置要求

* Python >= 3.7
* [frida-tools](https://pypi.org/project/frida-tools/) Python 包

### 可选依赖

* [libimobiledevice](https://github.com/libimobiledevice/libimobiledevice)（用于 `inetcat` 命令启动 SSH shell）
* Windows 上的 iTunes（用于 iOS USB 连接）

如果你在 Windows 上，需要保持 iTunes 打开才能通过 USB 与 iOS 设备交互。

### 安装 frida-tools

由于 [PEP0668](https://peps.python.org/pep-0668/)，全局运行 `pip3 install frida-tools` 可能会遇到错误。

推荐的方式是在 VSCode 中打开一个文件夹（工作区），然后使用 Python 扩展创建并激活虚拟环境。在这种情况下，扩展将使用当前激活的 Python venv 来加载 frida 命令。

或者，你可以使用包管理器如 [pipx](https://github.com/pypa/pipx) 或 [UV](https://docs.astral.sh/uv/guides/tools/) 将其安装到 $PATH，同时保持隔离。

## 功能特性

![demo](resources/doc/demo.gif)

### 应用和进程列表

在侧边栏面板中列出已连接设备上的应用和进程。右键点击可附加、启动、以挂起模式启动、终止进程，或将设备/进程信息复制到剪贴板。支持本地、USB 和远程设备。

### 交互式运行时面板

#### 模块和导出浏览器

浏览任何已附加进程的已加载原生模块及其导出函数。按名称筛选模块，检查基地址、大小和路径，然后选择导出函数用于 Hook 生成。

#### 类和方法浏览器

探索 Java 和 Objective-C 的运行时类和方法。筛选类，在自有方法和继承方法之间切换，批量选择方法用于 Hook 生成。

#### Objective-C 层级视图（iOS）

可视化完整的 Objective-C 类继承树，支持展开/折叠控制和类筛选。

#### Java 包树（Android）

按包命名空间分层浏览 Java 类。

### Hook 生成

从模块和类面板生成 Frida Hook 代码：

* **原生 Hook** — 使用 `onEnter` / `onLeave` 回调的 `Interceptor.attach()` 用于导出函数
* **Objective-C Hook** — 基于类和选择器的 Hook，正确使用 ObjC 桥接
* **Java Hook** — `Java.perform()` / `Java.use()` Hook，支持方法重载
* **AI 驱动 Hook** — 使用 GitHub Copilot 推断原生函数签名（参数类型、返回类型）并生成类型感知的参数日志

### 智能自动补全（LSP）

Frida 脚本的上下文感知补全，支持 JavaScript / TypeScript：

* `ObjC.classes.<ClassName>` — 补全 Objective-C 类名
* `ObjC.classes.Foo['<method>']` — 补全方法选择器
* `ObjC.classes.Foo.method` — 补全类方法选择器
* `Java.use('<ClassName>')` — 补全 Java 类名
* `Process.getModuleByName('<name>')` — 补全已加载模块名

由于语言服务器依赖于目标进程上下文，你需要在工作区中创建 Frida 目标配置文件：`.vscode/frida.json`。你可以使用 **Set LSP Target** 命令通过选定的进程或应用来生成它。

### JavaScript REPL

在底部打开并激活 REPL。使用任何活动的 `js` / `typescript` 文档顶部的 "frida" 按钮将代码发送到活动的 REPL。

### 系统日志

从已附加进程流式传输实时应用日志。

### 项目脚手架

* **新建 Agent** — 创建支持 TypeScript 的新 Frida Agent 项目
* **新建 C 模块** — 创建新的 Frida C 模块项目
* **下载类型定义** — 下载 Frida TypeScript 类型定义用于自动补全

### 调试配置

生成 VSCode `launch.json` 和 `tasks.json`，用于带断点调试 Frida 脚本。

### Android 工具

* **下载并启动 frida-server** 在 Android 设备上（自动架构检测）
* **拉取 APK** 从设备

### 外部工具集成

* [Objection](https://github.com/sensepost/objection) — 运行时移动探索

### Shell

对于 Android 设备，**打开 Shell** 是 `adb shell` 的封装。

对于越狱 iOS，一键打开 SSH shell。可能需要配置凭据。

### 远程设备支持

直接从侧边栏通过 `host:port` 连接到远程 Frida 设备。

## [更新日志](CHANGELOG.md)

## 贡献者

![](https://contrib.rocks/image?repo=chichou/vscode-frida)