![Icon](icon.png)

# Frida Workbench for VSCode

**Unofficial** frida workbench for VSCode [![](https://img.shields.io/visual-studio-marketplace/v/CodeColorist.vscode-frida?color=%230af&label=install&logo=visual-studio-code&logoColor=%230ac&style=plastic)](https://marketplace.visualstudio.com/items?itemName=CodeColorist.vscode-frida)

## Prerequisites

* Python >= 3.7
* [frida-tools](https://pypi.org/project/frida-tools/) python package

### Optional dependencies

* [libimobiledevice](https://github.com/libimobiledevice/libimobiledevice) (for `inetcat` command to start a SSH shell)
* iTunes on Windows (for iOS USB connection)

If you are on Windows, you need to keep iTunes open in order to interact with iOS devices via USB.

### Install frida-tools

Because of [PEP0668](https://peps.python.org/pep-0668/), you might encounter an error when running `pip3 install frida-tools` globally.

The recommended way is to open a folder (workspace) in VSCode, then create and activate a virtual environment using the Python extension. In this case, the extension will use your current active Python venv to load frida commands.

Alternatively, you can use a package manager like [pipx](https://github.com/pypa/pipx) or [UV](https://docs.astral.sh/uv/guides/tools/) to install it to $PATH, while keeping it isolated.

## Features

![demo](resources/doc/demo.gif)

### Apps and Processes List

List apps and processes on connected devices in a sidebar panel. Right-click to attach, spawn, spawn in suspended mode, kill processes, or copy device/process info to clipboard. Supports local, USB, and remote devices.

### Interactive Runtime Panels

#### Modules & Exports Browser

Browse loaded native modules and their exported functions for any attached process. Filter modules by name, inspect base address, size, and path, then select exports for hook generation.

#### Classes & Methods Browser

Explore runtime classes and methods for both Java and Objective-C. Filter classes, toggle between own and inherited methods, and batch-select methods for hook generation.

#### Objective-C Hierarchy View (iOS)

Visualize the complete Objective-C class inheritance tree with expand/collapse controls and class filtering.

#### Java Package Tree (Android)

Browse Java classes organized by package namespace in a hierarchical tree view.

### Hook Generation

Generate Frida hook code from the Modules and Classes panels:

* **Native hooks** — `Interceptor.attach()` with `onEnter` / `onLeave` callbacks for exported functions
* **Objective-C hooks** — class and selector based hooks with proper ObjC bridge usage
* **Java hooks** — `Java.perform()` / `Java.use()` hooks with method overload support
* **AI-powered hooks** — use GitHub Copilot to infer native function signatures (parameter types, return types) and generate type-aware argument logging

### Smart Autocomplete (LSP)

Context-aware completions for Frida scripts in JavaScript / TypeScript:

* `ObjC.classes.<ClassName>` — completes Objective-C class names
* `ObjC.classes.Foo['<method>']` — completes method selectors
* `Java.use('<ClassName>')` — completes Java class names
* `Process.getModuleByName('<name>')` — completes loaded module names

Requires a `.vscode/frida.json` target configuration. Use the **Set LSP Target** command to generate it.

### JavaScript REPL

Open and activate a REPL at the bottom. Use the "frida" button at the top of any active `js` / `typescript` document to send the code to the active REPL.

### Syslog

Stream real-time application logs from attached processes.

### Project Scaffolding

* **New Agent** — create a new Frida Agent project with TypeScript support
* **New C Module** — create a new Frida C Module project
* **Download Typings** — download Frida TypeScript type definitions for autocomplete

### Debug Configuration

Generate VSCode `launch.json` and `tasks.json` for debugging Frida scripts with breakpoints.

### Android Tools

* **Download and start frida-server** on Android device (automatic architecture detection)
* **Pull APK** from device

### External Tools Integration

* [Objection](https://github.com/sensepost/objection) — Runtime Mobile Exploration

### Shell

For Android devices, **Open Shell** is a wrapper for `adb shell`.

For iOS it gives an SSH shell. It might ask for credentials depending on your setup.

### Remote Device Support

Connect to remote Frida devices via `host:port` directly from the sidebar.

## [CHANGELOG](CHANGELOG.md)

## Contributors

![](https://contrib.rocks/image?repo=chichou/vscode-frida)
