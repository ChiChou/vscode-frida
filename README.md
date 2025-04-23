# vscode-frida

**Unofficial** frida workbench for VSCode [![](https://img.shields.io/visual-studio-marketplace/v/CodeColorist.vscode-frida?color=%230af&label=install&logo=visual-studio-code&logoColor=%230ac&style=plastic)](https://marketplace.visualstudio.com/items?itemName=CodeColorist.vscode-frida)

## Prerequisites

* libimobiledevices (for `inetcat` command)
* Python >= 3.7
* frida-tools python package
* iTunes on Windows

If you are on Windows, you need to keep iTunes open in order to interact with iOS devices via USB.

### Install frida-tools

Because of [PEP0668](https://peps.python.org/pep-0668/), you might encounter error when `pip3 install frida-tools` globally.

The recommended way is to open a folder (workspace) in VSCode, then create and activate a virtual environment using python extension. In this case, the extension will pick your current active python venv to load frida commands.

Or you can use package manager like [pipx](https://github.com/pypa/pipx) or [UV](https://docs.astral.sh/uv/guides/tools/) to install it to $PATH, meanwhile keeping it isolated.

## Features

![demo](resources/doc/demo.gif)

### Target Selector

User friendly UI

### Debug Log

Now supports both iOS syslog and Android logcat!

![Debug Log](resources/doc/syslog.gif)

### Download and Apply frida-gum Typing Info

![Typing](resources/doc/typing.gif)

### Objection

* [Objection](https://github.com/sensepost/objection) Runtime Mobile Exploration

### Javascript REPL shortcut

Open and activate an REPL at the bottom. Use the "frida" button at the top of any active `js` / `typescript` document, it will send the code to the active REPL.

### Shell

For Android devices, **Open Shell** is simply a wrapper for `adb shell`. 

For iOS it gives a SSH shell. It might ask for credentials depending on your setup.

## Todo

* More Android features
* More mobile security terminal tools intergration

## [CHANGELOG](CHANGELOG.md)

## Contributors

![](https://contrib.rocks/image?repo=chichou/vscode-frida)
