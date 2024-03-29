# vscode-frida

**Unofficial** frida workbench for VSCode [![](https://img.shields.io/visual-studio-marketplace/v/CodeColorist.vscode-frida?color=%230af&label=install&logo=visual-studio-code&logoColor=%230ac&style=plastic)](https://marketplace.visualstudio.com/items?itemName=CodeColorist.vscode-frida)

## Prerequisites

* Python >= 3.7
* `pip3 install -U frida-tools` If you have more than one python3 in your path, you need to config the python path in settings
* nodejs and `npm install -g fruity-frida` (optional, for lldb related features)
* iTunes on Windows

If you are on Windows, you need to keep iTunes open in order to interact with iOS devices. 

You only need to install `fruity-frida` for iOS specific features, like lldb debugging and remote shell. For more information, please refer to [fruity-frida](https://github.com/chichou/fruity-frida).

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

For iOS it gives a SSH shell. It requires `fruity-frida` to be installed.

## Todo

* More Android features
* More mobile security terminal tools intergration

## Release Note:

Please refer to [CHANGELOG](CHANGELOG.md)
