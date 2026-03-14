# Change Log

### v0.12.7 - 14 Mar, 2026

* Faster AndroidManifest.xml parser
* Fix some UI issues

### v0.12.3 - 11 Mar, 2026

* Add Objective-C protocol inspection panel

### v0.12.2 - 10 Mar, 2026

* Objective-C class dump
* Java class dump
* Add package and imports to Java header generation
* Add dump buttons to hierarchy and package tree views
* Add shift-click range selection for checkboxes
* Fix empty class name
* Remove hierarchy and package tree views
* Cleanup tslint leftover

### v0.12.1 - 03 Mar, 2026

* Add syntax highlight to CModule (c source)

### v0.12.0 - 03 Mar, 2026

* Remove bagbak
* Support split APK
* Remove iOS app dump (bagbak)
* Device dashboard view
* AndroidManifest and Info.plist viewing
* Memory scanning and dumping functionality
* Interactive session support for backend communication
* i18n improvements and localizations

### v0.11.5 - 02 Mar, 2026

* Fix "frida.ProtocolError: connection closed" error
* ObjC class method completion
* Fix LSP crash for unknown type encodings
* Frida 17 support
* Objective-C Hierarchy View and Java Packages View
* Modules & Classes panels with hook code generation
* Use AI to generate inform function signatures

Notice: do not use v0.11.0-v0.11.4, I accidently broke package.json and they could only
run in debug, not production.

### v0.9.0 - 10 Sep, 2024

* Support frida-tools installed from virtualenv, pipx, etc.

### v0.8.3 - 9 Sep, 2024

* **Remove** lldb shortcut because it's impossible to adapt to different jailbreaks

### v0.7.3 - 25 Jun, 2023

* Bring back `bagbak`

### v0.7.0 - 14 Jun, 2023

* Use `fruity-frida` to support iOS debugging and SSH
* Temporary disable bagbak for compatibility issue

### v0.4.11 - 07 Apr, 2023

* Remove Fouldecrypt

### v0.4.6 - 13 Aug, 2022

* add idevicesyslog

### v0.4.2 - 07 Aug, 2022

* Bugfix: Debug config only works for local device
* Bugfix: Debug config does not handle attaching to app properly
* Bugfix: Context menu for USB devices is missing

### v0.4.0 - 07 Aug, 2022

* Supports frida js debug!

### v0.3.19 - 06 Aug, 2022

* Supports connecting / disconnecting remote devices

### v0.3.17 - 05 Aug, 2022

* Bring back `execute` command

### v0.3.16 - 29 Mar, 2022

* Ask to install frida-tools when not found
* Fix issue #26 when multiple python interpreters are present

### v0.3.14 - 25 Jan, 2022

* Fix `iproxy` command

### v0.3.12 - 27 Nov, 2021

* Replace FlexDecrypt with Fouldecrypt
* Bugfix: Shutdown iproxy when ref count is 0
* Bugfix: Decryptor failes when App path has spaces

### v0.0.8 - 8 Aug, 2020

* Bugfix: Attaching objection to a running application
* Do not close terminal immediatly when exit code is not 0
* More error logs

### v0.0.6 - 4 Aug, 2020

Bugfix: `iproxy` fallback
New: show ipa in folder

### v0.0.4 - 3 Aug, 2020

* Add experimental lldb shortcut

### v0.0.3 - 2 Aug, 2020

Added

* Shell for both iOS (requires libimobiledevice) and Androd (requires adb)
* Install public SSH key to iOS (like `ssh-copy-id`, but also supports Windows)
* FlexDecrypt support. Requires `flexdecrypt` and `zip` on iOS, `ssh` and `iproxy` on desktop
* FlexDecrypt installer

Deprecation

* [bagbak](https://github.com/ChiChou/bagbak) has been removed, in favor of [FlexDecrypt](https://github.com/JohnCoates/flexdecrypt)

### v0.0.2 - 22 Jul, 2020

* support logcat for Android
* pull `frida-gum.d.ts` from github

### v0.0.1 - 19 Jul, 2020

* first release
