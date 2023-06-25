# Change Log

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
