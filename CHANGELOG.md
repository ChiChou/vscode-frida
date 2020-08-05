# Change Log

### v0.0.6

Bugfix: `iproxy` fallback
New: show ipa in folder

### v0.0.4 - 3 Aug, 2020

* Add experimental lldb shortcut

### v0.0.3 - 2 Aug, 2020

Added

* Shell for both iOS (requires libimobiledevice) and Androd (requires adb)
* Install public SSH key to iOS (like `ssh-copy-id`, but also supports Windows)
* FlexDecrypt support. Requires `flexdecrypt` and `zip` on iOS, `ssh` and `iproxy` on desktop
* FlexDecrypt GitHub installer

Deprecation

* [bagbak](https://github.com/ChiChou/bagbak) has been removed, in favor of [FlexDecrypt](https://github.com/JohnCoates/flexdecrypt)

### v0.0.2 - 22 Jul, 2020

* support logcat for Android
* pull `frida-gum.d.ts` from github

### v0.0.1 - 19 Jul, 2020

* first release