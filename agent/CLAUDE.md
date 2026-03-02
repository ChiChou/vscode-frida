from frida 17, `Module.getExportByName` and `Module.findExportByName` are removed, 
use `Module.getGlobalExportByName` or `Process.findModuleByName(...).findExportByName(...)` instead.
to resolve exports without specifying module name, we have polyfill for both frida 16 and frida 17 in
polyfill.ts.

When you need to use `ObjC` or `Java` APIs, import the bridge modules:

```typescript
import { ObjC } from 'frida-objc-bridge';
import { Java } from 'frida-java-bridge';
```