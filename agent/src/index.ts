/* eslint-disable curly */
/* eslint-disable @typescript-eslint/naming-convention */

import { start, stop } from './log.js';

enum Runtime {
    Java = 'Java',
    ObjectiveC = 'Objective-C',
    Generic = 'Generic',
};

const main = typeof Process.mainModule === 'object' && Process.mainModule !== null ?
    Process.mainModule : Process.enumerateModules()[0];

const notImplemented = () => { throw new Error('Not implemented'); };

rpc.exports = {
    start,
    stop,

    main: () => main.path,
    runtime() {
        if (Java.available) return Runtime.Java;
        if (ObjC.available) return Runtime.ObjectiveC;
        return Runtime.Generic;
    },

    ping: () => Process.id,

    classes: async () => [] as string[],
    protocols: async () => [] as string[],

    methodsOf: notImplemented,
    ownMethodsOf: notImplemented,
    superClass: notImplemented,

    modules: () => Process.enumerateModules(),
    exports: (name: string) => Process.findModuleByName(name)?.enumerateExports(),
    imports: (name: string) => Process.findModuleByName(name)?.enumerateImports(),
    symbols: (name: string) => Process.findModuleByName(name)?.enumerateSymbols(),
};

if (Java.available) {
    function perform<T>(fn: () => T): Promise<T> {
        return new Promise<T>((resolve) => {
            Java.perform(() => {
                resolve(fn());
            });
        });
    };

    rpc.exports.classes = async () => perform(() => Java.enumerateLoadedClassesSync());
    rpc.exports.ownMethodsOf =
        rpc.exports.methodsOf =
        async (name: string) => perform(() => Java.use(name).class.getMethods());
    rpc.exports.fieldsOf = async (name: string) => perform(() => Java.use(name).class.getDeclaredFields());
    rpc.exports.superClass = async (name: string) => perform<string>(() => Java.use(name).class.getSuperclass()?.getName());

} else if (ObjC.available) {
    rpc.exports.classes = async () => Object.keys(ObjC.classes);
    rpc.exports.protocols = async () => Object.keys(ObjC.protocols);

    function getClass(name: string) {
        if (ObjC.classes.hasOwnProperty(name)) return ObjC.classes[name];
        throw new Error(`Class ${name} not found`);
    }

    rpc.exports.ownMethodsOf = async (name: string) => getClass(name).$ownMethods;
    rpc.exports.methodsOf = async (name: string) => getClass(name).$methods;
    rpc.exports.fieldsOf = async (name: string) => getClass(name).$ivars;
    rpc.exports.superClass = async (name: string) => getClass(name).$superClass?.name;
}
