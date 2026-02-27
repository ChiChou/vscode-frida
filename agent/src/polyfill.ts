interface Module16 {
  findExportByName(
    moduleName: string | null,
    exportName: string,
  ): NativePointer | null;
  getExportByName(moduleName: string | null, exportName: string): NativePointer;
}

const isLegacy = "findExportByName" in Module;
const mod = Module as unknown as Module16;

export const findGlobalExport: (name: string) => NativePointer | null = isLegacy
  ? (name) => mod.findExportByName(null, name)
  : (name) => Module.findGlobalExportByName(name);

export const getGlobalExport: (name: string) => NativePointer = isLegacy
  ? (name) => mod.getExportByName(null, name)
  : (name) => Module.getGlobalExportByName(name);
