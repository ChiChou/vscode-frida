import { Uri, window } from "vscode";
import { rpc } from "../driver/backend";
import { TargetItem } from "../providers/devices";

interface Module {
  name: string;
  base: string;
  size: number;
  path: string;
};

type ClassesResult = string[];
type ModulesResult = Module[];

function create(name: string, content: string) {
  window.showTextDocument(Uri.parse(`untitled:${encodeURIComponent(name)}`)).then((editor) => {
    editor.edit((editBuilder) => {
      editBuilder.insert(editor.selection.active, content);
    });
  });
}

export function classes(target: TargetItem) {
  rpc(target, 'classes')
    .then((result: ClassesResult) => {
      const text = result.join('\n');
      create(`classes - ${target.label}.txt`, text);
    })
    .catch(err => window.showErrorMessage(err.message));
}

export function modules(target: TargetItem) {
  rpc(target, 'modules')
    .then((modules: ModulesResult) => {
      const text = modules.map(m => `${m.base} ${m.name} ${m.size} ${m.path}`).join('\n');
      create(`modules - ${target.label}.txt`, text);
    })
    .catch(err => window.showErrorMessage(err.message));
}
