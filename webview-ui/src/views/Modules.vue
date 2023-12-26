<script setup lang="ts">
import {
  provideVSCodeDesignSystem,
  vsCodeButton,
  vsCodeDataGrid, vsCodeDataGridCell, vsCodeDataGridRow
} from "@vscode/webview-ui-toolkit";

import { vscode } from "../utilities/vscode";

provideVSCodeDesignSystem()
  .register(vsCodeButton())
  .register(vsCodeDataGrid())
  .register(vsCodeDataGridRow())
  .register(vsCodeDataGridCell());

</script>

<template>
  <main>
    <h1>Modules</h1>
  </main>
</template>