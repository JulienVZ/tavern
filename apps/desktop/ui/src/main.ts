// SPDX-License-Identifier: AGPL-3.0-or-later
import { mount } from "svelte";

import App from "./App.svelte";
import "./app.css";
import { currentLocale } from "./lib/i18n";

const target = document.getElementById("app");
if (target === null) {
  throw new Error("missing #app element");
}

document.documentElement.lang = currentLocale();

export default mount(App, { target });
