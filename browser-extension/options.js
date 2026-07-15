// 扩展配对页只允许配置本机 HTTP ingest；token 留在 chrome.storage.local，不写入 manifest。

import { DEFAULT_INGEST_URL, normalizeIngestUrl } from "./lib/failure_event.mjs";
import { SETTINGS_UPDATED_MESSAGE } from "./lib/settings_update.mjs";

const SETTINGS_KEY = "janetSettingsV1";
const form = document.querySelector("#settings-form");
const enabled = document.querySelector("#enabled");
const ingestUrl = document.querySelector("#ingest-url");
const token = document.querySelector("#token");
const status = document.querySelector("#status");

async function load() {
  const stored = await chrome.storage.local.get(SETTINGS_KEY);
  const settings = stored[SETTINGS_KEY] || {};
  enabled.checked = settings.enabled !== false;
  ingestUrl.value = normalizeIngestUrl(settings.ingestUrl || DEFAULT_INGEST_URL);
  token.value = String(settings.token || "");
  document.querySelector("#extension-id").textContent = chrome.runtime.id;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const normalizedUrl = normalizeIngestUrl(ingestUrl.value);
  if (normalizedUrl !== ingestUrl.value.replace(/\/$/, "")) {
    status.textContent = "Only a local http://127.0.0.1 or localhost ingest URL is allowed.";
    ingestUrl.value = normalizedUrl;
    return;
  }
  await chrome.storage.local.set({
    [SETTINGS_KEY]: {
      enabled: enabled.checked,
      ingestUrl: normalizedUrl,
      token: token.value.slice(0, 256)
    }
  });
  try {
    const result = await chrome.runtime.sendMessage({ type: SETTINGS_UPDATED_MESSAGE });
    if (!result?.ok) throw new Error(result?.error || "worker did not confirm the update");
    status.textContent = enabled.checked
      ? "Saved. Immediate refresh requested with the new settings."
      : "Saved. Collector disabled and queued failures cleared.";
  } catch {
    status.textContent = enabled.checked
      ? "Saved. The worker will refresh on its next alarm."
      : "Saved as disabled, but queue cleanup was not confirmed; reload the extension to retry.";
  }
});

void load();
