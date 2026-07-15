// Options 与 worker 共用的设置刷新协议；纯逻辑便于验证“启用刷新、关闭清队列”的分支。

export const SETTINGS_UPDATED_MESSAGE = "janet-settings-updated";

export async function applySettingsUpdate(settings, { clearQueue, refresh }) {
  if (settings?.enabled === false) {
    await clearQueue();
    return { enabled: false, queueCleared: true, refreshRequested: false };
  }
  await refresh();
  return { enabled: true, queueCleared: false, refreshRequested: true };
}
