import { AdminApiClient } from './api/client'

interface TauriInternals {
  invoke?: (command: string) => Promise<unknown>
}

declare global {
  interface Window {
    __TAURI_INTERNALS__?: TauriInternals
  }
}

export async function acquireDeviceId(): Promise<string> {
  const invoke = window.__TAURI_INTERNALS__?.invoke
  if (invoke) {
    const value = await invoke('device_id')
    if (typeof value !== 'string' || !/^[a-f0-9]{32}$/.test(value)) {
      throw new Error('Device identity could not be verified')
    }
    return value
  }
  if (!import.meta.env.DEV) throw new Error('Device identity is unavailable')
  return crypto.randomUUID().replaceAll('-', '')
}

export const defaultAdminClient = new AdminApiClient()
