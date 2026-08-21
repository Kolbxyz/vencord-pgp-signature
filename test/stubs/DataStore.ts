/*
 * In-memory stand-in for Vencord's `@api/DataStore` (an IndexedDB wrapper).
 *
 * Vitest aliases `@api/DataStore` here so the modules that persist state — the keyring, the
 * trusted signers, the channel policy — can be tested as they are actually written, rather than
 * through a hand-injected seam that production never uses.
 */

const store = new Map<string, unknown>();

export async function get<T>(key: string): Promise<T | undefined> {
    return store.get(key) as T | undefined;
}

export async function set(key: string, value: unknown): Promise<void> {
    // Round-trip through JSON so tests cannot accidentally share a mutable object with the module
    // under test — IndexedDB gives you a copy, and a test that relies on aliasing would be lying.
    store.set(key, JSON.parse(JSON.stringify(value)));
}

export async function del(key: string): Promise<void> {
    store.delete(key);
}

/** Test-only: wipe everything between cases. */
export function __reset(): void {
    store.clear();
}
