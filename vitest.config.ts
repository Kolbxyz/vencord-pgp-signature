import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

const stub = (name: string) => fileURLToPath(new URL(`./test/stubs/${name}.ts`, import.meta.url));

export default defineConfig({
    resolve: {
        // Vencord resolves these aliases inside its own build. Point them at in-memory stubs so
        // the plugin's modules can be tested unmodified, exactly as they ship.
        alias: {
            "@api/DataStore": stub("DataStore")
        }
    },
    test: {
        globals: true,
        include: ["src/plugins/invisiblePgp/__tests__/**/*.test.ts"]
    }
});
