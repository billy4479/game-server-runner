import { defineConfig, loadEnv } from "vite";
import type { UserConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import tailwindcss from "@tailwindcss/vite";

import path from "path";

// https://vite.dev/config/
export default defineConfig(({ command, mode }) => {
  const configBase = {
    plugins: [svelte(), tailwindcss()],
    resolve: {
      alias: {
        $: path.resolve(__dirname, "./src"),
        $lib: path.resolve(__dirname, "./src/lib"),
      },
    },
  } satisfies UserConfig;

  if (command === "serve") {
    const devConfig: UserConfig = configBase;
    const env = loadEnv(mode, path.join(process.cwd(), ".."), "");

    devConfig.server = {
      proxy: {
        "/api": {
          target: `http://localhost:${env.PORT ?? 4479}`,
          changeOrigin: true,
          ws: true,
        },
      },
    };
    return devConfig;
  } else {
    return configBase;
  }
});
