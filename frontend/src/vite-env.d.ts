/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Backend origin for a decoupled prod deploy, e.g. https://sentinel-soc-api.onrender.com.
   *  Leave unset in dev / Docker to use the same-origin proxy (`/api`, `/ws`). */
  readonly VITE_API_URL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
