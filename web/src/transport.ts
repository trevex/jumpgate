import { createConnectTransport } from "@connectrpc/connect-web";

export const transport = createConnectTransport({
  baseUrl: "/",
  fetch: (input, init) =>
    globalThis.fetch(input, { ...init, credentials: "include" }),
});
