import "./index.css";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TransportProvider } from "@connectrpc/connect-query";
import { Code, ConnectError } from "@connectrpc/connect";
import { transport } from "./transport";
import { RequireAuth } from "./auth";
import { LoginPage } from "./routes/login";
import { AppShell } from "./routes/app";
import { CatalogPage } from "./routes/catalog/catalog";
import { MyAccessPage } from "./routes/access/access";
import { ApprovalsPage } from "./routes/approvals/approvals";
import { RecordingsPage } from "./routes/recordings/recordings";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Auth errors are deterministic — never retry them, so an unauthenticated
      // WhoAmI resolves immediately and the auth gate redirects to /login without
      // the default 3-retry backoff (~7s) stalling on a blank page.
      retry: (failureCount, error) => {
        const code = ConnectError.from(error).code;
        if (code === Code.Unauthenticated || code === Code.PermissionDenied) {
          return false;
        }
        return failureCount < 2;
      },
    },
  },
});

const router = createBrowserRouter([
  {
    path: "/login",
    element: <LoginPage />,
  },
  {
    path: "/",
    element: (
      <RequireAuth>
        <AppShell />
      </RequireAuth>
    ),
    children: [
      { index: true, element: <CatalogPage /> },
      { path: "access", element: <MyAccessPage /> },
      { path: "approvals", element: <ApprovalsPage /> },
      { path: "recordings", element: <RecordingsPage /> },
      { path: "recordings/:sessionId", element: <RecordingsPage /> },
    ],
  },
]);

const root = document.getElementById("root");
if (root == null) throw new Error("no #root element");

createRoot(root).render(
  <StrictMode>
    <TransportProvider transport={transport}>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </TransportProvider>
  </StrictMode>
);
