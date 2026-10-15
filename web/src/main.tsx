import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import { App } from "@/app/app";

// Keep existing bookmarks working while all new navigation uses real routes.
const legacy = window.location.hash.slice(1);
if (
  ["overview", "queries", "policies", "clients", "filters", "upstreams", "history"].includes(legacy)
) {
  window.history.replaceState(null, "", `/${legacy}`);
}
const root = document.getElementById("root");
if (root)
  createRoot(root).render(
    <StrictMode>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </StrictMode>,
  );
