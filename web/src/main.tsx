import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

const root = document.getElementById("root");
if (!root) throw new Error("no #root element");

createRoot(root).render(
  <StrictMode>
    <div>jumpgate</div>
  </StrictMode>
);
