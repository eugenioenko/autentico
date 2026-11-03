import "@yarcl/react";
import "./fonts.css";
import "./styles.css";
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { applyStoredTheme } from "./theme";

applyStoredTheme();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
