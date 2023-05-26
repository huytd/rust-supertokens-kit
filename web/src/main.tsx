import React from "react"
import ReactDOM from "react-dom/client"
import App from "./App.tsx"
import { MantineProvider } from "@mantine/core"
import { BrowserRouter as Router } from "react-router-dom"

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
    <React.StrictMode>
        <Router>
            <MantineProvider withGlobalStyles withNormalizeCSS>
                <App />
            </MantineProvider>
        </Router>
    </React.StrictMode>
)
