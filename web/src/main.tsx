import { TooltipProvider } from "@huskdev/ui";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./app.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 10_000 },
  },
});

// biome-ignore lint/style/noNonNullAssertion: #root is defined in index.html
ReactDOM.createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider delayDuration={200}>
        <App />
      </TooltipProvider>
    </QueryClientProvider>
  </StrictMode>,
);
