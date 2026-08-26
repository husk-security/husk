import { CodeBlock, CommandBlock, PageHeader } from "@huskdev/ui";
import { ArrowUpRight, ChevronDown } from "lucide-react";
import { type ReactNode, useState } from "react";
import { useAgents } from "@/lib/api";

export const AI_AGENT_SETUP_DOCS_URL =
  "https://husk-security.dev/docs/ai-agent-setup";
/** The section of that page listing what to actually ask an agent for. */
export const AI_AGENT_USAGE_DOCS_URL = `${AI_AGENT_SETUP_DOCS_URL}#ask-your-agent`;
const AI_AGENT_PROTOCOL_URL = "https://husk-security.dev/install.md";

const AGENT_SETUP_PROMPT =
  "Install Husk from https://husk-security.dev/install.md.";

// `open` key for the catch-all row; not a real agent name so it can't collide.
const CATCH_ALL = "__catch_all__";

// One entry per agent the user might have. Clicking a row expands its install
// guide. `id` (when set) is the `husk mcp install <id>` arg and the key into
// /api/agents for the "Configured" chip; source of truth: src/agent.rs. Claude
// Code uses the plugin path instead, so it has no id.
type Agent = { name: string; id?: string; guide: ReactNode };

const AGENTS: Agent[] = [
  {
    name: "Claude Code",
    id: "claude-code",
    guide: (
      <>
        <p className="mb-2.5 text-[13px] leading-relaxed text-fg-muted">
          The plugin registers the husk MCP server and the{" "}
          <code className="font-mono text-[12px]">using-husk</code> skill and
          guardrail hooks. Run both in Claude Code:
        </p>
        <CommandBlock command="/plugin marketplace add husk-security/husk" />
        <CommandBlock command="/plugin install husk@husk" className="mt-1.5" />
      </>
    ),
  },
  { name: "Cursor", id: "cursor", guide: <Install agent="cursor" /> },
  {
    name: "VS Code (Copilot)",
    id: "vscode",
    guide: <Install agent="vscode" />,
  },
  { name: "Codex", id: "codex", guide: <Install agent="codex" /> },
  { name: "Gemini CLI", id: "gemini", guide: <Install agent="gemini" /> },
  {
    name: "Claude Desktop",
    id: "claude-desktop",
    guide: <Install agent="claude-desktop" />,
  },
  { name: "OpenCode", id: "opencode", guide: <Install agent="opencode" /> },
];

/** The "AI agent setup" tab: pick your agent, expand its install guide, wire
 *  husk in over MCP. Static onboarding plus live per-agent config status. */
export function AgentSetup() {
  // Keep a real manual command visible on first render; other clients remain
  // available without hiding the agent-driven path above it.
  const [open, setOpen] = useState<string | null>("Codex");
  const [copied, setCopied] = useState(false);
  const agents = useAgents();

  async function copyPrompt() {
    await navigator.clipboard.writeText(AGENT_SETUP_PROMPT);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div
      data-tour="agent-setup"
      className="mx-auto w-full max-w-2xl px-6 pb-10 pt-7"
    >
      <PageHeader title="AI agent setup" />

      <p className="mt-6 text-[13px] font-medium text-fg">Ask your agent</p>
      <section className="mt-2 overflow-hidden rounded-lg border border-border bg-bg-subtle">
        <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
          <p className="text-[12px] font-medium text-fg-muted">
            Paste into your agent
          </p>
          <button
            type="button"
            onClick={() => void copyPrompt()}
            className="rounded px-2 py-1 text-[12px] font-medium text-fg-muted hover:bg-bg hover:text-fg focus-ring"
          >
            {copied ? "Copied" : "Copy prompt"}
          </button>
        </div>
        <pre className="whitespace-pre-wrap break-words px-4 py-3.5 font-mono text-[12px] leading-relaxed text-fg">
          {AGENT_SETUP_PROMPT}
        </pre>
        <p className="border-t border-border px-4 py-3 text-[12px] leading-relaxed text-fg-subtle">
          Before pasting, read the{" "}
          <a
            href={AI_AGENT_PROTOCOL_URL}
            target="_blank"
            rel="noreferrer"
            className="text-accent hover:underline focus-ring"
          >
            raw installation protocol
          </a>{" "}
          just as you would read an install script.
        </p>
      </section>

      <div className="my-6 flex items-center gap-3" aria-hidden="true">
        <span className="h-px flex-1 bg-border" />
        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-fg-subtle">
          or
        </span>
        <span className="h-px flex-1 bg-border" />
      </div>

      <p className="text-[13px] font-medium text-fg">Set up manually</p>
      <div className="mt-2 grid gap-2.5">
        {AGENTS.map((a) => {
          const isOpen = open === a.name;
          const configured = a.id ? agents.data?.[a.id] : undefined;
          return (
            <div
              key={a.name}
              className="rounded-lg border border-border bg-bg-subtle"
            >
              <button
                type="button"
                aria-expanded={isOpen}
                onClick={() => setOpen(isOpen ? null : a.name)}
                className="flex w-full items-baseline justify-between gap-3 px-4 py-3 text-left focus-ring"
              >
                <span className="text-[14px] text-fg">{a.name}</span>
                <span className="flex items-center gap-3">
                  {configured !== undefined && (
                    <StatusChip configured={configured} />
                  )}
                  <ChevronDown
                    size={15}
                    className={`shrink-0 text-fg-muted transition-transform ${
                      isOpen ? "rotate-180" : ""
                    }`}
                  />
                </span>
              </button>
              {isOpen && (
                <div className="border-t border-border px-4 py-3.5">
                  {a.guide}
                </div>
              )}
            </div>
          );
        })}

        {/* Long-tail catch-all: same dropdown affordance, dashed to set it
            apart from the named agents. husk speaks plain MCP, so any client
            takes the same server entry. */}
        <div className="rounded-lg border border-dashed border-border bg-bg-subtle/50">
          <button
            type="button"
            aria-expanded={open === CATCH_ALL}
            onClick={() => setOpen(open === CATCH_ALL ? null : CATCH_ALL)}
            className="flex w-full items-baseline justify-between gap-3 px-4 py-3 text-left focus-ring"
          >
            <span className="text-[14px] text-fg-muted">
              Don’t see your agent?
            </span>
            <ChevronDown
              size={15}
              className={`shrink-0 text-fg-muted transition-transform ${
                open === CATCH_ALL ? "rotate-180" : ""
              }`}
            />
          </button>
          {open === CATCH_ALL && (
            <div className="border-t border-border px-4 py-3.5">
              <p className="mb-2.5 text-[13px] leading-relaxed text-fg-muted">
                Add husk to your agent’s MCP server list (usually an{" "}
                <code className="font-mono text-[12px]">mcpServers</code> object
                in a JSON settings file):
              </p>
              <CodeBlock copyable>
                {`{
  "mcpServers": {
    "husk": {
      "command": "husk",
      "args": ["mcp"]
    }
  }
}`}
              </CodeBlock>
              <p className="mt-2.5 text-[12px] leading-snug text-fg-subtle">
                Husk must be on your <code className="font-mono">PATH</code>.
                Restart the agent, then verify below.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* #4, the universal final step: confirm the server actually starts. */}
      <section className="mt-6 rounded-lg border border-border bg-bg-subtle px-4 py-3.5">
        <p className="mb-1 text-[13px] text-fg">Verify it worked</p>
        <p className="mb-2.5 text-[13px] leading-relaxed text-fg-muted">
          After setup, confirm husk can start and report its cache state. A
          clean exit means the server runs on this shell's PATH; restart the
          agent to pick it up.
        </p>
        <CommandBlock command="husk mcp --selfcheck" />
      </section>

      <a
        href={AI_AGENT_SETUP_DOCS_URL}
        target="_blank"
        rel="noreferrer"
        className="mt-8 inline-flex items-center gap-1.5 text-[13px] text-accent hover:underline focus-ring"
      >
        Full setup guide
        <ArrowUpRight size={14} />
      </a>
    </div>
  );
}

/** Live "Configured" / "Not configured" pill from /api/agents. The endpoint
 *  reads local config files only, so it proves registration, not a live link. */
function StatusChip({ configured }: { configured: boolean }) {
  return (
    <span
      title={
        configured
          ? "husk is registered in this agent's config. Husk has not tested a live connection."
          : "No husk entry found in this agent's config."
      }
      className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] ${
        configured ? "bg-success/10 text-success" : "bg-bg text-fg-subtle"
      }`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${
          configured ? "bg-success" : "bg-fg-subtle"
        }`}
      />
      {configured ? "Configured" : "Not configured"}
    </span>
  );
}

/** The shared `husk mcp install <agent>` body. */
function Install({ agent }: { agent: string }) {
  return (
    <>
      <p className="mb-2.5 text-[13px] leading-relaxed text-fg-muted">
        <code className="font-mono text-[12px]">husk mcp install</code> writes
        the MCP-server entry for you, idempotent, leaves the rest of the file
        intact. Add <code className="font-mono text-[12px]">--global</code> for
        the user-level config, or{" "}
        <code className="font-mono text-[12px]">--dry-run</code> to preview.
      </p>
      <CommandBlock command={`husk mcp install ${agent}`} />
      <p className="mt-2.5 text-[12px] leading-snug text-fg-subtle">
        husk must be on your <code className="font-mono">PATH</code>; restart
        the agent to pick up the new server.
      </p>
    </>
  );
}
