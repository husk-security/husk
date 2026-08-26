import { Badge, Button, Card, PageHeader, Spinner } from "@huskdev/ui";
import { CircleCheck, Hexagon, LogIn, PlugZap } from "lucide-react";
import { useAccount, useDeviceLogin, useLive } from "@/lib/api";

const ACCOUNT_SIGN_IN_AVAILABLE = false;

export function Account() {
  const account = useAccount();
  const live = useLive();
  const ctx = live.data?.report.context;
  const a = account.data;
  const connected = a?.connected && a.account;
  const errored = a?.detail && a.detail !== "not connected";

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col px-6 py-8 lg:min-h-full lg:justify-center lg:py-12">
      <PageHeader
        title="Account & connection"
        lede="Husk works fully without an account. Existing sessions remain connected; new account sign-in is coming soon."
      />

      <div className="mt-6 grid grid-cols-1 items-stretch gap-4 lg:grid-cols-2">
        <Card className="grid min-w-0 gap-3.5 p-5">
          <h3 className="text-[13.5px] font-semibold text-fg">
            Cloud connection
          </h3>
          <div className="flex min-w-0 items-start gap-2.5 rounded-md border border-border bg-bg-subtle px-3.5 py-3">
            {connected ? (
              <CircleCheck
                size={18}
                className="mt-0.5 shrink-0 text-severity-info"
              />
            ) : errored ? (
              <Hexagon size={18} className="mt-0.5 shrink-0 text-fg-subtle" />
            ) : (
              <PlugZap size={18} className="mt-0.5 shrink-0 text-fg-subtle" />
            )}
            <div className="min-w-0 flex-1">
              <b className="block text-[13.5px]">
                {connected ? "Connected" : "Not connected"}
              </b>
              <span className="mt-0.5 block font-mono text-[12px] leading-relaxed text-fg-muted [overflow-wrap:anywhere]">
                {connected
                  ? `${a?.account?.display_name ?? a?.account?.email} · ${a?.backend_url}`
                  : errored
                    ? "Couldn't reach the Husk backend."
                    : `would connect to ${a?.backend_url ?? "the husk backend"}`}
              </span>
            </div>
            {connected && a?.account?.tier && (
              <Badge variant="accent" className="shrink-0 uppercase">
                {a.account.tier}
              </Badge>
            )}
          </div>
          {!connected && <LoginPanel />}
        </Card>

        <Card className="grid min-w-0 gap-3.5 p-5">
          <h3 className="text-[13.5px] font-semibold text-fg">This machine</h3>
          <dl className="grid gap-3">
            <KV
              label="user"
              value={ctx?.git_name ?? ctx?.user ?? "developer"}
            />
            <KV label="system" value={ctx?.distro ?? ctx?.os ?? "unknown"} />
            <KV
              label="kernel / arch"
              value={
                [ctx?.kernel, ctx?.arch].filter(Boolean).join(" · ") ||
                "unknown"
              }
            />
            <KV
              label="git identity"
              value={
                ctx?.git_name && ctx?.git_email
                  ? `${ctx.git_name} <${ctx.git_email}>`
                  : "not configured"
              }
            />
            <KV
              label="dev tools"
              value={
                (ctx?.package_managers ?? []).slice(0, 10).join(", ") ||
                "none detected"
              }
            />
          </dl>
        </Card>
      </div>
    </div>
  );
}

/** In-UI device-flow state machine. The availability flag keeps its network
 *  entry point disabled until account sign-in is ready. */
function LoginPanel() {
  const login = useDeviceLogin();

  if (login.phase === "starting" || login.phase === "waiting") {
    return (
      <div className="grid gap-2 rounded-md border border-border bg-bg-subtle px-3.5 py-3">
        <p className="text-[13px] leading-relaxed text-fg-muted">
          Approve this machine in the tab that just opened; it connects here
          automatically.
        </p>
        {login.userCode && (
          <p className="flex items-baseline gap-2">
            <span className="text-[12px] text-fg-subtle">code</span>
            <span className="font-mono text-[15px] tracking-[0.2em] text-fg">
              {login.userCode}
            </span>
          </p>
        )}
        <p className="flex items-center gap-2 text-[12px] text-fg-subtle">
          <Spinner className="size-3.5" /> waiting for approval…
          {login.verificationUrl && (
            <a
              href={login.verificationUrl}
              target="_blank"
              rel="noreferrer"
              className="underline decoration-border-strong underline-offset-2 hover:text-fg"
            >
              reopen tab
            </a>
          )}
        </p>
      </div>
    );
  }

  const failure =
    login.phase === "denied"
      ? "Approval was denied."
      : login.phase === "expired"
        ? "That request expired."
        : login.phase === "error"
          ? (login.error ?? "Sign-in failed.")
          : null;

  return (
    <div className="grid justify-items-start gap-2">
      {failure && (
        <p className="text-[13px] text-severity-high [overflow-wrap:anywhere]">
          {failure}
        </p>
      )}
      <Button
        variant="secondary"
        size="sm"
        disabled={!ACCOUNT_SIGN_IN_AVAILABLE}
        onClick={() => login.start()}
      >
        <LogIn size={14} />
        {ACCOUNT_SIGN_IN_AVAILABLE
          ? failure
            ? "Try again"
            : "Sign in"
          : "Coming soon"}
      </Button>
      <p className="text-[12px] leading-relaxed text-fg-subtle">
        {ACCOUNT_SIGN_IN_AVAILABLE
          ? "Opens your browser to approve this machine; no terminal needed."
          : "Account sign-in is not available yet. Everything else works without it."}
      </p>
    </div>
  );
}

function KV({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-[10.5px] tracking-wider text-fg-subtle">{label}</dt>
      <dd className="mt-1 font-mono text-[13px] text-fg [overflow-wrap:anywhere]">
        {value}
      </dd>
    </div>
  );
}
