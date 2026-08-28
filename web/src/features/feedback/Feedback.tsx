import {
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from "@huskdev/ui";
import { CheckCircle2, MessageSquare } from "lucide-react";
import { useState } from "react";
import { HttpError, useSendFeedback } from "@/lib/api";

/** Mirrors the server-side message cap (`cloud::feedback::MAX_MESSAGE_CHARS`
 *  in the Rust CLI and the backend intake); keep in sync. */
const MAX_MESSAGE_CHARS = 4096;

/** Send-feedback dialog, opened from the sidebar Help menu. The message goes
 *  to the local husk server (`POST /api/feedback`), which forwards it to the
 *  Husk backend; no account and no browser cross-origin call. Bug reports are
 *  better as GitHub issues (the Help menu links there); this is for everything
 *  else: rough edges, ideas, praise. */
export function FeedbackDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [message, setMessage] = useState("");
  const [contact, setContact] = useState("");
  const send = useSendFeedback();

  const close = (next: boolean) => {
    onOpenChange(next);
    if (!next) {
      // Keep an unsent draft for reopen; clear only after a successful send.
      if (send.isSuccess) {
        setMessage("");
        setContact("");
      }
      send.reset();
    }
  };

  const submit = () => {
    if (message.trim().length === 0 || send.isPending) return;
    send.mutate({
      message,
      ...(contact.trim() ? { contact: contact.trim() } : {}),
    });
  };

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent>
        <div className="mb-4 flex size-9 items-center justify-center rounded-md bg-bg-subtle text-fg-subtle">
          <MessageSquare size={18} />
        </div>
        <DialogTitle>Send feedback</DialogTitle>
        {send.isSuccess ? (
          <>
            <div className="mt-4 flex items-center gap-2 text-sm text-fg">
              <CheckCircle2 size={16} className="shrink-0 text-success" />
              Feedback sent. Thanks!
            </div>
            <div className="mt-6 flex justify-end">
              <Button onClick={() => close(false)}>Done</Button>
            </div>
          </>
        ) : (
          <>
            <DialogDescription className="leading-relaxed">
              Tell the husk developers what works, what does not, or what is
              missing. Goes straight to the team; no account needed.
            </DialogDescription>
            <label
              className="mt-4 block text-xs font-medium text-fg-muted"
              htmlFor="feedback-message"
            >
              Message
            </label>
            <textarea
              id="feedback-message"
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              maxLength={MAX_MESSAGE_CHARS}
              rows={5}
              autoFocus
              placeholder="What should we know?"
              className="mt-1.5 w-full resize-y rounded-md border border-border bg-bg px-3 py-2 text-sm text-fg placeholder:text-fg-subtle focus-ring"
            />
            <label
              className="mt-3 block text-xs font-medium text-fg-muted"
              htmlFor="feedback-contact"
            >
              Email (optional, if you want a reply)
            </label>
            <input
              id="feedback-contact"
              type="email"
              value={contact}
              onChange={(event) => setContact(event.target.value)}
              maxLength={254}
              placeholder="you@example.com"
              className="mt-1.5 w-full rounded-md border border-border bg-bg px-3 py-2 text-sm text-fg placeholder:text-fg-subtle focus-ring"
            />
            <p className="mt-3 text-xs leading-relaxed text-fg-muted">
              Your message, and the email if you give one, leave this machine
              and are stored by Husk so the team can read and reply. See the{" "}
              <a
                href="https://husk-security.dev/legal/privacy"
                target="_blank"
                rel="noreferrer"
                className="rounded-sm font-medium text-fg underline-offset-2 hover:underline focus-ring"
              >
                privacy notice
              </a>
              .
            </p>
            {send.isError && (
              <p className="mt-3 text-xs text-danger" role="alert">
                {send.error instanceof HttpError
                  ? send.error.message
                  : "Could not send the feedback. Check your connection and try again."}
              </p>
            )}
            <div className="mt-6 flex items-center justify-end gap-2">
              <Button variant="ghost" onClick={() => close(false)}>
                Cancel
              </Button>
              <Button
                onClick={submit}
                disabled={message.trim().length === 0 || send.isPending}
              >
                {send.isPending ? "Sending..." : "Send feedback"}
              </Button>
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
