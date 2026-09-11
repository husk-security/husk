import {
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
} from "@huskdev/ui";
import { CornerLeftUp, Folder, FolderOpen } from "lucide-react";
import { useState } from "react";
import { useDirs, usePickFolder } from "@/lib/api";
// Display only; the real path is still what gets sent to the API.
import { shortPath as short } from "@/lib/path";

/** Mouse-driven local folder picker. Opens a modal that browses the machine one
 *  directory level at a time (served by `/api/dirs`) and hands the chosen
 *  absolute path back via `onPick`. No typing required. Where the machine has a
 *  folder dialog of its own, the modal also offers that instead. */
export function DirPicker({
  current,
  disabled,
  onPick,
}: {
  current: string;
  disabled?: boolean;
  onPick: (path: string) => void;
}) {
  const [open, setOpen] = useState(false);
  // Where the browser is pointing. Seeded from the current scan root each open.
  const [path, setPath] = useState<string | null>(current || null);
  const { data, isLoading } = useDirs(open ? path : null);
  const native = usePickFolder();

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (o) setPath(current || null);
      }}
    >
      <Button
        variant="secondary"
        size="sm"
        disabled={disabled}
        onClick={() => setOpen(true)}
        className="max-w-[16rem] font-mono text-xs"
      >
        <Folder size={14} />
        <span className="truncate">{short(current) || "Pick folder"}</span>
      </Button>

      <DialogContent size="md">
        <DialogTitle>Pick a folder to scan</DialogTitle>
        <DialogDescription className="font-mono text-xs">
          {data ? short(data.path) : "…"}
        </DialogDescription>

        <div className="mt-2 max-h-72 overflow-auto rounded-lg border border-border">
          {data?.parent != null && (
            <button
              type="button"
              onClick={() => setPath(data.parent)}
              className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-fg-muted hover:bg-bg-subtle"
            >
              <CornerLeftUp size={14} className="shrink-0" />
              ..
            </button>
          )}
          {isLoading && (
            <div className="px-3 py-2 text-sm text-fg-subtle">Loading…</div>
          )}
          {data?.dirs.length === 0 && !isLoading && (
            <div className="px-3 py-2 text-sm text-fg-subtle">
              No subfolders here.
            </div>
          )}
          {data?.dirs.map((d) => (
            <button
              key={d.path}
              type="button"
              onClick={() => setPath(d.path)}
              className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-bg-subtle"
            >
              <FolderOpen size={14} className="shrink-0 text-fg-subtle" />
              <span className="truncate">{d.name}</span>
            </button>
          ))}
        </div>

        {native.error && (
          <p className="mt-2 text-xs text-danger" role="alert">
            {native.error.message}
          </p>
        )}

        <DialogFooter>
          <Button variant="ghost" size="sm" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          {data?.native && (
            <Button
              variant="secondary"
              size="sm"
              disabled={native.isPending}
              onClick={() =>
                native.mutate(undefined, {
                  onSuccess: ({ path: picked }) => {
                    // No path means the user closed the system dialog: leave
                    // this one open so they can browse here instead.
                    if (picked) {
                      onPick(picked);
                      setOpen(false);
                    }
                  },
                })
              }
            >
              {native.isPending
                ? "Waiting for your picker…"
                : "Use system picker"}
            </Button>
          )}
          <Button
            variant="primary"
            size="sm"
            disabled={!data}
            onClick={() => {
              if (data) onPick(data.path);
              setOpen(false);
            }}
          >
            Scan this folder
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
