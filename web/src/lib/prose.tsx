import { Code } from "@huskdev/ui";
import type { ReactElement } from "react";

/** Guide entries and advisory summaries are authored as Markdown, so a
 *  backticked span is inline code. Rendered raw it is worse than unstyled: in
 *  the proportional face `--cached` reads as one long dash, which the product
 *  bans, and the reader cannot tell the literal from the prose around it. */
export function Prose({ text }: { text: string }): ReactElement {
  return (
    <>
      {text.split(/`([^`\n]+)`/g).map((part, i) =>
        i % 2 === 0 ? (
          part
        ) : (
          // Index parity is what marks a capture group; the pair is the key.
          // biome-ignore lint/suspicious/noArrayIndexKey: position is the identity here
          <Code key={`${i}:${part}`}>{part}</Code>
        ),
      )}
    </>
  );
}
