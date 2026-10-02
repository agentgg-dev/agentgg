import ReactMarkdown from "react-markdown";
import { diffLineKinds } from "@/app/lib/diff";

// react-markdown emits React elements (no dangerouslySetInnerHTML), and its
// default URL sanitizer strips javascript:/data:/vbscript: links — so even
// hostile model output can't inject scripts.

/** A ```diff block, one element per line so added and removed lines can be
 *  coloured. A suggested fix is stored as a diff. */
function DiffCode({ source }: { source: string }) {
  const lines = source.replace(/\n$/, "").split("\n");
  const kinds = diffLineKinds(lines);
  return (
    <code className="language-diff">
      {lines.map((line, i) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: the lines of a rendered diff never reorder
        <span key={i} className={`diff-line diff-${kinds[i]}`}>
          {line === "" ? " " : line}
        </span>
      ))}
    </code>
  );
}

export default function Markdown({ source }: { source: string }) {
  return (
    <div className="prose-finding">
      <ReactMarkdown
        components={{
          a: ({ href, children }) => (
            <a href={href} target="_blank" rel="noreferrer">
              {children}
            </a>
          ),
          code: ({ className, children }) =>
            className === "language-diff" ? (
              <DiffCode source={String(children)} />
            ) : (
              <code className={className}>{children}</code>
            ),
        }}
      >
        {source}
      </ReactMarkdown>
    </div>
  );
}
