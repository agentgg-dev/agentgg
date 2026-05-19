import ReactMarkdown from "react-markdown";

// react-markdown emits React elements (no dangerouslySetInnerHTML), and its
// default URL sanitizer strips javascript:/data:/vbscript: links — so even
// hostile model output can't inject scripts.

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
        }}
      >
        {source}
      </ReactMarkdown>
    </div>
  );
}
