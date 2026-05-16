// Tiny, dependency-free markdown renderer for finding bodies. Handles
// the subset the agentgg prompt template emits: paragraphs, fenced code
// blocks (```lang ... ```), inline code, headers, bullet/numbered lists,
// bold, italic, and links. Output is escaped before any markup is
// applied, so model-generated strings can't inject HTML.

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function inlineFormat(s: string): string {
  let out = escapeHtml(s);
  // inline code first so its contents don't get re-formatted
  out = out.replace(/`([^`]+)`/g, '<code>$1</code>');
  // links
  out = out.replace(
    /\[([^\]]+)\]\(([^)]+)\)/g,
    '<a href="$2" target="_blank" rel="noreferrer">$1</a>',
  );
  // bold
  out = out.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  // italic — avoid matching word_word
  out = out.replace(/(^|[\s(])\*([^*\n]+)\*/g, '$1<em>$2</em>');
  return out;
}

function renderToHtml(md: string): string {
  const lines = md.replace(/\r\n/g, '\n').split('\n');
  const out: string[] = [];
  let i = 0;
  let listType: 'ul' | 'ol' | null = null;

  function closeList() {
    if (listType) {
      out.push(`</${listType}>`);
      listType = null;
    }
  }

  while (i < lines.length) {
    const line = lines[i];

    // fenced code block
    if (line.startsWith('```')) {
      closeList();
      const lang = line.slice(3).trim();
      i++;
      const buf: string[] = [];
      while (i < lines.length && !lines[i].startsWith('```')) {
        buf.push(lines[i]);
        i++;
      }
      // closing fence (or EOF)
      i++;
      const langAttr = lang ? ` data-lang="${escapeHtml(lang)}"` : '';
      out.push(`<pre${langAttr}><code>${escapeHtml(buf.join('\n'))}</code></pre>`);
      continue;
    }

    // header
    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    if (h) {
      closeList();
      const lvl = Math.min(6, h[1].length);
      out.push(`<h${lvl}>${inlineFormat(h[2])}</h${lvl}>`);
      i++;
      continue;
    }

    // bullet list
    const bullet = /^[-*]\s+(.*)$/.exec(line);
    if (bullet) {
      if (listType !== 'ul') {
        closeList();
        out.push('<ul>');
        listType = 'ul';
      }
      out.push(`<li>${inlineFormat(bullet[1])}</li>`);
      i++;
      continue;
    }

    // numbered list
    const numbered = /^\d+\.\s+(.*)$/.exec(line);
    if (numbered) {
      if (listType !== 'ol') {
        closeList();
        out.push('<ol>');
        listType = 'ol';
      }
      out.push(`<li>${inlineFormat(numbered[1])}</li>`);
      i++;
      continue;
    }

    // blank line ends a paragraph / list
    if (line.trim() === '') {
      closeList();
      i++;
      continue;
    }

    // paragraph — coalesce consecutive non-blank, non-special lines
    closeList();
    const buf = [line];
    i++;
    while (
      i < lines.length &&
      lines[i].trim() !== '' &&
      !lines[i].startsWith('```') &&
      !/^(#{1,6})\s/.test(lines[i]) &&
      !/^[-*]\s/.test(lines[i]) &&
      !/^\d+\.\s/.test(lines[i])
    ) {
      buf.push(lines[i]);
      i++;
    }
    out.push(`<p>${inlineFormat(buf.join(' '))}</p>`);
  }

  closeList();
  return out.join('\n');
}

export default function Markdown({ source }: { source: string }) {
  return (
    <div
      className="prose-finding"
      // Markdown is rendered server-side from agent output. inlineFormat
      // escapes raw HTML before applying markup, so model strings can't
      // inject scripts.
      dangerouslySetInnerHTML={{ __html: renderToHtml(source) }}
    />
  );
}
