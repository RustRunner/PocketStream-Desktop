/**
 * PocketStream Desktop — minimal Markdown rendering for the shipped
 * license documents.
 *
 * Deliberately not a Markdown library: the three documents this feeds
 * (THIRD-PARTY-NOTICES.md, the cargo-about-generated crate notices,
 * libjpeg-turbo's LICENSE.md) use a small fixed set of constructs —
 * headings, paragraphs, bold, inline code, `-` lists, `---` rules,
 * autolink URLs, and ~~~/``` fenced license texts. Anything else
 * degrades to a plain paragraph. A real renderer dependency would also
 * have to appear in the very notices it renders.
 *
 * Every input line is HTML-escaped before any transform, so the only
 * tags in the output are the ones this module emits. Links render as
 * styled text, not anchors — a real <a> would navigate the WebView.
 */

import { escapeHtml } from "./state.ts";

/** Inline transforms, applied to already-escaped text. Code spans go
 *  first so their contents are never restyled by the bold pass. */
function inline(escaped: string): string {
  return escaped
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/&lt;(https?:\/\/[^\s&]+)&gt;/g, '<span class="md-link">$1</span>')
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, '<span class="md-link">$1</span>');
}

export function renderMarkdownLite(src: string): string {
  const out: string[] = [];
  let para: string[] = [];
  let inList = false;
  let fence: string | null = null;
  let fenceLines: string[] = [];

  const flushPara = (): void => {
    if (para.length > 0) {
      out.push(`<p>${inline(escapeHtml(para.join(" ")))}</p>`);
      para = [];
    }
  };
  const closeList = (): void => {
    if (inList) {
      out.push("</ul>");
      inList = false;
    }
  };
  const flushFence = (): void => {
    out.push(`<pre>${escapeHtml(fenceLines.join("\n"))}</pre>`);
    fence = null;
    fenceLines = [];
  };

  for (const raw of src.split(/\r?\n/)) {
    if (fence !== null) {
      if (raw.trim() === fence) {
        flushFence();
      } else {
        fenceLines.push(raw);
      }
      continue;
    }

    const line = raw.trim();

    const fenceOpen = /^(```|~~~)/.exec(line);
    if (fenceOpen) {
      flushPara();
      closeList();
      fence = fenceOpen[1]!;
      continue;
    }
    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      flushPara();
      closeList();
      const level = heading[1]!.length;
      out.push(`<h${level}>${inline(escapeHtml(heading[2]!))}</h${level}>`);
      continue;
    }
    if (/^(-{3,}|\*{3,})$/.test(line)) {
      flushPara();
      closeList();
      out.push("<hr>");
      continue;
    }
    const item = /^[-*]\s+(.*)$/.exec(line);
    if (item) {
      flushPara();
      if (!inList) {
        out.push("<ul>");
        inList = true;
      }
      out.push(`<li>${inline(escapeHtml(item[1]!))}</li>`);
      continue;
    }
    if (line === "") {
      flushPara();
      closeList();
      continue;
    }
    para.push(line);
  }

  // Unterminated fence: emit what accumulated rather than dropping it.
  if (fence !== null) flushFence();
  flushPara();
  closeList();
  return out.join("\n");
}
