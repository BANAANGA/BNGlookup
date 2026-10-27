function escapeAboutHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// Renders a small, safe Markdown subset. Everything is escaped first; only
// http(s), mailto and same-site links are turned into anchors.
function renderAboutInline(text) {
  const codeSpans = [];
  let html = escapeAboutHtml(text).replace(/`([^`]+)`/g, (_match, code) => {
    codeSpans.push(`<code>${code}</code>`);
    return `\u0000${codeSpans.length - 1}\u0000`;
  });
  html = html.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (match, label, url) => {
    const decoded = url.replaceAll("&amp;", "&");
    const allowed = /^(?:https?:\/\/|mailto:)/i.test(decoded) || (/^\/(?!\/)/.test(decoded));
    if (!allowed) return match;
    const external = /^https?:\/\//i.test(decoded);
    return `<a href="${url}"${external ? ' target="_blank" rel="noopener noreferrer"' : ""}>${label}</a>`;
  });
  html = html
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[^*])\*([^*\s][^*]*)\*/g, "$1<em>$2</em>")
    .replace(/(^|[\s(])_([^_\s][^_]*)_(?=$|[\s).,!?:;])/g, "$1<em>$2</em>");
  return html.replace(/\u0000(\d+)\u0000/g, (_match, index) => codeSpans[Number(index)]);
}

function renderAboutMarkdown(markdown) {
  const lines = String(markdown || "").replace(/\r\n/g, "\n").split("\n");
  const blocks = [];
  let paragraph = [];
  let list = null;
  let quote = [];
  const flushParagraph = () => {
    if (paragraph.length) blocks.push(`<p>${paragraph.map(renderAboutInline).join("<br>")}</p>`);
    paragraph = [];
  };
  const flushList = () => {
    if (list) blocks.push(`<${list.tag}>${list.items.map((item) => `<li>${renderAboutInline(item)}</li>`).join("")}</${list.tag}>`);
    list = null;
  };
  const flushQuote = () => {
    if (quote.length) blocks.push(`<blockquote>${quote.map(renderAboutInline).join("<br>")}</blockquote>`);
    quote = [];
  };
  const flushAll = () => {
    flushParagraph();
    flushList();
    flushQuote();
  };
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (/^```/.test(line.trim())) {
      flushAll();
      const code = [];
      index += 1;
      while (index < lines.length && !/^```/.test(lines[index].trim())) {
        code.push(lines[index]);
        index += 1;
      }
      blocks.push(`<pre><code>${escapeAboutHtml(code.join("\n"))}</code></pre>`);
      continue;
    }
    const heading = line.match(/^(#{1,3})\s+(.+)$/);
    const bullet = line.match(/^\s*[-*]\s+(.+)$/);
    const numbered = line.match(/^\s*\d+[.)]\s+(.+)$/);
    const quoted = line.match(/^>\s?(.*)$/);
    if (!line.trim()) {
      flushAll();
    } else if (/^(?:-{3,}|\*{3,})$/.test(line.trim())) {
      flushAll();
      blocks.push("<hr>");
    } else if (heading) {
      flushAll();
      const level = heading[1].length + 1;
      blocks.push(`<h${level}>${renderAboutInline(heading[2])}</h${level}>`);
    } else if (bullet || numbered) {
      flushParagraph();
      flushQuote();
      const tag = bullet ? "ul" : "ol";
      if (list && list.tag !== tag) flushList();
      list ||= { tag, items: [] };
      list.items.push((bullet || numbered)[1]);
    } else if (quoted) {
      flushParagraph();
      flushList();
      quote.push(quoted[1]);
    } else {
      flushList();
      flushQuote();
      paragraph.push(line);
    }
  }
  flushAll();
  return blocks.join("\n");
}

async function loadAboutPage() {
  const container = document.querySelector("#about-content");
  if (!container) return;
  try {
    const response = await fetch("/api/about", { credentials: "same-origin" });
    const data = await response.json();
    if (data.setupRequired) {
      window.location.replace("/setup.html");
      return;
    }
    if (!response.ok) throw new Error(data.error || "The About page could not be loaded.");
    container.innerHTML = renderAboutMarkdown(data.content);
    const firstHeading = container.querySelector("h2");
    if (firstHeading) {
      const separator = document.title.indexOf(" · ");
      document.title = `${firstHeading.textContent}${separator === -1 ? "" : document.title.slice(separator)}`;
    }
  } catch (error) {
    container.innerHTML = `<p class="error-message">${escapeAboutHtml(error.message)}</p>`;
  }
}

loadAboutPage();
