// Converts docs/ into GitHub wiki pages: node scripts/build-wiki.js <wiki checkout> <owner/repo>
// docs/README.md becomes Home, links between pages drop ".md", links into the repository
// become full GitHub links, images are copied, and a sidebar is built from the index.
// Pages in the wiki that came from docs/ but no longer exist there are removed.
const fs = require("node:fs");
const path = require("node:path");

const [wikiDir, repository = "BANAANGA/BNGlookup"] = process.argv.slice(2);
if (!wikiDir) {
  console.error("Usage: node scripts/build-wiki.js <wiki checkout> [owner/repo]");
  process.exit(1);
}
const docsDir = path.join(__dirname, "..", "docs");
const repoUrl = `https://github.com/${repository}/blob/main`;
const pageName = (file) => (file === "README.md" ? "Home" : file.replace(/\.md$/, ""));

function convertLinks(markdown) {
  return markdown.replace(/(!?)\[([^\]]*)\]\(([^)\s]+)\)/g, (match, bang, text, target) => {
    if (/^(https?:|mailto:|#)/.test(target)) return match;
    if (bang) return match; // images keep their relative path; the folder is copied
    const [file, anchor] = target.split("#");
    const suffix = anchor ? `#${anchor}` : "";
    if (file.startsWith("../")) return `[${text}](${repoUrl}/${file.slice(3)}${suffix})`;
    if (/^[\w.-]+\.md$/.test(file)) return `[${text}](${pageName(file)}${suffix})`;
    return match;
  });
}

const files = fs.readdirSync(docsDir).filter((file) => file.endsWith(".md")).sort();
const written = new Set();
for (const file of files) {
  const source = fs.readFileSync(path.join(docsDir, file), "utf8");
  const name = `${pageName(file)}.md`;
  fs.writeFileSync(path.join(wikiDir, name), convertLinks(source));
  written.add(name);
}

// Sidebar: the index's section headings and page links, in order.
const index = fs.readFileSync(path.join(docsDir, "README.md"), "utf8");
const sidebar = ["**[Home](Home)**", ""];
for (const line of index.split("\n")) {
  const heading = line.match(/^## (.+)$/);
  if (heading && !/who can use/i.test(heading[1])) sidebar.push("", `**${heading[1]}**`, "");
  const link = line.match(/^\| \[([^\]]+)\]\(([\w.-]+)\.md\)/);
  if (link) sidebar.push(`- [${link[1]}](${link[2]})`);
}
sidebar.push("", "---", "", `[README](${repoUrl}/README.md)`, "");
fs.writeFileSync(path.join(wikiDir, "_Sidebar.md"), sidebar.join("\n").replace(/\n{3,}/g, "\n\n"));
written.add("_Sidebar.md");
fs.writeFileSync(path.join(wikiDir, "_Footer.md"), `Generated from [docs/](https://github.com/${repository}/tree/main/docs) in the repository; edit the files there, not here.\n`);
written.add("_Footer.md");

// Images.
const imagesTarget = path.join(wikiDir, "images");
fs.rmSync(imagesTarget, { recursive: true, force: true });
fs.cpSync(path.join(docsDir, "images"), imagesTarget, { recursive: true });

// Remove pages that were generated before but whose source is gone.
const manifestPath = path.join(wikiDir, ".generated-pages");
const previous = fs.existsSync(manifestPath) ? fs.readFileSync(manifestPath, "utf8").split("\n").filter(Boolean) : [];
for (const name of previous) {
  if (!written.has(name) && fs.existsSync(path.join(wikiDir, name))) fs.rmSync(path.join(wikiDir, name));
}
fs.writeFileSync(manifestPath, `${[...written].sort().join("\n")}\n`);
console.log(`Wrote ${written.size} pages and ${fs.readdirSync(imagesTarget).length} images.`);
