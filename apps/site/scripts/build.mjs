import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";
import { build } from "vite";
import { notFoundRoute, prerenderRoutes } from "./prerender-routes.mjs";

const root = process.cwd();
const dist = join(root, "dist");
const serverOut = await mkdtemp(join(root, ".prerender-"));

function escapeAttribute(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function setMeta(html, attribute, name, content) {
  const pattern = new RegExp(
    `<meta ${attribute}="${name}" content="[^"]*"\\s*/?>`,
  );
  return html.replace(
    pattern,
    `<meta ${attribute}="${name}" content="${escapeAttribute(content)}" />`,
  );
}

function applyDocument(template, rendered, output) {
  const { metadata, appHtml } = rendered;
  let html = template
    .replace(/<html lang="[^"]*">/, `<html lang="${metadata.htmlLang}">`)
    .replace(/<title>[^<]*<\/title>/, `<title>${metadata.title}</title>`)
    .replace(
      /<link rel="canonical" href="[^"]*"\s*\/>/,
      `<link rel="canonical" href="${metadata.canonical}" />`,
    )
    .replace("<!--app-html-->", appHtml);
  html = setMeta(html, "name", "description", metadata.description);
  html = setMeta(html, "property", "og:title", metadata.title);
  html = setMeta(html, "property", "og:description", metadata.description);
  html = setMeta(html, "property", "og:url", metadata.canonical);
  html = setMeta(html, "property", "og:locale", metadata.ogLocale);
  html = setMeta(html, "name", "twitter:title", metadata.title);
  html = setMeta(html, "name", "twitter:description", metadata.description);
  if (metadata.notFound) {
    html = html.replace(
      "</head>",
      '    <meta name="robots" content="noindex, nofollow" />\n  </head>',
    );
  }
  return mkdir(dirname(output), { recursive: true }).then(() => writeFile(output, html));
}

try {
  await build();
  const template = await readFile(join(dist, "index.html"), "utf8");
  await build({
    build: {
      emptyOutDir: true,
      outDir: serverOut,
      ssr: "src/app/entry-server.ts",
    },
  });
  const serverEntry = join(serverOut, "entry-server.js");
  const { render } = await import(`${pathToFileURL(serverEntry).href}?v=${Date.now()}`);
  for (const route of [...prerenderRoutes, notFoundRoute]) {
    await applyDocument(template, await render(route.path), join(dist, route.output));
  }
} finally {
  await rm(serverOut, { recursive: true, force: true });
}
