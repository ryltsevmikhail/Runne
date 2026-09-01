import { readFile } from "node:fs/promises";
import { join } from "node:path";
import process from "node:process";
import { URL } from "node:url";
import { notFoundRoute, prerenderRoutes } from "./prerender-routes.mjs";

const dist = join(process.cwd(), "dist");

function escaped(value) {
  return value.replaceAll("&", "&amp;").replaceAll('"', "&quot;");
}

async function verify(route, notFound = false) {
  const html = await readFile(join(dist, route.output), "utf8");
  const canonical = new URL(route.path, "https://runne.run").toString();
  const expected = [
    `<html lang="en">`,
    `<title>${route.title} · Runne</title>`,
    `name="description" content="${escaped(route.description)}"`,
    `rel="canonical" href="${canonical}"`,
    `property="og:url" content="${canonical}"`,
    `property="og:locale" content="en_US"`,
    `<h1>${route.heading}</h1>`,
    `id="main" tabindex="-1"`,
  ];
  for (const fragment of expected) {
    if (!html.includes(fragment)) throw new Error(`${route.output}: missing ${fragment}`);
  }
  if (html.includes("<!--app-html-->")) {
    throw new Error(`${route.output}: application body was not rendered`);
  }
  const hasNoIndex = html.includes('name="robots" content="noindex, nofollow"');
  if (hasNoIndex !== notFound) throw new Error(`${route.output}: invalid robots metadata`);
}

for (const route of prerenderRoutes) await verify(route);
await verify(notFoundRoute, true);
process.stdout.write(
  `Verified ${prerenderRoutes.length} prerendered routes and 404.html\n`,
);
