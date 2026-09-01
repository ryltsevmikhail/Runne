import { describe, expect, it } from "vitest";
import appSource from "./App.vue?raw";
import navSource from "./ui/SiteNav.vue?raw";
import { comic, contract, demo, footer, hero } from "./content";

describe("landing content contract", () => {
  it("links to a programmatically focusable main landmark", () => {
    expect(navSource).toMatch(/class="brand"/);
    expect(appSource).toMatch(/<main\s+id="main"\s+tabindex="-1"/);
  });

  it("keeps the hero free of availability promises and fake proof", () => {
    expect(hero.headline).toMatch(/survives its own window/);
    expect(hero.subtitle).toContain("verification evidence");
  });

  it("has six numbered comic panels with speech and body copy", () => {
    expect(comic.panels).toHaveLength(6);
    for (const panel of comic.panels) {
      expect(panel.speech).toBeTruthy();
      expect(panel.body).toBeTruthy();
    }
  });

  it("shows one runtime between clients and the journal", () => {
    expect(contract.nodes.map((node) => node.title)).toEqual([
      "Clients",
      "runned",
      "Event journal",
    ]);
  });

  it("renders demo states as explicit text, not suppressed errors", () => {
    expect(demo.steps.some((step) => step.active)).toBe(true);
    expect(footer.status).toContain("OPERATIONAL");
  });
});
