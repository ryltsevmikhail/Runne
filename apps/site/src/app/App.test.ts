import { describe, expect, it } from "vitest";
import appSource from "./App.vue?raw";
import navSource from "./ui/SiteNav.vue?raw";
import { contents } from "./content";

const en = contents.en;
const ru = contents.ru;

describe("landing content contract", () => {
  it("links to a programmatically focusable main landmark", () => {
    expect(navSource).toMatch(/class="brand"/);
    expect(appSource).toMatch(/<main\s+id="main"\s+tabindex="-1"/);
  });

  it("offers a language switch in the navigation", () => {
    expect(navSource).toMatch(/lang-switch/);
    expect(en.langSwitch.to).toBe("ru");
    expect(ru.langSwitch.to).toBe("en");
  });

  it("keeps en and ru dictionaries structurally identical", () => {
    expect(ru.comic.panels.map((p) => p.n)).toEqual(en.comic.panels.map((p) => p.n));
    expect(ru.demo.steps).toHaveLength(en.demo.steps.length);
    expect(ru.contract.nodes.map((n) => n.title)).toHaveLength(3);
    expect(ru.footer.copyright).toContain("2026");
  });

  it("hero stays free of availability promises and fake proof", () => {
    expect(en.hero.headline).toMatch(/survives its own window/);
    expect(en.hero.subtitle).toContain("verification evidence");
    expect(ru.hero.subtitle).toContain("подтверждений");
  });

  it("shows one runtime between clients and the journal", () => {
    expect(en.contract.nodes.map((node) => node.title)).toEqual([
      "Clients",
      "runned",
      "Event journal",
    ]);
  });
});
