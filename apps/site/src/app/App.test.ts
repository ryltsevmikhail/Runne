import { describe, expect, it } from "vitest";
import appSource from "./App.vue?raw";
import headerSource from "../shared/ui/site-header/SiteHeader.vue?raw";

describe("skip navigation target", () => {
  it("links to a programmatically focusable main landmark", () => {
    expect(headerSource).toMatch(/<a\s+class="skip-link"\s+href="#main"/);
    expect(appSource).toMatch(/<main\s+id="main"\s+tabindex="-1"/);
  });
});
