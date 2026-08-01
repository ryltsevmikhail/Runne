import type { SiteDictionary } from "../../page-types";
import { architecture } from "./architecture";
import { home } from "./home";
import { privacy } from "./privacy";
import { product } from "./product";
import { roadmap } from "./roadmap";
import { security } from "./security";
import { shared } from "./shared";
import { status } from "./status";

export const ko = {
  shared,
  pages: { home, product, architecture, security, roadmap, status, privacy },
} satisfies SiteDictionary;
