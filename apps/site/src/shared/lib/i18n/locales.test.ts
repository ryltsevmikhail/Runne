import { describe, expect, it, vi } from "vitest";
import {
  localeFromLanguage,
  localeStorageKey,
  persistLocale,
  readStoredLocale,
  resolveLocale,
} from "./locales";

describe("locale helpers", () => {
  it("maps regional browser languages to supported locales", () => {
    expect(localeFromLanguage("zh-Hant-TW")).toBe("zh-cn");
    expect(localeFromLanguage("pt-PT")).toBe("pt-br");
    expect(localeFromLanguage("de-AT")).toBe("de");
  });

  it("prefers a valid saved locale over browser languages", () => {
    expect(resolveLocale("ru", ["fr-FR"])).toBe("ru");
    expect(resolveLocale("unknown", ["ja-JP"])).toBe("ja");
    expect(resolveLocale(null, ["unknown"])).toBe("en");
  });

  it("reads and persists the stable storage key", () => {
    const storage = { getItem: vi.fn(() => "es"), setItem: vi.fn() };
    expect(readStoredLocale(storage)).toBe("es");
    persistLocale(storage, "fr");
    expect(storage.setItem).toHaveBeenCalledWith(localeStorageKey, "fr");
  });

  it("fails closed when browser storage is unavailable", () => {
    const storage = {
      getItem: vi.fn(() => {
        throw new Error("blocked");
      }),
      setItem: vi.fn(() => {
        throw new Error("blocked");
      }),
    };
    expect(readStoredLocale(storage)).toBeNull();
    expect(() => persistLocale(storage, "ko")).not.toThrow();
  });
});
