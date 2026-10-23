import { expect, test, type Page } from '@playwright/test'

async function dimensions(page: Page) {
  return page.evaluate(() => ({
    viewport: [innerWidth, innerHeight],
    screen: [screen.width, screen.height],
    available: [screen.availWidth, screen.availHeight],
    outer: [outerWidth, outerHeight],
    dpr: devicePixelRatio,
    matchMediaSource: String(window.matchMedia),
    queries: Object.fromEntries([
      '(width: 1440px)', '(width: 640px)', '(width: 1023px)', '(height: 900px)',
      '(max-width: 1023px)', '(min-width: 1024px)',
      '(device-width: 1440px)', '(device-width: 640px)', '(device-width: 1023px)',
      '(device-height: 900px)', '(device-width: 1920px)', '(device-height: 1080px)',
      '(pointer: fine)', '(pointer: coarse)', '(prefers-color-scheme: light)',
      '(prefers-reduced-motion: no-preference)',
    ].map(query => [query, matchMedia(query).matches])),
  }))
}

function expectDimensions(actual: Awaited<ReturnType<typeof dimensions>>, width: number) {
  expect(actual.viewport).toEqual([width, 900])
  // Historically omitted screen dimensions follow both context viewport and later resize.
  expect(actual.screen).toEqual([width, 900])
  expect(actual.dpr).toBe(1)
  expect(actual.matchMediaSource).toContain('[native code]')
  expect(actual.queries).toEqual({
    '(width: 1440px)': width === 1440,
    '(width: 640px)': width === 640,
    '(width: 1023px)': width === 1023,
    '(height: 900px)': true,
    '(max-width: 1023px)': width <= 1023,
    '(min-width: 1024px)': width >= 1024,
    '(device-width: 1440px)': width === 1440,
    '(device-width: 640px)': width === 640,
    '(device-width: 1023px)': width === 1023,
    '(device-height: 900px)': true,
    '(device-width: 1920px)': false,
    '(device-height: 1080px)': false,
    '(pointer: fine)': true,
    '(pointer: coarse)': false,
    '(prefers-color-scheme: light)': true,
    '(prefers-reduced-motion: no-preference)': true,
  })
}

for (const width of [1440, 640, 1023]) {
  test.describe(`desktop dimensions at context viewport ${width}px`, () => {
    test.use({ viewport: { width, height: 900 } })

    test('preserves viewport-derived screen and native media queries through resize', async ({ page }, info) => {
      await page.goto('/projects/open')
      await expect(page.getByRole('button', { name: 'Choose project folder' })).toBeVisible()
      const before = await dimensions(page)
      const resizedWidth = width === 1440 ? 640 : 1440
      await page.setViewportSize({ width: resizedWidth, height: 900 })
      const after = await dimensions(page)
      await info.attach('dimensions', {
        body: JSON.stringify({ before, after }, null, 2), contentType: 'application/json',
      })
      expectDimensions(before, width)
      expectDimensions(after, resizedWidth)
      expect(await page.locator('main').evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true)
    })
  })
}
