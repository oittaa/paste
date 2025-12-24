// tests/paste.spec.ts
import { test, expect, Page } from '@playwright/test';

// Helper to wait for status message and return its text
async function getStatusText(page: Page): Promise<string> {
  const status = page.locator('#status.show');
  await expect(status).toBeVisible({ timeout: 10000 });
  return await status.textContent() ?? '';
}

// Helper to enter edit mode and type content
async function typePasteContent(page: Page, content: string) {
  await expect(page.locator('#output')).toBeVisible();
  await page.locator('#output').fill(content);
}

// Helper to create a paste and return the full URL (including #id:key)
async function createPaste(page: Page, content: string): Promise<string> {
  await typePasteContent(page, content);
  await page.locator('#actionBtn').click();

  // Wait for success status
  const statusText = await getStatusText(page);
  expect(statusText).toMatch(/Paste created!/);

  await expect(page.locator('#viewer')).toBeVisible({ timeout: 10000 });
  await expect(page.locator('#code')).toHaveText(content);

  return page.url(); // Includes full #id:key
}

// Helper to parse id and key from a paste URL
function parsePasteUrl(url: string): { id: string; key: string } {
  const hash = new URL(url).hash.slice(1); // removes leading #
  const parts = hash.split(':');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error('Invalid paste URL format – expected #id:key');
  }
  const [id, key] = parts;
  return { id, key };
}

test.describe('Paste E2E tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('http://localhost:8080');
    await expect(page).toHaveTitle('Paste');
    await expect(page.locator('#output')).toBeVisible();
    await expect(page.locator('#viewer')).toBeHidden();
  });

  test('1. front page loads correctly', async ({ page }) => {
    await expect(page.locator('#output')).toHaveAttribute('placeholder', 'Paste your text here...');
    await expect(page.locator('#actionBtn')).toHaveText('Create Paste');
    await expect(page.locator('#toggleBtn')).toHaveText('View');
    await expect(page.locator('#newBtn')).toHaveText('New');
    await expect(page.locator('#copyBtn')).toHaveText('Copy');
  });

  test('2. creation of paste succeeds (happy path)', async ({ page }) => {
    const content = `Happy path test content ${crypto.randomUUID()}\nLine 2\nLine 3 with code: console.log("hello");`;

    const pasteUrl = await createPaste(page, content);

    await expect(page.locator('#code')).toHaveText(content);
    await expect(page.locator('.hljs')).toBeVisible();

    await page.goto(pasteUrl);
    await expect(page.locator('#viewer')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('#code')).toHaveText(content);
  });

  test('3. opening url with completely incorrect id and key gives error', async ({ page }) => {
    await page.goto('http://localhost:8080/#nonexistent:deadbeefwrongkey1234567890');

    const statusText = await getStatusText(page);
    expect(statusText).toMatch(/Invalid URL format|Paste not found|Decryption failed/);

    await expect(page.locator('#output')).toBeVisible();
    await expect(page.locator('#viewer')).toBeHidden();
  });

  test('4. opening url with correct id but wrong (real) key gives decryption error', async ({ page }) => {
    const content1 = `First paste content ${crypto.randomUUID()}`;
    const url1 = await createPaste(page, content1);
    const { id: id1, key: key1 } = parsePasteUrl(url1);

    await page.locator('#newBtn').click();
    await expect(page.locator('#output')).toHaveValue('');

    const content2 = `Second paste content ${crypto.randomUUID()}`;
    const url2 = await createPaste(page, content2);
    const { id: id2, key: key2 } = parsePasteUrl(url2);

    await page.locator('#newBtn').click();
    await expect(page.locator('#output')).toHaveValue('');

    const wrongUrl1 = `http://localhost:8080/#${id1}:${key2}`;
    await page.goto(wrongUrl1);

    const statusText1 = await getStatusText(page);
    expect(statusText1).toMatch(/Decryption failed. Wrong or invalid key./);

    await expect(page.locator('#output')).toBeVisible();
    await expect(page.locator('#viewer')).toBeHidden();
    await expect(page.locator('#output')).toHaveValue('');

    await page.locator('#newBtn').click();

    const wrongUrl2 = `http://localhost:8080/#${id2}:${key1}`;
    await page.goto(wrongUrl2);

    const statusText2 = await getStatusText(page);
    expect(statusText2).toMatch(/Decryption failed. Wrong or invalid key./);

    await expect(page.locator('#output')).toBeVisible();
    await expect(page.locator('#viewer')).toBeHidden();
    await expect(page.locator('#output')).toHaveValue('');
  });

  test('5. syntax highlighting works on reload', async ({ page }) => {
    const jsCode = `function hello() {\n  console.log("world");\n}`;
    await createPaste(page, jsCode);

    await page.reload();
    await expect(page.locator('#viewer')).toBeVisible({ timeout: 10000 });

    await expect(page.locator('#code .hljs-keyword')).toContainText('function');
  });

  test('6. large paste creation and view (reasonable size)', async ({ page }) => {
    // ~500 lines, each ~100 chars → total ~50KB (well under limit, but still "large" enough to test multi-line rendering/highlighting)
    const line = `// Line with some realistic code-like content: const x = ${crypto.randomUUID()}; console.log(x);\n`;
    const largeContent = line.repeat(500);

    await typePasteContent(page, largeContent);
    await page.locator('#actionBtn').click();

    // Wait for view mode (success)
    await expect(page.locator('#viewer')).toBeVisible({ timeout: 15000 });

    // Verify highlighting applied and multi-line content renders
    await expect(page.locator('.hljs')).toBeVisible();
    await expect(page.locator('#code')).toContainText('// Line with some realistic code-like content');
    await expect(page.locator('#code')).toContainText('console.log');

    // Button reset confirms success path
    await expect(page.locator('#actionBtn')).toHaveText('Create Paste');
  });
});