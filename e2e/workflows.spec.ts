import { expect, test } from '@playwright/test'
import { mkdirSync, writeFileSync } from 'node:fs'

const SHOTS = '../docs/screenshots'
mkdirSync(SHOTS, { recursive: true })
const API = process.env.API_URL ?? 'http://127.0.0.1:8000'

test.describe.configure({ mode: 'serial' })

test.beforeAll(async ({ request }) => {
  const r = await request.post(`${API}/api/ingestion/reset?confirm=RESET`)
  expect(r.ok()).toBeTruthy()
})

test('Workflow A: ingest, explore, detect, inspect evidence', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByText('No log data yet')).toBeVisible()
  await page.screenshot({ path: `${SHOTS}/00-empty-state.png` })
  await page.getByRole('button', { name: 'Load synthetic sample dataset' }).click()
  await expect(page.getByText('Events ingested (total)')).toBeVisible()
  await page.waitForTimeout(800)
  await page.screenshot({ path: `${SHOTS}/01-overview.png` })

  await page.getByRole('link', { name: 'Log Explorer' }).click()
  await expect(page.locator('tbody tr').first()).toBeVisible()
  await page.getByLabel('Search query').fill('outcome = failure AND src_ip = "203.0.113.45"')
  await page.getByRole('button', { name: 'Search', exact: true }).click()
  await expect(page.getByText('14 results')).toBeVisible()
  await page.locator('tbody tr').first().click()
  await expect(page.getByRole('heading', { name: 'Original event' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Normalized fields' })).toBeVisible()
  await page.screenshot({ path: `${SHOTS}/02-log-explorer.png` })
  await page.keyboard.press('Escape')

  // invalid query gives a useful error
  await page.getByLabel('Search query').fill('(unclosed')
  await page.getByRole('button', { name: 'Search', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('Invalid query')

  await page.getByRole('link', { name: 'Detections' }).click()
  await expect(page.getByText('Successful login from 203.0.113.45 after 14 failures')).toBeVisible()
  await page.getByText('Successful login from 203.0.113.45 after 14 failures').click()
  await expect(page.getByText('Why it triggered')).toBeVisible()
  await expect(page.getByText('Supporting events (15)')).toBeVisible()
  await page.screenshot({ path: `${SHOTS}/03-detection-detail.png` })
})

test('Workflow B: hunt from a finding, collect evidence, create case, persist', async ({ page }) => {
  await page.goto('/detections?rule_id=HF-002')
  await page.locator('tbody tr').first().click()
  await page.getByRole('button', { name: 'Start hunt' }).click()
  await expect(page.getByLabel('Hunt search')).not.toHaveValue('')
  await page.getByLabel('Hypothesis').fill('Attacker guessed the admin password from a single external IP.')
  await page.getByRole('button', { name: 'Save hypothesis' }).click()
  await page.getByLabel('Entry text').fill('Failures stopped immediately after the success.')
  await page.getByRole('button', { name: 'Add entry' }).click()
  await expect(page.getByText('Failures stopped immediately after the success.')).toBeVisible()
  await page.getByLabel('Entry kind').selectOption('alternative')
  await page.getByLabel('Entry text').fill('Admin mistyped while on a new VPN.')
  await page.getByRole('button', { name: 'Add entry' }).click()
  await page.locator('tbody tr').first().click()
  await page.getByRole('button', { name: 'Save to this hunt' }).click()
  await expect(page.getByText('Saved evidence (1)')).toBeVisible()
  await page.keyboard.press('Escape')
  await page.getByRole('button', { name: 'Relationship graph' }).click()
  await expect(page.getByRole('img', { name: 'Entity relationship graph' })).toBeVisible()
  await page.waitForTimeout(800)
  await page.screenshot({ path: `${SHOTS}/04-hunt-workspace.png` })
  await page.getByRole('button', { name: 'Create case from hunt' }).click()
  await expect(page).toHaveURL(/\/cases\/CASE-0001/)
  await page.getByLabel('Case Conclusion').fill('Admin account compromised via credential guessing.')
  await page.getByRole('button', { name: 'Save Conclusion' }).click()
  await page.getByLabel('New note').fill('Contacted account owner; no knowledge of the login.')
  await page.getByRole('button', { name: 'Add note' }).click()
  await expect(page.getByText('Contacted account owner')).toBeVisible()
  await page.reload()
  await expect(page.getByLabel('Case Conclusion')).toHaveValue('Admin account compromised via credential guessing.')
  await expect(page.getByText('Contacted account owner')).toBeVisible()
  await page.screenshot({ path: `${SHOTS}/05-case.png` })
})

test('Workflow C: report reflects the case', async ({ page, request }) => {
  await page.goto('/cases/CASE-0001')
  await page.getByRole('link', { name: 'Generate report' }).click()
  await expect(page.getByTitle('Report preview')).toBeVisible()
  await page.waitForTimeout(800)
  await page.screenshot({ path: `${SHOTS}/06-report.png` })
  const md = await (await request.get(`${API}/api/reports/cases/CASE-0001?format=markdown`)).text()
  for (const s of ['Admin account compromised via credential guessing.', 'Contacted account owner', '203.0.113.45', 'Alternative explanation']) {
    expect(md).toContain(s)
  }
  const html = await (await request.get(`${API}/api/reports/cases/CASE-0001?format=html`)).text()
  expect(html).toContain('Admin account compromised')
})

test('Workflow D: malformed upload is rejected and data is intact', async ({ page, request }) => {
  const before = (await (await request.get(`${API}/api/events?page_size=1`)).json()).total
  await page.goto('/data')
  writeFileSync('bad.jsonl', '{not valid json}\n<<<garbage>>>\n')
  await page.setInputFiles('#up', 'bad.jsonl')
  await expect(page.getByRole('alert')).toContainText('Upload rejected')
  await expect(page.getByRole('alert')).toContainText('Existing data was not modified')
  const after = (await (await request.get(`${API}/api/events?page_size=1`)).json()).total
  expect(after).toBe(before)
})

test('Rules, entities, global search', async ({ page }) => {
  await page.goto('/rules')
  await page.getByText('Repeated failed logins from one source').click()
  await page.getByRole('button', { name: 'Run sample test' }).click()
  await expect(page.getByText('✓ Detects 203.0.113.45')).toBeVisible()
  await page.screenshot({ path: `${SHOTS}/07-rules.png` })
  await page.getByLabel('Global search').fill('203.0.113.45')
  await page.getByRole('button', { name: 'Open IP entity 203.0.113.45' }).click()
  await expect(page.getByText('External intelligence')).toBeVisible()
  await expect(page.getByText('does not indicate this entity is safe')).toBeVisible()
  await page.screenshot({ path: `${SHOTS}/08-entity.png` })
})
