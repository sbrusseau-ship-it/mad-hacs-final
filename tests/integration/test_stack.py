"""Run inside Docker against the built frontend, proxy, API and Chromium scanner."""
import asyncio
import time
import requests
from playwright.sync_api import sync_playwright

BASE = 'http://frontend'


def submit(identifiers):
    response = requests.post(f'{BASE}/api/search', json={'identifiers': identifiers}, timeout=10)
    assert response.status_code == 202, response.text
    job = response.json()
    assert job['id'] and job['status'] in ('queued', 'running')
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        response = requests.get(f"{BASE}/api/search/{job['id']}", timeout=10)
        assert response.status_code == 200, response.text
        job = response.json()
        if job['status'] in ('completed', 'failed'):
            assert job['status'] == 'completed', job
            return job['result']
        time.sleep(.2)
    raise AssertionError(f'Job did not finish: {job}')


for _ in range(60):
    try:
        if requests.get(f'{BASE}/api/health', timeout=2).ok:
            break
    except requests.RequestException:
        pass
    time.sleep(1)
else:
    raise AssertionError('Stack never became healthy')

assert requests.get(BASE, timeout=10).status_code == 200
assert requests.get(f'{BASE}/openapi.json', timeout=10).status_code == 200
for payload in ({}, {'identifiers': {}}, {'identifiers': {'email': 'invalid'}},
                {'identifiers': {'ip': '999.0.0.1'}}, {'identifiers': {'unknown': 'value'}}):
    response = requests.post(f'{BASE}/api/search', json=payload, timeout=10)
    assert 400 <= response.status_code < 500, (payload, response.text)
    assert isinstance(response.json()['error'], str), response.text
response = requests.post(f'{BASE}/api/search', data='{broken', headers={'Content-Type': 'application/json'}, timeout=10)
assert 400 <= response.status_code < 500 and isinstance(response.json()['error'], str)
assert requests.get(f'{BASE}/api/search/missing', timeout=10).status_code == 404

identifiers = {'email': 'sample@example.com', 'username': 'sample_user', 'name': 'Sample Person',
               'ssn': '000-00-0000', 'phone': '(202) 555-0142', 'address': '123 Example Street', 'ip': '2001:db8::1'}
result = submit(identifiers)
assert result['summary']['total_queries'] == 7, result
assert result['summary']['total_tools_searched'] == 21, result
assert result['summary']['results_by_status'] == {'success': 7, 'no_match': 7, 'blocked': 7, 'error': 0, 'manual_review': 0}, result
assert len(result['matches']) == 7
assert {row['input_type'] for row in result['results']} >= {'email', 'ssn', 'ip_address'}
print('PASS API: validation, malformed JSON, missing jobs, all 7 identifiers, match/no-match/blocked results', flush=True)

async def check_echo_page():
    from SecurityApp import Backend as scanner
    from playwright.async_api import async_playwright
    async with async_playwright() as p:
        browser = await p.chromium.launch(args=['--no-sandbox'])
        page = await browser.new_page()
        tool = scanner.Tool('Query echo', 'http://fixtures:9000/search/echo', 'Username', 'Username')
        result = await scanner.analyze_page(page, tool, 'sample_user', scanner.InputType.USERNAME)
        assert result.status == 'no_match' and result.match_count == 0, result
        await browser.close()
    print('PASS scanner: title/HTML/form/navigation/hidden echoes do not count as matches', flush=True)

asyncio.run(check_echo_page())

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=['--no-sandbox'])
    page = browser.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(BASE)
    page.get_by_placeholder('name@example.com', exact=True).fill('sample@example.com')
    with page.expect_response(lambda r: r.url.endswith('/api/search') and r.request.method == 'POST') as response_info:
        page.get_by_role('button', name='RUN EXPOSURE CHECK').click()
    assert response_info.value.status == 202
    page.get_by_role('heading', name='Search results', exact=True).wait_for(timeout=45000)
    assert page.locator('summary').filter(has_text='Fixture match').count() >= 1
    assert page.locator('summary').filter(has_text='Fixture empty').count() >= 1
    assert page.locator('summary').filter(has_text='Fixture blocked').count() >= 1
    page.get_by_placeholder('name@example.com', exact=True).fill('bad-email')
    page.get_by_role('button', name='RUN EXPOSURE CHECK').click()
    page.get_by_role('alert').first.wait_for()
    page.get_by_placeholder('name@example.com', exact=True).fill('sample@example.com')
    page.route('**/api/search', lambda route: route.fulfill(status=503, content_type='application/json', body='{"error":"Scanner unavailable for test"}'))
    page.get_by_role('button', name='RUN EXPOSURE CHECK').click()
    page.get_by_text('Scanner unavailable for test', exact=False).wait_for(timeout=10000)
    assert not errors, errors
    browser.close()
print('PASS browser: form → proxy → async API → real scanner → rendered results; validation and server-error display', flush=True)
