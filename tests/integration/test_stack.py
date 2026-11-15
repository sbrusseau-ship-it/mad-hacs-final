"""Run inside Docker against the built frontend, proxy, API and Chromium scanner."""
import asyncio
import json
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
assert result['summary']['total_tools_searched'] == 31, result
assert result['summary']['results_by_status'] == {'success': 8, 'no_match': 15, 'blocked': 8, 'error': 0, 'manual_review': 0}, result
assert result['grade'] == {'percent_matches': 25.81, 'total_sites': 31, 'sites_with_hits': 8, 'total_matches': 8}, result['grade']
assert len(result['matches']) == 8
assert {r['status'] for r in result['results'] if r['backend'] == 'sherlock'} == {'success', 'no_match', 'blocked'}
assert not any('Repository-only' in r['tool_name'] for r in result['results'])
assert not any(r['tool_name'].casefold() in {'sherlock · 7cups', 'sherlock · f3.cool', 'sherlock · houzz'} for r in result['results'])
assert {row['input_type'] for row in result['results']} >= {'email', 'ssn', 'ip_address'}
print('PASS API: validation, malformed JSON, missing jobs, all 7 identifiers, match/no-match/blocked results', flush=True)

started = time.monotonic()
job = requests.post(f'{BASE}/api/search', json={'identifiers': {'username': 'stream_sample'}}, timeout=10).json()
first_partial = None
with requests.get(f"{BASE}/api/search/{job['id']}/events", stream=True, timeout=(5, 20)) as response:
    assert response.status_code == 200 and response.headers['Content-Type'].startswith('text/event-stream')
    for line in response.iter_lines(chunk_size=1):
        if not line.startswith(b'data: '):
            continue
        snapshot = json.loads(line[6:])
        count = snapshot.get('progress', {}).get('completed_sources', 0) if snapshot.get('progress') else 0
        total = snapshot.get('progress', {}).get('total_sources', 0) if snapshot.get('progress') else 0
        if snapshot['status'] == 'running' and 0 < count < total and first_partial is None:
            first_partial = time.monotonic() - started
        if snapshot['status'] in ('completed', 'failed'):
            assert snapshot['status'] == 'completed', snapshot
            assert snapshot['progress'] == {'completed_sources': 7, 'total_sources': 7}, snapshot
            break
    else:
        raise AssertionError('Stream closed before terminal event')
finished = time.monotonic() - started
assert first_partial is not None and finished - first_partial >= 4, (first_partial, finished)
print(f'PASS SSE through Nginx: first partial result {first_partial:.2f}s; full scan {finished:.2f}s', flush=True)

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

async def check_sherlock_cancellation():
    import os
    from unittest.mock import patch
    from SecurityApp import sherlock_backend
    original_spawn = asyncio.create_subprocess_exec
    processes = []
    ready = asyncio.Event()

    async def spawn(*args, **kwargs):
        process = await original_spawn(*args, **kwargs)
        processes.append(process)
        return process

    with patch.dict(os.environ, {'SHERLOCK_SITES_URL': 'http://fixtures:9000/sherlock-slow.json'}), patch.object(asyncio, 'create_subprocess_exec', side_effect=spawn):
        task = asyncio.create_task(sherlock_backend.run_sherlock('sample_user', lambda _: ready.set(), lambda _: None))
        await asyncio.wait_for(ready.wait(), timeout=15)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert processes and processes[0].returncode is not None, 'Sherlock worker was left running'
    print('PASS Sherlock: cancellation terminates and reaps the real worker process', flush=True)

asyncio.run(check_sherlock_cancellation())

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=['--no-sandbox'])
    page = browser.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(BASE)
    toggles = page.locator('form button[type="button"]')
    assert toggles.first.get_attribute('aria-pressed') == 'true'
    assert 'USERNAME' in toggles.first.inner_text()
    assert page.locator('form button[aria-pressed="true"]').count() == 1
    assert page.get_by_placeholder('name@example.com').count() == 0
    page.get_by_role('button', name='EMAIL ADDRESS').click()
    page.get_by_placeholder('name@example.com', exact=True).fill('sample@example.com')
    with page.expect_response(lambda r: r.url.endswith('/api/search') and r.request.method == 'POST') as response_info:
        page.get_by_role('button', name='RUN EXPOSURE CHECK').click()
    assert response_info.value.status == 202
    page.locator('summary').filter(has_text='Fixture match').first.wait_for(timeout=10000)
    assert page.get_by_role('button', name='SEARCHING PUBLIC SOURCES').is_disabled()
    assert page.get_by_role('progressbar', name='Source search progress').get_attribute('value') != '4'
    page.get_by_role('button', name='RUN EXPOSURE CHECK').wait_for(timeout=45000)
    page.get_by_role('heading', name='Search results', exact=True).wait_for(timeout=45000)
    assert page.locator('summary').filter(has_text='Fixture match').count() >= 1
    stats = page.get_by_role('region', name='Scan statistics')
    assert stats.get_by_text('25%', exact=True).count() == 1
    assert stats.get_by_text('4', exact=True).count() == 1
    assert stats.get_by_text('1', exact=True).count() == 1
    assert page.locator('summary').filter(has_text='Fixture empty').count() >= 1
    assert page.locator('summary').filter(has_text='Fixture blocked').count() >= 1
    # Simulate a proxy that refuses SSE: polling must still deliver partial results.
    page.route('**/events', lambda route: route.fulfill(status=503, body='stream unavailable'))
    page.get_by_placeholder('name@example.com', exact=True).fill('fallback@example.com')
    page.get_by_placeholder('your_handle', exact=True).fill('sample_user')
    with page.expect_response(lambda response: '/api/search/' in response.url and not response.url.endswith('/events')):
        page.get_by_role('button', name='RUN EXPOSURE CHECK').click()
    page.locator('summary').filter(has_text='Fixture match').first.wait_for(timeout=10000)
    assert page.get_by_role('button', name='SEARCHING PUBLIC SOURCES').is_disabled()
    page.get_by_role('button', name='RUN EXPOSURE CHECK').wait_for(timeout=45000)
    assert page.locator('summary').filter(has_text='Sherlock · Fixture Sherlock found').count() == 1
    print('PASS browser: username-first defaults, Sherlock results, and polling fallback', flush=True)
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
