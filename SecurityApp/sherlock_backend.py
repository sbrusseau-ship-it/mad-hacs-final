"""Run real Sherlock username checks in a cancellable worker process.

The worker emits only JSON lines. Usernames are passed over stdin, never through
shell commands or process arguments. The parent publishes per-site results to
our existing SSE/polling contract.
"""
import asyncio
from dataclasses import asdict
import json
import os
import sys

from .Backend import ToolResult


EXCLUDED_SITES = frozenset({"7cups", "f3.cool", "houzz"})


async def run_sherlock(username, on_plan, on_result):
    process = await asyncio.create_subprocess_exec(
        sys.executable, '-m', 'SecurityApp.sherlock_backend', '--worker',
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        process.stdin.write(json.dumps({'username': username}).encode() + b'\n')
        await process.stdin.drain()
        process.stdin.close()
        timeout = float(os.environ.get('SHERLOCK_REQUEST_TIMEOUT', '10'))
        while True:
            line = await asyncio.wait_for(process.stdout.readline(), timeout=max(45, timeout * 4 + 5))
            if not line:
                break
            event = json.loads(line)
            if event['type'] == 'plan':
                on_plan(event['total'])
            elif event['type'] == 'result':
                on_result(ToolResult(**event['result']))
            elif event['type'] == 'error':
                raise RuntimeError('Sherlock could not complete its search.')
        if await process.wait() != 0:
            raise RuntimeError('Sherlock worker exited unexpectedly.')
    finally:
        if process.returncode is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()


def worker():
    # Imports are isolated here so normal API startup stays light.
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from contextlib import redirect_stdout
    from copy import deepcopy
    from importlib.resources import files
    import threading

    from sherlock_project.notify import QueryNotify
    from sherlock_project.result import QueryStatus
    from sherlock_project.sherlock import sherlock
    from sherlock_project.sites import SitesInformation

    output = sys.stdout
    lock = threading.Lock()

    def emit(event):
        with lock:
            output.write(json.dumps(event) + '\n')
            output.flush()

    try:
        config = json.loads(sys.stdin.readline())
        username = config['username']
        concurrency = int(os.environ.get('SHERLOCK_CONCURRENCY', '8'))
        timeout = float(os.environ.get('SHERLOCK_REQUEST_TIMEOUT', '10'))
        if not 1 <= concurrency <= 20 or timeout <= 0:
            raise ValueError('Invalid Sherlock concurrency or timeout')

        # Sherlock may print upstream warnings; keep them off the JSON protocol.
        with redirect_stdout(sys.stderr):
            catalog = os.environ.get('SHERLOCK_SITES_FILE') or os.environ.get('SHERLOCK_SITES_URL')
            if catalog:
                sites = SitesInformation(catalog, honor_exclusions=False)
            else:
                try:
                    sites = SitesInformation()
                except (OSError, ValueError):
                    sites = SitesInformation(str(files('sherlock_project').joinpath('resources/data.json')))
            sites.remove_nsfw_sites()
            selected = [site for site in sites if site.name.strip().casefold() not in EXCLUDED_SITES]
            emit({'type': 'plan', 'total': len(selected)})

            def inspect(site):
                reported = False

                class Notify(QueryNotify):
                    def update(self, result):
                        nonlocal reported
                        if reported:
                            return
                        status = {
                            QueryStatus.CLAIMED: 'success',
                            QueryStatus.AVAILABLE: 'no_match',
                            QueryStatus.WAF: 'blocked',
                            QueryStatus.UNKNOWN: 'error',
                            QueryStatus.ILLEGAL: 'error',
                        }[result.status]
                        details = [f'Sherlock verdict: {result.status.value}.']
                        if status == 'success':
                            details.append('Username reported present; account ownership is unverified.')
                        error = None
                        if result.status == QueryStatus.ILLEGAL:
                            error = 'Username format is not supported by this site.'
                        elif status == 'blocked':
                            error = 'Site blocked the Sherlock request.'
                        elif status == 'error':
                            error = 'Sherlock could not determine username availability.'
                        row = ToolResult(
                            input_value=username, input_type='username',
                            tool_name=f'Sherlock · {site.name}', category='Username',
                            url_searched=result.site_url_user, status=status,
                            match_count=int(status == 'success'), match_details=details,
                            error=error, source_url=site.url_home, backend='sherlock',
                        )
                        emit({'type': 'result', 'result': asdict(row)})
                        reported = True

                try:
                    # One site per call avoids Sherlock's ordered result loop
                    # delaying a fast site behind a slow one. The outer pool caps
                    # actual outstanding requests across all sites.
                    sherlock(username, {site.name: deepcopy(site.information)}, Notify(), timeout=timeout)
                except Exception:
                    if reported:
                        return
                    emit({'type': 'result', 'result': asdict(ToolResult(
                        username, 'username', f'Sherlock · {site.name}', 'Username',
                        site.url_username_format.replace('{}', username), 'error',
                        error='Sherlock could not inspect this site.',
                        source_url=site.url_home, backend='sherlock',
                    ))})

            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                for future in as_completed([pool.submit(inspect, site) for site in selected]):
                    future.result()
    except Exception:
        emit({'type': 'error'})
        raise SystemExit(1)


if __name__ == '__main__':
    worker()
