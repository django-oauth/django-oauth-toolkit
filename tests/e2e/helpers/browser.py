"""
Small Playwright helpers for the browser layer.

Kept free of a top-level ``playwright`` import so it can be imported from the
browser package without breaking protocol-only environments; the Playwright
error type surfaces as an ordinary exception that ``click_until`` catches.
"""


def click_until(locator, check, attempts=20):
    """Click ``locator`` repeatedly until ``check()`` succeeds.

    SvelteKit hydrates asynchronously, so an early click can land before the
    handler is attached and simply be dropped. Rather than sleeping a fixed
    amount and hoping hydration finished, re-click until an observable condition
    holds. ``check`` must block briefly and raise until the expected state is
    reached (e.g. ``lambda: page.wait_for_url(..., timeout=1000)``); its own
    timeout paces the retries, so there is no fixed delay.
    """
    locator.wait_for(state="visible")
    last_exc = None
    for _ in range(attempts):
        locator.click()
        try:
            check()
            return
        except Exception as exc:  # Playwright TimeoutError (or the check's own AssertionError)
            last_exc = exc
    raise AssertionError(f"condition not met after {attempts} clicks") from last_exc
