# Since-reviewed acceptance

All data in these fixtures is invented. Do not start either watcher or point them at a real
`data/` directory for this feature's tests.

The inert-DOM suite runs the actual dashboard script and clicks its real control handlers:

```
node --test tests/test_dashboard_health.js
```

The new cases distinguish timestamp-only or path-only filtering, identity completion,
signing changes, polling noise, startup additions/changes/removals, late events, exposed
listener suppression, storage failure/corruption, and adoption of a rejected render. They
also assert that detail panels and input evidence survive marking. A green source inspection
is not an executed result.

For the required real-browser/BrewShot acceptance, a named build delegate starts an isolated
static server in this checkout under an admitted machine slot, for example:

```
python3 -m http.server 18743 --bind 127.0.0.1
```

Use an otherwise unused port and a fresh browser profile. Open/capture
`http://127.0.0.1:18743/tests/since_reviewed_browser.html` with BrewShot, wait for the result
(up to 20 seconds per frame), and retain the visible result plus
`window.BROWSER_RESULTS`. Expected terminal result is `PASS 5/5` and
`document.documentElement.dataset.testResult === "PASS"`. RUNNING, missing output, timeout,
script errors, FAIL or a different denominator are failures, not passes. The five cases are
mark/filter/details, same-path identity change, startup change, retained/new exposed
listeners, and storage denial in a sandboxed frame. The page instruments only startup data
loading and adds fixture assertions to the real dashboard script; it does not test the
watcher's data publication, and it does not call the real watcher or database. The static
server and browser must be stopped afterward.

Before accepting this gate, prove its discriminator: in the owned browser-test checkout,
temporarily insert `if (sinceReviewed && review) f = { ...f, exposed: [] };` at the start of
`renderAttention`. The browser's exposed-listener case must fail. Restore the exact
published source and show `PASS 5/5` again. Also run the inert-DOM suite against a
pre-feature dashboard to show the new real-control cases fail; missing controls are an
expected instrument failure for that baseline, not a semantic-red runtime result.

The producer parity gate remains required because both Python and Java deliver this shared
page. Run the repository's documented synthetic parity gate and record actual results;
source equality is not execution. No database schema or producer projection changed here.
All runtime work is Fixpoint's or an explicitly named delegate's, never implied by this
source-only handoff. Record actual JDK, browser, BrewShot, commands, exits and raw outputs.
