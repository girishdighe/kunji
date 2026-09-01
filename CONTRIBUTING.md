# Contributing to Kunji

Thanks for looking. Bug reports, doc fixes, test additions, and well-scoped
features are all welcome. Kunji has a few hard rules, though — read these first
so a PR doesn't hit a wall in review.

## The hard rules

A change **cannot** land if it:

1. **Adds a network capability.** No `fetch`, `XMLHttpRequest`, `WebSocket`,
   `sendBeacon`; no `<script src>`, `<link>`, `@import`, or any `http(s)://` in
   `src/`. `npm run check` enforces this and will fail your PR. (The only
   exception is `dist/pwa/sw.js` serving the local app shell.)
2. **Adds a dependency or a build tool.** The build is file concatenation by
   `tools/build.mjs`. No npm packages, no bundler, no transpiler.
3. **Makes `kunji.html` not self-contained.** No external fonts, images, or
   assets. Inline everything (see the wordmark: it's inline SVG, not a webfont).
4. **Changes a `v1` password.** `tests/vectors/v1.json` is frozen. A different
   KDF, iteration count, charset, or shaping is a **new profile** (`v2`), added
   as an object in `PROFILES` in `src/derive.js`, opt-in per entry. Never edit
   `v1` in place.
5. **Loosens the CSP** without that being the explicit, discussed point of the
   change.
6. **Persists a secret** anywhere (`localStorage`, cookies, IndexedDB, a file
   written without the user asking).

If your idea needs one of these, open an issue and let's talk about the design
before you write code.

## Workflow

1. **Open an issue** for anything beyond a typo or an obvious bug fix. Describe
   the problem and the proposed approach. For features, we write a short design
   doc in `docs/specs/` first (see the existing ones for the shape) and an
   implementation plan in `docs/plans/`.
2. **Branch** off `main`.
3. **Write it**, with tests.
4. **`npm run verify` must pass** — that's `npm test` + build +
   `npm run check`, in order. CI runs the same plus a determinism check and a
   clean-tree check.
5. **Open a PR** against `main`. Fill in the template. Link the issue.

## Tests

- Every behaviour change needs a test in the matching `tests/*.test.mjs`.
- Anything touching `derive.js` or `webcrypto.js` needs **known-answer tests**:
  compare against a published RFC vector or `node:crypto`, not against "what the
  code currently does".
- A new profile needs its own frozen vector file, like `tests/vectors/v1.json`.
- Run a single suite while iterating: `node --test tests/derive.test.mjs`.

## Code style

- Plain modern JavaScript. `src/` files are ES modules (real `import`/`export`)
  so editors and `node:test` understand them; `tools/build.mjs` strips the
  keywords for the shipped single script. Don't rely on bundler features.
- No framework. Each UI module owns its DOM subtree and its own small state.
- Keep secrets in local variables / typed arrays with a short lifetime. Clear
  input fields after use (see `app.js` clearing the passphrase on generate).
- Match the surrounding style: 2-space indent, semicolons, `const`/`let`,
  early returns. The existing files are the reference.
- New module? Add it to `JS_ORDER` in `tools/build.mjs` at the right point in the
  dependency order, and keep the ordering assertions in `tests/build.test.mjs`
  true.

## Commits and PRs

- Present-tense summary line, in the imperative: "Add v2 profile scaffold", not
  "Added…". Explain *why* in the body if it isn't obvious.
- One logical change per PR. Rebase rather than merge `main` in.
- It's fine to co-author; keep trailers if you use them.

## Reporting security issues

**Do not** open a public issue for anything exploitable. See
[SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the
[MIT License](LICENSE), the same as the rest of the project.
