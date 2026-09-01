<!-- Thanks for contributing to Kunji. Please keep PRs to one logical change. -->

## What and why

<!-- What does this change, and what problem does it solve? Link the issue. -->

Closes #

## Checklist

- [ ] `npm run verify` passes locally (tests + build + `npm run check`)
- [ ] Tests added/updated for the behaviour change
- [ ] No network calls, dependencies, external resources, or CSP changes
      (or: the CSP change *is* the point of this PR and is discussed in an issue)
- [ ] Does **not** alter any `v1` password (`tests/vectors/v1.json` unchanged);
      new KDF/charset/shaping is a new profile instead
- [ ] Docs updated if user-facing (`docs/USAGE.md`) or structural
      (`docs/ARCHITECTURE.md` / `docs/BUILD.md`)
- [ ] `CHANGELOG.md` updated under **Unreleased**

## Notes for the reviewer

<!-- Anything non-obvious: trade-offs, alternatives considered, follow-ups. -->
