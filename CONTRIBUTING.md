# Contributing

Contributions are welcome, especially test cases based on **synthetic** Okta System Log fixtures, accessibility improvements, event taxonomy, and policy-safe diagnostics.

1. Open an issue describing the proposed feature and the observable troubleshooting problem it solves.
2. Add tests for parsing, filters, failure conditions and exported output before changing behavior.
3. Run `node --test tests/*.test.cjs` and `node --check src/core.js && node --check src/content.js`.
4. Do not commit credentials, internal login identifiers, company configuration, real log exports, or screenshots from production tenants.
5. Document supported events, assumptions, and limitations; distinguish a recorded Okta outcome from a proven root cause.

The project is independent of Okta and Rockstar. Do not represent contributions as official support or upstream acceptance.