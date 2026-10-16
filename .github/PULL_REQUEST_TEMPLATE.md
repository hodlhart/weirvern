## What changed, and why

<!-- One paragraph. What does the tree do differently after this, and why does that matter? -->

## Evidence

<!-- The exact commands run and their output -- not adjectives. Claims need proof. -->

```console
$ <command>
<output>
```

## The house rules

- [ ] `sh scripts/gate.sh` passes, in full (a partial run is not a run)
- [ ] The identifier sanitizer is clean: `python -m weirvern.tools.sanitize_identifiers --check`
- [ ] New behaviour is pinned by a test that goes RED without the change (say how you checked)
- [ ] No real addresses, hostnames, domains or credentials anywhere -- code, comments,
      commit messages, or this description

Fixes #
