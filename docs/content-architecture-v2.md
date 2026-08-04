# Content architecture V2 pilot

The pilot treats a concept as a canonical semantic object and every page, video,
post, talk, demo or source repository as a projection of that object.

## Projection pipeline

```text
Canonical concept
        |
        +-- audience: Family / Business / Scientist
        +-- explanation: WTF / DUCKS / TECH / Psi
        +-- depth: Summary / Deeper / Full evidence
        +-- channel: Web / Video / Audio / Social / Talk / Demo / Source
        |
        `-- rendered output
```

The source meaning exists once. A renderer selects what to expose for a
particular audience and channel without creating a second canonical copy.

## Pilot structure

| Path | Role |
|---|---|
| `content/schema/concept-v2.schema.json` | Semantic contract for canonical concepts |
| `wwwroot/wavefunctionlabs.com/data/concepts/` | Public, versioned concept objects |
| `wwwroot/wavefunctionlabs.com/_pages/v2/` | Architecture overview |
| `wwwroot/wavefunctionlabs.com/_pages/v2/concepts/` | Interactive web projections |
| `scripts/validate-content-v2.mjs` | Dependency-free structural validation |

The first concept is `engineering-is-only-half-the-job`. It contains the
observation, problem, principle, interpretation, evidence, perspectives,
experiments, trade-offs, guidance, open questions and relationships, plus
audience and explanation-mode projections.

## Platform boundaries

- `willeastbury.com` is the eventual canonical conceptual and leadership home.
- WaveFunctionLabs runs experiments, evidence and rendering capabilities.
- GitHub stores source, schemas, implementation and revision history.
- External channels point back to the canonical concept rather than becoming
  independent sources of truth.

This branch pilots the model on WaveFunctionLabs before any production migration
or split between domains.

## Validation

```sh
npm run validate:content-v2
npm run smoke:playwright
```

The browser smoke test exercises audience, explanation-mode and depth changes
against the same canonical JSON object.
