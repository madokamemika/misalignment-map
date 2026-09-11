# Misalignment map

A hand-written corpus of cases where an AI system did something nobody asked it to,
and of the links between them. It is the data behind the map at
[goveronica.com/misalignment-map.html](https://goveronica.com/misalignment-map.html),
kept in its own repository so it can be read, forked and cited on its own.

## What is in it

`data/misalignment-incidents.json` is the corpus. Four things live in it:

- **episodes** — one dated event each, with what happened, the models involved,
  what was reached, and its sources. An episode is written by hand from those
  sources; nothing enters it automatically.
- **links** — typed edges between episodes: `same-campaign`, `disclosure-of`,
  `investigation-of`, `response-to`, `precedent-for`, `parallel`. Most of what
  gets reported as a separate incident is one campaign continuing, and these
  are where that is recorded.
- **chains** — the campaigns and groups the episodes belong to.
- **mechanisms** — the failure each episode is an instance of, with the papers
  that named it: misspecification, reward hacking, instrumental convergence,
  goal misgeneralization, deception, evaluation awareness, persona vectors.

Two fields carry the map's distinctions. `context: "evaluation"` marks real
damage done inside a test — an evaluation, a red-team exercise or a training
run that was never supposed to touch anything outside itself, which is where
most of the production systems on this map were reached from. `evidence` marks
an episode resting on something weaker than a company disclosure or a database
record, and says what.

`data/misalignment-feed.json` is not the corpus. It is a weekly sweep of the
public incident databases for candidates, and every entry in it is a keyword
match awaiting a human reading.

## The weekly sweep

`scripts/fetch-misalignment-feed.py` reads three keyless public sources:

- the [AI Incident Database](https://incidentdatabase.ai/)'s page data,
- the MIT AI Risk Repository classifications carried inside AIID's weekly
  snapshot, which is also what the
  [MIT AI Incident Tracker](https://airisk.mit.edu/ai-incident-tracker) runs on,
- the [OECD AI Incidents Monitor](https://oecd.ai/en/incidents).

It scores entries against a misalignment vocabulary, drops anything already on
the map, and writes the rest to the queue. `.github/workflows/` runs it on
Thursdays. Run it yourself with:

```sh
python3 scripts/fetch-misalignment-feed.py
```

`AIID_SNAPSHOT_FILE=<path to a downloaded snapshot>` skips the 110 MB download
when working offline.

## Corrections

Corrections are the point. Open an issue or a pull request against
`data/misalignment-incidents.json` — a wrong date, a source that does not say
what the episode claims, an episode that is really two, or two that are really
one. Every source URL in the corpus has been fetched at least once; if one has
rotted, say so.

## Licence and attribution

Incident records and MIT taxonomy classifications drawn from the AI Incident
Database are © their contributors under CC BY-SA; entries sourced from the
OECD AI Incidents Monitor are credited on each episode. Everything written here
— the episode text, the links, the mechanism definitions — is by
[Veronica](https://goveronica.com) and may be reused with attribution.
