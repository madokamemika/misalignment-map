# Misalignment map

A written corpus of cases where an AI system did something nobody asked it to,
and of the links between them. It is the data behind the map at
[goveronica.com/misalignment-map.html](https://goveronica.com/misalignment-map.html),
kept in its own repository so it can be read, forked and cited on its own.

## What is in it

`data/misalignment-incidents.json` is the corpus. Four things live in it:

- **episodes** — one dated event each, with what happened, the models involved,
  what was reached, and its sources. Episodes are written by Claude from those
  sources, one at a time, and edited by Veronica; nothing enters the corpus
  from a keyword match.
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

`scripts/fetch-misalignment-feed.py` reads four keyless public sources:

- the [AI Incident Database](https://incidentdatabase.ai/)'s page data,
- the MIT AI Risk Repository classifications carried inside AIID's weekly
  snapshot, which is also what the
  [MIT AI Incident Tracker](https://airisk.mit.edu/ai-incident-tracker) runs on,
- the [OECD AI Incidents Monitor](https://oecd.ai/en/incidents),
- the [AIAAIC Repository](https://www.aiaaic.org/aiaaic-repository), whose
  index is links and nothing else, so the slug is all there is to filter on
  before paying for a page fetch.

It scores entries against a misalignment vocabulary, drops anything already on
the map, and writes the rest to the queue.

The window is three months by default, not two years. The job runs weekly, so
that is everything new with a wide margin for a database that back-dates its
entries; `SWEEP_MONTHS=24` widens it for a one-off backfill. The wide window
was harmless only while the OECD stage could not see past its own last week —
once that was fixed, two years of press about episodes already on the map
arrived every Thursday and buried the few entries worth reading.

The OECD monitor is read in week-wide slices, and that is not a detail. It
serves at most 100 cards per response and offers no offset, page or cursor
parameter; `num_results` above 100 returns an empty page, and the
`autonomy_levels` filter in its query string is applied in the browser rather
than on the server, so it changes nothing a script can see. Ordered by date,
100 cards covered seven days when this was written — which means a single
request over a two-year window reports on its last week and says nothing about
that. Reading the last year in slices returns 5,184 entries where one request
returns 100. A slice that comes back full is halved and re-read, so a busy week
cannot hide entries behind the cap.

The hard part is not finding incidents, it is telling two sentences apart:
*an agent exfiltrated a database* and *an attacker used an agent to exfiltrate
a database* share almost every word. Misuse terms therefore score −4, hard
enough to sink an entry on their own, and evaluation-context terms score +2,
because an attacker's write-up never mentions the evaluation the model was
inside. Measured against the eighteen AI Incident Database records that are
already episodes on the map, the filter now recalls sixteen; the four
human-misuse entries that had been sitting in the queue score −2 to −17 and
are gone.

The two it still misses are worth naming, because they are the shape of what
this instrument cannot see: an agent that cancelled a stranger's gym booking,
and an internal assistant that posted bad advice to a company forum. Neither
write-up contains a destructive verb or an evaluation, so no keyword net will
raise them. They reached the map because the database was read record by
record, which is the one thing a keyword net cannot do. `.github/workflows/` runs it on
Thursdays. Run it yourself with:

```sh
python3 scripts/fetch-misalignment-feed.py
```

`AIID_SNAPSHOT_FILE=<path to a downloaded snapshot>` skips the 110 MB download
when working offline.

## What the other registers hold

Checked by hand, and worth writing down so the next sweep does not repeat it:

- **[AIAAIC](https://www.aiaaic.org/aiaaic-repository)** — 2,155 entries, and
  the only register besides AIID that carries cases this corpus wants. It is
  the one place that had the ByteDance agentic phone and the WSJ vending
  machine. Its coverage of the lab incidents is thinner than this corpus: where
  it has one entry for an Anthropic evaluation reaching a real company, the map
  has the four separate runs and the disclosure that followed.
- **[AVID](https://avidml.org/database/)** — 1,745 records, of which 1,079 are
  CVEs in AI software and most of the rest are benchmark runs. Path traversal
  in an agent framework is not a model doing something nobody asked for. Not a
  source for this corpus.
- **[FelonyBench](https://www.felonybench.com/)** and the
  [Loss of Control Observatory](https://www.longtermresilience.org/reports/the-loss-of-control-observatory-a-prototype-to-detect-real-world-ai-control-incidents/)
  answer a browser and refuse a script — a Vercel checkpoint and a 202
  respectively, and the browser's TLS handshake is dropped too. Their counts in
  `trackers` carry the date they were read; they cannot be refreshed by the
  weekly job.
- **The MIT taxonomy is the wrong lens, twice over.** Three of AIID's 1,671
  incidents sit under subdomain 7.1, *AI pursuing its own goals*, and the
  newest is from 2016. The neighbouring cut — entity `AI`, intent
  `Intentional`, 271 records — looks promising and is not: read through, it is
  deepfakes and investment scams, where the intent being classified is the
  person's.

## Corrections

Corrections are the point. Open an issue or a pull request against
`data/misalignment-incidents.json` — a wrong date, a source that does not say
what the episode claims, an episode that is really two, or two that are really
one. Every source URL in the corpus has been fetched at least once; if one has
rotted, say so.

## Licence and attribution

Incident records and MIT taxonomy classifications drawn from the AI Incident
Database are © their contributors under CC BY-SA; entries sourced from the
OECD AI Incidents Monitor are credited on each episode. The writing here — the episode
text, the links between episodes, the mechanism definitions — was done by
Claude for this project and edited by [Veronica](https://goveronica.com), who
owns it. Reuse it with attribution.
