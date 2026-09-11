#!/usr/bin/env python3
"""Collect candidate misalignment incidents into data/misalignment-feed.json.

Three keyless public sources:

- **AI Incident Database** — the Gatsby page data behind /apps/incidents/
  (https://incidentdatabase.ai/page-data/apps/incidents/page-data.json), one
  JSON array of every numbered incident with title, description and date.
- **AIID's MIT taxonomy classifications** — `classifications_MIT.csv` inside
  the weekly database snapshot, which is where an incident id is joined to
  the MIT AI Risk Repository's risk domain and subdomain, to whether the
  entity was the AI or a human, and to whether the act was intentional. This
  is the classification behind the MIT AI Risk Initiative's AI Incident
  Tracker (https://airisk.mit.edu/ai-incident-tracker).
- **OECD AI Incidents Monitor** — the server-rendered search page, one
  `card--incident` block per entry.
- **AIAAIC** — the AI, Algorithmic and Automation Incidents and Controversies
  repository, a Google Sites index of every entry as a link. It is the only
  register besides AIID that carries cases this corpus wants, and it is the
  one place several of them appeared first.

AIID's incidents and classifications are licensed CC BY-SA, so the file this
writes carries the same licence and the attribution with it.

Both are filtered against VOCAB: an entry is kept when it scores at least
MIN_SCORE, counting distinct matched terms: AGENTIC terms weigh double
because "AI incident" alone is mostly bias, defamation and fabricated
citations, not misalignment; ADVOCACY terms weigh -3 because a warning about
agents is written in the same words as an incident involving one; and MISUSE
terms weigh -4 because an attacker wielding an agent is not the subject of
this corpus, however agentic the sentence describing it. Everything kept lands in an inbox the page shows
separately — nothing here enters the graph on the strength of a keyword.

Three things will surprise you:

- **The AIID GraphQL API is closed to scripts.** It answers `Forbidden -
  Invalid origin`, and with an Origin header `Forbidden - Invalid client`.
  The page-data JSON is the way in; a site rebuild is what refreshes it.
- **The MIT classification is precise and very thin.** Three of AIID's ~1,700
  incidents are filed under subdomain 7.1, "AI pursuing its own goals in
  conflict with human goals or values", and the most recent of the three is
  from 2016; classification also runs well behind new incidents. So it is an
  enrichment and a rescue clause — a 7.1 is kept whatever it scores — never
  the filter. The counts go into the file so the page can say this out loud.
- **The OECD page needs its whole query string.** A bare /en/incidents 302s
  to a URL carrying date range, ordering and an empty properties_config, and
  serves nothing without them.
- **AIAAIC publishes no summary in its index.** The repository page is 2,155
  links and nothing else, so the slug is all there is to filter on before
  paying for a page fetch. Slugs are written as sentences — the register's own
  headline, hyphenated — which is enough to sort an agent deleting a drive from
  a deepfake, and AIAAIC_FETCH_MAX caps how many pages one run will open. Its
  dates are months, not days, and go into the queue as written.
- **The OECD monitor serves 100 cards and no second page.** There is no
  offset, page or cursor parameter, and num_results above 100 returns an
  empty page; the autonomy_levels filter in properties_config is applied in
  the browser, not on the server, so it changes nothing a script can see.
  Ordered by date those 100 cards cover about a week, so the window is read
  in slices and a full slice is halved and re-read.
- **A curated episode must not come back as news.** Anything whose URL is
  already cited in data/misalignment-incidents.json is dropped, as is
  anything matching CURATED_MARKERS — the events on the map are reported by
  dozens of outlets, and every one of them would otherwise arrive as new.
  When an inbox entry is written up as an episode, put the entry's own URL in
  that file's `feed_placed` list; the markers are a coarse net and will not
  catch a database's paraphrase of a headline.

The previous file is carried over whenever a run cannot stand on its own, so
a failing source never empties the inbox.

Stdlib only. Run from anywhere:
    python3 scripts/fetch-misalignment-feed.py
"""

import csv
import html
import io
import json
import os
import re
import sys
import tarfile
import urllib.error
import urllib.request
from datetime import date as date_cls, datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(ROOT, "data", "misalignment-feed.json")
CURATED_PATH = os.path.join(ROOT, "data", "misalignment-incidents.json")

AIID_URL = "https://incidentdatabase.ai/page-data/apps/incidents/page-data.json"
AIID_INCIDENT = "https://incidentdatabase.ai/cite/{}/"
AIID_SNAPSHOTS = "https://incidentdatabase.ai/research/snapshots"
SNAPSHOT_RE = re.compile(r"https://[a-z0-9-]+\.r2\.dev/backup-(\d{8})\d*\.tar\.bz2")
MIT_MEMBER = "mongodump_full_snapshot/classifications_MIT.csv"
OWN_GOALS = "7.1"          # MIT subdomain: AI pursuing its own goals
OECD_URL = (
    "https://oecd.ai/en/incidents?search_terms=%5B%5D&and_condition=false"
    "&from_date={frm}&to_date={to}&properties_config=%7B%22principles%22:%5B%5D,"
    "%22industries%22:%5B%5D,%22harm_types%22:%5B%5D,%22harm_levels%22:%5B%5D,"
    "%22harmed_entities%22:%5B%5D,%22business_functions%22:%5B%5D,"
    "%22ai_tasks%22:%5B%5D,%22autonomy_levels%22:%5B%5D,%22languages%22:%5B%5D%7D"
    "&order_by=date&num_results=100"
)
OECD_SITE = "https://oecd.ai"
AIAAIC_INDEX = "https://www.aiaaic.org/aiaaic-repository"
AIAAIC_ENTRY = AIAAIC_INDEX + "/ai-algorithmic-and-automation-incidents/"
# Slugs worth paying a page fetch for. Deliberately generous: this only
# decides what gets read, and the score decides what gets kept.
AIAAIC_SLUG_RE = re.compile(
    r"agent|autonom|rogue|scheme|deceiv|deception|lying|blackmail|sabotage|"
    r"exfiltrat|delet|wipe|bypass|circumvent|guardrail|shutdown|refus|disobey|"
    r"unauthoris|unauthoriz|self-|reward-hack|misalign|sandbox|unintend|"
    r"unprompted|escape|its-own|without-permission|goes-rogue")
AIAAIC_FETCH_MAX = 40
# The monitor caps a response at 100 cards and has no way to ask for the
# next 100, so the window is read in slices this many days wide.
OECD_SLICE_DAYS = 7
OECD_PAGE_MAX = 100
OECD_MAX_DEPTH = 4

UA = "goveronica.com misalignment map (contact: madokamemika@gmail.com)"
TIMEOUT = 90
# The job runs weekly, so the window only has to cover what is new plus a
# generous margin for a database that back-dates its entries. It used to be 24
# months, which was harmless only while the OECD stage could not see past its
# last week anyway; now that the window is actually read, two years of press
# about episodes already on the map arrives every Thursday and buries the few
# entries worth reading. SWEEP_MONTHS=24 restores the wide window for a
# one-off backfill.
MONTHS_BACK = int(os.environ.get("SWEEP_MONTHS", "3"))
MAX_ITEMS = 60
MIN_SCORE = 5

# Weighted double: these are what separates a misalignment case from the rest
# of the incident corpus.
AGENTIC = [
    "misalign", "misaligned", "reward hack", "specification gaming", "scheming",
    "deceptive", "deception", "sabotage", "self-exfiltrat", "exfiltrat",
    "sandbagging", "situational awareness", "power-seeking", "autonomous agent",
    "agentic", "rogue", "out of control", "loss of control", "blackmail",
    "unauthorized access", "unauthorised access", "escaped", "circumvent",
    # An agent wrecking a live system rarely says any of the words above. These
    # are how the databases actually write those incidents up.
    "coding agent", "autonomously", "without human", "despite instructions",
    "ignored instructions", "deleted production", "destroyed production",
    "deleted the production", "code freeze", "fabricated test",
]
# An attacker's write-up does not mention the evaluation the model was inside,
# because there wasn't one. These terms are the cheapest available signal that
# the actor was the model rather than a person holding it, so they weigh as
# much as the agentic vocabulary itself.
EVAL_CONTEXT = [
    "evaluation", "cybersecurity evaluation", "red team", "sandbox",
    "testing environment", "test environment", "during testing",
    "training run", "reinforcement learning", "unsanctioned", "unintended",
    "beyond the sandbox", "exceeded", "of its own", "on its own",
    "not requested", "without being asked", "production infrastructure",
]
SUPPORTING = [
    "ai agent", "agent", "agents", "llm", "language model", "frontier model",
    "alignment", "safety", "guardrail", "oversight", "instructions", "goal",
    "autonomy", "shutdown", "autonomous", "production", "database", "backup",
    "terraform", "compromised",
]
# The distinction the whole corpus rests on, and the one the vocabulary cannot
# make on its own: "an agent exfiltrated a database" and "an attacker used an
# agent to exfiltrate a database" share almost every word. Four of the first
# five entries that survived every other filter were this — a threat actor
# driving agents, a jailbreak, a poisoned package — so misuse is scored hard
# enough to sink an entry on its own.
MISUSE = [
    "threat actor", "attacker", "attackers", "hacker", "hackers", "cybercrim",
    "state-sponsored", "state-linked", "china-linked", "russia-linked",
    "jailbroken", "jailbreak", "weaponize", "weaponise", "malicious package",
    "malicious versions", "supply-chain attack", "supply chain attack",
    "phishing", "extortion", "scam", "fraudster", "deepfake", "impersonat",
    "poisoned", "prompt injection attack", "compromised its ci", "ransomware",
]

# Forecasts, warnings and calls for regulation are written in the same words
# as the incidents they are about, and the monitors carry a lot of them.
ADVOCACY = [
    "warns", "warned", "calls for", "urges", "raises alarm", "could pose",
    "could boost", "report finds", "study finds", "survey", "predicts",
    "forecast", "op-ed", "guidelines", "framework for",
    # A launch is the largest single class the OECD monitor files alongside
    # incidents — it logs the arrival of an autonomous product as a hazard,
    # and the write-up is full of the same words an incident uses. Nothing
    # has happened yet, so none of it belongs in a queue of things that did.
    # Kept deliberately narrow. "raises concerns" and "threatens" read as
    # announcement language and are also how half the incident write-ups end,
    # so they are not here: one pass with them in silently dropped a real case.
    "launches", "launched", "launch of", "unveils", "unveiled", "announces",
    "rolls out", "plans to", "is planning", "considers", "receives approval",
    "begins testing", "starts testing", "pilot programme", "pilot program",
    "roadmap", "outpaces",
]
VOCAB = ([(t, 2) for t in AGENTIC] + [(t, 2) for t in EVAL_CONTEXT]
         + [(t, 1) for t in SUPPORTING]
         + [(t, -3) for t in ADVOCACY] + [(t, -4) for t in MISUSE])

# Events already on the map, named by the event and never by the vendor. A
# vendor-wide marker ("claude", "openai agents") looks tidy and quietly hides
# every new incident that company has: three real ones were suppressed that
# way, and surfaced only when the database was read record by record. Anything
# narrower than an event phrase belongs in feed_placed instead.
CURATED_MARKERS = [
    "hugging face", "dsewiki", "dse wiki", "german wiki", "german programming wiki",
    "wiki incident", "rathbun", "matplotlib", "artifactory", "openai bots escape",
    # Reading the OECD monitor in full turned every one of these into a dozen
    # write-ups of an episode already on the map. Each phrase names an event,
    # not a behaviour, so none of them can hide a new case.
    "escape sandbox", "escapes sandbox", "escape sandboxes", "escaping containment",
    "escape containment", "escapes containment", "escape test", "escapes test",
    "escape their test", "breach external systems", "breached external",
    "breach real systems", "hack corporate systems", "hacks corporate",
    "hack external systems", "autonomously hack", "unauthorized cyberattack",
    "unauthorised cyberattack", "kimi k3", "peer-preservation", "peer preservation",
    "loss of control observatory", "pocketos", "gym booking", "melbourne gym",
    "deletes user files and databases", "skynet day", "ai kill switch",
]


def get(url, decode=True):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        raw = r.read()
    return raw.decode("utf-8", "replace") if decode else raw


def score(text):
    low = text.lower()
    hits, total = [], 0
    for term, weight in VOCAB:
        if term in low:
            hits.append(term)
            total += weight
    return total, hits


def curated_urls():
    with open(CURATED_PATH, encoding="utf-8") as f:
        data = json.load(f)
    urls = {u.rstrip("/") for u in data.get("feed_placed", [])}
    # A candidate that was read and turned down must not come back next week.
    urls |= {r["url"].rstrip("/") for r in data.get("feed_rejected", [])}
    for ep in data["episodes"]:
        for s in ep.get("sources", []):
            urls.add(s["u"].rstrip("/"))
    return urls


STATS = {}


def fetch_mit_risks():
    """incident id → MIT risk classification, from the newest weekly snapshot.

    The archive is ~110 MB and the CSV sits near the front of it, so it is
    read as a stream and the loop breaks at the member rather than unpacking
    the rest. Set AIID_SNAPSHOT_FILE to a downloaded archive to work offline.
    """
    local = os.environ.get("AIID_SNAPSHOT_FILE", "").strip()
    if local:
        stream = open(local, "rb")
    else:
        page = get(AIID_SNAPSHOTS)
        found = sorted(set(SNAPSHOT_RE.finditer(page)), key=lambda m: m.group(1))
        if not found:
            raise ValueError("no snapshot link on the snapshots page")
        url = found[-1].group(0)
        print(f"[feed] MIT: reading {url.rsplit('/', 1)[-1]}")
        stream = urllib.request.urlopen(
            urllib.request.Request(url, headers={"User-Agent": UA}), timeout=TIMEOUT)

    risks, raw = {}, None
    with stream, tarfile.open(fileobj=stream, mode="r|bz2") as tar:
        for member in tar:
            if member.name.endswith(MIT_MEMBER):
                raw = tar.extractfile(member).read().decode("utf-8", "replace")
                break
    if raw is None:
        raise ValueError(f"{MIT_MEMBER} not in the snapshot")

    for row in csv.DictReader(io.StringIO(raw)):
        risks[str(row["Incident ID"])] = {
            "domain": row["Risk Domain"],
            "subdomain": row["Risk Subdomain"],
            "entity": row["Entity"],
            "intent": row["Intent"],
        }
    return risks


def taxonomy_summary(risks, total_incidents):
    own = [i for i, r in risks.items() if r["subdomain"].startswith(OWN_GOALS)]
    return {
        "source": "AI Incident Database, MIT AI Risk Repository taxonomy (CC BY-SA)",
        "tracker": "https://airisk.mit.edu/ai-incident-tracker",
        "incidents": total_incidents,
        "classified": len(risks),
        "own_goals_subdomain": next(
            (risks[i]["subdomain"] for i in own), "7.1. AI pursuing its own goals"),
        "own_goals": len(own),
        "own_goals_ids": sorted(int(i) for i in own),
        "own_goals_latest": max((STATS.get("dates", {}).get(i, "") for i in own), default=""),
        "newest_classified_id": max((int(i) for i in risks), default=0),
    }


def fetch_aiid(cutoff, risks):
    payload = json.loads(get(AIID_URL))
    nodes = payload["result"]["data"]["incidents"]["nodes"]
    STATS["incidents"] = len(nodes)
    STATS["dates"] = {str(n["incident_id"]): (n.get("date") or "")[:10] for n in nodes}
    out = []
    for n in nodes:
        date = (n.get("date") or "")[:10]
        if date < cutoff:
            continue
        text = f"{n.get('title', '')} {n.get('description', '')}"
        total, hits = score(text)
        risk = risks.get(str(n["incident_id"]))
        # An AI acting on its own, deliberately, is the thing this map is about,
        # so the classification both lifts a score and rescues a 7.1 outright.
        if risk and risk["domain"].startswith("7") and risk["entity"] == "AI":
            total += 2 if risk["intent"] == "Intentional" else 1
        rescued = bool(risk and risk["subdomain"].startswith(OWN_GOALS))
        if total < MIN_SCORE and not rescued:
            continue
        out.append({
            "id": f"aiid-{n['incident_id']}",
            "source": "AI Incident Database",
            "date": date,
            "title": (n.get("title") or "").strip(),
            "summary": (n.get("description") or "").strip()[:600],
            "url": AIID_INCIDENT.format(n["incident_id"]),
            "score": total,
            "matched": hits[:8],
            "risk": risk,
        })
    return out


# One card per entry: an <a href="/en/incidents/<id>"> holding the title, a
# `small-meta` span holding the date, and an `incident-summary` paragraph the
# monitor labels [AI generated]. The class names are the only stable handle
# the page offers — there is no JSON payload behind it, and scoring the title
# alone never clears MIN_SCORE, so the summary has to come along.
CARD_RE = re.compile(
    r'class="card--incident.*?href="(/en/incidents/[^"]+)"[^>]*>(.*?)</a>'
    r'.*?class="small-meta">\s*(\d{4}-\d{2}-\d{2})\s*</span>'
    r'(.*?)(?=class="card--incident|\Z)',
    re.S,
)


def strip_tags(fragment):
    return html.unescape(re.sub(r"<[^>]+>", " ", fragment))


# Every OECD card prints the monitor's own reading of how much of the action
# was the machine's. It is a gate, not a score: a card the monitor files as
# human-in-the-loop or advisory is dropped however it scores, because somebody
# approved the act. It must not be read the other way round — half the cards
# in any week are high-action, so rewarding the label admits every write-up
# about agents along with the agents.
AUTONOMY_RE = re.compile(r"Autonomy level:\s*(?:</?[^>]+>\s*)*([A-Za-z][^<]{3,60})")
AUTONOMY_EXCLUDED = ("low-action", "no-action")


def autonomy_label(fragment):
    m = AUTONOMY_RE.search(fragment)
    if not m:
        return None
    return " ".join(strip_tags(m.group(1)).split())


def oecd_slice(frm, to):
    """One OECD request. Returns every card on the page, unscored."""
    page = get(OECD_URL.format(frm=frm, to=to))
    out = []
    for path, title, date, rest in CARD_RE.findall(page):
        title = " ".join(strip_tags(title).split())
        body = re.search(r'class="incident-summary".*?<p[^>]*>(.*?)</p>', rest, re.S)
        summary = " ".join(strip_tags(body.group(1)).split()) if body else ""
        out.append((path, title, date,
                    summary.replace("[AI generated]", "").strip(),
                    autonomy_label(rest)))
    return out


def fetch_oecd(cutoff, today):
    """Walk the window in slices, because one request only ever returns 100.

    The monitor serves at most OECD_PAGE_MAX cards and offers no offset,
    page or cursor parameter of any kind; num_results above that returns an
    empty page. Ordered by date, those 100 cards covered seven days when this
    was written, so a single request over a two-year window silently reports
    on its last week. Slicing the window is the only way through. A slice that
    comes back full is split in half and re-read, so a busy week cannot hide
    entries behind the cap.
    """
    out, seen = [], set()

    def walk(frm, to, depth=0):
        cards = oecd_slice(str(frm), str(to))
        if len(cards) >= OECD_PAGE_MAX and depth < OECD_MAX_DEPTH and (to - frm).days > 1:
            mid = frm + (to - frm) / 2
            walk(frm, mid, depth + 1)
            walk(mid, to, depth + 1)
            return
        for path, title, date, summary, label in cards:
            if path in seen:
                continue
            seen.add(path)
            if label and label.lower().startswith(AUTONOMY_EXCLUDED):
                continue
            total, hits = score(f"{title} {summary}")
            if total < MIN_SCORE:
                continue
            if label:
                hits = hits + [label]
            out.append({
                "id": "oecd-" + path.rsplit("/", 1)[-1],
                "source": "OECD AI Incidents Monitor",
                "date": date,
                "title": title,
                "summary": summary[:600],
                "url": OECD_SITE + path,
                "score": total,
                "matched": hits[:8],
            })

    start = date_cls.fromisoformat(cutoff)
    end = date_cls.fromisoformat(today)
    step = timedelta(days=OECD_SLICE_DAYS)
    cursor = start
    while cursor < end:
        walk(cursor, min(cursor + step, end))
        cursor += step
    return out


# Entries carry "Occurred: <Month Year>"; a few older ones only ever got a
# "Page published:" line, which is the later of the two and says so.
AIAAIC_DATE_RE = re.compile(
    r"(?:Occurred|Page published):\s*([A-Z][a-z]+ \d{4}|\d{4})")


def fetch_aiaaic(known):
    """Read AIAAIC's index, then only the pages whose slug looks relevant.

    The index carries no dates and no summaries, so an entry cannot be scored
    without opening it; the slug filter is what keeps that bounded. Anything
    already cited in the corpus is skipped before the fetch, not after.
    """
    index = get(AIAAIC_INDEX)
    slugs = sorted(set(re.findall(
        r"/aiaaic-repository/ai-algorithmic-and-automation-incidents/([a-z0-9\-]+)",
        index)))
    STATS["aiaaic_entries"] = len(slugs)
    out, opened = [], 0
    for slug in slugs:
        if opened >= AIAAIC_FETCH_MAX:
            break
        if not AIAAIC_SLUG_RE.search(slug):
            continue
        url = AIAAIC_ENTRY + slug
        if url.rstrip("/") in known:
            continue
        try:
            page = get(url)
        except (urllib.error.URLError, TimeoutError, OSError):
            continue
        opened += 1
        text = " ".join(strip_tags(page).split())
        head = re.search(r"<title>(.*?)</title>", page, re.S)
        title = " ".join(strip_tags(head.group(1)).split()) if head else ""
        title = re.sub(r"^AIAAIC\s*[-–]\s*", "", title) or slug.replace("-", " ")
        when = AIAAIC_DATE_RE.search(text)
        body = re.search(r"Report incident.{0,80}?Access database\s*(.{80,900})", text)
        summary = body.group(1).strip() if body else ""
        summary = summary.lstrip("🔢 ").strip()
        total, hits = score(f"{title} {summary}")
        if total < MIN_SCORE:
            continue
        out.append({
            "id": "aiaaic-" + slug[:60],
            "source": "AIAAIC",
            "date": when.group(1) if when else "undated",
            "title": title,
            "summary": summary[:600],
            "url": url,
            "score": total,
            "matched": hits[:8],
        })
    STATS["aiaaic_opened"] = opened
    return out


# Words that carry no event. Two write-ups of the same incident share their
# nouns and differ in everything else, so these are dropped before comparing.
STOPWORDS = frozenset("""
a an and are as at be been by during for from has have in into is it its of on
or over that the their to under with without after against amid ai artificial
intelligence model models system systems new report reports says said
""".split())


def title_key(title):
    return frozenset(w for w in re.findall(r"[a-z0-9]+", title.lower())
                     if len(w) > 2 and w not in STOPWORDS)


def collapse_retellings(items, threshold=0.5):
    """One incident, a dozen write-ups: keep the best-scoring of each cluster.

    The OECD monitor indexes articles, not events, so reading its whole window
    returns the same escape or deletion ten or twenty times over, each under a
    different headline. Nothing upstream deduplicates them — the URLs differ,
    the dates differ by days, and the summaries are written separately. Titles
    sharing half their content words are treated as one event; the highest
    score survives and carries the count of what it stood in for.
    """
    kept = []
    for item in sorted(items, key=lambda i: i["score"], reverse=True):
        key = title_key(item["title"])
        if not key:
            kept.append(item)
            continue
        for other in kept:
            shared = key & other["_key"]
            union = key | other["_key"]
            if union and len(shared) / len(union) >= threshold:
                other["retellings"] = other.get("retellings", 1) + 1
                break
        else:
            item["_key"] = key
            kept.append(item)
    for item in kept:
        item.pop("_key", None)
    return kept


def main():
    today = datetime.now(timezone.utc).date()
    cutoff = str(today - timedelta(days=30 * MONTHS_BACK))
    known = curated_urls()

    risks, taxonomy = {}, None
    try:
        risks = fetch_mit_risks()
        print(f"[feed] MIT: {len(risks)} classified incidents")
    except (urllib.error.URLError, ValueError, KeyError, OSError, TimeoutError,
            tarfile.TarError) as e:
        print(f"[feed] MIT: FAILED — {e}")

    items, failed = [], []
    for name, fn in (("AIID", lambda: fetch_aiid(cutoff, risks)),
                     ("OECD", lambda: fetch_oecd(cutoff, str(today))),
                     ("AIAAIC", lambda: fetch_aiaaic(known))):
        try:
            got = fn()
            print(f"[feed] {name}: {len(got)} candidates")
            items += got
        except (urllib.error.URLError, ValueError, KeyError, TimeoutError) as e:
            print(f"[feed] {name}: FAILED — {e}")
            failed.append(name)

    kept, seen = [], set()
    for it in items:
        url = it["url"].rstrip("/")
        low = it["title"].lower()
        if url in known or url in seen:
            continue
        if any(m in low for m in CURATED_MARKERS):
            continue
        seen.add(url)
        kept.append(it)

    if risks:
        taxonomy = taxonomy_summary(risks, STATS.get("incidents", 0))

    before = len(kept)
    kept = collapse_retellings(kept)
    print(f"[feed] collapsed {before} candidates to {len(kept)} events")

    kept.sort(key=lambda i: (i["date"], i["score"]), reverse=True)
    kept = kept[:MAX_ITEMS]

    if failed and not kept:
        print("[feed] every source failed — previous file kept")
        return 0

    payload = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "window_from": cutoff,
        "sources_failed": failed,
        "min_score": MIN_SCORE,
        "license": "Incident records and MIT classifications from the AI Incident "
                   "Database (incidentdatabase.ai), CC BY-SA. OECD entries from the "
                   "OECD AI Incidents Monitor (oecd.ai/en/incidents). AIAAIC "
                   "entries from the AIAAIC Repository (aiaaic.org), CC BY-SA.",
        "taxonomy": taxonomy,
        "items": kept,
    }
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print(f"[feed] wrote {len(kept)} items to {OUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
