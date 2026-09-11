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
from datetime import datetime, timedelta, timezone

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

UA = "goveronica.com misalignment map (contact: madokamemika@gmail.com)"
TIMEOUT = 90
MONTHS_BACK = 24
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


def fetch_oecd(cutoff, today):
    page = get(OECD_URL.format(frm=cutoff, to=today))
    out = []
    for path, title, date, rest in CARD_RE.findall(page):
        title = " ".join(strip_tags(title).split())
        body = re.search(r'class="incident-summary".*?<p[^>]*>(.*?)</p>', rest, re.S)
        summary = " ".join(strip_tags(body.group(1)).split()) if body else ""
        summary = summary.replace("[AI generated]", "").strip()
        total, hits = score(f"{title} {summary}")
        if total < MIN_SCORE:
            continue
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
    return out


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
                     ("OECD", lambda: fetch_oecd(cutoff, str(today)))):
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
                   "OECD AI Incidents Monitor (oecd.ai/en/incidents).",
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
