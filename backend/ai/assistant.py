"""AI Security Assistant - local intelligent analyst helper.

Implements a lightweight, fully-local AI using:
  * intent detection (TF-IDF + cosine similarity over an analyst knowledge base)
  * structured retrieval over live alerts / MITRE ATT&CK data
  * deterministic explanation and remediation text generation

An optional BARAQ AI endpoint can be enabled through config for
richer prose, but the platform ships and works 100% offline by default.
"""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import UTC, datetime

from sqlalchemy import func, select

from backend.ai.knowledge import INTENTS
from backend.config import AI_API_KEY, AI_API_URL, AI_MODEL, AI_EXTERNAL_ENABLED
from backend.database.models import (
    Alert,
    AssistantMessage,
    Endpoint,
    NormalizedEvent,
)

logger = logging.getLogger("baraq.ai")

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity

    HAS_SKLEARN = True
except ImportError:  # pragma: no cover
    HAS_SKLEARN = False


class SecurityAssistant:
    """Answers analyst questions about alerts, incidents and remediation."""

    def __init__(self, session, org: str | None = None, user_id: int | None = None):
        self.session = session
        self.org = org
        self.user_id = user_id
        self._vectorizer = None
        self._intent_matrix = None
        self._index_built = False
        self._rag_vectorizer = None
        self._rag_matrix = None
        self._rag_docs: list[Alert] = []
        self._rag_indexed = 0

    # ------------------------------------------------------------------
    # Knowledge retrieval
    # ------------------------------------------------------------------
    def _ensure_index(self):
        """Build the TF-IDF intent index once per assistant instance."""
        if self._index_built or not HAS_SKLEARN:
            return
        self._build_intent_index()
        self._index_built = True

    def _build_intent_index(self):
        [i["examples"] for i in INTENTS]
        corpus = [" ".join(i["examples"]) for i in INTENTS]
        self._vectorizer = TfidfVectorizer(
            lowercase=True, stop_words="english", ngram_range=(1, 2)
        )
        self._intent_matrix = self._vectorizer.fit_transform(corpus)

    def _classify_intent(self, message: str) -> str:
        if not HAS_SKLEARN or self._vectorizer is None:
            return self._keyword_intent(message)
        query_vec = self._vectorizer.transform([message])
        scores = cosine_similarity(query_vec, self._intent_matrix)[0]
        best = int(scores.argmax())
        if scores[best] < 0.12:
            return self._keyword_intent(message)
        return INTENTS[best]["id"]

    @staticmethod
    def _keyword_intent(message: str) -> str:
        msg = message.lower()
        if any(k in msg for k in ("explain", "what is", "what's", "about this")):
            return "explain_alert"
        if any(k in msg for k in ("summar", "summary", "overview", "incident")):
            return "summarize"
        if any(
            k in msg for k in ("remediat", "mitigat", "fix", "how to respond", "action")
        ):
            return "remediate"
        if any(k in msg for k in ("score", "health", "status", "security posture")):
            return "security_score"
        if any(k in msg for k in ("note", "report", "document")):
            return "analyst_note"
        if any(k in msg for k in ("mitre", "tactic", "technique", "framework")):
            return "mitre"
        if any(k in msg for k in ("hello", "hi ", "hey")):
            return "greeting"
        return "general"

    # ------------------------------------------------------------------
    # Context helpers
    # ------------------------------------------------------------------
    def _scope(self, model):
        return None if self.org is None else model.org == self.org

    def _latest_alerts(self, limit: int = 5) -> list[Alert]:
        stmt = select(Alert).where(Alert.status == "open")
        scope = self._scope(Alert)
        if scope is not None:
            stmt = stmt.where(scope)
        return list(
            self.session.scalars(stmt.order_by(Alert.created_at.desc()).limit(limit))
        )

    def _find_alert(self, query: str) -> Alert | None:
        """Resolve an alert from an ID or a name/keyword mention."""
        m = re.search(r"#?(\d+)", query)
        if m:
            stmt = select(Alert).where(Alert.id == int(m.group(1)))
            scope = self._scope(Alert)
            if scope is not None:
                stmt = stmt.where(scope)
            return self.session.scalars(stmt).first()
        lowered = query.lower()
        # Scan recent alerts first (bounded), then the rest of the table.
        recent_stmt = select(Alert).order_by(Alert.created_at.desc()).limit(50)
        recent_scope = self._scope(Alert)
        if recent_scope is not None:
            recent_stmt = recent_stmt.where(recent_scope)
        recent = list(self.session.scalars(recent_stmt))
        for alert in recent:  # fresh alerts match best
            if alert.name and (
                alert.name.lower() in lowered or lowered in alert.name.lower()
            ):
                return alert
        all_stmt = select(Alert)
        all_scope = self._scope(Alert)
        if all_scope is not None:
            all_stmt = all_stmt.where(all_scope)
        for alert in self.session.scalars(all_stmt).all():
            if (
                alert.name.lower() in lowered
                or lowered in alert.name.lower()
                or (alert.mitre_id and alert.mitre_id.lower() in lowered)
            ):
                return alert
        return None

    # ------------------------------------------------------------------
    # RAG: retrieval over resolved past incidents
    # ------------------------------------------------------------------
    def similar_resolved_alerts(self, query: str, limit: int = 2) -> list[Alert]:
        """Return past *resolved* alerts most similar to ``query``.

        Lightweight RAG: a TF-IDF retrieval corpus is built lazily over
        closed alerts (their name + evidence + recommendation), so the
        assistant can ground answers in how similar incidents were handled.
        """
        if not HAS_SKLEARN or not query.strip():
            return []
        stmt = select(Alert).where(Alert.status != "open")
        scope = self._scope(Alert)
        if scope is not None:
            stmt = stmt.where(scope)
        rows = list(self.session.scalars(stmt.order_by(Alert.updated_at.desc())))
        if not rows:
            return []
        if self._rag_docs != rows or len(rows) != self._rag_indexed:
            corpus = [
                str(a.name or "")
                + " "
                + str(a.evidence or "")[:500]
                + " "
                + str(a.recommendation or "")[:300]
                for a in rows
            ]
            vec = TfidfVectorizer(
                lowercase=True, stop_words="english", ngram_range=(1, 2)
            )
            self._rag_matrix = vec.fit_transform(corpus)
            self._rag_vectorizer = vec
            self._rag_docs = rows
            self._rag_indexed = len(rows)
        try:
            assert self._rag_vectorizer is not None
            q = self._rag_vectorizer.transform([query])
            scores = cosine_similarity(q, self._rag_matrix)[0]
        except Exception:
            return []
        best = scores.argsort()[::-1][:limit]
        return [rows[int(i)] for i in best if scores[int(i)] > 0.15]

    # ------------------------------------------------------------------
    def _alert_explanation(self, alert: Alert) -> str:
        base = (
            f"Alert #{alert.id} - {alert.name} ({alert.severity} severity, "
            f"MITRE {alert.mitre_id} / {alert.mitre_tactic}).\n"
            f"What it means: {alert.description}\n"
            f"Evidence: {alert.evidence}\n"
            f"Recommended response: {alert.recommendation}"
        )
        related = self.similar_resolved_alerts(alert.name)
        if not related:
            return base
        lines = [base, "", "Similar past incidents (resolved):"]
        for r in related[:2]:
            lines.append(
                f"- #{r.id} {r.name} [{r.severity}]: {r.evidence[:160]} "
                f"-> {r.recommendation[:160]}"
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Entity intelligence (why is this entity suspicious)
    # ------------------------------------------------------------------
    def explain_entity(self, kind: str, name: str) -> str:
        """Deterministic entity analyst report for a graph node.

        Grounds the reply in the entity graph (risk + relationships) plus
        live threat-intel verdicts and any recorded ML anomalies / alerts,
        so the explanation always answers *why* an entity is suspicious.
        When BARAQ AI is configured, the structured context is sent to the
        model for a richer, more natural analyst-style explanation.
        """
        from backend.graph import get_graph_store
        from backend.threatintel.service import lookup_indicator

        kind = "device" if kind == "host" else kind
        store = get_graph_store()
        entity = store.get_entity(self.session, kind, name)
        if not entity:
            return (
                f"'{name}' ({kind}) is not in the entity graph. Run the pipeline "
                "and rebuild the graph (Entity Graph -> Rebuild) so this entity "
                "can be analysed."
            )

        lines = [
            (
                f"Entity Analysis - {entity['display_name']}"
                f" [risk {entity['risk_level']} {entity['risk_score']:.0f}/100]"
            ),
        ]
        if entity.get("first_seen"):
            lines.append(
                f"First seen: {entity['first_seen']} | "
                f"Last seen: {entity.get('last_seen') or 'n/a'}"
            )

        subgraph = store.graph(
            self.session, center_kind=kind, center_name=name, depth=1
        )
        edges = sorted(subgraph.get("edges", []), key=lambda e: -(e.get("weight") or 0))

        evidences: list[str] = []
        relations: list[str] = []
        for e in edges[:8]:
            src, dst = e["source"], e["target"]
            if (src["kind"] == kind and src["name"] == name) or (
                dst["kind"] == kind and dst["name"] == name
            ):
                other = dst if src["name"] == name and src["kind"] == kind else src
                relations.append(f"- {other['kind']}:{other['name']} ({e['rel']})")

        # 1) Threat-intel verdict for indicators
        if kind in ("ip", "domain", "file") and name:
            try:
                verdict = lookup_indicator(self.session, name)
                cat = (verdict or {}).get("category", "unknown")
                label = (verdict or {}).get("label", "")
                conf = (verdict or {}).get("confidence")
                if verdict:
                    evidences.append(
                        f"Threat-intel: {kind} flagged {cat} "
                        f"({label}) confidence {conf:.0%}"
                    )
            except Exception as exc:
                logger.debug("entity intel lookup failed: %s", exc)

        # 2) Related alerts + anomalies
        total_events = int(entity.get("events_count") or 0)
        alert_count = int(entity.get("alerts_count") or 0)
        if alert_count:
            evidences.append(
                f"Linked to {alert_count} alert(s) - repeated engagement by the "
                "detection rules is the strongest signal."
            )

        # 3) Neighbourhood weight (most frequent co-activity)
        if relations:
            evidences.append(
                f"Connected to {len(edges)} other entities; densest link: "
                + relations[0]
            )

        # 4) MITRE techniques shown by the subgraph
        technique_nodes = [
            n for n in subgraph.get("nodes", []) if n.get("kind") == "technique"
        ]
        if technique_nodes:
            names = sorted({n["name"] for n in technique_nodes})[:4]
            evidences.append("Exhibits MITRE techniques: " + ", ".join(names))

        # 5) Live event / anomaly footprint
        if kind in ("user", "device"):
            event_col = NormalizedEvent.user if kind == "user" else NormalizedEvent.host
            event_stmt = select(NormalizedEvent).where(event_col == name)
            event_scope = self._scope(NormalizedEvent)
            if event_scope is not None:
                event_stmt = event_stmt.where(event_scope)
            rows = self.session.scalars(
                event_stmt.order_by(NormalizedEvent.timestamp.desc()).limit(400)
            ).all()
            recent_anomalies = sum(1 for r in rows if r.is_anomaly)
            if rows:
                peak = max((r.ml_score or 0.0) for r in rows)
                evidences.append(
                    f"{len(rows)} of {total_events} recent event log entries "
                    f"examined; {recent_anomalies} ML-flagged; "
                    f"peak ML anomaly score {peak:.2f}."
                )

        # Compose
        if not evidences:
            evidences.append(
                "No active threats: the entity is within normal behavioural baseline "
                "and carries no open alerts or suspicious relationships."
            )

        header = lines
        body = ["", "Why it matters:"]
        body += [f"  - {e}" for e in evidences][:6]
        if relations:
            body.append("")
            body.append("Notable relationships:")
            body += relations[:6]
        if alert_count:
            body.append("")
            body.append(
                "Recommended response: isolate/contain if still active, preserve "
                "evidence, review the linked alerts and close them after action."
            )

        # When BARAQ AI is available AND externally enabled, send the
        # structured context for a richer analyst-style explanation.
        if AI_API_URL and AI_EXTERNAL_ENABLED:
            try:
                import httpx

                context = "\n".join(header + body)
                url = AI_API_URL.rstrip("/")
                if not url.endswith("/chat/completions"):
                    url += "/chat/completions"

                payload = {
                    "model": AI_MODEL,
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are the BARAQ SOC AI analyst. "
                                "Start with '**BARAQ AI Analysis**' as the header. "
                                "Given the structured entity analysis below, "
                                "write a concise, actionable explanation of "
                                "why this entity is suspicious and what the "
                                "analyst should do next. Use markdown: bold labels, "
                                "bullet lists, numbered steps, '###' section headers. "
                                "Reference MITRE ATT&CK techniques where applicable.\n\n"
                                f"ENTITY DATA:\n{context}"
                            ),
                        },
                        {
                            "role": "user",
                            "content": f"Explain why {kind}:{name} is suspicious based on this data.",
                        },
                    ],
                    "temperature": 1,
                    "top_p": 0.95,
                    "max_tokens": 4096,
                    "stream": True,
                    "chat_template_kwargs": {"enable_thinking": True},
                    "reasoning_budget": 0,
                }

                reasoning_parts: list[str] = []
                content_parts: list[str] = []

                with httpx.Client(
                    timeout=httpx.Timeout(connect=5, read=15, write=5, pool=5)
                ) as hclient, hclient.stream(
                    "POST",
                    url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {AI_API_KEY}",
                    },
                ) as resp:
                    resp.raise_for_status()
                    for line in resp.iter_lines():
                        if not line.startswith("data: "):
                            continue
                        data = line[6:]
                        if data.strip() == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data)
                        except json.JSONDecodeError:
                            continue
                        choices = chunk.get("choices", [])
                        if not choices:
                            continue
                        delta = choices[0].get("delta", {})
                        reasoning = delta.get("reasoning_content")
                        if reasoning:
                            reasoning_parts.append(reasoning)
                        content = delta.get("content")
                        if content is not None:
                            content_parts.append(content)

                if reasoning_parts:
                    safe_reasoning = "".join(reasoning_parts)[:500].encode("ascii", "replace").decode("ascii")
                    logger.info(
                        "BARAQ AI entity reasoning (%d tokens): %s",
                        len("".join(reasoning_parts)),
                        safe_reasoning,
                    )

                answer = "".join(content_parts).strip()
                if answer:
                    return self._scrub_identity(answer)
            except Exception as exc:
                safe_exc = str(exc).encode("ascii", "replace").decode("ascii")
                logger.warning(
                    "BARAQ AI entity explanation failed (%s); using local", safe_exc
                )

        return "\n".join(header + body)

    # ------------------------------------------------------------------
    # Identity filter — strip upstream model/brand references
    # ------------------------------------------------------------------
    _IDENTITY_PATTERNS = [
        (re.compile(r"(?i)\bNVIDIA\b"), "BARAQ"),
        (re.compile(r"(?i)\bnemotron\b"), "BARAQ AI"),
        (re.compile(r"(?i)\bnemotron[\s-]*\d[\w\-]*"), "BARAQ AI"),
        (re.compile(r"(?i)\bLlama\b"), "BARAQ AI"),
        (re.compile(r"(?i)\bMeta\b AI"), "BARAQ AI"),
        (re.compile(r"(?i)\bMistral\b"), "BARAQ AI"),
        (re.compile(r"(?i)\bOpenAI\b"), "BARAQ"),
        (re.compile(r"(?i)\bGPT[\s\-]*\d"), "BARAQ AI"),
        (re.compile(r"(?i)\bClaude\b"), "BARAQ AI"),
        (re.compile(r"(?i)\bAnthropic\b"), "BARAQ"),
        (re.compile(r"(?i)\bGoogle\b AI"), "BARAQ AI"),
        (re.compile(r"(?i)\bGemini\b"), "BARAQ AI"),
        (re.compile(r"(?i)I('m| am) (an? )?(NVIDIA|Meta|Mistral|OpenAI|Anthropic|Google)\b"), "I am BARAQ AI"),
        (re.compile(r"(?i)trained by (NVIDIA|Meta|Mistral|OpenAI|Anthropic|Google)\b"), "developed for BARAQ SOC"),
    ]

    @staticmethod
    def _scrub_identity(text: str) -> str:
        """Replace upstream model/brand mentions with BARAQ equivalents."""
        for pattern, replacement in SecurityAssistant._IDENTITY_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    # ------------------------------------------------------------------
    def _respond(self, intent: str, message: str) -> str:
        alert = self._resolve_alert(message)
        alerts = self._latest_alerts()

        if intent == "greeting":
            return (
                "Hello, I am the BARAQ Security Assistant. I can explain alerts, "
                "summarize incidents, recommend remediation, and generate analyst notes. "
                f"There are currently {len(alerts)} open alerts."
            )

        if intent == "explain_alert":
            if alert:
                return self._alert_explanation(alert)
            if alerts:
                top = alerts[0]
                return (
                    "I don't see a specific alert in your question, so here's the most recent one.\n"
                    + self._alert_explanation(top)
                )
            return "No alerts are currently open to explain. Run a collection or simulation first."

        if intent == "summarize":
            if not alerts:
                return "No open alerts. The environment is currently quiet - no active threats detected."
            lines = [
                f"Incident summary: {len(alerts)} open alerts.",
                "",
            ]
            for a in alerts:
                lines.append(
                    f"- #{a.id} {a.name} [{a.severity}] ({a.mitre_id}, {a.mitre_tactic}) "
                    f"- {a.description[:120]}"
                )
            lines.append("")
            lines.append(
                "Overall posture: "
                + (
                    "CRITICAL - immediate response required."
                    if any(a.severity == "critical" for a in alerts)
                    else "ATTENTION - investigate all open alerts."
                )
            )
            return "\n".join(lines)

        if intent == "remediate":
            if alert:
                return f"Remediation plan for {alert.name} ({alert.mitre_id}):\n{alert.recommendation}"
            lines = ["Recommended remediation actions for current threats:"]
            seen = set()
            for a in alerts:
                if a.recommendation not in seen:
                    lines.append(f"- {a.name}: {a.recommendation}")
                    seen.add(a.recommendation)
            return (
                "\n".join(lines) if alerts else "No open alerts requiring remediation."
            )

        if intent == "security_score":
            score = self._compute_score()
            counts = dict(
                self.session.execute(
                    select(Alert.severity, func.count(Alert.id))
                    .where(Alert.status == "open")
                    .group_by(Alert.severity)
                ).all()
            )
            return (
                f"Security score: {score:.1f}/100.\n"
                f"Open alerts by severity: "
                + (", ".join(f"{k}: {v}" for k, v in counts.items()) or "none")
                + ".\n"
                + (
                    "The environment shows elevated threat activity."
                    if score < 70
                    else "The environment is in a healthy state."
                )
            )

        if intent == "mitre":
            if alert:
                return (
                    f"MITRE ATT&CK mapping for #{alert.id}:\n"
                    f"Technique: {alert.mitre_id} - {alert.mitre_name}\n"
                    f"Tactic: {alert.mitre_tactic}\n"
                    f"Recommended action: {alert.recommendation}"
                )
            return (
                "The detection rules map to these MITRE ATT&CK techniques: "
                "T1110 (Brute Force), T1059.001 (PowerShell), T1068 (Privilege Escalation), "
                "T1547 (Persistence), T1046 (Network Service Discovery), "
                "T1021 (Lateral Movement), T1074 (Data Staging)."
            )

        if intent == "analyst_note":
            return self._generate_note(alerts)

        if intent == "alert_search":
            return self._search_alerts(message)

        if intent == "recent_events":
            return self._recent_events(message)

        if intent == "threat_intel":
            return self._threat_intel(message)

        if intent == "fleet_status":
            return self._fleet_status()

        if intent == "ml_anomalies":
            return self._ml_anomalies()

        # general fallback with context
        msg_lower = message.lower().strip()
        # Conversational follow-ups that don't match a specific SOC intent
        if any(
            k in msg_lower
            for k in ("how are", "how is", "how's", "what's up", "who are you")
        ):
            return (
                f"I'm the BARAQ Security Assistant, running strong. "
                f"Current SOC status: {len(alerts)} open alerts, "
                f"security score {self._compute_score():.1f}/100. "
                "Ask me to explain an alert, summarize incidents, or check threat intel."
            )
        if any(k in msg_lower for k in ("thanks", "thank you", "good job", "nice")):
            return (
                "You're welcome! Let me know if you need anything else — "
                "alert explanations, incident summaries, threat-intel lookups, or remediation plans."
            )
        if any(k in msg_lower for k in ("help", "what can you", "commands", "options")):
            return (
                "I can help with:\n"
                "- Explain alerts (e.g. 'explain alert 3')\n"
                "- Summarize incidents ('summarize open alerts')\n"
                "- Recommend remediation ('how to fix')\n"
                "- MITRE ATT&CK mapping ('what MITRE technique')\n"
                "- Threat-intel lookups (paste an IP, domain, or hash)\n"
                "- Show recent events, endpoints, or ML anomalies\n"
                "- Generate analyst notes ('write a note')"
            )
        return (
            f"Here is the current SOC picture: {len(alerts)} open alerts, "
            f"security score {self._compute_score():.1f}/100. "
            "I can explain alerts (e.g. 'explain alert 3'), summarize incidents, "
            "recommend remediation, search alerts, show recent events or endpoints, "
            "perform threat-intel lookups, and generate analyst notes."
        )

    # ------------------------------------------------------------------
    # New intents: alert search, events, threat intel, fleet, ML anomalies
    # ------------------------------------------------------------------
    _SEVERITY_WORDS = {"critical", "high", "medium", "low"}

    def _search_alerts(self, message: str) -> str:
        """Alert search with severity / status / keyword filters."""
        lowered = message.lower()
        statuses = {"open", "closed"}
        status = "open"
        for s in statuses:
            if s in lowered:
                status = s
                break
        severities = {w for w in self._SEVERITY_WORDS if w in lowered}

        query = select(Alert)
        if status == "open":
            query = query.where(Alert.status == "open")
        else:
            query = query.where(Alert.status != "open")
        if severities:
            query = query.where(Alert.severity.in_(severities))
        scope = self._scope(Alert)
        if scope is not None:
            query = query.where(scope)
        query = query.order_by(Alert.created_at.desc()).limit(20)
        rows = list(self.session.scalars(query))

        keyword = None
        if not severities:
            stripped = re.sub(
                r"\b(?:alerts?|show|list|what|any|find|open|closed|about|for|host|"
                r"from|today|me|the|do|we|have|are|there|with|severity|severe)\b",
                " ",
                lowered,
            )
            stripped = re.sub(r"\s+", " ", stripped).strip()
            if len(stripped) >= 3:
                keyword = stripped

        if keyword:
            kw = keyword.lower()
            rows = [
                r
                for r in rows
                if kw in (r.name or "").lower()
                or kw in (r.rule or "").lower()
                or kw in (r.mitre_id or "").lower()
                or kw in (r.mitre_tactic or "").lower()
                or kw in (r.evidence or "").lower()
            ]

        if not rows:
            filters = ", ".join(list(severities) + [status]) or "all"
            return (
                f"No {'open' if status == 'open' else 'closed'} alerts"
                f"{' matching "' + keyword + '"' if keyword else ''}"
                f" ({filters})."
            )
        lines = [f"{len(rows)} {'open' if status == 'open' else 'closed'} alert(s):"]
        for a in rows[:15]:
            lines.append(f"- #{a.id} {a.name} [{a.severity}] ({a.rule}, {a.mitre_id})")
        if len(rows) > 15:
            lines.append(f"  ... and {len(rows) - 15} more")
        return "\n".join(lines)

    def _recent_events(self, message: str) -> str:
        """Latest normalized events, optionally filtered by host or user."""
        lowered = message.lower()
        host = user = None
        m = re.search(r"\bhost\s+([\w.\-]+)", lowered)
        if m:
            host = m.group(1)
        m = re.search(r"\buser\s+([\w.\-]+)", lowered)
        if m:
            user = m.group(1)

        query = select(NormalizedEvent)
        if host:
            query = query.where(NormalizedEvent.host == host)
        if user:
            query = query.where(NormalizedEvent.user == user)
        scope = self._scope(NormalizedEvent)
        if scope is not None:
            query = query.where(scope)
        query = query.order_by(NormalizedEvent.timestamp.desc()).limit(15)
        rows = list(self.session.scalars(query))

        if not rows:
            scope = f" for {host or user}" if (host or user) else ""
            return f"No events in the database{scope} yet."
        lines = [
            f"Latest {len(rows)} events"
            + (f" - {host or user}" if (host or user) else "")
            + ":"
        ]
        for e in rows:
            flags = []
            if e.is_anomaly:
                flags.append("ML-flagged")
            if e.ml_score and e.ml_score >= 0.8:
                flags.append(f"score {e.ml_score:.2f}")
            lines.append(
                f"- [{e.timestamp:%H:%M:%S}] #{e.event_id} {e.category} "
                f"{e.user}@{e.host} risk={e.risk_score}"
                + (f" ({', '.join(flags)})" if flags else "")
            )
        return "\n".join(lines)

    _DOMAIN_RE = re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE
    )

    def _extract_indicator(self, message: str) -> str | None:
        import ipaddress

        for token in message.split():
            candidate = token.strip("(),;:[]'\"")
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                pass
            if re.fullmatch(
                r"[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32}", candidate
            ):
                return candidate
        m = self._DOMAIN_RE.search(message)
        if m and "lookup" not in m.group(0):
            return m.group(0)
        return None

    def _threat_intel(self, message: str) -> str:
        from backend.threatintel.service import lookup_indicator

        indicator = self._extract_indicator(message)
        if not indicator:
            return (
                "I didn't find an IP, domain or hash in your question. "
                "Ask e.g. 'is 203.0.113.9 malicious?' or 'check hash <sha256>'."
            )
        try:
            verdict = lookup_indicator(self.session, indicator) or {}
        except Exception as exc:
            logger.debug("threat intel lookup failed: %s", exc)
            verdict = {}
        if not verdict:
            return (
                f"No reputation data for '{indicator}'. "
                "If a provider key is configured the live feed is used; "
                "otherwise the offline baseline applies."
            )
        label = verdict.get("label") or verdict.get("category") or "unknown"
        conf = verdict.get("confidence")
        conf_str = f"{conf:.0%}" if isinstance(conf, (int, float)) else "n/a"
        detail = verdict.get("detail") or verdict.get("reason") or ""
        lines = [
            f"Threat intelligence - {indicator}",
            f"  Verdict: {label} (confidence {conf_str})",
        ]
        if detail:
            lines.append(f"  Detail: {detail}")
        related = self.similar_resolved_alerts(indicator, limit=1)
        if related:
            lines.append(
                f"  Related resolved incident: #{related[0].id} {related[0].name}"
            )
        return "\n".join(lines)

    def _fleet_status(self) -> str:
        endpoint_stmt = select(Endpoint)
        endpoint_scope = self._scope(Endpoint)
        if endpoint_scope is not None:
            endpoint_stmt = endpoint_stmt.where(endpoint_scope)
        endpoints = list(self.session.scalars(endpoint_stmt.order_by(Endpoint.host)))
        if not endpoints:
            return (
                "No endpoints are registered yet. Install the fleet agent "
                "on target hosts and they will appear here automatically."
            )
        now = datetime.now(UTC)
        online: list = []
        stale: list = []
        for ep in endpoints:
            last = ep.last_seen
            age = (now - last).total_seconds() if last else float("inf")
            (online if age <= 300 else stale).append((ep, age))
        lines = [
            (
                f"Fleet status: {len(endpoints)} endpoint(s) - "
                f"{len(online)} reporting (within 5 min), {len(stale)} stale."
            )
        ]
        for ep, age in sorted(online, key=lambda x: -x[0].alerts_total):
            lines.append(
                f"- {ep.host} ({ep.agent_id}) online, {ep.events_total} events, "
                f"{ep.alerts_total} alerts"
            )
        for ep, age in sorted(stale, key=lambda x: -x[1]):
            mins = int(age // 60)
            lines.append(
                f"- {ep.host} ({ep.agent_id}) STALE - last seen {mins} min ago"
            )
        return "\n".join(lines)

    def _ml_anomalies(self) -> str:
        anomaly_stmt = select(NormalizedEvent).where(
            NormalizedEvent.is_anomaly.is_(True)
        )
        scope = self._scope(NormalizedEvent)
        if scope is not None:
            anomaly_stmt = anomaly_stmt.where(scope)
        rows = list(
            self.session.scalars(
                anomaly_stmt.order_by(NormalizedEvent.timestamp.desc()).limit(15)
            )
        )
        if not rows:
            return (
                "No ML-flagged anomalies in the recent event stream. "
                "The behavioral models are currently at baseline."
            )
        lines = [f"{len(rows)} recent ML-flagged anomaly/ies:"]
        for e in rows:
            lines.append(
                f"- [{e.timestamp:%Y-%m-%d %H:%M:%S}] {e.user}@{e.host} "
                f"event #{e.event_id} {e.category} ml_score={e.ml_score:.2f}"
            )
        return "\n".join(lines)

    def _generate_note(self, alerts: list[Alert]) -> str:
        if not alerts:
            return "Analyst note: no active threats. Environment normal; continue routine monitoring."
        lines = [
            f"ANALYST NOTE - {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
            f"During this shift {len(alerts)} alert(s) required attention.",
        ]
        for a in alerts[:5]:
            lines.append(
                f"  - {a.name} ({a.mitre_id}/{a.mitre_tactic}) severity={a.severity}"
            )
        lines.append(
            "Actions taken: initial triage; evidence preserved; MITRE mapping recorded."
        )
        return "\n".join(lines)

    def _compute_score(self) -> float:
        from backend.analyzers.dashboard import compute_security_score

        return compute_security_score(self.session, org=self.org)

    # ------------------------------------------------------------------
    # Chat
    # ------------------------------------------------------------------
    def _recent_history(self, limit: int = 8) -> list[AssistantMessage]:
        """Last N stored turns, oldest first (multi-turn conversation memory)."""
        stmt = select(AssistantMessage)
        if self.user_id is None:
            stmt = stmt.where(AssistantMessage.user_id.is_(None))
        else:
            stmt = stmt.where(AssistantMessage.user_id == self.user_id)
        rows = self.session.scalars(
            stmt.order_by(AssistantMessage.id.desc()).limit(limit)
        ).all()
        return list(reversed(rows))

    def _resolve_alert(self, message: str) -> Alert | None:
        """Resolve an alert from the message, falling back to conversation memory.

        Follow-up questions like "and how do I remediate that?" resolve to the
        alert most recently mentioned in the conversation history.
        """
        alert = self._find_alert(message)
        if alert is not None:
            return alert
        for row in reversed(self._recent_history(limit=10)):
            if row.role != "user":
                continue
            mentioned = self._find_alert(row.content)
            if mentioned is not None:
                return mentioned
        return None

    def clear_history(self) -> int:
        """Delete this user's stored conversation turns; returns the number removed."""
        owner_filter = (
            AssistantMessage.user_id.is_(None)
            if self.user_id is None
            else AssistantMessage.user_id == self.user_id
        )
        count = self.session.scalar(
            select(func.count(AssistantMessage.id)).where(owner_filter)
        ) or 0
        self.session.execute(
            AssistantMessage.__table__.delete().where(owner_filter)
        )
        self.session.commit()
        return int(count)

    def chat(self, message: str, role: str = "user", persist: bool = True) -> str:
        self._ensure_index()
        intent = self._classify_intent(message)
        logger.info("Assistant intent=%s for: %s", intent, message[:80])

        if persist:
            self.session.add(
                AssistantMessage(user_id=self.user_id, role="user", content=message)
            )

        if AI_API_URL and AI_EXTERNAL_ENABLED:
            response = self._remote_completion(message, intent)
        else:
            response = self._respond(intent, message)

        if persist:
            self.session.add(
                AssistantMessage(
                    user_id=self.user_id,
                    role="assistant",
                    content=response,
                )
            )
            self.session.commit()
        return response

    def history(self, limit: int = 50) -> list[dict]:
        stmt = select(AssistantMessage)
        if self.user_id is None:
            stmt = stmt.where(AssistantMessage.user_id.is_(None))
        else:
            stmt = stmt.where(AssistantMessage.user_id == self.user_id)
        rows = self.session.scalars(
            stmt.order_by(AssistantMessage.id.desc()).limit(limit)
        ).all()
        return [r.to_dict() for r in reversed(rows)]

    # ------------------------------------------------------------------
    # Optional remote completion (BARAQ AI)
    # ------------------------------------------------------------------
    def _context_block(self) -> str:
        """Compact live SOC context so the remote model can ground its reply."""
        alerts = self._latest_alerts(5)
        lines = [f"Security score: {self._compute_score():.1f}/100."]
        if not alerts:
            lines.append("Open alerts: none.")
        else:
            lines.append(f"Open alerts: {len(alerts)}.")
            for a in alerts:
                lines.append(
                    f"- Alert #{a.id}: {a.name} ({a.severity}) MITRE {a.mitre_id} - {a.mitre_tactic}"
                )
        try:
            from backend.database.models import Endpoint

            endpoint_stmt = select(Endpoint)
            endpoint_scope = self._scope(Endpoint)
            if endpoint_scope is not None:
                endpoint_stmt = endpoint_stmt.where(endpoint_scope)
            eps = list(self.session.scalars(endpoint_stmt))
            online = sum(
                1
                for e in eps
                if e.last_seen
                and (datetime.now(UTC) - e.last_seen).total_seconds() <= 300
            )
            lines.append(f"Endpoints: {online}/{len(eps)} reporting")
        except Exception:
            pass
        return "\n".join(lines)

    def _remote_completion(self, message: str, intent: str) -> str:
        """Call BARAQ AI via streaming with raw httpx for minimum latency."""
        try:
            if not AI_API_URL or not AI_API_KEY:
                raise RuntimeError("BARAQ AI endpoint not configured")

            import httpx

            messages: list[dict] = [
                {
                    "role": "system",
                    "content": (
                        "You are the BARAQ Security Operations Center AI analyst. "
                        "Always start alert explanations with '**BARAQ AI Analysis**' "
                        "as the header. Use markdown formatting: bold for labels, "
                        "bullet lists with '-' for actions, numbered lists for steps, "
                        "and '###' for section headers. Ground all statements in MITRE "
                        "ATT&CK where applicable. Be precise, actionable, and "
                        "security-focused. You can hold casual conversation too, "
                        "but always tie back to security when relevant.\n\n"
                        f"LIVE SOC CONTEXT:\n{self._context_block()}"
                    ),
                }
            ]
            for row in self._recent_history(limit=6):
                messages.append({"role": row.role, "content": row.content})
            messages.append({"role": "user", "content": message})

            url = AI_API_URL.rstrip("/")
            if not url.endswith("/chat/completions"):
                url += "/chat/completions"

            payload = {
                "model": AI_MODEL,
                "messages": messages,
                "temperature": 1,
                "top_p": 0.95,
                "max_tokens": 4096,
                "stream": True,
                "chat_template_kwargs": {"enable_thinking": True},
                "reasoning_budget": 0,
            }

            t0 = time.monotonic()
            reasoning_parts: list[str] = []
            content_parts: list[str] = []

            with httpx.Client(
                timeout=httpx.Timeout(connect=5, read=15, write=5, pool=5)
            ) as client, client.stream(
                "POST",
                url,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {AI_API_KEY}",
                },
            ) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if not line.startswith("data: "):
                        continue
                    data = line[6:]
                    if data.strip() == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    choices = chunk.get("choices", [])
                    if not choices:
                        continue
                    delta = choices[0].get("delta", {})
                    reasoning = delta.get("reasoning_content")
                    if reasoning:
                        reasoning_parts.append(reasoning)
                    content = delta.get("content")
                    if content is not None:
                        content_parts.append(content)

            elapsed = time.monotonic() - t0

            if reasoning_parts:
                full_reasoning = "".join(reasoning_parts)
                logger.info(
                    "BARAQ AI reasoning (%d tokens, %.1fs): %s",
                    len(full_reasoning),
                    elapsed,
                    full_reasoning[:500],
                )

            answer = "".join(content_parts).strip()
            if answer:
                answer = self._scrub_identity(answer)
                safe_answer = answer[:200].encode("ascii", "replace").decode("ascii")
                logger.info("BARAQ AI response (%.1fs): %s", elapsed, safe_answer)
                return answer
            raise RuntimeError("Empty response from BARAQ AI")

        except Exception as exc:
            safe_exc = str(exc).encode("ascii", "replace").decode("ascii")
            logger.warning(
                "BARAQ AI remote completion failed (%s: %s); using local engine",
                type(exc).__name__,
                safe_exc,
            )
            return self._respond(self._keyword_intent(message), message)
