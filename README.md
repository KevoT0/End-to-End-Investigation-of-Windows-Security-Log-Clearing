# Incident Response: End-to-End Investigation of Windows Security Log Clearing

**Lab environment:** Microsoft Sentinel Training Lab dataset
**SC-200 domain:** Respond to security incidents
**Detection surface:** Microsoft Sentinel (Defender portal) · Incident queue · NRT analytics rule

---

## Summary

I investigated an active Sentinel incident — *"NRT Security Event log cleared"* — end to end, from queue triage through verdict, impact assessment, and a full containment/response plan. The incident captured an attacker (`mirage`) clearing the Windows security event log on host `win11a` to destroy evidence. Reading the wider incident queue first revealed this was one action within a broader multi-front campaign by the same actor, which shaped the response.

**Verdict:** True positive, corroborated by raw evidence (Event ID 1102). High impact — evidence destruction indicating an active, mid-stage intrusion.

---

## Environment note

Performed in a lab tenant on the Sentinel Training Lab dataset. The incident, entities, and underlying events are pre-recorded; the triage methodology and response reasoning transfer directly to production.

---

## Step 1 — Read the queue before opening anything

Before drilling into a single incident, I reviewed the whole queue. A pattern was immediately visible: the actor **`mirage`** appeared across almost every incident, spanning multiple systems:

![Incident queue: mirage appears across multiple incidents — AWS CLI execution, AWS Config deletion, and repeated Windows log clearing, all tagged Defense evasion — revealing one attacker's campaign](8.png)

- Suspicious AWS CLI command execution (cloud activity)
- AWS Config service resource deletion attempts (*Defense evasion* — deleting the service that records AWS changes)
- Security event log cleared, ×4 (*Defense evasion* — wiping Windows logs on `win11a`)

**Interpretation:** this is not a set of unrelated alerts — it is **one attacker's campaign** seen from multiple angles, with a clear theme of **evidence destruction** across both cloud (AWS Config deletion) and endpoint (Windows log clearing). Recognising the campaign at the queue level, before opening any incident, framed everything that followed.

I selected **Incident #5** (Active, host `win11a`, actor `PKWORK\mirage`) for full investigation.

---

## Step 2 — Understand the detection type

The incident was raised by an **NRT (Near-Real-Time)** rule, which runs roughly every minute — unlike a scheduled rule that may run hourly. This is the correct rule type for log clearing: when an attacker wipes the security log, the SOC needs to know immediately, not up to an hour later, because log clearing almost always signals an attacker actively covering their tracks.


---

## Step 3 — Establish entities and what happened

**Entities:** account `PKWORK\mirage`, host `win11a`.

**Alert:** the security event log on `win11a` was cleared at **1:59:13 PM on May 9, 2026**. Sentinel tagged the technique as **T1070 – Indicator Removal**.

---

## Step 4 — Corroborate with raw evidence

Rather than trusting the alert title, I confirmed it against the underlying event in the incident's *Related events* panel:

| Field | Value |
|---|---|
| EventID | **1102** |
| Activity | "1102 - The audit log was cleared." |
| Account | PKWORK\mirage |
| HostName | win11a |
| EndTimeUtc | May 9, 2026 1:59:13 PM |

![Incident graph linking mirage to win11a, with the Related events panel confirming EventID 1102 "audit log was cleared" at 1:59:13 PM](9.png)

This is the actual Windows log record, not the alert's description of it. The alert is therefore **corroborated by raw evidence** — Event ID 1102, on `win11a`, by `mirage`, at 1:59:13 PM.

> **Lesson:** evidence is rarely labelled "evidence." It sits in a *Related events* / *Query results* panel, and the analyst must recognise that the row containing EventID 1102 with the actor's name *is* the proof. Verifying the alert against the raw event makes the verdict bulletproof.

---

## Step 5 — Impact assessment

**High impact.** The significance of log clearing is not the act itself but **what it conceals**. Clearing the security log on `win11a` destroys local evidence of everything `mirage` did on that host beforehand, causing a **loss of visibility** for the investigator. Log clearing is rarely an attacker's first action — it typically occurs mid- or late-campaign, indicating an **active intrusion** rather than an early-stage probe.

**Key insight — centralised logging defeats local clearing:** `mirage` cleared the *local* Windows log on `win11a`, but that data was very likely already **forwarded to Sentinel** before the clearing. The endpoint logs are gone; the copies in the SIEM (`SecurityEvent`) remain. This is precisely why centralised logging exists, and it reframes the investigation: reconstruct the lost host activity from forwarded logs in Sentinel.

The open questions (backdoors, persistence, C2, credential theft, data exfiltration) become an **investigation plan**, not vague concern: hunt `win11a` for each of these to confirm or rule them out.

---

## Step 6 — Containment & response (host compromise)

**Critical distinction learned in this lab:** containment is **asset-specific**. The correct response to a compromised Windows *endpoint* is entirely different from the response to a compromised cloud *identity*. Cloud-identity actions (revoking OAuth grants, API tokens, Conditional Access) do not apply to a Windows log-clearing event — those belong to the separate Okta front of the same campaign.

**Response sequence for `win11a` (PICERL):**

1. **Isolate the host** (`win11a`) via Defender device isolation — cut it from the network to stop the bleeding. *This is done first* to prevent **lateral movement**: every second the host stays connected, the attacker can pivot to other machines or accounts. Isolation freezes the blast radius. (Defender's selective isolation keeps the agent connected, so the host can still be investigated remotely while the attacker is locked out.)
2. **Disable the account** (`mirage`) in AD — reset password, terminate active sessions.
3. **Preserve evidence** — pull forwarded logs from Sentinel (local logs are cleared); do not reboot or reimage yet.
4. **Hunt** — with host isolated and account disabled, investigate what the log clearing was meant to hide: persistence, backdoors, C2, credential theft, exfiltration.
5. **Eradicate** — remove *what the hunt finds* (specific backdoor/persistence), rotate any affected credentials.
6. **Recover** — once verified clean, restore the host to the network and normal operations.
7. **Cross-link containment** — ensure the *cloud identity* front of `mirage`'s campaign (Okta API token / OAuth grants / Conditional Access) is contained in parallel, since it is the same actor operating on a second front.

**Precision note:** you *isolate a host* and *disable an account* — two different actions on two different objects. Isolation is a network-level action on a device; disabling is a credential-level action on an account.

---

## MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Defense Evasion | T1070.001 – Indicator Removal: Clear Windows Event Logs | Event ID 1102 on `win11a` by `mirage` |

---

## Lessons learned

- **Triage the queue, not just the ticket.** The campaign theme (one actor, evidence destruction across cloud and endpoint) was visible only by reading the whole queue first.
- **Corroborate alerts with raw evidence.** The 1102 event in *Related events* turns "the alert says so" into "I verified it."
- **Log clearing matters for what it hides.** The impact is loss of visibility and a likely active intrusion, not the clearing itself.
- **Centralised logging defeats local log clearing.** Forwarded logs in the SIEM survive an attacker wiping the endpoint.
- **Containment is asset-specific.** A compromised endpoint (isolate host + disable account) is contained differently from a compromised cloud identity (revoke tokens/OAuth). Reciting a previous incident's steps is a failure mode; reason from the current asset.
- **Isolate first to prevent lateral movement.** Containing the spread takes priority over investigating detail while an attacker is live.
- **Correlate across incidents.** Same actor across multiple incidents = one campaign requiring containment on every front.

---

## Skills demonstrated

Incident triage · Queue-level campaign correlation · Alert corroboration with raw evidence · NRT vs. scheduled rule reasoning · Impact assessment · PICERL incident-response lifecycle · Asset-specific containment · Lateral-movement prevention · MITRE ATT&CK mapping
