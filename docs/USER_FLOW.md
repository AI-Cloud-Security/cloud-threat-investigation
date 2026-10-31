# Analyst journey

The analyst brings a set of security records to investigate an identity's access to a resource. The application organizes the records, explains its configured score, records the analyst's decision and preserves the investigation.

```mermaid
flowchart TD
    Start["Open empty workspace"] --> Import["Import normalized records and optional policy"]
    Import --> Inbox["Select an incident"]
    Inbox --> Review["Review source timeline and score"]
    Review --> Assess{"Analyst assessment"}
    Assess -->|Expected activity| Expected["Record expected-activity rationale"]
    Assess -->|More evidence needed| Evidence["Attach records or updated policy"]
    Evidence --> Revision["New revision; reassessment required"]
    Revision --> Review
    Assess -->|Suspected threat| Plan{"Permitted response available?"}
    Plan -->|Yes| Preview["Preview and approve response"]
    Preview --> External["Perform change externally"]
    External --> Outcome{"Record external outcome"}
    Outcome -->|Completed| Resolve["Close as resolved"]
    Outcome -->|Failed or not applied| Escalate["Close as escalated with reference"]
    Plan -->|No| Escalate
    Plan -->|Need policy context| Evidence
    Expected --> Close["Close as expected"]
    Resolve --> Export["Export signed investigation archive"]
    Escalate --> Export
    Close --> Export
    Export --> Verify["Verify against separately trusted public key"]
```

A suspected threat may also be escalated directly with a handoff reference. The diagram shows the primary paths. Open cases can be exported as interim snapshots. Closed cases are read-only, and every evidence revision and recorded workflow action remains available.

An approval records permission for the selected response; it does not execute it. Completion is an analyst statement about an action performed in an external cloud or security console. Use the ticket reference and outcome note to record how completion was checked.
