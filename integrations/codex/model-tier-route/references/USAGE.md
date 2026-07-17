# Model Tier Route Usage

Invoke `$model-tier-route` explicitly with one UTF-8 strict JSON request:

```json
{"schema_version":"model_tier_router_advisory_request_v1alpha1","request_id":"example","requirements":{"modalities":["text"],"maximum_cost_class":"medium"},"preferences":["higher_reasoning"],"evidence":{"modalities":true}}
```

The supported command is:

```powershell
Get-Content -Raw -Encoding UTF8 request.json | model-tier-router assess
```

The command emits exactly one canonical JSON object. It performs deterministic
hard-constraint filtering before soft-preference ranking. It does not call a
provider, execute the task, read credentials, switch models, authorize writes,
or automatically escalate. Escalation metadata only describes when a caller
may request a new assessment.

Historical governed calls remain separately documented in
`docs/governed-mode.md`; their verifier ports are never constructed by this
Skill.
