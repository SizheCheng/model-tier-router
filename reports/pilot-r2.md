# Automated dogfood pilot R2

- Codex process starts: 4
- Observable real-model executions: 4
- Usage totals: {"cached_input_tokens": 140544, "input_tokens": 224610, "output_tokens": 8867, "reasoning_output_tokens": 2656}
- Lanes: [{"case_id": "mtr-docs-private-executor-r1", "escalation_count": 1, "escalation_eligible": false, "final_profile_success": false, "final_status": "HOST_POLICY_REJECTED_CHILD_FILESYSTEM_ACCESS", "initial_profile": "balanced", "initial_profile_success": false}, {"case_id": "qwen-docx-hidden-elements-r1", "escalation_count": 1, "escalation_eligible": false, "final_profile_success": false, "final_status": "HOST_POLICY_REJECTED_CHILD_FILESYSTEM_ACCESS", "initial_profile": "balanced", "initial_profile_success": false}]
- Fixed-premium control diff: 2 files, 180 insertions, 0 deletions; each Router attempt changed 0 files and 0 lines.
- Comparison classification: HOST_EXECUTION_POLICY_DIVERGENCE_NOT_MODEL_TIER_UNDER_ROUTING.
- The existing fixed-premium control was read only and was not rerun or merged.
- Wall-time observations are concurrency-contaminated; no causal latency claim is made.
