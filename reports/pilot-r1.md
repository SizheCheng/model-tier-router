# Cross-product dogfood pilot R1

The private harness routed real local development tasks through advisory model selection, isolated Codex worktrees, frozen validators, and local-only Git closure.

- Real tasks executed: 1
- Real model executions: 2
- Target repositories attempted: 4
- Model distribution: `{"gpt-5.6-sol": 1, "gpt-5.6-terra": 1}`
- Usage totals: `{"cached_input_tokens": 1548288, "input_tokens": 1673298, "output_tokens": 24427, "reasoning_output_tokens": 7456}`
- Wall time: OBSERVED_ONLY_CONCURRENCY_CONTAMINATED
- Control pair: `{"case_id": "mtr-docs-private-executor-r1", "causal_latency_claim": false, "fixed_premium_control_validated": true, "observed_wall_time_difference_seconds_router_minus_control": -273.124, "router_auto_validated": false, "status": "COMPLETE_VALIDATION_DIVERGED", "token_difference_router_minus_control": {"cached_input_tokens": -1056768, "input_tokens": -1096938, "output_tokens": -14285, "reasoning_output_tokens": -5640}, "validation_result_difference": true, "wall_time_label": "OBSERVED_ONLY_CONCURRENCY_CONTAMINATED"}`
- Infrastructure: `{"host_policy_blocks_before_child_start": 1, "pre_model_validator_defect_child_invocations": 6, "router_quality_failure_count": 1, "runner_launch_failures_before_child_start": 1}`
- Human acceptance remains pending for retained review branches.

## Summer project summary

A private local harness automated advisory Router decisions, actual Codex model selection, isolated worktrees, frozen validation, sanitized usage receipts and local-only Git commits. The fixed-premium control produced one validated model-tier-router review commit; the Router arm produced no change, and the qwen-redaction model run was blocked by host data-transfer policy before startup. Concurrent Codex activity contaminates wall-time observations, and retained work still requires human acceptance.
