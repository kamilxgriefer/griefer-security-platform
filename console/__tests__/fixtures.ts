import type {
  AuditEntry,
  Incident,
  ResponseAction,
  SecurityEvent,
  SystemStatus,
} from "@/lib/types";

/**
 * Synthetic fixtures mirroring what the GRIEFER API returns for the demo
 * scenario. They are hand-written from real API output rather than invented, so
 * a shape change in the backend surfaces here.
 */

export const systemStatus: SystemStatus = {
  status: "ready",
  version: "0.1.0",
  time: "2026-08-23T12:00:00Z",
  components: [
    { name: "storage", kind: "postgres", healthy: true, required: true },
    { name: "policy_kernel", kind: "remote", healthy: true, required: true },
    { name: "event_bus", kind: "nats-jetstream", healthy: true, required: false },
  ],
  response_mode: "simulate",
  simulation_only: true,
  events_ingested: 5,
  incidents_open: 1,
  graph_entities: 12,
  graph_edges: 14,
  detection_rules: 6,
};

export const degradedStatus: SystemStatus = {
  ...systemStatus,
  status: "degraded",
  components: [
    { name: "storage", kind: "postgres", healthy: true, required: true },
    {
      name: "policy_kernel",
      kind: "unavailable",
      healthy: false,
      required: true,
      detail: "policy kernel cannot evaluate; response actions will fail closed",
    },
    {
      name: "event_bus",
      kind: "nats-jetstream",
      healthy: false,
      required: false,
      detail: "event bus is unavailable; ingestion continues without fan-out",
    },
  ],
};

export const incident: Incident = {
  id: "inc-01a02e7e-a36d-7ce4-bd04-368597500ebe",
  schema_version: "0.1",
  title: "Multi-stage activity involving j.okafor@halberd.example (5 evidence categories)",
  status: "open",
  severity: "critical",
  risk_score: 81,
  confidence: 0.95,
  first_seen: "2026-08-23T09:14:22Z",
  last_seen: "2026-08-23T09:41:58Z",
  updated_at: "2026-08-23T09:41:59Z",
  primary_identity: "identity:u-1042",
  entities: [
    { id: "identity:u-1042", type: "identity", name: "j.okafor@halberd.example", criticality: "high" },
    { id: "endpoint:wks-4471", type: "endpoint", name: "wks-4471.halberd.example", criticality: "medium" },
    { id: "secret:sec-billing-api-key", type: "secret", name: "billing-portal/api-key", criticality: "critical" },
    {
      id: "cloud_resource:arn:aws:s3:::halberd-finance-archive",
      type: "cloud_resource",
      name: "halberd-finance-archive",
      criticality: "critical",
    },
  ],
  findings: [
    {
      id: "fnd-1",
      rule_id: "GRF-CORR-0001",
      title: "Sign-in from an address not previously seen for this identity",
      description: "The identity provider reported a successful interactive sign-in from a new source address.",
      category: "authentication",
      severity: "medium",
      confidence: 0.55,
      techniques: [{ id: "T1078", name: "Valid Accounts", tactic: "Initial Access" }],
      event_ids: ["evt-1"],
      first_seen: "2026-08-23T09:14:22Z",
      last_seen: "2026-08-23T09:14:22Z",
    },
    {
      id: "fnd-2",
      rule_id: "GRF-CORR-0004",
      title: "Application secret retrieved",
      description: "A stored application secret was read.",
      category: "credential_access",
      severity: "high",
      confidence: 0.8,
      techniques: [{ id: "T1552.001", name: "Unsecured Credentials: Credentials In Files" }],
      event_ids: ["evt-4"],
      first_seen: "2026-08-23T09:33:12Z",
      last_seen: "2026-08-23T09:33:12Z",
    },
  ],
  attack_techniques: [
    { id: "T1078", name: "Valid Accounts", tactic: "Initial Access" },
    { id: "T1552.001", name: "Unsecured Credentials: Credentials In Files" },
  ],
  blast_radius: {
    score: 96,
    max_hops: 2,
    critical_assets: 2,
    summary: "10 entities reachable within 2 hops, including 2 assets classified critical.",
    reachable: [
      { id: "identity:u-1042", type: "identity", name: "j.okafor@halberd.example", criticality: "high", hops: 0 },
      { id: "secret:sec-billing-api-key", type: "secret", name: "billing-portal/api-key", criticality: "critical", hops: 0 },
      {
        id: "service:svc-payments-api",
        type: "service",
        name: "Payments API",
        criticality: "high",
        hops: 1,
        via: "runs_on",
        from: "cloud_resource:arn:aws:s3:::halberd-finance-archive",
      },
    ],
  },
  recommended_actions: [
    {
      action_type: "preserve_evidence",
      title: "Preserve evidence",
      rationale: "Evidence should be held before any containment step changes the state an investigation depends on.",
      reversible: true,
      destructive: false,
      rollback_action: "release_evidence_hold",
      target_entity_id: "identity:u-1042",
      targets_critical_asset: false,
    },
    {
      action_type: "rotate_exposed_secret",
      title: "Rotate exposed secret",
      rationale: "A stored secret was read; rotation retires the value the attacker may now hold.",
      reversible: false,
      destructive: false,
      target_entity_id: "secret:sec-billing-api-key",
      targets_critical_asset: true,
    },
  ],
  evidence: [
    {
      event_id: "evt-1",
      occurred_at: "2026-08-23T09:14:22Z",
      category: "authentication",
      summary: "j.okafor@halberd.example: user_signin on Halberd Billing Portal",
      source_name: "synthetic-idp-lab",
    },
    {
      event_id: "evt-4",
      occurred_at: "2026-08-23T09:33:12Z",
      category: "credential_access",
      summary: "j.okafor@halberd.example: secret_accessed on billing-portal/api-key",
      source_name: "synthetic-vault-lab",
    },
  ],
};

export const allowedAction: ResponseAction = {
  id: "act-allow",
  incident_id: incident.id,
  action_type: "preserve_evidence",
  mode: "simulate",
  status: "simulated",
  requested_by: "analyst:demo",
  reason: "Action is non-destructive and reversible.",
  reversible: true,
  destructive: false,
  rollback_action: "release_evidence_hold",
  created_at: "2026-08-23T09:45:00Z",
  policy_decision: {
    effect: "allow",
    allow: true,
    reasons: [
      'Action "preserve_evidence" is non-destructive and reversible via "release_evidence_hold", corroborated by 5 independent evidence categories at risk score 81, and runs in "simulate" mode.',
    ],
    policy_package: "griefer.response",
    policy_version: "0.1.0",
    evaluated_at: "2026-08-23T09:45:00Z",
    fail_closed: false,
    engine: "embedded",
  },
  simulated_effect: {
    description: "Would place a retention hold on 1 linked entities; no access is changed.",
    affected_entities: ["identity:u-1042"],
    rollback_plan: 'Run "release_evidence_hold" to reverse this action.',
  },
};

export const approvalAction: ResponseAction = {
  id: "act-approval",
  incident_id: incident.id,
  action_type: "rotate_exposed_secret",
  mode: "simulate",
  status: "requires_approval",
  requested_by: "analyst:demo",
  reason: "Action is not reversible.",
  reversible: false,
  destructive: false,
  created_at: "2026-08-23T09:46:00Z",
  policy_decision: {
    effect: "require_approval",
    allow: false,
    reasons: [
      'Action "rotate_exposed_secret" is not reversible. An action that cannot be undone requires an explicit human decision.',
      "Action targets an asset classified critical. Critical assets always require human approval.",
    ],
    policy_package: "griefer.response",
    policy_version: "0.1.0",
    evaluated_at: "2026-08-23T09:46:00Z",
    fail_closed: false,
    engine: "embedded",
  },
};

export const failClosedAction: ResponseAction = {
  ...allowedAction,
  id: "act-failclosed",
  status: "denied",
  reason: "Policy Kernel is unreachable; GRIEFER fails closed and denies the action.",
  policy_decision: {
    effect: "deny",
    allow: false,
    reasons: ["Policy Kernel is unreachable; GRIEFER fails closed and denies the action."],
    policy_package: "griefer.response",
    policy_version: "0.1.0",
    evaluated_at: "2026-08-23T09:47:00Z",
    fail_closed: true,
    engine: "unavailable",
  },
};

export const events: SecurityEvent[] = [
  {
    id: "evt-1",
    schema_version: "0.1",
    timestamp: "2026-08-23T09:14:22Z",
    received_at: "2026-08-23T09:14:23Z",
    source_type: "identity_provider",
    source_name: "synthetic-idp-lab",
    event_type: "user_signin",
    category: "authentication",
    severity: "medium",
    actor: { type: "identity", id: "u-1042", name: "j.okafor@halberd.example" },
  },
  {
    id: "evt-5",
    schema_version: "0.1",
    timestamp: "2026-08-23T09:41:58Z",
    received_at: "2026-08-23T09:41:59Z",
    source_type: "cloud_audit",
    source_name: "synthetic-cloudtrail-lab",
    event_type: "cloud_resource_access",
    category: "cloud_access",
    severity: "critical",
    actor: { type: "identity", id: "u-1042", name: "j.okafor@halberd.example" },
  },
];

export const auditEntries: AuditEntry[] = [
  {
    id: "aud-1",
    sequence: 1,
    timestamp: "2026-08-23T09:14:23Z",
    actor: "system:griefer",
    action: "event.ingested",
    subject_type: "event",
    subject_id: "evt-1",
    outcome: "success",
    reason: "event accepted from identity_provider/synthetic-idp-lab",
  },
  {
    id: "aud-2",
    sequence: 2,
    timestamp: "2026-08-23T09:45:00Z",
    actor: "system:griefer",
    action: "policy.evaluated",
    subject_type: "action",
    subject_id: "act-allow",
    outcome: "success",
    reason: "Action is non-destructive and reversible.",
  },
];
