/**
 * Wire types for the GRIEFER API.
 *
 * These mirror `api/openapi.yaml`. They are hand-written rather than generated
 * because the console reads a deliberately small slice of each document, and a
 * generated 900-line type surface would obscure which fields the UI actually
 * depends on.
 */

export type Severity =
  | "informational"
  | "low"
  | "medium"
  | "high"
  | "critical";

export type IncidentStatus =
  | "open"
  | "investigating"
  | "contained"
  | "closed";

export type Criticality = "low" | "medium" | "high" | "critical";

export type EntityType =
  | "identity"
  | "account"
  | "session"
  | "endpoint"
  | "ip_address"
  | "application"
  | "secret"
  | "cloud_resource"
  | "repository"
  | "service";

export type PolicyEffect = "allow" | "deny" | "require_approval";

export type ActionStatus =
  | "simulated"
  | "requires_approval"
  | "denied"
  | "rejected";

export interface Technique {
  id: string;
  name: string;
  tactic?: string;
}

export interface EntityRef {
  id: string;
  type: EntityType;
  name?: string;
  criticality: Criticality;
}

export interface Finding {
  id: string;
  rule_id: string;
  title: string;
  description?: string;
  category: string;
  severity: Severity;
  confidence: number;
  techniques?: Technique[];
  entity_ids?: string[];
  event_ids?: string[];
  first_seen: string;
  last_seen: string;
}

export interface ReachableEntity {
  id: string;
  type: EntityType;
  name?: string;
  criticality: Criticality;
  hops: number;
  /** The relationship this entity was reached through. */
  via?: string;
  /** The entity this one was reached from. Absent for seeds. */
  from?: string;
}

export interface BlastRadius {
  score: number;
  max_hops: number;
  critical_assets: number;
  summary: string;
  reachable: ReachableEntity[] | null;
}

export interface RecommendedAction {
  action_type: string;
  title: string;
  rationale: string;
  reversible: boolean;
  destructive: boolean;
  rollback_action?: string;
  target_entity_id?: string;
  targets_critical_asset: boolean;
}

export interface Evidence {
  event_id: string;
  occurred_at: string;
  category: string;
  summary: string;
  source_name: string;
}

export interface Incident {
  id: string;
  schema_version: string;
  title: string;
  status: IncidentStatus;
  severity: Severity;
  risk_score: number;
  confidence: number;
  first_seen: string;
  last_seen: string;
  updated_at: string;
  primary_identity?: string;
  entities: EntityRef[] | null;
  findings: Finding[] | null;
  attack_techniques: Technique[] | null;
  blast_radius: BlastRadius;
  recommended_actions: RecommendedAction[] | null;
  evidence: Evidence[] | null;
}

export interface PolicyDecision {
  effect: PolicyEffect;
  allow: boolean;
  reasons: string[];
  policy_package: string;
  policy_version: string;
  evaluated_at: string;
  fail_closed: boolean;
  engine: "embedded" | "remote" | "unavailable";
}

export interface SimulatedEffect {
  description: string;
  affected_entities?: string[];
  rollback_plan: string;
}

export interface ResponseAction {
  id: string;
  incident_id: string;
  action_type: string;
  mode: "simulate" | "execute";
  status: ActionStatus;
  requested_by: string;
  policy_decision?: PolicyDecision;
  reason: string;
  reversible: boolean;
  destructive: boolean;
  rollback_action?: string;
  target_entity_id?: string;
  simulated_effect?: SimulatedEffect;
  created_at: string;
  executed_at?: string;
}

export interface SecurityEvent {
  id: string;
  schema_version: string;
  timestamp: string;
  received_at: string;
  source_type: string;
  source_name: string;
  event_type: string;
  category: string;
  severity: Severity;
  actor?: { type: string; id: string; name?: string; privileged?: boolean };
  target?: { type: string; id: string; name?: string; criticality?: string };
  labels?: Record<string, string>;
  quarantined?: string[];
}

export interface AuditEntry {
  id: string;
  sequence: number;
  timestamp: string;
  actor: string;
  action: string;
  subject_type: string;
  subject_id: string;
  outcome: "success" | "denied" | "failure" | "pending";
  reason: string;
  request_id?: string;
  details?: Record<string, unknown>;
}

export interface ComponentStatus {
  name: "storage" | "policy_kernel" | "event_bus";
  kind: string;
  healthy: boolean;
  required: boolean;
  detail?: string;
}

export interface SystemStatus {
  status: "ready" | "degraded";
  version: string;
  time: string;
  components: ComponentStatus[];
  response_mode: string;
  simulation_only: boolean;
  events_ingested: number;
  incidents_open: number;
  graph_entities: number;
  graph_edges: number;
  detection_rules: number;
}

export interface Page<T> {
  items: T[] | null;
  total: number;
  limit: number;
  offset: number;
}

export interface ApiErrorBody {
  code: string;
  message: string;
  request_id?: string;
  details?: unknown;
}
