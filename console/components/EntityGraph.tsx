import type { Criticality, EntityRef, ReachableEntity } from "@/lib/types";
import { criticalityRank } from "@/lib/format";

const TYPE_GLYPH: Record<string, string> = {
  identity: "ID",
  account: "AC",
  session: "SE",
  endpoint: "EP",
  ip_address: "IP",
  application: "AP",
  secret: "SK",
  cloud_resource: "CR",
  repository: "RE",
  service: "SV",
};

const CRITICALITY_COLOR: Record<string, string> = {
  critical: "var(--color-sev-critical)",
  high: "var(--color-sev-high)",
  medium: "var(--color-sev-low)",
  low: "var(--color-text-muted)",
};

interface Node {
  id: string;
  label: string;
  type: string;
  criticality: Criticality;
  hops: number;
  from?: string | undefined;
  via?: string | undefined;
  x: number;
  y: number;
}

const COLUMN_WIDTH = 250;
const ROW_HEIGHT = 44;
const TOP_PADDING = 34;
const LEFT_PADDING = 26;
const NODE_RADIUS = 13;
const LABEL_CHARS = 24;

/**
 * EntityGraph lays the incident's entities out in columns by hop distance:
 * column 0 is what the attacker touched, column 1 is one step away, and so on.
 *
 * Two decisions are load-bearing.
 *
 * It draws only edges the API actually reported. Each reachable entity carries
 * the entity it was reached from, so every line here corresponds to a real
 * relationship in the Security Graph. A diagram that infers plausible-looking
 * links is worse than no diagram: it invents evidence.
 *
 * It is hand-written SVG rather than a graph library. "How far is this from the
 * compromise" is the entire question the picture answers, and a force-directed
 * layout would obscure exactly that while adding a large client-side dependency
 * to a security console.
 */
export function EntityGraph({
  entities,
  reachable,
}: {
  readonly entities: readonly EntityRef[];
  readonly reachable: readonly ReachableEntity[];
}) {
  const { nodes, columns } = layout(entities, reachable);

  if (nodes.length === 0) {
    return (
      <p className="py-6 text-center text-[13px] text-[var(--color-text-muted)]">
        No entities are linked to this incident yet.
      </p>
    );
  }

  const byId = new Map(nodes.map((node) => [node.id, node]));
  const tallest = Math.max(...columns.map((column) => column.length));
  const width = LEFT_PADDING * 2 + columns.length * COLUMN_WIDTH;
  const height = TOP_PADDING + tallest * ROW_HEIGHT + 16;
  const maxHops = columns.length - 1;

  return (
    <figure className="m-0">
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          aria-label={`Entity relationship map: ${columns[0]?.length ?? 0} entities directly involved, ${
            nodes.length - (columns[0]?.length ?? 0)
          } further entities reachable within ${maxHops} hops`}
          className="h-auto w-full"
          style={{ minWidth: `${Math.min(width, 900)}px` }}
        >
          <g>
            {columns.map((_column, index) => (
              <text
                key={`heading-${index}`}
                x={LEFT_PADDING + index * COLUMN_WIDTH}
                y={16}
                fontSize="10"
                fontFamily="var(--font-mono)"
                fill="var(--color-text-muted)"
              >
                {index === 0 ? "INVOLVED" : `${index} HOP${index === 1 ? "" : "S"}`}
              </text>
            ))}
          </g>

          <g stroke="var(--color-surface-border-strong)" strokeWidth="1">
            {nodes.map((node) => {
              if (!node.from) return null;
              const parent = byId.get(node.from);
              if (!parent) return null;
              return (
                <line
                  key={`edge-${parent.id}-${node.id}`}
                  x1={parent.x + NODE_RADIUS}
                  y1={parent.y}
                  x2={node.x - NODE_RADIUS}
                  y2={node.y}
                />
              );
            })}
          </g>

          {nodes.map((node) => (
            <g key={node.id}>
              <circle
                cx={node.x}
                cy={node.y}
                r={NODE_RADIUS}
                fill="var(--color-surface-overlay)"
                stroke={CRITICALITY_COLOR[node.criticality] ?? CRITICALITY_COLOR.medium}
                strokeWidth={node.hops === 0 ? 2 : 1}
              />
              <text
                x={node.x}
                y={node.y + 3.5}
                textAnchor="middle"
                fontSize="9"
                fontFamily="var(--font-mono)"
                fill="var(--color-text-secondary)"
              >
                {TYPE_GLYPH[node.type] ?? "??"}
              </text>
              <text
                x={node.x + NODE_RADIUS + 7}
                y={node.y - 1}
                fontSize="11"
                fill="var(--color-text-primary)"
              >
                {truncate(node.label, LABEL_CHARS)}
              </text>
              <text
                x={node.x + NODE_RADIUS + 7}
                y={node.y + 11}
                fontSize="9"
                fontFamily="var(--font-mono)"
                fill="var(--color-text-muted)"
              >
                {node.via ? `${node.type} · ${node.via}` : node.type}
              </text>
            </g>
          ))}
        </svg>
      </div>
      <figcaption className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-[var(--color-text-muted)]">
        <span>Columns are hop distance from the entities the attacker touched.</span>
        <span>Lines are relationships the Security Graph actually recorded.</span>
        <span>Outline colour indicates asset criticality.</span>
      </figcaption>
    </figure>
  );
}

function layout(
  entities: readonly EntityRef[],
  reachable: readonly ReachableEntity[],
): { nodes: Node[]; columns: Node[][] } {
  const seeds = new Map<string, Omit<Node, "x" | "y">>();
  for (const entity of entities) {
    seeds.set(entity.id, {
      id: entity.id,
      label: entity.name || entity.id,
      type: entity.type,
      criticality: entity.criticality,
      hops: 0,
    });
  }

  const byHop = new Map<number, Omit<Node, "x" | "y">[]>();
  for (const item of reachable) {
    if (item.hops === 0) {
      // The blast-radius seeds and the incident's entities are the same set;
      // prefer the incident's richer reference when both exist.
      if (!seeds.has(item.id)) {
        seeds.set(item.id, {
          id: item.id,
          label: item.name || item.id,
          type: item.type,
          criticality: item.criticality,
          hops: 0,
        });
      }
      continue;
    }
    const bucket = byHop.get(item.hops) ?? [];
    bucket.push({
      id: item.id,
      label: item.name || item.id,
      type: item.type,
      criticality: item.criticality,
      hops: item.hops,
      from: item.from,
      via: item.via,
    });
    byHop.set(item.hops, bucket);
  }
  byHop.set(0, [...seeds.values()]);

  const columns: Node[][] = [];
  const nodes: Node[] = [];
  const hopValues = [...byHop.keys()].sort((a, b) => a - b);

  for (const [columnIndex, hops] of hopValues.entries()) {
    const bucket = (byHop.get(hops) ?? []).sort(
      (a, b) =>
        criticalityRank(b.criticality) - criticalityRank(a.criticality) ||
        a.id.localeCompare(b.id),
    );
    const placed = bucket.map((item, row) => ({
      ...item,
      x: LEFT_PADDING + columnIndex * COLUMN_WIDTH + NODE_RADIUS,
      y: TOP_PADDING + row * ROW_HEIGHT,
    }));
    columns.push(placed);
    nodes.push(...placed);
  }

  return { nodes, columns };
}

function truncate(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}
