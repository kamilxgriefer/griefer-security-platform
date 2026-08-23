import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { IncidentDetail } from "@/components/IncidentDetail";
import { allowedAction, approvalAction, failClosedAction, incident } from "./fixtures";

describe("IncidentDetail", () => {
  it("renders the incident header with severity, status and identity", () => {
    render(<IncidentDetail incident={incident} actions={[]} />);

    const header = screen.getByRole("heading", { level: 1 }).closest("header");
    expect(header).not.toBeNull();
    expect(header).toHaveTextContent(/multi-stage activity/i);
    expect(within(header as HTMLElement).getByText("critical")).toBeInTheDocument();
    expect(within(header as HTMLElement).getByText("open")).toBeInTheDocument();
    expect(within(header as HTMLElement).getByText("identity:u-1042")).toBeInTheDocument();
  });

  it("shows risk, confidence, blast radius and evidence counts", () => {
    render(<IncidentDetail incident={incident} actions={[]} />);

    expect(screen.getByTestId("stat-risk-score")).toHaveTextContent("81");
    expect(screen.getByTestId("stat-confidence")).toHaveTextContent("95%");
    expect(screen.getByTestId("stat-blast-radius")).toHaveTextContent("96");
    expect(screen.getByTestId("stat-blast-radius")).toHaveTextContent(/2 critical assets/);
    expect(screen.getByTestId("stat-evidence")).toHaveTextContent(/2 independent categories/);
  });

  it("annotates ATT&CK techniques", () => {
    render(<IncidentDetail incident={incident} actions={[]} />);

    expect(screen.getByText("T1078")).toBeInTheDocument();
    expect(screen.getByText("T1552.001")).toBeInTheDocument();
    expect(screen.getByText(/not a coverage claim/i)).toBeInTheDocument();
  });

  it("renders the timeline in order with source attribution", () => {
    render(<IncidentDetail incident={incident} actions={[]} />);

    const timeline = screen.getByRole("heading", { name: /^timeline$/i }).closest("section");
    expect(timeline).not.toBeNull();
    const items = within(timeline as HTMLElement).getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent("user_signin");
    expect(items[0]).toHaveTextContent("synthetic-idp-lab");
    expect(items[1]).toHaveTextContent("secret_accessed");
  });

  it("lists findings with their rule id and confidence", () => {
    render(<IncidentDetail incident={incident} actions={[]} />);

    expect(screen.getByText("GRF-CORR-0001")).toBeInTheDocument();
    expect(screen.getByText("GRF-CORR-0004")).toBeInTheDocument();
    expect(screen.getByText(/Confidence: 55%/)).toBeInTheDocument();
  });

  it("draws the entity relationship map", () => {
    render(<IncidentDetail incident={incident} actions={[]} />);

    const figure = screen.getByRole("img", { name: /entity relationship map/i });
    expect(figure).toBeInTheDocument();
    expect(screen.getByText(/outline colour indicates asset criticality/i)).toBeInTheDocument();
  });

  it("separates what was touched from what it unlocks", () => {
    render(<IncidentDetail incident={incident} actions={[]} />);

    const reachable = screen
      .getByRole("heading", { name: /reachable within the graph/i })
      .closest("section");
    expect(reachable).not.toBeNull();
    // Only entities more than zero hops away belong in this panel.
    expect(within(reachable as HTMLElement).getByText("Payments API")).toBeInTheDocument();
    expect(within(reachable as HTMLElement).getByText(/1 hop$/)).toBeInTheDocument();
  });

  it("states reversibility and rollback for every recommended action", () => {
    render(<IncidentDetail incident={incident} actions={[]} />);

    expect(screen.getByText("reversible")).toBeInTheDocument();
    expect(screen.getByText("not reversible")).toBeInTheDocument();
    expect(screen.getByText("release_evidence_hold")).toBeInTheDocument();
    expect(screen.getByText(/none defined — requires human approval/i)).toBeInTheDocument();
    expect(screen.getByText("critical asset")).toBeInTheDocument();
  });

  it("shows the Policy Kernel verdict and the simulated effect", () => {
    render(<IncidentDetail incident={incident} actions={[allowedAction, approvalAction]} />);

    const allowed = screen.getByTestId("policy-decision-preserve_evidence");
    expect(allowed).toHaveTextContent("Allow");
    expect(allowed).toHaveTextContent("griefer.response@0.1.0");
    expect(allowed).toHaveTextContent(/would place a retention hold/i);
    expect(allowed).toHaveTextContent(/release_evidence_hold.*to reverse/i);

    const approval = screen.getByTestId("policy-decision-rotate_exposed_secret");
    expect(approval).toHaveTextContent("Require approval");
    expect(approval).toHaveTextContent(/is not reversible/i);
    expect(approval).toHaveTextContent(/classified critical/i);
    // An action awaiting approval must not show an effect it did not have.
    expect(approval).not.toHaveTextContent(/simulated:/i);
  });

  it("marks a decision produced by the fail-closed path", () => {
    render(<IncidentDetail incident={incident} actions={[failClosedAction]} />);

    const decision = screen.getByTestId("policy-decision-preserve_evidence");
    expect(decision).toHaveTextContent("fail-closed");
    expect(decision).toHaveTextContent("Deny");
    expect(decision).toHaveTextContent(/unreachable/i);
  });

  it("renders an incident whose optional collections are null", () => {
    // The Go API omits empty slices, which arrive as null rather than [].
    render(
      <IncidentDetail
        incident={{
          ...incident,
          findings: null,
          entities: null,
          evidence: null,
          attack_techniques: null,
          recommended_actions: null,
          blast_radius: { ...incident.blast_radius, reachable: null },
        }}
        actions={[]}
      />,
    );

    expect(screen.getByRole("heading", { level: 1 })).toBeInTheDocument();
    expect(screen.getByText(/no evidence recorded/i)).toBeInTheDocument();
    expect(screen.getByText(/no actions recommended/i)).toBeInTheDocument();
    expect(screen.getByText(/no entities are linked to this incident yet/i)).toBeInTheDocument();
  });
});
