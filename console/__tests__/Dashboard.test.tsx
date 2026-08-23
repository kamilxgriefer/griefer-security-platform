import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Dashboard, type DashboardData } from "@/components/Dashboard";
import { degradedStatus, events, incident, systemStatus } from "./fixtures";

function build(overrides: Partial<DashboardData> = {}): DashboardData {
  return {
    status: systemStatus,
    incidents: [incident],
    events,
    ...overrides,
  };
}

describe("Dashboard", () => {
  it("renders the pipeline counters", () => {
    render(<Dashboard data={build()} />);

    expect(screen.getByRole("heading", { name: /operations overview/i })).toBeInTheDocument();
    expect(screen.getByTestId("stat-active-incidents")).toHaveTextContent("1");
    expect(screen.getByTestId("stat-events-ingested")).toHaveTextContent("5");
    expect(screen.getByTestId("stat-graph-entities")).toHaveTextContent("12");
    expect(screen.getByTestId("stat-detection-rules")).toHaveTextContent("6");
  });

  it("shows every platform component and its transport", () => {
    render(<Dashboard data={build()} />);

    for (const label of ["Storage", "Policy kernel", "Event bus"]) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
    expect(screen.getByText("postgres")).toBeInTheDocument();
    expect(screen.getByText("nats-jetstream")).toBeInTheDocument();
    expect(screen.getAllByText("healthy")).toHaveLength(3);
  });

  it("distinguishes a required dependency that is down from an optional one", () => {
    render(<Dashboard data={build({ status: degradedStatus })} />);

    // A dead Policy Kernel stops every response action.
    expect(screen.getByText("down")).toBeInTheDocument();
    // A dead event bus only stops fan-out; ingestion continues.
    expect(screen.getByText("degraded")).toBeInTheDocument();
    expect(
      screen.getByText(/ingestion continues without fan-out/i),
    ).toBeInTheDocument();
  });

  it("breaks incidents down by severity", () => {
    render(<Dashboard data={build()} />);

    const panel = screen.getByRole("heading", { name: /incidents by severity/i }).closest("section");
    expect(panel).not.toBeNull();
    expect(within(panel as HTMLElement).getByText("critical")).toBeInTheDocument();
  });

  it("lists open incidents with their risk score", () => {
    render(<Dashboard data={build()} />);

    const link = screen.getByRole("link", { name: /multi-stage activity/i });
    expect(link).toHaveAttribute("href", `/incidents/${incident.id}`);
    expect(screen.getByText("81")).toBeInTheDocument();
  });

  it("renders the latest telemetry feed", () => {
    render(<Dashboard data={build()} />);

    expect(screen.getByText(/User signin/)).toBeInTheDocument();
    expect(screen.getByText(/Cloud resource access/)).toBeInTheDocument();
  });

  it("tells the analyst the difference between 'no incidents' and 'cannot see the platform'", () => {
    const { unmount } = render(<Dashboard data={build({ incidents: [] })} />);
    const emptyCard = screen.getByRole("heading", { name: /open incidents/i }).closest("section");
    expect(within(emptyCard as HTMLElement).getByText(/run `make demo`/i)).toBeInTheDocument();
    expect(screen.queryByTestId("error-panel")).not.toBeInTheDocument();
    unmount();

    render(
      <Dashboard
        data={build({
          incidents: [],
          incidentsError: {
            message: "The GRIEFER API could not be reached.",
            code: "api_unreachable",
            requestId: "req-123",
          },
        })}
      />,
    );
    const panel = screen.getByTestId("error-panel");
    expect(panel).toHaveTextContent(/could not be reached/i);
    expect(panel).toHaveTextContent("api_unreachable");
    expect(panel).toHaveTextContent("req-123");
  });

  it("never shows a reassuring zero when the incident count is unknown", () => {
    // A console that cannot see the platform must not report "0 active
    // incidents" — that is the most dangerous thing this page could display.
    render(
      <Dashboard
        data={build({
          incidents: [],
          incidentsError: { message: "The GRIEFER API could not be reached.", code: "api_unreachable" },
        })}
      />,
    );

    const stat = screen.getByTestId("stat-active-incidents");
    expect(stat).not.toHaveTextContent(/\b0\b/);
    expect(stat).toHaveTextContent("—");
    expect(stat).toHaveTextContent(/unknown/i);
  });

  it("surfaces a platform-status failure without blanking the page", () => {
    render(
      <Dashboard
        data={build({
          status: null,
          statusError: { message: "The GRIEFER API did not respond within 8s.", code: "api_unreachable" },
        })}
      />,
    );

    expect(screen.getByText(/platform status unavailable/i)).toBeInTheDocument();
    // The incident list still rendered.
    expect(screen.getByRole("link", { name: /multi-stage activity/i })).toBeInTheDocument();
  });

  it("flags a deployment that loaded no detection rules", () => {
    render(<Dashboard data={build({ status: { ...systemStatus, detection_rules: 0 } })} />);

    expect(screen.getByTestId("stat-detection-rules")).toHaveTextContent("0");
  });
});
