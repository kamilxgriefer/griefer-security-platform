import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AuditTrail } from "@/components/AuditTrail";
import { auditEntries } from "./fixtures";

describe("AuditTrail", () => {
  it("renders entries in sequence with their reason", () => {
    render(<AuditTrail entries={auditEntries} />);

    const rows = screen.getAllByRole("row").slice(1); // skip the header row
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("event.ingested");
    expect(rows[1]).toHaveTextContent("policy.evaluated");
    expect(rows[1]).toHaveTextContent(/non-destructive and reversible/i);
  });

  it("is honest that v0.1 is tamper-resistant rather than tamper-evident", () => {
    render(<AuditTrail entries={auditEntries} />);

    expect(screen.getByText(/tamper-resistant, not tamper-evident/i)).toBeInTheDocument();
  });

  it("distinguishes an empty trail from an unreachable one", () => {
    const { unmount } = render(<AuditTrail entries={[]} />);
    expect(screen.getByText(/no audit entries yet/i)).toBeInTheDocument();
    expect(screen.queryByTestId("error-panel")).not.toBeInTheDocument();
    unmount();

    render(
      <AuditTrail
        entries={[]}
        error={{ message: "The GRIEFER API could not be reached.", code: "api_unreachable" }}
      />,
    );
    expect(screen.getByTestId("error-panel")).toHaveTextContent(/could not be reached/i);
  });
});
