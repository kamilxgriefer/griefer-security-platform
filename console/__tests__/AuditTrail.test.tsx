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

  it("states both what the chain detects and what it is not evidence against", () => {
    render(<AuditTrail entries={auditEntries} />);

    // Both halves are pinned. The claim alone would overstate what a chain
    // stored beside the entries it protects can prove, and the caveat alone
    // would undersell a check that does detect an alteration.
    expect(screen.getByText(/hash-chained/i)).toBeInTheDocument();
    expect(screen.getByText(/not externally anchored/i)).toBeInTheDocument();
    expect(screen.getByText(/not evidence against whoever controls the database/i)).toBeInTheDocument();
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
