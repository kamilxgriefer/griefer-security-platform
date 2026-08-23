import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { Nav } from "@/components/Nav";
import { SimulationBanner } from "@/components/SimulationBanner";

vi.mock("next/navigation", () => ({
  usePathname: () => "/incidents",
}));

describe("Nav", () => {
  it("marks the current section for assistive technology", () => {
    render(<Nav username="admin" role="admin" />);

    const nav = screen.getByRole("navigation", { name: /primary/i });
    const current = within(nav).getAllByRole("link", { name: "Incidents" })[0];
    expect(current).toHaveAttribute("aria-current", "page");

    const dashboard = within(nav).getAllByRole("link", { name: "Dashboard" })[0];
    expect(dashboard).not.toHaveAttribute("aria-current");
  });

  it("collapses behind a disclosure button on a narrow screen", async () => {
    const user = userEvent.setup();
    render(<Nav username="admin" role="admin" />);

    const toggle = screen.getByRole("button", { name: /open navigation/i });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(toggle).toHaveAttribute("aria-controls", "primary-navigation-mobile");
    // The mobile list is not in the DOM until it is opened.
    expect(document.getElementById("primary-navigation-mobile")).toBeNull();

    await user.click(toggle);

    expect(screen.getByRole("button", { name: /close navigation/i })).toHaveAttribute(
      "aria-expanded",
      "true",
    );
    const mobileList = document.getElementById("primary-navigation-mobile");
    expect(mobileList).not.toBeNull();
    expect(within(mobileList as HTMLElement).getByRole("link", { name: "Audit trail" })).toBeInTheDocument();
  });

  it("closes the mobile menu when a destination is chosen", async () => {
    const user = userEvent.setup();
    render(<Nav username="admin" role="admin" />);

    await user.click(screen.getByRole("button", { name: /open navigation/i }));
    const mobileList = document.getElementById("primary-navigation-mobile") as HTMLElement;
    await user.click(within(mobileList).getByRole("link", { name: "Dashboard" }));

    expect(document.getElementById("primary-navigation-mobile")).toBeNull();
  });

  it("hides administrator destinations from an analyst", () => {
    render(<Nav username="nadia" role="analyst" />);

    const nav = screen.getByRole("navigation", { name: /primary/i });
    expect(within(nav).queryByRole("link", { name: "Audit trail" })).toBeNull();
    expect(within(nav).queryByRole("link", { name: "Accounts" })).toBeNull();
    // The analyst's own work is still there.
    expect(within(nav).getAllByRole("link", { name: "Incidents" })[0]).toBeInTheDocument();
  });

  it("shows administrator destinations to an administrator", () => {
    render(<Nav username="admin" role="admin" />);

    const nav = screen.getByRole("navigation", { name: /primary/i });
    expect(within(nav).getAllByRole("link", { name: "Audit trail" })[0]).toBeInTheDocument();
    expect(within(nav).getAllByRole("link", { name: "Accounts" })[0]).toBeInTheDocument();
  });

  it("names the signed-in account and its role", () => {
    render(<Nav username="nadia" role="analyst" />);

    const nav = screen.getByRole("navigation", { name: /primary/i });
    expect(within(nav).getAllByText("nadia")[0]).toBeInTheDocument();
    // Shown so that a missing link reads as a permission, not an outage.
    expect(within(nav).getAllByText("Analyst")[0]).toBeInTheDocument();
  });
});

describe("SimulationBanner", () => {
  it("states plainly that nothing is executed", () => {
    render(<SimulationBanner />);

    const banner = screen.getByTestId("simulation-banner");
    expect(banner).toHaveTextContent(/simulation only/i);
    expect(banner).toHaveTextContent(
      /does not contact identity providers, endpoints or cloud platforms/i,
    );
  });

  it("is announced rather than purely decorative", () => {
    render(<SimulationBanner />);

    const banner = screen.getByRole("status");
    expect(banner).toHaveAttribute("aria-live", "polite");
  });
});
