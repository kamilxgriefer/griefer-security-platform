import { describe, expect, it } from "vitest";

import { DEFAULT_ROLE, ROLES, isRole, mayAccess, mayManageAccounts, roleLabel } from "@/lib/roles";

describe("roles", () => {
  it("recognises only the roles it defines", () => {
    for (const role of ROLES) expect(isRole(role)).toBe(true);
    for (const bad of ["root", "ADMIN", "", "superuser", null, undefined, 1, {}]) {
      expect(isRole(bad)).toBe(false);
    }
  });

  it("gives a new account the lower privilege by default", () => {
    // If this ever becomes "admin", every account provisioned without an
    // explicit role silently becomes an administrator.
    expect(DEFAULT_ROLE).toBe("analyst");
  });

  it("lets an administrator reach everything", () => {
    for (const path of ["/", "/incidents", "/incidents/abc", "/audit", "/admin/users"]) {
      expect(mayAccess("admin", path)).toBe(true);
    }
  });

  it("keeps an analyst out of account management and the audit trail", () => {
    for (const path of ["/admin", "/admin/users", "/audit", "/audit/anything"]) {
      expect(mayAccess("analyst", path)).toBe(false);
    }
  });

  it("keeps an analyst out of the same resources through the API", () => {
    // Gating the page but not the route it calls would leave the data readable
    // by anyone who opened the network tab.
    for (const path of [
      "/api/griefer/audit",
      "/api/griefer/audit/1",
      // The integrity endpoint publishes the trail's size and its head hash.
      // It sits under the audit prefix so this rule already covers it; the case
      // is written out because a future move out of that prefix would silently
      // open it.
      "/api/griefer/audit/verify",
      "/api/griefer/identity/users",
    ]) {
      expect(mayAccess("analyst", path)).toBe(false);
    }
  });

  it("lets an analyst work with incidents", () => {
    for (const path of ["/", "/incidents", "/incidents/abc", "/api/griefer/incidents"]) {
      expect(mayAccess("analyst", path)).toBe(true);
    }
  });

  it("does not treat a path that merely starts with the same letters as protected", () => {
    // "/auditor-notes" is not inside "/audit", and a naive startsWith would
    // block it. The reverse mistake matters more: "/administer" must not be
    // mistaken for a public path either way round.
    expect(mayAccess("analyst", "/auditorium")).toBe(true);
    expect(mayAccess("analyst", "/administrivia")).toBe(true);
    expect(mayAccess("analyst", "/audit")).toBe(false);
    expect(mayAccess("analyst", "/audit/")).toBe(false);
  });

  it("restricts account management to administrators", () => {
    expect(mayManageAccounts("admin")).toBe(true);
    expect(mayManageAccounts("analyst")).toBe(false);
  });

  it("labels roles for display", () => {
    expect(roleLabel("admin")).toBe("Administrator");
    expect(roleLabel("analyst")).toBe("Analyst");
  });
});
