import { Card } from "@/components/Card";
import { configuredAccounts } from "@/lib/accounts";
import { currentSession } from "@/lib/currentSession";
import { roleLabel } from "@/lib/roles";

export const dynamic = "force-dynamic";
export const revalidate = 0;

/**
 * Who can sign in to this console.
 *
 * middleware.ts has already refused anyone who is not an administrator, so this
 * page does not repeat the check. It lists the accounts the deployment was
 * provisioned with, and says plainly how new ones are made — there is no form
 * here yet, and a form that looked real but saved nothing would be worse than
 * its absence.
 *
 * No salt, hash or password appears on this page or in the payload that renders
 * it. The account list is not secret, but there is no reason for credential
 * material to travel to a browser at all.
 */
export default async function AccountsPage() {
  const accounts = configuredAccounts();
  const session = await currentSession();

  return (
    <div className="flex flex-col gap-4">
      <header>
        <h1 className="text-[20px] font-semibold text-[var(--color-text-primary)]">Accounts</h1>
        <p className="mt-1 text-[13px] text-[var(--color-text-secondary)]">
          Who can sign in, and what each of them may reach.
        </p>
      </header>

      <Card title="Provisioned accounts" subtitle={`${accounts.length} configured`}>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[520px] border-collapse text-[13px]">
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wider text-[var(--color-text-muted)]">
                <th className="border-b border-[var(--color-surface-border)] pb-2 pr-4 font-medium">
                  Username
                </th>
                <th className="border-b border-[var(--color-surface-border)] pb-2 pr-4 font-medium">
                  Role
                </th>
                <th className="border-b border-[var(--color-surface-border)] pb-2 font-medium">
                  May reach
                </th>
              </tr>
            </thead>
            <tbody>
              {accounts.map((account) => (
                <tr key={account.username} data-testid={`account-${account.username}`}>
                  <td className="border-b border-[var(--color-surface-border)] py-2.5 pr-4 font-mono text-[var(--color-text-primary)]">
                    {account.username}
                    {session?.username === account.username && (
                      <span className="ml-2 text-[11px] text-[var(--color-text-muted)]">you</span>
                    )}
                  </td>
                  <td className="border-b border-[var(--color-surface-border)] py-2.5 pr-4">
                    <span
                      className={`rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider ${
                        account.role === "admin"
                          ? "bg-[var(--color-brand-dim)] text-[var(--color-brand-bright)]"
                          : "bg-[var(--color-surface-overlay)] text-[var(--color-text-muted)]"
                      }`}
                    >
                      {roleLabel(account.role)}
                    </span>
                  </td>
                  <td className="border-b border-[var(--color-surface-border)] py-2.5 text-[var(--color-text-secondary)]">
                    {account.role === "admin"
                      ? "Everything, including the audit trail and this page"
                      : "Dashboard and incidents"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Adding an account">
        <div className="flex flex-col gap-3 text-[13px] text-[var(--color-text-secondary)]">
          <p>
            Accounts are provisioned with the deployment, not created from this page. There is no
            self-service registration anywhere in this console: nobody can give themselves an
            account, and no route creates one without an administrator.
          </p>
          <p>
            To add or rotate one, run <code className="font-mono text-[var(--color-brand)]">make secrets</code>{" "}
            and apply the generated values to the deployment. The passwords are written to a file
            with mode 600 on the operator&rsquo;s machine and are never printed, logged or committed.
          </p>
          <p className="text-[var(--color-text-muted)]">
            Creating accounts from this page needs somewhere durable to keep them and an audit
            record of who created whom. That is the next piece of work, and until it exists this
            page deliberately shows no form.
          </p>
        </div>
      </Card>
    </div>
  );
}
