import { desc, eq, sql } from "drizzle-orm";

import { db } from "@/db";
import { bastionCredential, session, user } from "@/db/schema/auth";
import { requireAdmin } from "@/lib/session";

import { RevokeForm } from "./revoke-form";

/**
 * Non-admins get a 404 from `requireAdmin`, not a 403 — a 403 would confirm
 * the route exists.
 */
export default async function AdminPage() {
  const admin = await requireAdmin();

  const rows = db
    .select({
      id: user.id,
      email: user.email,
      role: user.role,
      bastionUserId: user.bastionUserId,
      createdAt: user.createdAt,
      sessionCount: sql<number>`count(distinct ${session.id})`,
      credentialCount: sql<number>`count(distinct ${bastionCredential.id})`,
    })
    .from(user)
    .leftJoin(session, eq(session.userId, user.id))
    .leftJoin(bastionCredential, eq(bastionCredential.sessionId, session.id))
    .groupBy(user.id)
    .orderBy(desc(user.createdAt))
    .all();

  return (
    <>
      <h1 className="text-2xl font-semibold">Admin</h1>
      <p className="mt-2 text-sm text-bark-600">
        Signed in as {admin.email}. Revocation calls Bastion directly — it is the only page here
        that does.
      </p>

      <table className="mt-6 w-full border-collapse overflow-hidden rounded-lg border border-bark-200 bg-white text-sm">
        <thead className="bg-bark-100 text-left">
          <tr>
            <th className="p-3 font-medium">Email</th>
            <th className="p-3 font-medium">Role</th>
            <th className="p-3 font-medium">Sessions</th>
            <th className="p-3 font-medium">Credentials</th>
            <th className="p-3" />
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id} className="border-t border-bark-200">
              <td className="p-3">{row.email}</td>
              <td className="p-3">{row.role}</td>
              <td className="p-3">{row.sessionCount}</td>
              {/* One credential per session — two devices means two rows. */}
              <td className="p-3">{row.credentialCount}</td>
              <td className="p-3 text-right">
                {row.bastionUserId && <RevokeForm bastionUserId={row.bastionUserId} />}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
