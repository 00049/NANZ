export type Role = "owner" | "admin" | "analyst" | "viewer" | "billing_admin";

export type Permission =
  | "domains.create" | "domains.delete" | "domains.edit" | "domains.view"
  | "scans.run" | "scans.view"
  | "reports.view" | "reports.export" | "reports.share"
  | "team.invite" | "team.remove" | "team.edit_roles"
  | "billing.view" | "billing.manage"
  | "settings.edit" | "settings.view"
  | "monitoring.configure"
  | "audit.view"
  | "api_keys.manage";

const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  owner: [
    "domains.create", "domains.delete", "domains.edit", "domains.view",
    "scans.run", "scans.view",
    "reports.view", "reports.export", "reports.share",
    "team.invite", "team.remove", "team.edit_roles",
    "billing.view", "billing.manage",
    "settings.edit", "settings.view",
    "monitoring.configure",
    "audit.view",
    "api_keys.manage",
  ],
  admin: [
    "domains.create", "domains.delete", "domains.edit", "domains.view",
    "scans.run", "scans.view",
    "reports.view", "reports.export", "reports.share",
    "team.invite", "team.remove",
    "settings.edit", "settings.view",
    "monitoring.configure",
    "audit.view",
    "api_keys.manage",
  ],
  analyst: [
    "domains.create", "domains.edit", "domains.view",
    "scans.run", "scans.view",
    "reports.view", "reports.export", "reports.share",
    "settings.view",
    "monitoring.configure",
  ],
  viewer: [
    "domains.view",
    "scans.view",
    "reports.view",
    "settings.view",
  ],
  billing_admin: [
    "billing.view", "billing.manage",
    "settings.view",
    "audit.view",
  ],
};

export function hasPermission(role: Role, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role]?.includes(permission) ?? false;
}

export function getRoleLabel(role: Role): string {
  const labels: Record<Role, string> = {
    owner: "Owner",
    admin: "Admin",
    analyst: "Analyst",
    viewer: "Viewer",
    billing_admin: "Billing Admin",
  };
  return labels[role] ?? role;
}

export function getRoleBadgeColor(role: Role): string {
  const colors: Record<Role, string> = {
    owner: "bg-nanz-600/20 text-nanz-400 border-nanz-600/30",
    admin: "bg-purple-600/20 text-purple-400 border-purple-600/30",
    analyst: "bg-emerald-600/20 text-emerald-400 border-emerald-600/30",
    viewer: "bg-gray-600/20 text-gray-400 border-gray-600/30",
    billing_admin: "bg-amber-600/20 text-amber-400 border-amber-600/30",
  };
  return colors[role] ?? "";
}
