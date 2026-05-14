export interface MockUser {
  id: string;
  name: string;
  email: string;
  avatar: string;
  role: "owner" | "admin" | "analyst" | "viewer" | "billing_admin";
  company: string;
  createdAt: string;
}

export const currentUser: MockUser = {
  id: "usr_01",
  name: "Admin User",
  email: "admin@nanz.ai",
  avatar: "",
  role: "owner",
  company: "NANZ Security",
  createdAt: "2025-11-15T10:00:00Z",
};

export const teamMembers: MockUser[] = [
  currentUser,
  { id: "usr_02", name: "Priya Sharma", email: "priya@nanz.ai", avatar: "", role: "admin", company: "NANZ Security", createdAt: "2025-12-01T10:00:00Z" },
  { id: "usr_03", name: "Arjun Mehta", email: "arjun@nanz.ai", avatar: "", role: "analyst", company: "NANZ Security", createdAt: "2026-01-15T10:00:00Z" },
  { id: "usr_04", name: "Neha Kapoor", email: "neha@client.com", avatar: "", role: "viewer", company: "Client Corp", createdAt: "2026-02-10T10:00:00Z" },
  { id: "usr_05", name: "Ravi Kumar", email: "ravi@nanz.ai", avatar: "", role: "billing_admin", company: "NANZ Security", createdAt: "2026-03-01T10:00:00Z" },
];
