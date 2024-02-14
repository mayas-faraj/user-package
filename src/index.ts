import { PermissionError } from "./error.js";

export type User = {
  sub: string;
  aud: string;
  name: string;
  role: string;
};

export enum Role {
  SUBSCRIBER,
  SYSTEM,
  CONTENT_READER,
  CONTENT_MANAGER,
  LOGISTICS_MANAGER,
  ADMIN,
  SUPER_ADMIN,
}

export const checkAuthorization = (
  role: string,
  ...allowedRoles: Role[]
): true | never => {
  const userRole = Role[role as keyof typeof Role] as Role;

  for (const allowedRole of allowedRoles)
    if (userRole === allowedRole) return true;
  throw new PermissionError(
    `${
      role ? Role[userRole].toLowerCase() : "user without a role"
    } is unauthorized to access resources, only allowd for roles: ${allowedRoles.map(
      (role) => Role[role]?.toLowerCase()
    )}`
  );
};
