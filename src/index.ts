import { PermissionError } from "./error.js";

type NodeCache = {
  get(key: string | number): string[] | undefined;
};

export type User = {
  sub: string;
  aud: string;
  name: string;
  roles: string[];
};

type PermissionNameGetter = (permissionType: string, resourceName: string) => string;

export class Authorization {
  constructor(cache: NodeCache, roles: string[], permissionNameGetter?: PermissionNameGetter, isDevelopment?: boolean) {
    this.cache = cache;
    this.roles = roles;
    this.getPermissionName = permissionNameGetter ?? this.getDefaultGetPermissionName();
    this.isDevelopment = isDevelopment === true;
  }

  check(permissionType: string, resourceName: string): never | true {
    const permissions = new Set<string>();
    for (const role of this.roles) {
      const rolePermissions = this.cache.get(role);
      if (rolePermissions !== undefined) for (const permission of rolePermissions) permissions.add(permission);
    }
    if (permissions.has(this.getPermissionName(permissionType, resourceName))) return true;
    else {
      const message = `${this.roles.length === 1 ? "The" : ""} ${this.roles.join(", ")} ${this.roles.length === 1 ? "is" : "are"} unauthorized to access the resource: ${resourceName}. `;
      const details = `the required permission: ${this.getPermissionName(permissionType, resourceName)} is not found in the permission list: ${Array.from(permissions).join(", ")}.`;
      throw new PermissionError(`${message}${this.isDevelopment && details}`);
    }
  }

  public getDefaultGetPermissionName(): PermissionNameGetter {
    return (permissionType, resourceName) => `${permissionType.toLowerCase()}-${this.pascalToKabab(resourceName)}`;
  }

  private pascalToKabab(text: string) {
    return text.replace(/([a-z])([A-Z])/g, "$1-$2").toLowerCase();
  }

  private cache: NodeCache;
  private roles: string[];
  private getPermissionName: PermissionNameGetter;
  private isDevelopment: boolean;
}
