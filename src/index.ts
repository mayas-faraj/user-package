import { PermissionError } from "./error.js";

type NodeCache = {
  get(key: string | number): string[] | undefined;
};

export type User = {
  sub?: string;
  aud?: string;
  name?: string;
  roles?: string[];
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
    if (this.roles !== undefined)
      for (const role of this.roles) {
        const rolePermissions = this.cache.get(role);
        if (rolePermissions !== undefined) for (const permission of rolePermissions) permissions.add(permission);
      }
    if (permissions.has(this.getPermissionName(permissionType, resourceName))) return true;
    else {
      const message = `Access to ${resourceName} is denied for ${this.roles?.length === 1 ? "the" : ""} ${this.roles?.join(", ")}.`;
      const details = `The required permission '${this.getPermissionName(permissionType, resourceName)}' is missing from the assigned permissions: ${Array.from(permissions).map(permission => `'${permission}'`).join(", ")}.`;
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
  private roles: string[] | undefined;
  private getPermissionName: PermissionNameGetter;
  private isDevelopment: boolean;
}
