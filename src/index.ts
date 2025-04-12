import { PermissionError } from "./error.js";
import NodeCache from "node-cache";
import Redis from "redis";
import dotenv from "dotenv";

// Read redis info
const redisUrl = process.env.REDIS_URL;
const redisRolesChannel = process.env.REDIS_ROLES_CHANNEL;
const isDevelopment = process.env.NODE_ENV === "development";

// Define types
export type User = {
  sub?: string;
  aud?: string;
  name?: string;
  roles?: string[];
};

type Role = {
  name: string;
  permissions: Array<{
    type: string;
    resource: { name: string };
  }>;
};

type Logger = {
  info: (message?: string) => void;
  error: (message?: string) => void;
};

type PermissionNameGetter = (permissionType: string, resourceName: string) => string;

export class Authorization {
  constructor(roles: Role[], permissionNameGetter?: PermissionNameGetter, logger?: Logger) {
    this.getPermissionName = permissionNameGetter ?? this.getDefaultGetPermissionName();
    this.roleCache = null;
    this.roleRedisClient = null;

    // Save roles to cache
    if (redisUrl === undefined) this.setRoleCache(roles, logger);
    else this.setRoleRedisClient(roles, logger);
  }

  public async check(userRoles: string[], permissionType: string, resourceName: string): Promise<never | true> {
    // Get permissions of every user role to permissions set
    const permissions = new Set<string>();
    for (const role of userRoles) {
      let rolePermissions: string[] | null = null;
      // Get permissions from cache
      if (this.roleCache !== null) rolePermissions = this.roleCache.get(role) ?? null;
      else if (this.roleRedisClient !== null) rolePermissions = await this.roleRedisClient.sMembers(`role:${role}`);
      // Add permissions to set
      if (rolePermissions !== null) for (const permission of rolePermissions) permissions.add(permission);
    }

    if (permissions.has(this.getPermissionName(permissionType, resourceName))) return true;
    else {
      const message = `Access to ${resourceName} is denied for ${userRoles.length === 1 ? "the" : ""} ${userRoles.join(", ")}.`;
      const details = `The required permission '${this.getPermissionName(permissionType, resourceName)}' is missing from the assigned permissions: ${Array.from(permissions)
        .map((permission) => `'${permission}'`)
        .join(", ")}.`;
      throw new PermissionError(`${message}${isDevelopment ? details : ""}`);
    }
  }

  public getDefaultGetPermissionName(): PermissionNameGetter {
    return (permissionType, resourceName) => `${permissionType.toLowerCase()}-${this.pascalToKabab(resourceName)}`;
  }

  private pascalToKabab(text: string) {
    return text.replace(/([a-z])([A-Z])/g, "$1-$2").toLowerCase();
  }

  private setRoleCache(roles: Role[], logger?: Logger) {
    // Write roles into node cache
    this.roleCache = new NodeCache({ stdTTL: 0 });

    // Set node cache roles
    for (const role of roles)
      this.roleCache.set(
        role.name,
        role.permissions.map((permission) => this.getPermissionName(permission.type, permission.resource.name))
      );
    logger?.info("roles have been stored in role cache.");
  }

  private async setRoleRedisClient(roles: Role[], logger?: Logger) {
    // Write roles into redis cache
    this.roleRedisClient = Redis.createClient({ url: redisUrl });
    this.roleRedisClient.on("error", (err) => {
      logger?.error("error in redis client");
      logger?.error((err as Error).stack);
    });
    await this.roleRedisClient.connect();
    for (const role of roles) {
      await this.roleRedisClient.sAdd(
        `role:${role.name}`,
        role.permissions.map((permission) => this.getPermissionName(permission.type, permission.resource.name))
      );
    }

    // Notify system about completing redis roles
    if (redisRolesChannel !== undefined) {
      const redisMessage = "roles have been stored in redis";
      logger?.info(`publish to channel [${redisRolesChannel}] the message: ${redisMessage}`);
      await this.roleRedisClient.publish(redisRolesChannel, redisMessage);
    }
  }

  private roleCache: NodeCache | null;
  private roleRedisClient: Redis.RedisClientType | null;
  private getPermissionName: PermissionNameGetter;
}
