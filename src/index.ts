import { PermissionError } from "./error.js";
import NodeCache from "node-cache";
import Redis from "redis";
import dotenv from "dotenv";

// Read redis info
dotenv.config();
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

type RolePermission = { [key: string]: string[] };

type Logger = {
  info: (message?: string) => void;
  error: (message?: string) => void;
};

type PermissionNameGetter = (permissionType: string, resourceName: string) => string;

export class Authorization {
  constructor(permissionNameGetter?: PermissionNameGetter, logger?: Logger) {
    this.getPermissionName = permissionNameGetter ?? this.getDefaultGetPermissionName();
    this.logger = logger ?? null;
    this.roleCache = null;

    this.roleRedisClient = Redis.createClient({ url: redisUrl });
    this.roleRedisClient.on("error", (err) => {
      this.logger?.error("error in redis client");
      this.logger?.error((err as Error).stack);
    });

    const redisConnect = async () => await this.roleRedisClient?.connect();
    redisConnect();
  }

  public async SaveRolesToCache(roles?: Role[]) {
    // Convert roles array to rolePermissions object
    const rolePermissions: RolePermission = {};
    if (roles?.length) for (const role of roles) rolePermissions[role.name] = role.permissions.map((permission) => this.getPermissionName(permission.type, permission.resource.name));
    // Save roles to cache
    if (!roles?.length) this.logger?.info("No roles to save to cache.");
    else if (redisUrl === undefined) this.setRoleNodeCache(rolePermissions);
    else await this.setRoleRedisClient(rolePermissions);
  }

  public async check(userRoles: string[], permissionType: string, resourceName: string): Promise<never | true> {
    // Get permissions of every user role to permissions set
    const permissions = new Set<string>();
    for (const role of userRoles) {
      let rolePermissions: string[] | null = null;
      // Get permissions from cache
      if (this.roleCache !== null) rolePermissions = this.roleCache.get(role) ?? null;
      else if (this.roleRedisClient !== null) rolePermissions = await this.roleRedisClient.sMembers(`role:${role}`);
      else this.logger?.error("there is no roles in the cache");
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

  public setRoleNodeCache(rolePermissions: RolePermission) {
    // Write roles into node cache
    this.roleCache = new NodeCache({ stdTTL: 0 });

    // Set node cache roles
    for (const role of Object.keys(rolePermissions)) this.roleCache.set(role, rolePermissions[role as keyof typeof rolePermissions]);
    this.logger?.info("roles have been stored in role cache.");
  }

  private async setRoleRedisClient(rolePermissions: RolePermission) {
    // Write roles into redis cache
    if (this.roleRedisClient) {
      for (const role of Object.keys(rolePermissions)) await this.roleRedisClient.sAdd(`role:${role}`, rolePermissions[role as keyof typeof rolePermissions]);
      this.logger?.info("roles have been stored in redis");

      // Notify system about completing redis roles
      if (redisRolesChannel !== undefined) {
        const redisMessage = "roles has been updated";
        this.logger?.info(`publish to channel [${redisRolesChannel}] the message: ${redisMessage}`);
        await this.roleRedisClient.publish(redisRolesChannel, redisMessage);
      }
    } else this.logger?.error("redis client is not initialized.");
  }

  private pascalToKabab(text: string) {
    return text.replace(/([a-z])([A-Z])/g, "$1-$2").toLowerCase();
  }

  private logger: Logger | null;
  private roleCache: NodeCache | null;
  private roleRedisClient: Redis.RedisClientType | null;
  private getPermissionName: PermissionNameGetter;
}
