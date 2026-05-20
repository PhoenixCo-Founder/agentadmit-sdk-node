/**
 * agentadmit/storage.ts
 * Abstract storage interface + MongoDB + Memory implementations.
 */
export interface StorageBackend {
    storeConnection(connection: Record<string, any>): Promise<void>;
    getConnection(connectionId: string): Promise<Record<string, any> | null>;
    getActiveConnection(connectionId: string): Promise<Record<string, any> | null>;
    updateConnection(connectionId: string, updates: Record<string, any>): Promise<boolean>;
    revokeConnection(connectionId: string): Promise<boolean>;
    listConnections(userId: string): Promise<Record<string, any>[]>;
    countActiveConnections(userId: string): Promise<number>;
    storeToken(tokenRecord: Record<string, any>): Promise<void>;
    getToken(tokenHash: string): Promise<Record<string, any> | null>;
    markTokenUsed(tokenHash: string): Promise<boolean>;
    logAccess(entry: Record<string, any>): Promise<void>;
    countAuditCalls(userId: string, periodStart: Date, periodEnd: Date): Promise<number>;
    getUser(userId: string, lookupField: string): Promise<Record<string, any> | null>;
}
export declare class MongoDBStorage implements StorageBackend {
    private db;
    private connections;
    private auditLog;
    private tokens;
    private users;
    constructor(uri: string, database: string, connectionsCollection: string, auditLogCollection: string, tokensCollection: string);
    setUsersCollection(name: string): void;
    storeConnection(connection: Record<string, any>): Promise<void>;
    getConnection(connectionId: string): Promise<Record<string, any> | null>;
    getActiveConnection(connectionId: string): Promise<Record<string, any> | null>;
    updateConnection(connectionId: string, updates: Record<string, any>): Promise<boolean>;
    revokeConnection(connectionId: string): Promise<boolean>;
    listConnections(userId: string): Promise<Record<string, any>[]>;
    countActiveConnections(userId: string): Promise<number>;
    storeToken(tokenRecord: Record<string, any>): Promise<void>;
    getToken(tokenHash: string): Promise<Record<string, any> | null>;
    markTokenUsed(tokenHash: string): Promise<boolean>;
    logAccess(entry: Record<string, any>): Promise<void>;
    countAuditCalls(userId: string, periodStart: Date, periodEnd: Date): Promise<number>;
    getUser(userId: string, lookupField?: string): Promise<Record<string, any> | null>;
}
export declare class MemoryStorage implements StorageBackend {
    private _connections;
    private _tokens;
    private _auditLog;
    private _users;
    storeConnection(connection: Record<string, any>): Promise<void>;
    getConnection(connectionId: string): Promise<Record<string, any> | null>;
    getActiveConnection(connectionId: string): Promise<Record<string, any> | null>;
    updateConnection(connectionId: string, updates: Record<string, any>): Promise<boolean>;
    revokeConnection(connectionId: string): Promise<boolean>;
    listConnections(userId: string): Promise<Record<string, any>[]>;
    countActiveConnections(userId: string): Promise<number>;
    storeToken(tokenRecord: Record<string, any>): Promise<void>;
    getToken(tokenHash: string): Promise<Record<string, any> | null>;
    markTokenUsed(tokenHash: string): Promise<boolean>;
    logAccess(entry: Record<string, any>): Promise<void>;
    countAuditCalls(userId: string, periodStart: Date, periodEnd: Date): Promise<number>;
    getUser(userId: string, lookupField?: string): Promise<Record<string, any> | null>;
    addTestUser(userId: string, data: Record<string, any>): void;
}
export declare function createStorage(config: any): StorageBackend;
