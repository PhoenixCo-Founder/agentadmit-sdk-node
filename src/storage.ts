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

export class MongoDBStorage implements StorageBackend {
  private db: any;
  private connections: any;
  private auditLog: any;
  private tokens: any;
  private users: any = null;

  constructor(
    uri: string,
    database: string,
    connectionsCollection: string,
    auditLogCollection: string,
    tokensCollection: string,
  ) {
    // Lazy import to keep mongodb as optional peer dep
    const { MongoClient } = require('mongodb');
    const client = new MongoClient(uri);
    this.db = client.db(database);
    this.connections = this.db.collection(connectionsCollection);
    this.auditLog = this.db.collection(auditLogCollection);
    this.tokens = this.db.collection(tokensCollection);

    // Create indexes
    this.connections.createIndex({ connection_id: 1 }, { unique: true }).catch(() => {});
    this.connections.createIndex({ user_id: 1, status: 1 }).catch(() => {});
    this.tokens.createIndex({ token_hash: 1 }, { unique: true }).catch(() => {});
    this.auditLog.createIndex({ user_id: 1, timestamp: -1 }).catch(() => {});

    console.log(`[AgentAdmit] MongoDB storage initialized: ${database}`);
  }

  setUsersCollection(name: string) {
    this.users = this.db.collection(name);
  }

  async storeConnection(connection: Record<string, any>): Promise<void> {
    await this.connections.insertOne(connection);
  }

  async getConnection(connectionId: string): Promise<Record<string, any> | null> {
    return this.connections.findOne({ connection_id: connectionId });
  }

  async getActiveConnection(connectionId: string): Promise<Record<string, any> | null> {
    return this.connections.findOne({ connection_id: connectionId, status: 'active' });
  }

  async updateConnection(connectionId: string, updates: Record<string, any>): Promise<boolean> {
    const result = await this.connections.updateOne(
      { connection_id: connectionId },
      { $set: updates },
    );
    return result.modifiedCount > 0;
  }

  async revokeConnection(connectionId: string): Promise<boolean> {
    const result = await this.connections.updateOne(
      { connection_id: connectionId, status: 'active' },
      { $set: { status: 'revoked', revoked_at: new Date() } },
    );
    return result.modifiedCount > 0;
  }

  async listConnections(userId: string): Promise<Record<string, any>[]> {
    return this.connections.find({ user_id: userId }, { projection: { _id: 0 } }).sort({ created_at: -1 }).toArray();
  }

  async countActiveConnections(userId: string): Promise<number> {
    return this.connections.countDocuments({ user_id: userId, status: 'active' });
  }

  async storeToken(tokenRecord: Record<string, any>): Promise<void> {
    await this.tokens.insertOne(tokenRecord);
  }

  async getToken(tokenHash: string): Promise<Record<string, any> | null> {
    return this.tokens.findOne({ token_hash: tokenHash });
  }

  async markTokenUsed(tokenHash: string): Promise<boolean> {
    const result = await this.tokens.updateOne(
      { token_hash: tokenHash, used: false },
      { $set: { used: true, used_at: new Date() } },
    );
    return result.modifiedCount > 0;
  }

  async logAccess(entry: Record<string, any>): Promise<void> {
    try {
      await this.auditLog.insertOne(entry);
    } catch (err) {
      console.error('[AgentAdmit] Audit log failed:', err);
    }
  }

  async countAuditCalls(userId: string, periodStart: Date, periodEnd: Date): Promise<number> {
    return this.auditLog.countDocuments({
      user_id: userId,
      timestamp: { $gte: periodStart, $lt: periodEnd },
    });
  }

  async getUser(userId: string, lookupField: string = 'user_id'): Promise<Record<string, any> | null> {
    if (!this.users) return null;
    return this.users.findOne({ [lookupField]: userId });
  }
}

export class MemoryStorage implements StorageBackend {
  private _connections: Map<string, Record<string, any>> = new Map();
  private _tokens: Map<string, Record<string, any>> = new Map();
  private _auditLog: Record<string, any>[] = [];
  private _users: Map<string, Record<string, any>> = new Map();

  async storeConnection(connection: Record<string, any>): Promise<void> {
    this._connections.set(connection.connection_id, connection);
  }

  async getConnection(connectionId: string): Promise<Record<string, any> | null> {
    return this._connections.get(connectionId) || null;
  }

  async getActiveConnection(connectionId: string): Promise<Record<string, any> | null> {
    const conn = this._connections.get(connectionId);
    return conn?.status === 'active' ? conn : null;
  }

  async updateConnection(connectionId: string, updates: Record<string, any>): Promise<boolean> {
    const conn = this._connections.get(connectionId);
    if (!conn) return false;
    Object.assign(conn, updates);
    return true;
  }

  async revokeConnection(connectionId: string): Promise<boolean> {
    const conn = this._connections.get(connectionId);
    if (!conn || conn.status !== 'active') return false;
    conn.status = 'revoked';
    conn.revoked_at = new Date();
    return true;
  }

  async listConnections(userId: string): Promise<Record<string, any>[]> {
    return Array.from(this._connections.values()).filter(c => c.user_id === userId);
  }

  async countActiveConnections(userId: string): Promise<number> {
    return Array.from(this._connections.values()).filter(c => c.user_id === userId && c.status === 'active').length;
  }

  async storeToken(tokenRecord: Record<string, any>): Promise<void> {
    this._tokens.set(tokenRecord.token_hash, tokenRecord);
  }

  async getToken(tokenHash: string): Promise<Record<string, any> | null> {
    return this._tokens.get(tokenHash) || null;
  }

  async markTokenUsed(tokenHash: string): Promise<boolean> {
    const token = this._tokens.get(tokenHash);
    if (!token || token.used) return false;
    token.used = true;
    token.used_at = new Date();
    return true;
  }

  async logAccess(entry: Record<string, any>): Promise<void> {
    this._auditLog.push(entry);
  }

  async countAuditCalls(userId: string, periodStart: Date, periodEnd: Date): Promise<number> {
    return this._auditLog.filter(e =>
      e.user_id === userId &&
      e.timestamp >= periodStart &&
      e.timestamp < periodEnd
    ).length;
  }

  async getUser(userId: string, lookupField: string = 'user_id'): Promise<Record<string, any> | null> {
    return this._users.get(userId) || null;
  }

  addTestUser(userId: string, data: Record<string, any>): void {
    this._users.set(userId, data);
  }
}

export function createStorage(config: any): StorageBackend {
  const backend = config.storage?.backend || 'mongodb';

  if (backend === 'mongodb') {
    const s = new MongoDBStorage(
      config.storage.uri,
      config.storage.database,
      config.storage.connections_collection || 'agentadmit_connections',
      config.storage.audit_log_collection || 'agentadmit_audit_log',
      config.storage.tokens_collection || 'agentadmit_tokens',
    );
    return s;
  }

  if (backend === 'memory') {
    return new MemoryStorage();
  }

  throw new Error(`Unsupported storage backend: ${backend}`);
}
