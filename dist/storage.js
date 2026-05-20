"use strict";
/**
 * agentadmit/storage.ts
 * Abstract storage interface + MongoDB + Memory implementations.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.MemoryStorage = exports.MongoDBStorage = void 0;
exports.createStorage = createStorage;
class MongoDBStorage {
    constructor(uri, database, connectionsCollection, auditLogCollection, tokensCollection) {
        this.users = null;
        // Lazy import to keep mongodb as optional peer dep
        const { MongoClient } = require('mongodb');
        const client = new MongoClient(uri);
        this.db = client.db(database);
        this.connections = this.db.collection(connectionsCollection);
        this.auditLog = this.db.collection(auditLogCollection);
        this.tokens = this.db.collection(tokensCollection);
        // Create indexes
        this.connections.createIndex({ connection_id: 1 }, { unique: true }).catch(() => { });
        this.connections.createIndex({ user_id: 1, status: 1 }).catch(() => { });
        this.tokens.createIndex({ token_hash: 1 }, { unique: true }).catch(() => { });
        this.auditLog.createIndex({ user_id: 1, timestamp: -1 }).catch(() => { });
        console.log(`[AgentAdmit] MongoDB storage initialized: ${database}`);
    }
    setUsersCollection(name) {
        this.users = this.db.collection(name);
    }
    async storeConnection(connection) {
        await this.connections.insertOne(connection);
    }
    async getConnection(connectionId) {
        return this.connections.findOne({ connection_id: connectionId });
    }
    async getActiveConnection(connectionId) {
        return this.connections.findOne({ connection_id: connectionId, status: 'active' });
    }
    async updateConnection(connectionId, updates) {
        const result = await this.connections.updateOne({ connection_id: connectionId }, { $set: updates });
        return result.modifiedCount > 0;
    }
    async revokeConnection(connectionId) {
        const result = await this.connections.updateOne({ connection_id: connectionId, status: 'active' }, { $set: { status: 'revoked', revoked_at: new Date() } });
        return result.modifiedCount > 0;
    }
    async listConnections(userId) {
        return this.connections.find({ user_id: userId }, { projection: { _id: 0 } }).sort({ created_at: -1 }).toArray();
    }
    async countActiveConnections(userId) {
        return this.connections.countDocuments({ user_id: userId, status: 'active' });
    }
    async storeToken(tokenRecord) {
        await this.tokens.insertOne(tokenRecord);
    }
    async getToken(tokenHash) {
        return this.tokens.findOne({ token_hash: tokenHash });
    }
    async markTokenUsed(tokenHash) {
        const result = await this.tokens.updateOne({ token_hash: tokenHash, used: false }, { $set: { used: true, used_at: new Date() } });
        return result.modifiedCount > 0;
    }
    async logAccess(entry) {
        try {
            await this.auditLog.insertOne(entry);
        }
        catch (err) {
            console.error('[AgentAdmit] Audit log failed:', err);
        }
    }
    async countAuditCalls(userId, periodStart, periodEnd) {
        return this.auditLog.countDocuments({
            user_id: userId,
            timestamp: { $gte: periodStart, $lt: periodEnd },
        });
    }
    async getUser(userId, lookupField = 'user_id') {
        if (!this.users)
            return null;
        return this.users.findOne({ [lookupField]: userId });
    }
}
exports.MongoDBStorage = MongoDBStorage;
class MemoryStorage {
    constructor() {
        this._connections = new Map();
        this._tokens = new Map();
        this._auditLog = [];
        this._users = new Map();
    }
    async storeConnection(connection) {
        this._connections.set(connection.connection_id, connection);
    }
    async getConnection(connectionId) {
        return this._connections.get(connectionId) || null;
    }
    async getActiveConnection(connectionId) {
        const conn = this._connections.get(connectionId);
        return conn?.status === 'active' ? conn : null;
    }
    async updateConnection(connectionId, updates) {
        const conn = this._connections.get(connectionId);
        if (!conn)
            return false;
        Object.assign(conn, updates);
        return true;
    }
    async revokeConnection(connectionId) {
        const conn = this._connections.get(connectionId);
        if (!conn || conn.status !== 'active')
            return false;
        conn.status = 'revoked';
        conn.revoked_at = new Date();
        return true;
    }
    async listConnections(userId) {
        return Array.from(this._connections.values()).filter(c => c.user_id === userId);
    }
    async countActiveConnections(userId) {
        return Array.from(this._connections.values()).filter(c => c.user_id === userId && c.status === 'active').length;
    }
    async storeToken(tokenRecord) {
        this._tokens.set(tokenRecord.token_hash, tokenRecord);
    }
    async getToken(tokenHash) {
        return this._tokens.get(tokenHash) || null;
    }
    async markTokenUsed(tokenHash) {
        const token = this._tokens.get(tokenHash);
        if (!token || token.used)
            return false;
        token.used = true;
        token.used_at = new Date();
        return true;
    }
    async logAccess(entry) {
        this._auditLog.push(entry);
    }
    async countAuditCalls(userId, periodStart, periodEnd) {
        return this._auditLog.filter(e => e.user_id === userId &&
            e.timestamp >= periodStart &&
            e.timestamp < periodEnd).length;
    }
    async getUser(userId, lookupField = 'user_id') {
        return this._users.get(userId) || null;
    }
    addTestUser(userId, data) {
        this._users.set(userId, data);
    }
}
exports.MemoryStorage = MemoryStorage;
function createStorage(config) {
    const backend = config.storage?.backend || 'mongodb';
    if (backend === 'mongodb') {
        const s = new MongoDBStorage(config.storage.uri, config.storage.database, config.storage.connections_collection || 'agentadmit_connections', config.storage.audit_log_collection || 'agentadmit_audit_log', config.storage.tokens_collection || 'agentadmit_tokens');
        return s;
    }
    if (backend === 'memory') {
        return new MemoryStorage();
    }
    throw new Error(`Unsupported storage backend: ${backend}`);
}
