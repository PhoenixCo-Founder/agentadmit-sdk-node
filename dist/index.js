"use strict";
/**
 * @agentadmit/sdk — Node.js SDK for AgentAdmit
 *
 * User-mediated AI agent authorization. Plug-and-play for Express and Next.js.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.RateLimitError = exports.createAgentAdmitRouter = exports.setUserVerifier = exports.setStorage = exports.checkConnectionCap = exports.resolveAuth = exports.requireScopeIfAgent = exports.requireScope = exports.validateAgentToken = exports.createStorage = exports.MemoryStorage = exports.MongoDBStorage = exports.loadPublicKey = exports.loadPrivateKey = exports.generateKeyPair = exports.getTierLimits = exports.getDurationOptions = exports.getScopeMetadata = exports.getConfig = exports.loadConfig = void 0;
var config_1 = require("./config");
Object.defineProperty(exports, "loadConfig", { enumerable: true, get: function () { return config_1.loadConfig; } });
Object.defineProperty(exports, "getConfig", { enumerable: true, get: function () { return config_1.getConfig; } });
Object.defineProperty(exports, "getScopeMetadata", { enumerable: true, get: function () { return config_1.getScopeMetadata; } });
Object.defineProperty(exports, "getDurationOptions", { enumerable: true, get: function () { return config_1.getDurationOptions; } });
Object.defineProperty(exports, "getTierLimits", { enumerable: true, get: function () { return config_1.getTierLimits; } });
var keys_1 = require("./keys");
Object.defineProperty(exports, "generateKeyPair", { enumerable: true, get: function () { return keys_1.generateKeyPair; } });
Object.defineProperty(exports, "loadPrivateKey", { enumerable: true, get: function () { return keys_1.loadPrivateKey; } });
Object.defineProperty(exports, "loadPublicKey", { enumerable: true, get: function () { return keys_1.loadPublicKey; } });
var storage_1 = require("./storage");
Object.defineProperty(exports, "MongoDBStorage", { enumerable: true, get: function () { return storage_1.MongoDBStorage; } });
Object.defineProperty(exports, "MemoryStorage", { enumerable: true, get: function () { return storage_1.MemoryStorage; } });
Object.defineProperty(exports, "createStorage", { enumerable: true, get: function () { return storage_1.createStorage; } });
var auth_1 = require("./auth");
Object.defineProperty(exports, "validateAgentToken", { enumerable: true, get: function () { return auth_1.validateAgentToken; } });
Object.defineProperty(exports, "requireScope", { enumerable: true, get: function () { return auth_1.requireScope; } });
Object.defineProperty(exports, "requireScopeIfAgent", { enumerable: true, get: function () { return auth_1.requireScopeIfAgent; } });
Object.defineProperty(exports, "resolveAuth", { enumerable: true, get: function () { return auth_1.resolveAuth; } });
Object.defineProperty(exports, "checkConnectionCap", { enumerable: true, get: function () { return auth_1.checkConnectionCap; } });
Object.defineProperty(exports, "setStorage", { enumerable: true, get: function () { return auth_1.setStorage; } });
Object.defineProperty(exports, "setUserVerifier", { enumerable: true, get: function () { return auth_1.setUserVerifier; } });
var routes_1 = require("./routes");
Object.defineProperty(exports, "createAgentAdmitRouter", { enumerable: true, get: function () { return routes_1.createAgentAdmitRouter; } });
var errors_1 = require("./errors");
Object.defineProperty(exports, "RateLimitError", { enumerable: true, get: function () { return errors_1.RateLimitError; } });
