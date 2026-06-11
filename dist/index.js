"use strict";
/**
 * @agentadmit/sdk — Node.js SDK for AgentAdmit
 *
 * User-mediated AI agent authorization. Plug-and-play for Express and Next.js.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.ALERT_TYPES = exports.getAlertConfig = exports.listAlerts = exports.configureAlerts = exports.RateLimitError = exports.createAgentAdmitRouter = exports.DEFAULT_TOLERANCE_SECONDS = exports.SIGNATURE_HEADER = exports.WebhookSignatureError = exports.isValidWebhookSignature = exports.verifyWebhookSignature = exports.VERIFY_ERROR_CODES = exports.setUserVerifier = exports.setStorage = exports.checkConnectionCap = exports.resolveAuth = exports.requireScopeIfAgent = exports.requireScope = exports.validateAgentToken = exports.createStorage = exports.MemoryStorage = exports.MongoDBStorage = exports.loadPublicKey = exports.loadPrivateKey = exports.generateKeyPair = exports.getTierLimits = exports.getDurationOptions = exports.getScopeMetadata = exports.getConfig = exports.loadConfig = void 0;
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
Object.defineProperty(exports, "VERIFY_ERROR_CODES", { enumerable: true, get: function () { return auth_1.VERIFY_ERROR_CODES; } });
var webhooks_1 = require("./webhooks");
Object.defineProperty(exports, "verifyWebhookSignature", { enumerable: true, get: function () { return webhooks_1.verifyWebhookSignature; } });
Object.defineProperty(exports, "isValidWebhookSignature", { enumerable: true, get: function () { return webhooks_1.isValidWebhookSignature; } });
Object.defineProperty(exports, "WebhookSignatureError", { enumerable: true, get: function () { return webhooks_1.WebhookSignatureError; } });
Object.defineProperty(exports, "SIGNATURE_HEADER", { enumerable: true, get: function () { return webhooks_1.SIGNATURE_HEADER; } });
Object.defineProperty(exports, "DEFAULT_TOLERANCE_SECONDS", { enumerable: true, get: function () { return webhooks_1.DEFAULT_TOLERANCE_SECONDS; } });
var routes_1 = require("./routes");
Object.defineProperty(exports, "createAgentAdmitRouter", { enumerable: true, get: function () { return routes_1.createAgentAdmitRouter; } });
var errors_1 = require("./errors");
Object.defineProperty(exports, "RateLimitError", { enumerable: true, get: function () { return errors_1.RateLimitError; } });
var alerts_1 = require("./alerts");
Object.defineProperty(exports, "configureAlerts", { enumerable: true, get: function () { return alerts_1.configureAlerts; } });
Object.defineProperty(exports, "listAlerts", { enumerable: true, get: function () { return alerts_1.listAlerts; } });
Object.defineProperty(exports, "getAlertConfig", { enumerable: true, get: function () { return alerts_1.getAlertConfig; } });
Object.defineProperty(exports, "ALERT_TYPES", { enumerable: true, get: function () { return alerts_1.ALERT_TYPES; } });
