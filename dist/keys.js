"use strict";
/**
 * agentadmit/keys.ts
 *
 * DEPRECATED — AgentAdmit is a hosted service.
 *
 * All cryptographic operations (key generation, JWT signing, JWKS serving)
 * are performed by the AgentAdmit hosted service. The SDK does NOT generate
 * or load RSA key pairs. Calling any function in this module will throw.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateKeyPair = generateKeyPair;
exports.loadPrivateKey = loadPrivateKey;
exports.loadPublicKey = loadPublicKey;
function generateKeyPair(_outputDir) {
    throw new Error('[AgentAdmit] generateKeyPair() is not supported. ' +
        'AgentAdmit is a hosted service — all key management is handled server-side. ' +
        'Remove any calls to generateKeyPair() from your codebase.');
}
function loadPrivateKey(_keyPath) {
    throw new Error('[AgentAdmit] loadPrivateKey() is not supported. ' +
        'AgentAdmit is a hosted service — JWT signing is handled by the hosted service. ' +
        'Remove any calls to loadPrivateKey() from your codebase.');
}
function loadPublicKey(_keyPath) {
    throw new Error('[AgentAdmit] loadPublicKey() is not supported. ' +
        'AgentAdmit is a hosted service — token verification uses hosted introspection. ' +
        'Remove any calls to loadPublicKey() from your codebase.');
}
