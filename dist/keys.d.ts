/**
 * agentadmit/keys.ts
 *
 * DEPRECATED — AgentAdmit is a hosted service.
 *
 * All cryptographic operations (key generation, JWT signing, JWKS serving)
 * are performed by the AgentAdmit hosted service. The SDK does NOT generate
 * or load RSA key pairs. Calling any function in this module will throw.
 */
export declare function generateKeyPair(_outputDir?: string): never;
export declare function loadPrivateKey(_keyPath?: string): never;
export declare function loadPublicKey(_keyPath?: string): never;
