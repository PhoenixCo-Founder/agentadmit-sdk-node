/**
 * agentadmit/keys.ts
 * RS256 key pair generation and loading.
 */
export declare function generateKeyPair(outputDir?: string): {
    privatePath: string;
    publicPath: string;
};
export declare function loadPrivateKey(keyPath?: string): string;
export declare function loadPublicKey(keyPath?: string): string;
