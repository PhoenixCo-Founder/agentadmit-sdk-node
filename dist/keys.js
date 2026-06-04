"use strict";
/**
 * agentadmit/keys.ts
 * RS256 key pair generation and loading.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateKeyPair = generateKeyPair;
exports.loadPrivateKey = loadPrivateKey;
exports.loadPublicKey = loadPublicKey;
const crypto_1 = __importDefault(require("crypto"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
let _privateKey = null;
let _publicKey = null;
function generateKeyPair(outputDir = 'keys') {
    fs_1.default.mkdirSync(outputDir, { recursive: true });
    const { privateKey, publicKey } = crypto_1.default.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const privatePath = path_1.default.join(outputDir, 'agentadmit_private.pem');
    const publicPath = path_1.default.join(outputDir, 'agentadmit_public.pem');
    fs_1.default.writeFileSync(privatePath, privateKey, { mode: 0o600 });
    fs_1.default.writeFileSync(publicPath, publicKey);
    // Create .gitignore
    fs_1.default.writeFileSync(path_1.default.join(outputDir, '.gitignore'), '*.pem\n');
    console.log(`[AgentAdmit] Generated RS256 key pair in ${outputDir}/`);
    return { privatePath, publicPath };
}
function loadPrivateKey(keyPath = 'keys/agentadmit_private.pem') {
    if (_privateKey)
        return _privateKey;
    const envKey = process.env.AGENTADMIT_PRIVATE_KEY;
    if (envKey) {
        _privateKey = envKey;
        return _privateKey;
    }
    if (!fs_1.default.existsSync(keyPath)) {
        throw new Error(`Private key not found at ${keyPath}. Run 'agentadmit init' or set AGENTADMIT_PRIVATE_KEY.`);
    }
    _privateKey = fs_1.default.readFileSync(keyPath, 'utf-8');
    return _privateKey;
}
function loadPublicKey(keyPath = 'keys/agentadmit_public.pem') {
    if (_publicKey)
        return _publicKey;
    const envKey = process.env.AGENTADMIT_PUBLIC_KEY;
    if (envKey) {
        _publicKey = envKey;
        return _publicKey;
    }
    if (!fs_1.default.existsSync(keyPath)) {
        throw new Error(`Public key not found at ${keyPath}. Run 'agentadmit init' or set AGENTADMIT_PUBLIC_KEY.`);
    }
    _publicKey = fs_1.default.readFileSync(keyPath, 'utf-8');
    return _publicKey;
}
