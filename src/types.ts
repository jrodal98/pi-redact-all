// Shared types for pi-redact-all

export interface Match {
  start: number;
  end: number;
  type: string;
  replacement: string;
}

export interface LayerResult {
  matches: Match[];
}

export interface RedactionContext {
  toolName?: string;
  inputPath?: string;
  command?: string;
  config: Config;
  /** Path-based partial block tracker (for multi-chunk reads of private keys) */
  partialPrivateKeyPaths: Set<string>;
}

export interface Config {
  mode: "mask" | "block" | "off";
  blockMode: boolean;
  streamingRedaction: boolean;
  toolPolicy: {
    whitelist: string[];
    blacklist: string[];
  };
  layers: {
    vendor: boolean;
    pem: boolean;
    prefix: boolean;
    entropy: boolean;
    asn1: boolean;
    context: boolean;
    path: boolean;
    pii: boolean;
    connection: boolean;
    custom: boolean;
  };
  allowlistRegex: string[];
  allowlistLiteral: string[];
  allowlistEnv: string[];
  blocklistRegex: string[];
  blocklistLiteral: string[];
  blocklistEnv: string[];
  customRegex: string[];
  customLiterals: string[];
  envVars: string[];
  minEntropy: number;
  minLength: number;
  preservePrefixChars: number;
  asterisksMax: number;
}

export interface RedactionResult {
  text: string;
  count: number;
  hits: Match[];
}