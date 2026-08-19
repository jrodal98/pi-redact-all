import type { Config } from "./types.js";
export declare const DEFAULT_CONFIG: Config;
export interface DotenvDebug {
    manualLiterals: string[];
    manualPatterns: string[];
    discoverStrategies: string[];
    discoveredFiles: string[];
    expandedManualFiles: string[];
    loadedFiles: {
        path: string;
        entries: {
            key: string;
            value: string;
        }[];
        keys: string[];
        valuesCount: number;
        skippedKeys: string[];
    }[];
    skippedExampleFiles: string[];
    excludedKeys: string[];
    totalValues: number;
    placeholderSkipped: number;
    shortSkipped: number;
}
export declare function getDotenvDebug(): DotenvDebug | null;
export declare function getConfigPaths(): {
    global: string | null;
    project: string | null;
    usedProject: string | null;
};
export declare function loadConfig(): Config;
//# sourceMappingURL=config.d.ts.map