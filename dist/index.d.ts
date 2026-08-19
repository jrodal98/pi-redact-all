interface ExtensionAPI {
    on(event: string, handler: (...args: unknown[]) => unknown): void;
    registerCommand(name: string, config: {
        description: string;
        handler: (args: string, ctx: unknown) => Promise<string> | string;
    }): void;
}
export default function (pi: ExtensionAPI): void;
export {};
//# sourceMappingURL=index.d.ts.map