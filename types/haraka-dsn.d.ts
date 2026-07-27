declare module "haraka-dsn" {
    interface DsnResponse {
        code: number;
        reply: string;
    }

    class DSN {
        static sec_unauthorized(message?: string, code?: number): DsnResponse;
    }

    export = DSN;
}
