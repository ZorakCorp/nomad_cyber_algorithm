export type ServiceHandler = (body: Buffer, correlationId: string) => Promise<Buffer>;

export class TenantRouter {
    private handlers = new Map<string, ServiceHandler>();

    register(serviceId: string, handler: ServiceHandler): void {
        this.handlers.set(serviceId, handler);
    }

    async route(serviceId: string | undefined, body: Buffer, correlationId: string): Promise<Buffer> {
        const id = serviceId ?? 'default';
        const handler = this.handlers.get(id) ?? this.handlers.get('default');
        if (!handler) {
            return Buffer.from(JSON.stringify({ error: `No handler for service: ${id}` }));
        }
        return handler(body, correlationId);
    }
}
