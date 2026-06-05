export type Role = 'viewer' | 'operator' | 'admin' | 'sovereign';

const ROLE_RANK: Record<Role, number> = {
    viewer: 1,
    operator: 2,
    admin: 3,
    sovereign: 4,
};

export interface Principal {
    subject: string;
    roles: Role[];
}

export class RbacPolicy {
    private routeRoles = new Map<string, Role>();

    constructor() {
        this.routeRoles.set('GET /health', 'viewer');
        this.routeRoles.set('GET /metrics', 'operator');
        this.routeRoles.set('POST /api/encrypt', 'operator');
        this.routeRoles.set('GET /api/audit', 'admin');
        this.routeRoles.set('POST /console/login', 'viewer');
        this.routeRoles.set('POST /console/mfa', 'viewer');
        this.routeRoles.set('GET /console/status', 'admin');
        this.routeRoles.set('POST /console/rotate-keys', 'sovereign');
        this.routeRoles.set('POST /vault/upload', 'operator');
        this.routeRoles.set('GET /vault/download', 'operator');
    }

    register(method: string, path: string, minRole: Role): void {
        this.routeRoles.set(`${method.toUpperCase()} ${path}`, minRole);
    }

    authorize(principal: Principal | null, method: string, path: string): boolean {
        const required = this.routeRoles.get(`${method.toUpperCase()} ${path}`) ?? 'admin';
        if (!principal) return false;
        const need = ROLE_RANK[required];
        return principal.roles.some((r) => ROLE_RANK[r] >= need);
    }
}
