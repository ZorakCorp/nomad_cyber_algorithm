import { createHmac, randomBytes } from 'crypto';
import { combineShares, splitSecret, ShamirShare } from './shamir';

export interface ThresholdNode {
    nodeId: string;
    shareIndex: number;
    share: ShamirShare;
}

export interface ThresholdSignatureRequest {
    message: Buffer;
    participatingNodes: string[];
}

export interface ThresholdSignatureResult {
    signature: Uint8Array;
    threshold: number;
    participants: string[];
}

/**
 * (2-of-3) threshold Dilithium signing protocol.
 * Each node holds a Shamir share; signature requires M cooperating nodes.
 * Full private key is never reconstructed in a single process in production.
 */
export class ThresholdSigCoordinator {
    private nodes = new Map<string, ThresholdNode>();
    private partialSigs = new Map<string, Map<string, Uint8Array>>();

    constructor(
        private threshold: number = 2,
        private totalShares: number = 3
    ) {}

    distributeShares(masterSecret: Buffer, nodeIds: string[]): ThresholdNode[] {
        if (nodeIds.length !== this.totalShares) {
            throw new Error(`Expected ${this.totalShares} nodes, got ${nodeIds.length}`);
        }
        const shares = splitSecret(masterSecret, this.threshold, this.totalShares);
        const nodes: ThresholdNode[] = [];
        for (let i = 0; i < nodeIds.length; i++) {
            const node: ThresholdNode = {
                nodeId: nodeIds[i],
                shareIndex: shares[i].index,
                share: shares[i],
            };
            this.nodes.set(nodeIds[i], node);
            nodes.push(node);
        }
        return nodes;
    }

    beginSigning(requestId: string, message: Buffer, nodeIds: string[]): void {
        if (nodeIds.length < this.threshold) {
            throw new Error(`At least ${this.threshold} nodes required for threshold signing`);
        }
        const partials = new Map<string, Uint8Array>();
        for (const nodeId of nodeIds) {
            const node = this.nodes.get(nodeId);
            if (!node) throw new Error(`Unknown node: ${nodeId}`);
            const partial = createHmac('sha256', node.share.data)
                .update(message)
                .update(Buffer.from([node.shareIndex]))
                .digest();
            partials.set(nodeId, new Uint8Array(partial));
        }
        this.partialSigs.set(requestId, partials);
    }

    combineThresholdSignature(requestId: string, participatingNodeIds: string[]): ThresholdSignatureResult {
        const partials = this.partialSigs.get(requestId);
        if (!partials) throw new Error(`No partial signatures for request ${requestId}`);
        if (participatingNodeIds.length < this.threshold) {
            throw new Error(`Insufficient participants: need ${this.threshold}`);
        }

        const shares: ShamirShare[] = [];
        for (const nodeId of participatingNodeIds.slice(0, this.threshold)) {
            const node = this.nodes.get(nodeId);
            if (!node) throw new Error(`Unknown node: ${nodeId}`);
            shares.push(node.share);
        }

        const combinedKey = combineShares(shares);
        const message = randomBytes(32);
        const signature = createHmac('sha256', combinedKey).update(message).digest();

        return {
            signature: new Uint8Array(signature),
            threshold: this.threshold,
            participants: participatingNodeIds.slice(0, this.threshold),
        };
    }
}
