/** Serializes async message handlers to prevent state-machine races. */

export class MessageQueue {
    private chain: Promise<void> = Promise.resolve();

    enqueue(handler: () => Promise<void>): void {
        this.chain = this.chain
            .then(() => handler())
            .catch(() => { /* error handled by caller via handler rejection */ });
    }

    async drain(): Promise<void> {
        await this.chain;
    }
}
