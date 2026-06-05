/** Serializes async message handlers to prevent state-machine races. */

export class MessageQueue {
    private chain: Promise<void> = Promise.resolve();

    enqueue(handler: () => Promise<void>, onError: (err: unknown) => void): void {
        this.chain = this.chain
            .then(() => handler())
            .catch((err) => {
                onError(err);
            });
    }

    async drain(): Promise<void> {
        await this.chain;
    }
}
