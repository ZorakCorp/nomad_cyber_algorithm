import { PQCServerService } from './pqc_server_service';
import { PQCClientService } from './pqc_client_service';

async function runPQC_MicroserviceDemo() {
    console.log("--- PQC-Secured Microservice Communication Demo (TypeScript) ---");
    console.log("Demonstrates quantum-resistant key exchange (Kyber) and mutual authentication (Dilithium) ");
    console.log("for Top Secret / SCI data within an Air-Gapped Network.\n");

    const serverPort = 8443;

    // Start the PQC Server Service
    const serverService = new PQCServerService(serverPort);
    serverService.start();

    // Give server a moment to start listening
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Start the PQC Client Service
    const clientService = new PQCClientService('localhost', serverPort);
    await clientService.connect();

    // Wait for the PQC handshake to complete
    console.log("\n[DEMO] Waiting for PQC handshake to complete...");
    try {
        await clientService.waitForHandshake();
        console.log("\n[DEMO] PQC Handshake successful. Secure channel is ready for application data.");

        // Send a Top Secret / SCI message from client to server
        const secretMessage = "Access to Project Nightingale data requires Level 5 clearance. Quantum-resistant encryption validated.";
        await clientService.sendEncryptedMessage(secretMessage);

        // Give time for server to process and respond (the server will send an encrypted response back)
        await new Promise(resolve => setTimeout(resolve, 2000));

    } catch (error) {
        console.error(`\n[DEMO] PQC Handshake failed: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
        // Clean up
        console.log("\n[DEMO] Disconnecting client.");
        clientService.disconnect();
        // In a real system, server would remain running or be shut down gracefully.
        // For this demo, we'll let Node.js exit when the server has no more active connections.
    }
}

runPQC_MicroserviceDemo();
