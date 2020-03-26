import org.apache.commons.lang3.tuple.Pair;
import org.testng.annotations.Test;
import pt.ist.meic.sec.dpas.attacker.AttackType;
import pt.ist.meic.sec.dpas.attacker.Attacker;
import pt.ist.meic.sec.dpas.client.ClientExample;
import pt.ist.meic.sec.dpas.common.Status;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.ACKPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.AnnouncementsPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.EncryptedPayloadRequest;
import pt.ist.meic.sec.dpas.server.DPAServer;

import java.io.IOException;

import static org.testng.Assert.*;

@Test
public class Attacks {

    /**
     * Man in the Middle server detection for a POST operation, with different private key from legitimate client
     *
     * @throws IOException
     */
    public void MITM() throws IOException {
        DPAServer s = new DPAServer();
        Thread serverThread = new Thread (s::listen);
        serverThread.start();

        ClientExample c = new ClientExample("test");
        String command = "post hello world";
        Pair<EncryptedPayload, EncryptedPayload> sentAndReceived = c.doAction(command);

        EncryptedPayload sentEncrypted = sentAndReceived.getLeft();
        EncryptedPayload receivedEncrypted = sentAndReceived.getRight();

        Attacker attacker = new Attacker();
        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload((EncryptedPayloadRequest) sentEncrypted, AttackType.MITM);
            assertEquals(p.getStatus().getStatus(), Status.InvalidRequest);
        } catch (ClassCastException cce) {
            cce.printStackTrace();
        }
    }

    /**
     * Replay server detection for a READ operation, not using a private key
     *
     * @throws IOException
     */
    public void replayREAD() throws IOException {
        DPAServer s = new DPAServer();
        Thread serverThread = new Thread (s::listen);
        serverThread.start();

        ClientExample c = new ClientExample("test");
        String command = "read 4 keys/public/clients/pub1.der";
        Pair<EncryptedPayload, EncryptedPayload> sentAndReceived = c.doAction(command);

        EncryptedPayload sentEncrypted = sentAndReceived.getLeft();
        EncryptedPayload receivedEncrypted = sentAndReceived.getRight();

        Attacker attacker = new Attacker();
        try {
            AnnouncementsPayload p = (AnnouncementsPayload) attacker.sendInterceptedRequestPayload((EncryptedPayloadRequest) sentEncrypted, AttackType.REPLAY_READ);
            fail();
        } catch (ClassCastException | NullPointerException e) {
            System.out.println("Attacker: Unable to process payload.");
        }
    }

}
