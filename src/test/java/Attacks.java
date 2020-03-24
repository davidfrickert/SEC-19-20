import org.apache.commons.lang3.tuple.Pair;
import org.testng.annotations.Test;
import pt.ist.meic.sec.dpas.attacker.AttackType;
import pt.ist.meic.sec.dpas.attacker.Attacker;
import pt.ist.meic.sec.dpas.client.ClientExample;
import pt.ist.meic.sec.dpas.common.Status;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.ACKPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.EncryptedPayloadRequest;
import pt.ist.meic.sec.dpas.server.DPAServer;

import java.io.IOException;

import static org.testng.Assert.assertEquals;

@Test
public class Attacks {

    /**
     * Man in the Middle server detection for a POST operation
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

    public void drop() {

    }
}
