import org.apache.commons.lang3.tuple.Pair;
import org.testng.annotations.Test;
import pt.ist.meic.sec.dpas.attacker.AttackType;
import pt.ist.meic.sec.dpas.attacker.Attacker;
import pt.ist.meic.sec.dpas.client.ClientExample;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.Status;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.ACKPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.AnnouncementsPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.EncryptedPayloadRequest;
import pt.ist.meic.sec.dpas.server.DPAServer;

import java.io.IOException;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

@Test
public class Attacks {

    private DPAServer s = new DPAServer();

    {
        Thread serverThread = new Thread (s::listen);
        serverThread.start();
    }

    ClientExample c = new ClientExample("test", "keys/private/clients/2.p12", "client2");

    /**
     * Man in the Middle server detection for a POST operation, with different private key from legitimate client
     *
     * @throws IOException
     */
    public void MITM_Post() throws IOException {

        String command = "post hello world";
        Pair<EncryptedPayload, EncryptedPayload> sentAndReceived = c.doAction(command);

        EncryptedPayload sentEncrypted = sentAndReceived.getLeft();

        Attacker attacker = new Attacker();
        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload((EncryptedPayloadRequest) sentEncrypted, AttackType.MITM, Operation.POST);
            assertEquals(p.getStatus().getStatus(), Status.InvalidRequest);
        } catch (ClassCastException cce) {
            cce.printStackTrace();
        }
    }

    public void MITM_PostGeneral() throws IOException {

        String command = "post hello world";
        Pair<EncryptedPayload, EncryptedPayload> sentAndReceived = c.doAction(command);

        EncryptedPayload sentEncrypted = sentAndReceived.getLeft();

        Attacker attacker = new Attacker();
        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload((EncryptedPayloadRequest) sentEncrypted, AttackType.MITM, Operation.POST);
            assertEquals(p.getStatus().getStatus(), Status.InvalidRequest);
        } catch (ClassCastException cce) {
            cce.printStackTrace();
        }
    }
    public void MITM_Read() throws IOException {

        String command = "read 0";
        Pair<EncryptedPayload, EncryptedPayload> sentAndReceived = c.doAction(command);

        EncryptedPayload sentEncrypted = sentAndReceived.getLeft();

        Attacker attacker = new Attacker();
        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload((EncryptedPayloadRequest) sentEncrypted, AttackType.MITM, Operation.POST);
            assertEquals(p.getStatus().getStatus(), Status.InvalidRequest);
        } catch (ClassCastException cce) {
            cce.printStackTrace();
        }
    }
    public void MITM_ReadGeneral() throws IOException {

        String command = "read 0";
        Pair<EncryptedPayload, EncryptedPayload> sentAndReceived = c.doAction(command);

        EncryptedPayload sentEncrypted = sentAndReceived.getLeft();

        Attacker attacker = new Attacker();
        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload((EncryptedPayloadRequest) sentEncrypted, AttackType.MITM, Operation.POST);
            assertEquals(p.getStatus().getStatus(), Status.InvalidRequest);
        } catch (ClassCastException cce) {
            cce.printStackTrace();
        }
    }

    public void MITM_Register() throws IOException {

        String command = "register";
        Pair<EncryptedPayload, EncryptedPayload> sentAndReceived = c.doAction(command);

        EncryptedPayload sentEncrypted = sentAndReceived.getLeft();
        EncryptedPayload receivedEncrypted = sentAndReceived.getRight();

        Attacker attacker = new Attacker();
        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload((EncryptedPayloadRequest) sentEncrypted, AttackType.MITM, Operation.POST);
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

        String command = "read 4";
        Pair<EncryptedPayload, EncryptedPayload> sentAndReceived = c.doAction(command);

        EncryptedPayload sentEncrypted = sentAndReceived.getLeft();
        EncryptedPayload receivedEncrypted = sentAndReceived.getRight();

        Attacker attacker = new Attacker();
        try {
            AnnouncementsPayload p = (AnnouncementsPayload) attacker.sendInterceptedRequestPayload((EncryptedPayloadRequest) sentEncrypted, AttackType.REPLAY, Operation.READ);
            fail();
        } catch (ClassCastException | NullPointerException e) {
            System.out.println("Attacker: Unable to process payload.");
        }
    }


}
