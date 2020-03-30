import org.apache.commons.lang3.tuple.Pair;
import org.testng.annotations.Test;
import pt.ist.meic.sec.dpas.attacker.AttackType;
import pt.ist.meic.sec.dpas.attacker.Attacker;
import pt.ist.meic.sec.dpas.client.ClientExample;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.Status;
import pt.ist.meic.sec.dpas.common.StatusMessage;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.ACKPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.AnnouncementsPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.EncryptedPayloadRead;
import pt.ist.meic.sec.dpas.common.payloads.requests.EncryptedPayloadRequest;
import pt.ist.meic.sec.dpas.common.utils.exceptions.IncorrectSignatureException;
import pt.ist.meic.sec.dpas.server.DPAServer;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;

import static org.testng.Assert.*;

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
    public void MITM_Post() throws IOException, IncorrectSignatureException {

        String command = "post hello world";
        EncryptedPayload sentEncrypted = c.doAction(command);
        c.getEncryptedResponse();

        Attacker attacker = new Attacker();
        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload((EncryptedPayloadRequest) sentEncrypted, AttackType.MITM, Operation.POST);
            assertEquals(p.getStatus().getStatus(), Status.InvalidSignature);
        } catch (ClassCastException cce) {
            cce.printStackTrace();
        }
    }

    public void MITM_PostGeneral() throws IOException, IncorrectSignatureException {

        String command = "post hello world";
        EncryptedPayload sentEncrypted = c.doAction(command);
        c.getEncryptedResponse();

        Attacker attacker = new Attacker();
        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload((EncryptedPayloadRequest) sentEncrypted, AttackType.MITM, Operation.POST);
            assertEquals(p.getStatus().getStatus(), Status.InvalidSignature);
        } catch (ClassCastException cce) {
            cce.printStackTrace();
        }
    }
    public void MITM_Read() throws IOException, IncorrectSignatureException {

        String command = "read 0";
        EncryptedPayload sentEncrypted = c.doAction(command);
        c.getEncryptedResponse();

        Attacker attacker = new Attacker();
        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload((EncryptedPayloadRequest) sentEncrypted, AttackType.MITM, Operation.POST);
            assertEquals(p.getStatus().getStatus(), Status.InvalidSignature);
        } catch (ClassCastException cce) {
            cce.printStackTrace();
        }
    }

    public void MITM_ReadGeneral() throws IOException, IncorrectSignatureException {

        String command = "read 0";
        EncryptedPayload sentEncrypted = c.doAction(command);
        c.getEncryptedResponse();

        Attacker attacker = new Attacker();
        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload((EncryptedPayloadRequest) sentEncrypted, AttackType.MITM, Operation.POST);
            assertEquals(p.getStatus().getStatus(), Status.InvalidSignature);
        } catch (ClassCastException cce) {
            cce.printStackTrace();
        }
    }

    public void MITM_Register() throws IOException, IncorrectSignatureException {

        String command = "register";
        EncryptedPayload sentEncrypted = c.doAction(command);
        c.getEncryptedResponse();

        Attacker attacker = new Attacker();
        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload((EncryptedPayloadRequest) sentEncrypted, AttackType.MITM, Operation.POST);
            assertEquals(p.getStatus().getStatus(), Status.InvalidSignature);

        } catch (ClassCastException cce) {
            cce.printStackTrace();
        }
    }

    /**
     * Replay server detection for a READ operation, not using a private key
     *
     * @throws IOException
     */
    public void replayREAD() throws IOException, IncorrectSignatureException {

        String command = "read 4";
        EncryptedPayload sentEncrypted = c.doAction(command);
        c.getEncryptedResponse();

        Attacker attacker = new Attacker();
        try {
            AnnouncementsPayload p = (AnnouncementsPayload) attacker.sendInterceptedRequestPayload((EncryptedPayloadRequest) sentEncrypted, AttackType.REPLAY, Operation.READ);
            fail();
        } catch (ClassCastException | NullPointerException e) {
            System.out.println("Attacker: Unable to process payload.");
        }
    }

    public void missingInformation() throws IncorrectSignatureException, IOException {
        Attacker attacker = new Attacker();
        EncryptedPayloadRead e = new EncryptedPayloadRead(attacker.getPublicKey(), null, null, null, null, null);
        ACKPayload response = (ACKPayload) attacker.sendInterceptedRequestPayload(e, AttackType.REPLAY, Operation.READ);
        assertEquals(response.getStatus().getStatus(), Status.MissingData);


    }

    public void drop() throws SocketTimeoutException {
        String command = "read 0";
        // user attempts to read
        EncryptedPayload sent = c.doAction(command);

        // consume message to mimic packet loss so that user doesn't get any answer back
        try {
            c.getEncryptedResponse();
        } catch (SocketTimeoutException | IncorrectSignatureException e) {
            e.printStackTrace();
        }

        // attempt again
        Pair<DecryptedPayload, EncryptedPayload> receivedFromServer = c.getResponseOrRetry(sent);
        assertNotNull(receivedFromServer);

    }

    public void reject() {
        String command = "read 0";
        // user attempts to read
        EncryptedPayload sent = c.doAction(command);

        Pair<DecryptedPayload, EncryptedPayload> receivedFromServer = c.getResponseOrRetry(sent);
        DecryptedPayload original = receivedFromServer.getLeft();
        DecryptedPayload changed = new AnnouncementsPayload(original.getSenderKey(), original.getOperation(),
                original.getTimestamp(), new StatusMessage(Status.InvalidRequest), new ArrayList<>());

        assertFalse(c.getLibrary().validateReply(changed, receivedFromServer.getRight()));
    }

}
