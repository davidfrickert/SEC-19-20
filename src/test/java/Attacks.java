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
import pt.ist.meic.sec.dpas.common.payloads.reply.EncryptedPayloadAnnouncements;
import pt.ist.meic.sec.dpas.common.payloads.requests.EncryptedPayloadRead;
import pt.ist.meic.sec.dpas.common.payloads.requests.EncryptedPayloadRequest;
import pt.ist.meic.sec.dpas.common.utils.exceptions.IncorrectSignatureException;
import pt.ist.meic.sec.dpas.server.DPAServer;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.SocketTimeoutException;
import java.security.KeyPair;
import java.util.Base64;

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
     * Man in the Middle server detection for a POST operation,
     * Attacker attempts to replace the Client c's public key with his own.
     * Server detects and answers with InvalidSignature
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
        } catch (ClassCastException | SocketTimeoutException | IncorrectSignatureException cce) {
            cce.printStackTrace();
           fail();
        }
    }

    /**
     * Man in the Middle server detection for a POST_GENERAL operation,
     * Attacker attempts to replace the Client c's public key with his own.
     * Server detects and answers with InvalidSignature
     */

    public void MITM_PostGeneral() throws IncorrectSignatureException, SocketTimeoutException {

        String command = "postgeneral hello world";
        EncryptedPayload sentEncrypted = c.doAction(command);
        c.getEncryptedResponse();


        Attacker attacker = new Attacker();
        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload((EncryptedPayloadRequest) sentEncrypted, AttackType.MITM, Operation.POST_GENERAL);
            assertEquals(p.getStatus().getStatus(), Status.InvalidSignature);
        } catch (ClassCastException | SocketTimeoutException | IncorrectSignatureException cce) {
            fail();
            cce.printStackTrace();
        }
    }

    /**
     * Man in the Middle server detection for a READ operation,
     * Attacker attempts to replace the Client c's public key with his own.
     * Server detects and answers with InvalidSignature
     */

    public void MITM_Read() throws IncorrectSignatureException, SocketTimeoutException {

        String pkClient1 = Base64.getEncoder().encodeToString(c.getPublicKey().getEncoded());
        String command = "read " + pkClient1 + " 0";
        EncryptedPayload sentEncrypted = c.doAction(command);
        c.getEncryptedResponse();

        Attacker attacker = new Attacker();
        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload((EncryptedPayloadRequest) sentEncrypted, AttackType.MITM, Operation.READ);
            assertEquals(p.getStatus().getStatus(), Status.InvalidSignature);
        } catch (ClassCastException | SocketTimeoutException | IncorrectSignatureException cce) {
            cce.printStackTrace();
            fail();
        }
    }

    /**
     * Man in the Middle server detection for a READ_GENERAL operation,
     * Attacker attempts to replace the Client c's public key with his own.
     * Server detects and answers with InvalidSignature
     */

    public void MITM_ReadGeneral() throws IncorrectSignatureException, SocketTimeoutException {

        String command = "readgeneral 0";
        EncryptedPayload sentEncrypted = c.doAction(command);

        c.getEncryptedResponse();


        Attacker attacker = new Attacker();
        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload((EncryptedPayloadRequest) sentEncrypted, AttackType.MITM, Operation.READ_GENERAL);
            assertEquals(p.getStatus().getStatus(), Status.InvalidSignature);
        } catch (ClassCastException | SocketTimeoutException | IncorrectSignatureException cce) {
            cce.printStackTrace();
            fail();
        }

    }

    /**
     * Man in the Middle server detection for a REGISTER operation,
     * Attacker attempts to replace the Client c's public key with his own.
     * Server detects and answers with InvalidSignature
     */

    public void MITM_Register() throws IncorrectSignatureException, SocketTimeoutException {

        String command = "register";
        EncryptedPayload sentEncrypted = c.doAction(command);
        c.getEncryptedResponse();


        Attacker attacker = new Attacker();
        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload((EncryptedPayloadRequest) sentEncrypted, AttackType.MITM, Operation.REGISTER);
            assertEquals(p.getStatus().getStatus(), Status.InvalidSignature);

        } catch (ClassCastException | SocketTimeoutException | IncorrectSignatureException cce) {
            cce.printStackTrace();
            fail();
        }
    }

    /**
     * Replay server detection for a READ operation
     * Attacker is in possession of a payload sent by Client c
     * Attempts to send it as-is to server
     * Server detects he already received this payload and returns NotFresh status code.
     */
    public void replayREAD() throws IOException, IncorrectSignatureException, NoSuchFieldException, IllegalAccessException {

        String command = "readgeneral 4";

        // Client sent 'sentEncrypted'
        EncryptedPayload sentEncrypted = c.doAction(command);
        // server replied to client
        ACKPayload dp = (ACKPayload) c.getResponseOrRetry(sentEncrypted).getLeft();

        // first message should be fresh (so, -not- NotFresh)
        assertNotNull(dp);
        assertNotEquals(dp.getStatus().getStatus(), Status.NotFresh);

        // attacker - in this test case - it is the same client
        c.getLibrary().write(sentEncrypted);

        // since we don't want to make client keypair public use reflection to access it only for this test
        Field f = c.getClass().getDeclaredField("keyPair");
        f.setAccessible(true);
        KeyPair kp = (KeyPair) f.get(c);

        // process server answer
        ACKPayload replayResponse = (ACKPayload) c.getLibrary().receiveReply(kp.getPrivate()).getLeft();
        // second message should be marked NotFresh
        assertEquals(replayResponse.getStatus().getStatus(), Status.NotFresh);

    }

    /**
     * Attempt to send a payload with missing required information - in this test case, send a payload with only public key.
     * Server answers with status code MissingData
     */

    public void missingInformation() throws IncorrectSignatureException, IOException {
        Attacker attacker = new Attacker();
        EncryptedPayloadRead e = new EncryptedPayloadRead(attacker.getPublicKey(), null, null, null, null, null);
        ACKPayload response = (ACKPayload) attacker.sendInterceptedRequestPayload(e, AttackType.REPLAY, Operation.READ);
        assertEquals(response.getStatus().getStatus(), Status.MissingData);
    }

    /**
     * Simulation of how the client handles drop attack
     * By having a timeout of 15s, client retries the request, it doesn't wait indefinitely for an answer.
     */

    public void drop() throws IncorrectSignatureException, SocketTimeoutException {
        String command = "readgeneral 0";
        // user sends a readgeneral payload to server
        EncryptedPayload sent = c.doAction(command);

        // consume message to mimic packet loss so that user doesn't get any answer back
        c.getEncryptedResponse();

        // user is waiting for message
        // if timeout of 15 seconds passes, client retries the request, until eventually it succeeds,
        // or it reaches max attempts
        Pair<DecryptedPayload, EncryptedPayload> receivedFromServer = c.getResponseOrRetry(sent);
        assertNotNull(receivedFromServer);

    }

    /**
     * Simulation of an attacker rejecting a user's request
     * Client c attempts a POST operation
     *
     */

    public void reject() {
        String command = "post hello";
        // user attempts a POST
        EncryptedPayload sent = c.doAction(command);

        // Decrypted and Encrypted versions of the payload sent by server
        Pair<DecryptedPayload, EncryptedPayload> receivedFromServer = c.getResponseOrRetry(sent);
        // Original decrypted payload sent by server
        // Attacker got in possession of this payload, and, it didn't reach the client
        DecryptedPayload original = receivedFromServer.getLeft();
        // Attacker modifies the payload, changing the status message to an invalid request
        DecryptedPayload changed = new ACKPayload(original.getSenderKey(), original.getOperation(),
                original.getTimestamp(), new StatusMessage(Status.InvalidRequest));

        // check that message sent by server matches signature
        assertTrue(c.getLibrary().validateReply(original, receivedFromServer.getRight()));
        // check that altered message doesn't match signature
        assertFalse(c.getLibrary().validateReply(changed, receivedFromServer.getRight()));
    }

    /**
     * Man in the middle attack on the interaction server -> client
     * Any attempt on modifying the payload will be detected by the client
     */

    public void changeAnnouncements() {
        String command = "readgeneral 0";
        // user attempts a POST
        EncryptedPayload sent = c.doAction(command);

        // Decrypted and Encrypted versions of the payload sent by server
        Pair<DecryptedPayload, EncryptedPayload> receivedFromServer = c.getResponseOrRetry(sent);
        // Original decrypted payload sent by server
        // Attacker got in possession of this payload, and, it didn't reach the client
        EncryptedPayloadAnnouncements e = (EncryptedPayloadAnnouncements) receivedFromServer.getRight();
        EncryptedPayloadAnnouncements changed = new EncryptedPayloadAnnouncements(e.getSenderKey(), e.getOperation(),
                e.getTimestamp(), e.getSignature(), e.getStatusMessage(), new byte[] {1, 5, 2, 20});
        // check that message sent by server matches signature
        assertTrue(c.validateSignature(e));
        // check that altered message doesn't match signature
        assertFalse(c.validateSignature(changed));
    }

}
