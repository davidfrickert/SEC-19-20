import org.testng.annotations.Test;
import pt.ist.meic.sec.dpas.attacker.AttackType;
import pt.ist.meic.sec.dpas.attacker.Attacker;
import pt.ist.meic.sec.dpas.client.ClientExample;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.Status;
import pt.ist.meic.sec.dpas.common.StatusMessage;
import pt.ist.meic.sec.dpas.common.model.Announcement;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.ACKPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.AnnouncementsPayload;
import pt.ist.meic.sec.dpas.common.utils.exceptions.IncorrectSignatureException;
import pt.ist.meic.sec.dpas.common.utils.exceptions.QuorumNotReachedException;
import pt.ist.meic.sec.dpas.server.DPAServer;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

import static org.testng.Assert.*;

@Test
public class Attacks {

    // LAUNCH SERVERS MANUALLY FIRST

    ClientExample c = new ClientExample("test", "keys/private/clients/2.p12", "client2", 35000);
    Attacker attacker = new Attacker(35000);

    /**
     * Man in the Middle server detection for a POST operation,
     * Attacker attempts to replace the Client c's public key with his own.
     * Server detects and answers with InvalidSignature
     */
   public void MITM_Post() throws IOException, IncorrectSignatureException {

        String command = "post hello world";
        DecryptedPayload sentEncrypted = c.doAction(command);
        c.getResponse();

        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload(sentEncrypted, AttackType.MITM, Operation.POST);
            assertEquals(p.getStatus().getStatus(), Status.InvalidSignature);
        } catch (ClassCastException | QuorumNotReachedException | IncorrectSignatureException cce) {
            cce.printStackTrace();
           fail();
        }
    }

    /**
     * Man in the Middle server detection for a POST_GENERAL operation,
     * Attacker attempts to replace the Client c's public key with his own.
     * Server detects and answers with InvalidSignature
     */

    public void MITM_PostGeneral() throws IncorrectSignatureException, QuorumNotReachedException {

        String command = "postgeneral hello world";
        DecryptedPayload sentEncrypted = c.doAction(command);
        c.getResponse();

        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload(sentEncrypted, AttackType.MITM, Operation.POST_GENERAL);
            assertEquals(p.getStatus().getStatus(), Status.InvalidSignature);
        } catch (ClassCastException | QuorumNotReachedException | IncorrectSignatureException cce) {
            fail();
            cce.printStackTrace();
        }
    }

    /**
     * Man in the Middle server detection for a READ operation,
     * Attacker attempts to replace the Client c's public key with his own.
     * Server detects and answers with InvalidSignature
     */

    public void MITM_Read() throws IncorrectSignatureException, QuorumNotReachedException {

        String pkClient1 = Base64.getEncoder().encodeToString(c.getPublicKey().getEncoded());
        String command = "read " + pkClient1 + " 0";
        DecryptedPayload sentEncrypted = c.doAction(command);
        c.getResponse();

        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload(sentEncrypted, AttackType.MITM, Operation.READ);
            assertEquals(p.getStatus().getStatus(), Status.InvalidSignature);
        } catch (ClassCastException | QuorumNotReachedException | IncorrectSignatureException cce) {
            cce.printStackTrace();
            fail();
        }
    }

    /**
     * Man in the Middle server detection for a READ_GENERAL operation,
     * Attacker attempts to replace the Client c's public key with his own.
     * Server detects and answers with InvalidSignature
     */

    public void MITM_ReadGeneral() throws IncorrectSignatureException, QuorumNotReachedException {

        String command = "readgeneral 0";
        DecryptedPayload sentEncrypted = c.doAction(command);
        c.getResponse();

        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload(sentEncrypted, AttackType.MITM, Operation.READ_GENERAL);
            assertEquals(p.getStatus().getStatus(), Status.InvalidSignature);
        } catch (ClassCastException | QuorumNotReachedException | IncorrectSignatureException cce) {
            cce.printStackTrace();
            fail();
        }

    }

    /**
     * Man in the Middle server detection for a REGISTER operation,
     * Attacker attempts to replace the Client c's public key with his own.
     * Server detects and answers with InvalidSignature
     */

    public void MITM_Register() throws IncorrectSignatureException, QuorumNotReachedException {

        String command = "register";
        DecryptedPayload sentEncrypted = c.doAction(command);
        c.getResponse();

        try {
            // all replies can be casted to ACKPayload to view status message
            ACKPayload p = (ACKPayload) attacker.sendInterceptedRequestPayload(sentEncrypted, AttackType.MITM, Operation.REGISTER);
            assertEquals(p.getStatus().getStatus(), Status.InvalidSignature);

        } catch (ClassCastException | QuorumNotReachedException | IncorrectSignatureException cce) {
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
    public void replayREAD() throws IOException, IncorrectSignatureException {

        String command = "readgeneral 4";

        // Client sent 'sentEncrypted'
        DecryptedPayload sentEncrypted = c.doAction(command);
        // server replied to client
        ACKPayload dp = (ACKPayload) c.getResponseOrRetry(sentEncrypted);

        // first message should be fresh (so, -not- NotFresh)
        assertNotNull(dp);
        assertNotEquals(dp.getStatus().getStatus(), Status.NotFresh);

        // attacker - in this test case - it is the same client
        c.getLibrary().write(sentEncrypted);

        // process server answer
        ACKPayload replayResponse = (ACKPayload) c.getLibrary().receiveReply();
        // second message should be marked NotFresh
        assertEquals(replayResponse.getStatus().getStatus(), Status.NotFresh);

    }

    /**
     * Attempt to send a payload with missing required information - in this test case, send a payload with only public key.
     * Server answers with status code MissingData
     */

    public void missingInformation() throws IncorrectSignatureException, IOException {
        DecryptedPayload e = attacker.buildMissingInformationPayload();
        ACKPayload response = (ACKPayload) attacker.sendInterceptedRequestPayload(e, AttackType.REPLAY, Operation.READ);
        assertEquals(response.getStatus().getStatus(), Status.MissingData);
    }

    /**
     * Simulation of how the client handles drop attack
     * By having a timeout of 15s, client retries the request, it doesn't wait indefinitely for an answer.
     */

    public void drop() throws IncorrectSignatureException, QuorumNotReachedException {
        String command = "readgeneral 0";
        // user sends a readgeneral payload to server
        DecryptedPayload sent = c.doAction(command);

        // consume message to mimic packet loss so that user doesn't get any answer back
        c.getResponse();

        // user is waiting for message
        // if timeout of 15 seconds passes, client retries the request, until eventually it succeeds,
        // or it reaches max attempts
        DecryptedPayload receivedFromServer = c.getResponseOrRetry(sent);
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
        DecryptedPayload sent = c.doAction(command);

        // Original decrypted payload sent by server
        // Attacker got in possession of this payload, and, it didn't reach the client
        DecryptedPayload original = c.getResponseOrRetry(sent);

        // check that message sent by server matches signature
        assertTrue(c.getLibrary().validateReply(original));

        // Attacker modifies the payload, changing the status message to an invalid request
        ACKPayload changed = (ACKPayload) original;
        changed.setStatus(new StatusMessage(Status.InvalidRequest));

        // check that altered message doesn't match signature
        assertFalse(c.getLibrary().validateReply(changed));
    }

    /**
     * Man in the middle attack on the interaction server -> client
     * Any attempt on modifying the payload will be detected by the client
     */

    public void changeAnnouncements() {
        String command = "readgeneral 0";
        // user attempts a POST
        DecryptedPayload sent = c.doAction(command);

        // Decrypted and Encrypted versions of the payload sent by server
        DecryptedPayload receivedFromServer = c.getResponseOrRetry(sent);
        // Original decrypted payload sent by server
        // Attacker got in possession of this payload, and, it didn't reach the client

        // check that message sent by server matches signature
        assertTrue(c.validateSignature(receivedFromServer));

        AnnouncementsPayload modifiedByAttacker = (AnnouncementsPayload) receivedFromServer;
        modifiedByAttacker.setAnnouncements(
            new ArrayList<>(
                Arrays.asList(new Announcement("i was here", attacker.getPublicKey(), Instant.now()))
            )
        );
        // check that altered message doesn't match signature
        assertFalse(c.validateSignature(modifiedByAttacker));
    }

}
