package pt.ist.meic.sec.dpas.server;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.Status;
import pt.ist.meic.sec.dpas.common.StatusMessage;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.ACKPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.PostPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.ReadPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.RegisterPayload;
import pt.ist.meic.sec.dpas.common.utils.KeyManager;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

// OLD DPAServer

public class EncryptionTest {
    private final static Logger logger = Logger.getLogger(EncryptionTest.class);

    private List<PublicKey> clientPKs = new ArrayList<>();
    // to remove
    private List<PrivateKey> clientPriv = new ArrayList<>();
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public EncryptionTest() {
        loadPublicKeys();
        this.privateKey = KeyManager.loadPrivateKey("keys/private/priv-server.der");
        this.publicKey = KeyManager.loadPublicKey("keys/public/pub-server.der");
    }

    private void loadPublicKeys() {


        try (Stream<Path> walk = Files.walk(Paths.get("keys/public/clients"))) {
            List<String> result = walk.filter(Files::isRegularFile).map(Path::toString).collect(Collectors.toList());
            clientPKs.addAll(result.stream().map(KeyManager::loadPublicKey).collect(Collectors.toList()));
        } catch (IOException e) {
            e.printStackTrace();
        }

        // to remove
        try (Stream<Path> walk = Files.walk(Paths.get("keys/private/clients"))) {
            List<String> result = walk.filter(Files::isRegularFile).map(Path::toString).collect(Collectors.toList());
            clientPriv.addAll(result.stream().map(KeyManager::loadPrivateKey).collect(Collectors.toList()));
        } catch (IOException e) {
            e.printStackTrace();
        }
        //

    }


    private PrivateKey getPrivateKey(int index) {
        return this.clientPriv.get(index);
    }

    public PublicKey getPublicKey(int index) {
        return this.clientPKs.get(index);
    }

    public static void main(String[] args) {
       EncryptionTest s = new EncryptionTest();

       s.testPOST();
       s.testREAD();
       s.testREGISTER();

    }

    public void testPOST() {
        List<BigInteger> linkedAnnouncementIds = Arrays.asList(BigInteger.ONE);
        Instant timestamp = Instant.now();
        PublicKey idKey = this.getPublicKey(0);
        String data = new String("Olá");

        PostPayload postPayload = new PostPayload(data, idKey, Operation.POST, timestamp, linkedAnnouncementIds);

        EncryptedPayload ep = postPayload.encrypt(this.publicKey, this.getPrivateKey(0));
        DecryptedPayload dp = ep.decrypt(this.privateKey);
        boolean correctSignature = dp.verifySignature(ep, ep.getSenderKey());


        testPOSTReply();
    }

    public void testPOSTReply() {
        StatusMessage s = new StatusMessage(Status.Success, "Announcement registered with id 1-this is hardcoded test.");
        Instant timestamp = Instant.now();
        PublicKey idKey = this.publicKey;
        Operation o = Operation.POST;

        ACKPayload ackPayload = new ACKPayload(idKey, o, timestamp, s);
        EncryptedPayload ep = ackPayload.encrypt(this.getPublicKey(0), this.privateKey);
        DecryptedPayload dp = ep.decrypt(this.privateKey);
        boolean correctSignature = dp.verifySignature(ep, ep.getSenderKey());
    }

    public void testREAD() {
        int keyNumber = 5;
        BigInteger n = BigInteger.ONE;
        Instant timestamp = Instant.now();
        PublicKey idKey = this.getPublicKey(keyNumber);
        Operation o = Operation.READ;

        ReadPayload readPayload = new ReadPayload(n, idKey, o, timestamp);
        EncryptedPayload ep = readPayload.encrypt(this.publicKey, this.getPrivateKey(keyNumber));
        DecryptedPayload dp = ep.decrypt(this.privateKey);
        boolean correctSignature = dp.verifySignature(ep, ep.getSenderKey());

    }

    public void testREGISTER() {
        int keyNumber = 5;
        Instant timestamp = Instant.now();
        PublicKey idKey = this.getPublicKey(keyNumber);
        Operation o = Operation.REGISTER;

        RegisterPayload registerPayload = new RegisterPayload(idKey, o, timestamp);
        EncryptedPayload ep = registerPayload.encrypt(this.publicKey, this.getPrivateKey(keyNumber));
        DecryptedPayload dp = ep.decrypt(this.privateKey);
        boolean correctSignature = dp.verifySignature(ep, ep.getSenderKey());
    }






}
