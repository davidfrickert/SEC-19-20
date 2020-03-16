package pt.ist.meic.sec.dpas.client;

import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.PostPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.ReadPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.RegisterPayload;
import pt.ist.meic.sec.dpas.common.utils.KeyManager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;

public class ClientLibrary {
    private Socket clientSocket;
    private PrintWriter out;
    private BufferedReader in;
    private PrivateKey privateKey;
    public PublicKey publicKey;
    public PublicKey serverKey;

    public void start(String ip, int port) throws IOException {
        clientSocket = new Socket(ip, port);
        out = new PrintWriter(clientSocket.getOutputStream(), true);
        in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

        // not dynamic (yet)
        privateKey = KeyManager.loadPrivateKey("keys/private/clients/private1.der");
        publicKey = KeyManager.loadPublicKey("keys/public/clients/public1.der");
        serverKey = KeyManager.loadPublicKey("keys/public/pub-server.der");
    }

    public void stop() throws IOException {
        in.close();
        out.close();
        clientSocket.close();
    }

    public void register(PublicKey key) {

        Instant time = Instant.now();
        Operation op = Operation.REGISTER;
        /*
        byte[] encryptedOperation = Crypto.encryptBytes(op.name().getBytes(), serverKey);
        byte[] encryptedTimestamp = Crypto.encryptBytes(time.toString().getBytes(), serverKey);
        byte[] originalData = ArrayUtils.merge(null, publicKey.getEncoded(), op.name().getBytes(), null, time.toString().getBytes());

        byte[] signature = Crypto.sign(originalData, privateKey);

        EncryptedPayload payload =  new EncryptedPayloadRequest(key, encryptedOperation, encryptedTimestamp, signature, null,
                null);

        out.println(payload);
        */

        // new way to do it
        EncryptedPayload ePayload = new RegisterPayload(key, op, time).encrypt(serverKey, privateKey);
        out.println(ePayload);

    }

    public void post(PublicKey key, String message, List<BigInteger> announcements) {
        Instant time = Instant.now();
        Operation op = Operation.POST;

        EncryptedPayload ePayload = new PostPayload(message, key, op, time, announcements).encrypt(serverKey, privateKey);
        out.println(ePayload);
    }

    public void postGeneral(PublicKey key, String message, List<BigInteger> announcements) {
        Instant time = Instant.now();
        Operation op = Operation.POST_GENERAL;

        EncryptedPayload ePayload = new PostPayload(message, key, op, time, announcements).encrypt(serverKey, privateKey);
        out.println(ePayload);
    }


    public void read(PublicKey key, BigInteger number) {
        Instant time = Instant.now();
        Operation op = Operation.READ;

        EncryptedPayload ePayload = new ReadPayload(number, key, op, time).encrypt(serverKey, privateKey);
        out.println(ePayload);
    }

    public void readGeneral(BigInteger number) {
        Instant time = Instant.now();
        Operation op = Operation.READ_GENERAL;

        EncryptedPayload ePayload = new ReadPayload(number, null, op, time).encrypt(serverKey, privateKey);
        out.println(ePayload);
    }

    public static void main(String[] args) {
        try {
            ClientLibrary c = new ClientLibrary();
            c.start("127.0.0.1", 8081);
            c.register(c.publicKey);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
