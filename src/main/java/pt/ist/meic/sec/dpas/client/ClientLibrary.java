package pt.ist.meic.sec.dpas.client;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.PostPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.ReadPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.RegisterPayload;
import pt.ist.meic.sec.dpas.common.utils.KeyManager;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;

public class ClientLibrary {
    private final static Logger logger = Logger.getLogger(ClientLibrary.class);

    private Socket clientSocket;
    private ObjectOutputStream out;
    private ObjectInputStream in;
    public PublicKey serverKey;

    public void start(String ip, int port) throws IOException {
        clientSocket = new Socket(ip, port);
        out = new ObjectOutputStream(clientSocket.getOutputStream());
        in = new ObjectInputStream(clientSocket.getInputStream());

        serverKey = KeyManager.loadPublicKey("keys/public/pub-server.der");
    }

    public void stop() throws IOException {
        in.close();
        out.close();
        clientSocket.close();
    }

    public void register(PublicKey key, PrivateKey privateKey) {
        logger.info("Attempting REGISTER");
        Instant time = Instant.now();
        Operation op = Operation.REGISTER;

        EncryptedPayload ePayload = new RegisterPayload(key, op, time).encrypt(serverKey, privateKey);
        try {
            out.writeObject(ePayload);
            logger.info("Sent REGISTER");
            EncryptedPayload ep = (EncryptedPayload) in.readObject();
            DecryptedPayload dp = ep.decrypt(privateKey);
            boolean correctSignature = dp.verifySignature(ep, ep.getSenderKey());
            if (! correctSignature) {
                logger.warn("Received REGISTER Reply with bad signature");
            } else {
                logger.info("Received REGISTER Reply correctly!");
            }

        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }



    }

    public void post(PublicKey key, String message, List<BigInteger> announcements, PrivateKey privateKey) {
        logger.info("Attempting POST");
        Instant time = Instant.now();
        Operation op = Operation.POST;

        EncryptedPayload ePayload = new PostPayload(message, key, op, time, announcements).encrypt(serverKey, privateKey);
        try {
            out.writeObject(ePayload);
            logger.info("Sent POST with message: " + message + ", linked to: " + announcements);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void postGeneral(PublicKey key, String message, List<BigInteger> announcements, PrivateKey privateKey) {
        logger.info("Attempting POST_GENERAL");
        Instant time = Instant.now();
        Operation op = Operation.POST_GENERAL;

        EncryptedPayload ePayload = new PostPayload(message, key, op, time, announcements).encrypt(serverKey, privateKey);
        try {
            out.writeObject(ePayload);
            logger.info("Sent POST_GENERAL with message: " + message + ", linked to: " + announcements);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public void read(PublicKey key, BigInteger number, PrivateKey privateKey) {
        Instant time = Instant.now();
        Operation op = Operation.READ;

        EncryptedPayload ePayload = new ReadPayload(number, key, op, time).encrypt(serverKey, privateKey);
        try {
            out.writeObject(ePayload);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void readGeneral(BigInteger number, PrivateKey privateKey) {
        Instant time = Instant.now();
        Operation op = Operation.READ_GENERAL;

        EncryptedPayload ePayload = new ReadPayload(number, null, op, time).encrypt(serverKey, privateKey);
        try {
            out.writeObject(ePayload);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
    public static void main(String[] args) {
        try {
            ClientLibrary c = new ClientLibrary();
            c.start("127.0.0.1", 8081);
            c.register(c.publicKey);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
     */
}
