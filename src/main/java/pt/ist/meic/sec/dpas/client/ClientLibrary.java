package pt.ist.meic.sec.dpas.client;

import org.apache.commons.lang3.tuple.Pair;
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
import java.net.ConnectException;
import java.net.Socket;
import java.net.SocketException;
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

    private String ip;
    private int port;

    public void start(String ip, int port) {
        this.ip = ip;
        this.port = port;
        connect();
        serverKey = KeyManager.loadPublicKey("keys/public/pub-server.der");
    }

    private void connect() {
        boolean connected = false;

        while (!connected) {
            try {
                clientSocket = new Socket(ip, port);
                connected = true;
                out = new ObjectOutputStream(clientSocket.getOutputStream());
                in = new ObjectInputStream(clientSocket.getInputStream());
                logger.info("Connected to " + ip + ":" + port);
            } catch (IOException e) {
                try {
                    logger.info("Connection failure... Retrying in 3 seconds");
                    Thread.sleep(3000);
                } catch (InterruptedException ex) {
                    ex.printStackTrace();
                }
                if (! (e instanceof  ConnectException))
                e.printStackTrace();
            }
        }
    }

    private void write(EncryptedPayload e) {
        boolean done = false;
        int attempts = 0;
        while (!done && attempts < 10) {
            try {
                out.writeObject(e);
                done = true;
            } catch (SocketException se) {
                logger.info("Failed to send.. Retrying connection");
                connect();
            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
            attempts++;
        }
    }

    public void stop() throws IOException {
        in.close();
        out.close();
        clientSocket.close();
    }

    public Pair<EncryptedPayload, EncryptedPayload> register(PublicKey key, PrivateKey privateKey) {
        Operation op = Operation.REGISTER;
        EncryptedPayload sentEncrypted = registerSend(key, privateKey);
        Pair<DecryptedPayload, EncryptedPayload> received = sendGeneral(sentEncrypted, op, privateKey);
        DecryptedPayload receivedDecrypted = received.getLeft();
        EncryptedPayload receivedEncrypted = received.getRight();
        return Pair.of(sentEncrypted, receivedEncrypted);
    }

    public EncryptedPayload registerSend(PublicKey key, PrivateKey privateKey) {
        logger.info("Attempting REGISTER");
        Instant time = Instant.now();
        Operation op = Operation.REGISTER;

        return new RegisterPayload(key, op, time).encrypt(serverKey, privateKey);
    }

    public Pair<EncryptedPayload, EncryptedPayload> post(PublicKey key, String message, List<BigInteger> announcements, PrivateKey privateKey) {
        Operation op = Operation.POST;
        EncryptedPayload sentEncrypted = sendPost(key, message, announcements, privateKey, op);
        Pair<DecryptedPayload, EncryptedPayload> received = sendGeneral(sentEncrypted, op, privateKey);
        DecryptedPayload receivedDecrypted = received.getLeft();
        EncryptedPayload receivedEncrypted = received.getRight();
        return Pair.of(sentEncrypted, receivedEncrypted);
    }

    /**
     * Sends a POST payload to server
     *
     * @param key
     * @param message
     * @param announcements
     * @param privateKey
     * @return Payload sent to server
     */
    public EncryptedPayload sendPost(PublicKey key, String message, List<BigInteger> announcements, PrivateKey privateKey, Operation op) {
        if (op != Operation.POST && op != Operation.POST_GENERAL) {
            throw new IllegalArgumentException("Wrong Operation for this method " + op.name());
        }
        logger.info("Attempting " + op.name());
        Instant time = Instant.now();

        return new PostPayload(message, key, op, time, announcements).encrypt(serverKey, privateKey);
    }

    public Pair<EncryptedPayload, EncryptedPayload> postGeneral(PublicKey key, String message, List<BigInteger> announcements, PrivateKey privateKey) {
        Operation op = Operation.POST_GENERAL;
        EncryptedPayload sentEncrypted = sendPost(key, message, announcements, privateKey, op);
        Pair<DecryptedPayload, EncryptedPayload> received = sendGeneral(sentEncrypted, op, privateKey);
        DecryptedPayload receivedDecrypted = received.getLeft();
        EncryptedPayload receivedEncrypted = received.getRight();
        return Pair.of(sentEncrypted, receivedEncrypted);
    }


    public Pair<EncryptedPayload, EncryptedPayload> read(PublicKey key, BigInteger number, PrivateKey privateKey) {
        Operation op = Operation.READ;

        EncryptedPayload sentEncrypted = sendRead(key, number, privateKey, op);
        Pair<DecryptedPayload, EncryptedPayload> received = sendGeneral(sentEncrypted, op, privateKey);
        DecryptedPayload receivedDecrypted = received.getLeft();
        EncryptedPayload receivedEncrypted = received.getRight();
        return Pair.of(sentEncrypted, receivedEncrypted);
    }

    public EncryptedPayload sendRead(PublicKey key, BigInteger number, PrivateKey privateKey, Operation op) {
        if (op != Operation.READ && op != Operation.READ_GENERAL) {
            throw new IllegalArgumentException("Wrong Operation for this method " + op.name());
        }
        logger.info("Attempting READ");
        Instant time = Instant.now();
        return new ReadPayload(number, key, op, time).encrypt(serverKey, privateKey);
    }


    public Pair<EncryptedPayload, EncryptedPayload> readGeneral(BigInteger number, PrivateKey privateKey) {
        Operation op = Operation.READ_GENERAL;

        EncryptedPayload sentEncrypted = sendRead(null, number, privateKey, op);
        Pair<DecryptedPayload, EncryptedPayload> received = sendGeneral(sentEncrypted, op, privateKey);
        DecryptedPayload receivedDecrypted = received.getLeft();
        EncryptedPayload receivedEncrypted = received.getRight();
        return Pair.of(sentEncrypted, receivedEncrypted);
    }

    public Pair<DecryptedPayload, EncryptedPayload> sendGeneral(EncryptedPayload e, Operation o, PrivateKey senderPrivateKey) {
        write(e);

        try {
            EncryptedPayload ep = (EncryptedPayload) in.readObject();
            DecryptedPayload dp = ep.decrypt(senderPrivateKey);
            boolean correctSignature = dp.verifySignature(ep, ep.getSenderKey());
            if (! correctSignature) {
                logger.warn("Received " + o.name() + " Reply with bad signature");
            } else {
                logger.info("Received " + o.name() + " Reply correctly!");
            }
            return Pair.of(dp, ep);
        } catch (IOException | ClassNotFoundException exc) {
            exc.printStackTrace();
        }
        return null;
    }
}
