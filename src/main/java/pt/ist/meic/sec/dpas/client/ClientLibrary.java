package pt.ist.meic.sec.dpas.client;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.PostPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.ReadPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.RegisterPayload;
import pt.ist.meic.sec.dpas.common.utils.exceptions.IncorrectSignatureException;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.LinkedHashSet;

public class ClientLibrary {
    private final static Logger logger = Logger.getLogger(ClientLibrary.class);
    private static final String SERVER_CERT = "keys/public/server/pub-server1.crt";


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

        try{
            FileInputStream is = new FileInputStream(SERVER_CERT);

            CertificateFactory f = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) f.generateCertificate(is);
            serverKey = cert.getPublicKey();
        } catch (IOException | CertificateException e) {
            throw new IllegalStateException(e);
        }
    }

    private void connect() {
        boolean connected = false;

        while (!connected) {
            try {
                clientSocket = new Socket(ip, port);
                clientSocket.setSoTimeout(15000);
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

    public void write(DecryptedPayload e) {
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

    public DecryptedPayload register(String username, PublicKey key, PrivateKey privateKey) {
        DecryptedPayload sentEncrypted = createRegisterPayload(username, key, privateKey);
        write(sentEncrypted);
        return sentEncrypted;
    }

    public DecryptedPayload post(PublicKey authKey, String message, LinkedHashSet<BigInteger> announcements, PrivateKey signKey) {
        Operation op = Operation.POST;
        DecryptedPayload sentEncrypted = createPostPayload(authKey, message, announcements, signKey, op);
        write(sentEncrypted);
        return sentEncrypted;
    }

    public DecryptedPayload postGeneral(PublicKey authKey, String message, LinkedHashSet<BigInteger> announcements, PrivateKey signKey) {
        Operation op = Operation.POST_GENERAL;
        DecryptedPayload sentEncrypted = createPostPayload(authKey, message, announcements, signKey, op);
        write(sentEncrypted);
        return sentEncrypted;
    }


    public DecryptedPayload read(PublicKey authKey, PublicKey boardKey, BigInteger numberToRead, PrivateKey signKey) {
        Operation op = Operation.READ;

        DecryptedPayload sentEncrypted = createReadPayload(authKey, boardKey, numberToRead, signKey, op);
        write(sentEncrypted);
        return sentEncrypted;
    }

    public DecryptedPayload readGeneral(BigInteger number, PublicKey authKey, PrivateKey signKey) {
        Operation op = Operation.READ_GENERAL;

        DecryptedPayload sent = createReadPayload(authKey, null, number, signKey, op);
        write(sent);
        return sent;
    }

    /**
     * Creates a register payload
     * @param authKey public key of sender of this payload
     * @param signKey private key of sender of this payload (to sign)
     * @return Payload to send
     */

    public DecryptedPayload createRegisterPayload(String username, PublicKey authKey, PrivateKey signKey) {
        logger.info("Attempting REGISTER");
        Instant time = Instant.now();
        Operation op = Operation.REGISTER;

        return new RegisterPayload(username, authKey, op, time, signKey);
    }

    /**
     * Creates a post/postGeneral payload
     *
     * @param authKey public key of sender of this payload
     * @param announcementMessage announcement text
     * @param linkedAnnouncements linked announcements (id's)
     * @param signKey private key of sender of this payload (to sign)
     * @param op operation (must be post or postGeneral)
     * @return Payload to send
     */
    public DecryptedPayload createPostPayload(PublicKey authKey, String announcementMessage,
                                              LinkedHashSet<BigInteger> linkedAnnouncements, PrivateKey signKey,
                                              Operation op) {
        if (op != Operation.POST && op != Operation.POST_GENERAL) {
            throw new IllegalArgumentException("Wrong Operation for this method " + op.name());
        }
        logger.info("Attempting " + op.name());
        Instant time = Instant.now();
        PostPayload p = new PostPayload(announcementMessage, authKey, op, time, linkedAnnouncements, signKey);
        return p;
    }

    /**
     *
     * @param authKey public key of sender of this payload
     * @param boardKey public key of the board to read from
     * @param numberToFetch number of announcements to fetch (0 = all or 'n' to fetch 'n' most recent announcements)
     * @param signKey private key of sender of this payload (to sign)
     * @param op operation (must be read or readGeneral)
     * @return Payload to send
     */
    public DecryptedPayload createReadPayload(PublicKey authKey, PublicKey boardKey,
                                              BigInteger numberToFetch, PrivateKey signKey, Operation op) {
        if (op != Operation.READ && op != Operation.READ_GENERAL) {
            throw new IllegalArgumentException("Wrong Operation for this method " + op.name());
        }
        logger.info("Attempting READ");
        Instant time = Instant.now();
        ReadPayload r = new ReadPayload(numberToFetch, authKey, boardKey, op, time, signKey);
        logger.info("Sending " + r.toString());
        return r;
    }

    public DecryptedPayload receiveReply() throws SocketTimeoutException, IncorrectSignatureException {
        try {
            DecryptedPayload dp = (DecryptedPayload) in.readObject();

            boolean validReply = dp.verifySignature();
            if (!validReply) {
                logger.warn("Bad Signature.");

                throw new IncorrectSignatureException("Received reply with bad signature");
            }

            return dp;
        } catch (SocketTimeoutException ste) {
            throw ste;
        } catch (IOException | ClassNotFoundException | IllegalStateException | NullPointerException exc) {
            exc.printStackTrace();
        }
        return null;
    }

    public boolean validateReply(DecryptedPayload dp) {
        boolean correctSignature = dp.verifySignature();
        if (! correctSignature) {
            logger.info("bad sign");
            return false;
        } else {
            logger.info("Received reply correctly!");
            return true;
        }
    }

    public PublicKey getServerKey() {
        return serverKey;
    }
}
