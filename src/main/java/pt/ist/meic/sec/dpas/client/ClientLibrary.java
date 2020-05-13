package pt.ist.meic.sec.dpas.client;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.Status;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.ACKPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.AnnouncementsPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.LastTimestampPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.*;
import pt.ist.meic.sec.dpas.common.utils.exceptions.IncorrectSignatureException;
import pt.ist.meic.sec.dpas.common.utils.exceptions.QuorumNotReachedException;
import pt.ist.meic.sec.dpas.server.DPAServer;

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
import java.util.*;
import java.util.stream.Collectors;

public class ClientLibrary {
    private final static Logger logger = Logger.getLogger(ClientLibrary.class);
    private static final String SERVER_CERT = "keys/public/server/pub-server1.crt";

    private List<ObjectInputStream> ins= new ArrayList<>();
    private List<ObjectOutputStream> outs = new ArrayList<>();

    public PublicKey serverKey;

    private String ip;
    private int port;
    // N from N > 3f
    private static final int numberOfServers = 2;
    // f from f <= N / 3
    private int byzantineFaultsTolerated;
    // Q = (N+f)/2
    private int repliesNecessaryForQuorum;
    // incremented on each write on UserBoard
    private int writeId;
    // incremented on each read
    private int readId;
    // general board writeId
    private int gbWriteId;

    private static final int TIMEOUT = 5000;

    public void start(String ip, int port) {
        this.ip = ip;
        this.port = port;
        this.byzantineFaultsTolerated = (numberOfServers) / 3;
        this.repliesNecessaryForQuorum = (int) Math.ceil((numberOfServers + byzantineFaultsTolerated) / 2.);
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

    private int calcPort(int n) {
        return DPAServer.getBasePort() + n;
    }

    private void connect() {

        int serverPort = port;
        int connections = 0;
        while (!(connections == numberOfServers)) {
            try {
                logger.info("connecting to " + ip + ":" + serverPort);
                Socket clientSocket = new Socket(ip, serverPort);
                clientSocket.setSoTimeout(TIMEOUT);
                logger.info("Connected to " + ip + ":" + port);

                outs.add(new ObjectOutputStream(clientSocket.getOutputStream()));
                ins.add(new ObjectInputStream(clientSocket.getInputStream()));
                connections++;
                serverPort++;
            } catch (IOException e) {
                try {
                    logger.info("Connection failure to server " + connections +  ". Retrying in 3 seconds");
                    logger.error("exc:", e);
                    Thread.sleep(3000);
                } catch (InterruptedException ex) {
                    ex.printStackTrace();
                }
                if (! (e instanceof  ConnectException))
                    e.printStackTrace();
            }
        }
    }

    private Socket reconnect(Object stream) {
        System.out.println("Reconnecting...");
        int n;
        if (stream instanceof ObjectOutputStream) {
            n = outs.indexOf(stream);
        }
        else if (stream instanceof ObjectInputStream) {
            n = ins.indexOf(stream);
        } else throw new IllegalArgumentException("Must supply Object stream.");

        Socket socket = null;
        try {
            socket = new Socket(ip, calcPort(n));
            socket.setSoTimeout(TIMEOUT);
            outs.set(n, new ObjectOutputStream(socket.getOutputStream()));
            ins.set(n, new ObjectInputStream(socket.getInputStream()));
            return socket;
        } catch (SocketException ex) {
            System.out.println("Failed to reconnect.");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return null;
    }

    public boolean preparePostGeneral(PublicKey auth, PrivateKey signKey) throws QuorumNotReachedException, IncorrectSignatureException {
        PostGeneralPreparePayload pgp = new PostGeneralPreparePayload(auth, Instant.now(), signKey);
        write(pgp);
        DecryptedPayload received = receiveReply();
        ACKPayload ack = (ACKPayload) received;
        return ack.getStatus().getStatus() == Status.Success;
    }

    public int getLastTimestamp(PublicKey auth, PrivateKey signKey) throws QuorumNotReachedException, IncorrectSignatureException {
        GetLastTimestampPayload ts = new GetLastTimestampPayload(auth, Instant.now(), signKey);
        write(ts);
        DecryptedPayload received = receiveReply();
        LastTimestampPayload lts = (LastTimestampPayload) received;
        return lts.getTS();
    }

    public void write(DecryptedPayload e) {
        if (e.getMsgId() == -1)
            if (e.isRead())
                e.setMsgId(readId++);
            else if (e.isWrite())
                e.setMsgId(writeId++);
            else if (e.isGeneralBoardPrepare())
                e.setMsgId(gbWriteId);
            else if (e.isGeneralBoardWrite()) {
                e.setMsgId(gbWriteId++);
            }

        for (Iterator<ObjectOutputStream> it = outs.iterator(); it.hasNext(); ) {
            boolean done = false;
            ObjectOutputStream out = it.next();
            int attempts = 0;
            while (!done && attempts < 10) {
                try {
                    out.writeObject(e);
                    done = true;
                } catch (SocketException se) {
                    int n = outs.indexOf(out);
                    logger.info("Failed to send..");
                    Socket s = reconnect(out);
                    if (s != null) {
                        out = outs.get(n);
                    }

                } catch (IOException ioe) {
                    ioe.printStackTrace();
                }
                attempts++;
            }
        }
    }
    /*
    public void stop() throws IOException {
        for (ObjectOutputStream o : outs)
            o.close();
        for (ObjectInputStream i : ins)
            i.close();
        for (Socket s : sockets)
            s.close();
    }
    */
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

    public DecryptedPayload faultypost(PublicKey authKey, String message, LinkedHashSet<BigInteger> announcements, PrivateKey signKey) {
        Operation op = Operation.POST;
        DecryptedPayload sentEncrypted = createPostPayload(authKey, message, announcements, signKey, op);
        writeId = writeId - 2;
        write(sentEncrypted);
        return sentEncrypted;
    }

    public DecryptedPayload postGeneral(PublicKey authKey, String message, LinkedHashSet<BigInteger> announcements, PrivateKey signKey) {
        Operation op = Operation.POST_GENERAL;
        DecryptedPayload sentEncrypted = createPostPayload(authKey, message, announcements, signKey, op);
        try {
            gbWriteId = getLastTimestamp(authKey, signKey);
            logger.info("Received write ID " + gbWriteId + " from server");
            while (!preparePostGeneral(authKey, signKey)) {
                logger.info("Another user is attempting to post. Retrying...");
                Thread.sleep(new Random().nextInt(2000));
                gbWriteId = getLastTimestamp(authKey, signKey);
            }
        } catch (QuorumNotReachedException | IncorrectSignatureException | InterruptedException e) {
            e.printStackTrace();
        }
        logger.info("Prepare statement complete.");
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

    public void getID(PublicKey key, PrivateKey privateKey) throws QuorumNotReachedException, IncorrectSignatureException {
        DecryptedPayload getID = createGetIDrPayload(key, privateKey);
        write(getID);
        DecryptedPayload received = receiveReply();
        ACKPayload lts = (ACKPayload) received;
        readId = received.getMsgId();
        writeId = received.getMsgId();
        System.out.println("ID ATUAL: " + received.getMsgId());
    }

    public DecryptedPayload createGetIDrPayload(PublicKey authKey, PrivateKey signKey) {
        logger.info("Attempting REGISTER");
        Instant time = Instant.now();

        return new GetIdPayload(authKey, time, signKey);
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

    public DecryptedPayload select(List<DecryptedPayload> replies) {
        return replies.stream().max(Comparator.comparing(DecryptedPayload::getMsgId)).get();
    }

    public DecryptedPayload writeBack(PrivateKey signKey, PublicKey authKey, AnnouncementsPayload receivedPayload) throws QuorumNotReachedException, IncorrectSignatureException {
        WriteBackPayload wb = new WriteBackPayload(authKey, Instant.now(),
                signKey, receivedPayload);
        write(wb);
        return receiveReply();
    }

    public DecryptedPayload receiveReply() throws QuorumNotReachedException, IncorrectSignatureException {
        HashMap<Integer, List<DecryptedPayload>> received = new HashMap<>();
        List<DecryptedPayload> receivedPayloads = new ArrayList<>();
        for (ObjectInputStream in : ins) {
            try {
                DecryptedPayload dp = (DecryptedPayload) in.readObject();

                boolean validReply = dp.verifySignature();
                if (!validReply) {
                    logger.warn("Bad Signature.");

                    throw new IncorrectSignatureException("Received reply with bad signature");
                }

                if (!received.containsKey(dp.getMsgId())) {
                    List<DecryptedPayload> initial = new ArrayList<>(Arrays.asList(dp));
                    received.put(dp.getMsgId(), initial);
                } else {
                    List<DecryptedPayload> receivedAtTimeT = received.get(dp.getMsgId());
                    receivedAtTimeT.add(dp);
                }
                receivedPayloads.add(dp);


                if (receivedPayloads.size() > repliesNecessaryForQuorum && !dp.isRead()) {
                    return select(receivedPayloads);
                }

                if (dp.isRead()) {
                    // this checks in the received Map which times have achieved quorum
                    List<List<DecryptedPayload>> listOfQuorums = received.values().stream()
                            .filter(decryptedPayloads -> decryptedPayloads.size() > repliesNecessaryForQuorum)
                            .collect(Collectors.toList());

                    // if atleast one time achieved quorum
                    if (listOfQuorums.size() > 0) {
                        // we assume that only one quorum is possible
                        // since f <= N / 3 & Q > (N+f) / 2 (...) => Q > (4/6 * N)
                        // so, atleast 4/6 of the servers must answer the same value

                        // get first quorum (only one), and count each payload occurence
                        Map<DecryptedPayload, Long> count = listOfQuorums.get(0).stream()
                                .collect(Collectors.groupingBy(v -> v, Collectors.counting()));
                        // pick the most common payload. Since quorum has been achieved, there is one payload
                        Map.Entry<DecryptedPayload, Long> mostCommonPayload = Collections.max(count.entrySet(), Comparator.comparingLong(Map.Entry::getValue));
                        // if the most common payload meets the number of occurrences desired, return it.
                        if (mostCommonPayload.getValue() > repliesNecessaryForQuorum)
                            return mostCommonPayload.getKey();
                    }
                }


            } catch (SocketTimeoutException ste) {
                System.out.println("Timeout - ignoring...");
            } catch (IOException | ClassNotFoundException | IllegalStateException | NullPointerException exc) {
                exc.printStackTrace();
            }
        }

        // which payload to pick?
        // verify if all payloads are correct?
        throw new QuorumNotReachedException("Received " + receivedPayloads.size() + " replies, but needed " +
                repliesNecessaryForQuorum + " replies for Quorum.");
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
