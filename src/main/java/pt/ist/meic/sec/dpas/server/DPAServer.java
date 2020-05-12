package pt.ist.meic.sec.dpas.server;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.Status;
import pt.ist.meic.sec.dpas.common.StatusMessage;
import pt.ist.meic.sec.dpas.common.model.*;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.ACKPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.AnnouncementsPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.LastTimestampPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.*;
import pt.ist.meic.sec.dpas.common.utils.dao.AnnouncementDAO;
import pt.ist.meic.sec.dpas.common.utils.dao.DAO;
import pt.ist.meic.sec.dpas.common.utils.dao.UserDAO;
import pt.ist.meic.sec.dpas.common.utils.exceptions.InvalidKeystoreAccessException;
import pt.ist.meic.sec.dpas.common.utils.exceptions.MissingDataException;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class DPAServer {
    private final static Logger logger = Logger.getLogger(DPAServer.class);
    private static final String KEY_ALIAS = "server";

    private Map<PublicKey, UserBoard> allBoards;
    private Board general;

    private static ServerSocket server;
    private static int port;
    private static final int BASE_PORT = 35000;

    // incremented on each write on generalBoard
    private AtomicInteger generalWriteId;
    private PublicKey nextAnnouncer;

    private KeyPair keyPair;

    private DAO<UserBoard, Long> userBoardDAO = new DAO<>(UserBoard.class);
    private DAO<GeneralBoard, Long> generalBoardDAO = new DAO<>(GeneralBoard.class);
    private AnnouncementDAO announcementDAO = new AnnouncementDAO();
    private UserDAO userDAO = new UserDAO();
    private DAO<PayloadHistory, Long> payloadDAO = new DAO<>(PayloadHistory.class);

    private static HashMap<PublicKey, ArrayList<PublicKey>> listenerMap = new HashMap<>();
    private static HashMap<PublicKey, Integer> atomicRegister = new HashMap<>();

    public DPAServer(int serverPort, String keyPath, String keyStorePassword) {
        try {
            port = serverPort;
            FileInputStream is = new FileInputStream(keyPath);

            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(is, keyStorePassword.toCharArray());

            Key key = keystore.getKey(KEY_ALIAS, keyStorePassword.toCharArray());
            if (key instanceof PrivateKey) {
                // Get certificate of public key
                Certificate cert = keystore.getCertificate(KEY_ALIAS);

                // Get public key
                PublicKey publicKey = cert.getPublicKey();

                // Return a key pair
                this.keyPair = new KeyPair(publicKey, (PrivateKey) key);

            }
            else {
                throw new InvalidKeystoreAccessException("Invalid access to keystore.");
            }
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException | CertificateException | IOException keyStoreException) {
            keyStoreException.printStackTrace();
            throw new IllegalStateException("Problems with keystore, server not starting.");
        }

        try {
            server = new ServerSocket(port);
        } catch (IOException e) {
            e.printStackTrace();
            throw new IllegalStateException("ServerSocket could not be instantiated.");
        }

        initBoards();
        generalWriteId = new AtomicInteger(this.general.getAnnouncements().size());

    }

    // loads boards from db and if they dont exists creates them
    // not persisting new boards yet.
    private void initBoards() {
        initUserBoards();
        initGeneralBoard();
    }

    private Optional<UserBoard> getUserBoard(PublicKey pk) {
        UserBoard ub = this.allBoards.get(pk);
        return Optional.ofNullable(ub);
    }

    private void initUserBoards() {
        Map<PublicKey, UserBoard> boards = userBoardDAO.findAllAsStream().collect(Collectors.toMap(
                UserBoard::getOwner, u -> u));
        List<User> users = userDAO.findAll();
        for (User user : users) {
            if (! boards.containsKey(user.getPublicKey())) {
                UserBoard userBoard = new UserBoard(user.getPublicKey());
                userBoardDAO.persist(userBoard);
                boards.put(user.getPublicKey(), userBoard);
                //associate board with a wts = 0 and create a list of listeners
            }
            listenerMap.put(user.getPublicKey(), new ArrayList());
            atomicRegister.put(user.getPublicKey(), 0);
        }
        boards.values().forEach(u -> logger.info("UserBoard loaded: " + u));
        this.allBoards = boards;
    }

    private void initGeneralBoard() {
        List<GeneralBoard> generalBoards = generalBoardDAO.findAll();
        if (generalBoards.isEmpty()) {
            this.general = new GeneralBoard();
            generalBoardDAO.persist(this.general);
        } else {
            this.general = generalBoards.get(0);
        }
        logger.info("GeneralBoard loaded: " + this.general.toString());
    }

    public void listen() {
        while(true) {
            try {
                logger.info("Listening on " + server.getInetAddress().getHostAddress() + ":" + port);
                Socket inSoc = server.accept();
                logger.info("Accepted!");
                ServerThread newServerThread = new ServerThread(inSoc);
                newServerThread.start();
            } catch (IOException e) {
                logger.warn("Stopped listening");
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        int port;
        String keyStorePath, ksPassword;
        if(args.length != 3){
            System.out.println("ERROR: Wrong number of parameters.");
            System.out.println("Correct usage: java DPAServer <port> <keyStore path> <keyStore password>");
            System.exit(-1);
        } else {
            try {
                port = Integer.parseInt(args[0]);
                keyStorePath = args[1];
                ksPassword = args[2];
                DPAServer s = new DPAServer(port, keyStorePath, ksPassword);
                s.listen();
            } catch (NumberFormatException nfe) {
                System.out.println("ERROR: Invalid port.");
                System.out.println("Correct usage: java DPAServer <port> <keyStore path> <keyStore password>");
                System.exit(-1);
            }
        }

    }

    class ServerThread extends Thread {

        private Socket socket;
        private ObjectOutputStream outStream = null;
        private ObjectInputStream inStream = null;

        ServerThread(Socket inSoc) {
            socket = inSoc;
        }

        public void close() {
            try {
                this.outStream.close();
                this.inStream.close();
            } catch (NullPointerException | IOException e) {
                e.printStackTrace();
            }
        }

        public void run() {
            try{
                System.out.println("creating out");
                outStream = new ObjectOutputStream(socket.getOutputStream());
                System.out.println("created out");
                inStream = new ObjectInputStream(socket.getInputStream());
                System.out.println("created in");
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                while (!isInterrupted()) {
                    // all operations send EncryptedPayload, so, read and cast
                    DecryptedPayload dp = (DecryptedPayload) inStream.readObject();
                    // decrypt with server privatekey
                    try {
                        System.out.println(dp);
                        //boolean correctSignature = dp.verifySignature(ep, ep.getSenderKey());
                        boolean correctSignature = dp.verifySignature();
                        if (dp.getOperation() == null) throw new MissingDataException("Operation field is empty.");

                        if (!correctSignature) {
                            logger.warn("Received " + dp.getOperation() + " with bad signature from " + dp.getSenderKey().hashCode());
                            Operation o = dp.getOperation();
                            DecryptedPayload e = switch (o) {
                                case REGISTER:
                                case POST:
                                case POST_GENERAL:
                                case READ:
                                case READ_GENERAL:
                                case WRITE_BACK:
                                case GET_LAST_TIMESTAMP:
                                case VALUE:
                                case ACK:
                                case READ_COMPLETED:
                                case POST_GENERAL_PREPARE:
                                    yield defaultErrorMessage(Status.InvalidSignature, "Invalid Signature.", o, dp.getSenderKey());
                            };
                            e.setMsgId(dp.getMsgId());
                            outStream.writeObject(e);
                        } else {
                            logger.info("Received " + dp.getOperation() + " with correct signature from " + dp.getSenderKey().hashCode());

                            byte[] signature = dp.getSignature();
                            Instant timestamp = dp.getTimestamp();
                            DecryptedPayload e;
                            boolean fresh = payloadDAO.persist(new PayloadHistory(timestamp, signature));

                            if (fresh) {
                                e = switch (dp.getOperation()) {
                                    case REGISTER -> handleRegister((RegisterPayload) dp);
                                    case POST -> handlePost((PostPayload) dp);
                                    case POST_GENERAL -> handlePostGeneral((PostPayload) dp);
                                    case READ -> handleRead((ReadPayload) dp);
                                    case READ_GENERAL -> handleReadGeneral((ReadPayload) dp);
                                    case GET_LAST_TIMESTAMP -> handleGetLastTimestamp((GetLastTimestampPayload) dp);
                                    case WRITE_BACK -> handleWriteBack((WriteBackPayload) dp);
                                    case ACK -> null;
                                    case READ_COMPLETED -> handleReadCompleted((ReadCompletedPayload) dp);
                                    case POST_GENERAL_PREPARE -> handlePostGeneralPrepare((PostGeneralPreparePayload) dp);
                                    case VALUE -> null;
                                };
                            } else {
                                e = defaultErrorMessage(Status.NotFresh, "Message already received.",
                                        dp.getOperation(), dp.getSenderKey());
                            }
                            if(e != null){
                                e.setMsgId(dp.getMsgId());
                                outStream.writeObject(e);
                            }
                        }
                    } catch (MissingDataException e) {
                        if (dp.getSenderKey() != null) {
                            outStream.writeObject(defaultErrorMessage(Status.MissingData,"Missing data",
                                    Operation.READ, dp.getSenderKey()));
                        } else {
                            this.close();
                            this.interrupt();
                        }
                    }
                }
            }
            catch (ClassNotFoundException | IOException e) {
                logger.debug("Could not parse read information, tunnel possibly broken. Closing.", e);
                this.close();
                this.interrupt();
            }
        }

        private DecryptedPayload handleReadCompleted(ReadCompletedPayload dp) {
            PublicKey boardKey = dp.getBoardReadFrom();
            DPAServer.this.listenerMap.remove(boardKey).add(dp.getSenderKey());
            return null;
        }

        private DecryptedPayload handlePost(PostPayload p) {
            Announcement a = new Announcement(p.getData(), p.getSenderKey(), p.getLinkedAnnouncements(),p.getTimestamp(), p.getMsgId());
            Optional<UserBoard> optUB = getUserBoard(p.getSenderKey());
            boolean success;
            StatusMessage status;

            //atomic register process
            int writeId = p.getMsgId();
            if (writeId < DPAServer.this.atomicRegister.get(p.getSenderKey())) {
                status = new StatusMessage(Status.InvalidRequest, "Board has newer messages.");
                return new LastTimestampPayload(DPAServer.this.keyPair.getPublic(), Instant.now(), status,
                        DPAServer.this.getGeneralWriteId(), DPAServer.this.keyPair.getPrivate());
            }

            broadcastPost();

            if (optUB.isPresent()) {
                UserBoard ub = optUB.get();
                if (ub.announcementCanBePosted(a)) {
                    boolean allExists = announcementDAO.allExist(a.getReferred());
                    if (allExists) {
                        success = announcementDAO.safeInsert(a);
                        if (success) {
                            DPAServer.this.atomicRegister.put(p.getSenderKey(),
                                    DPAServer.this.atomicRegister.get(p.getSenderKey()) + 1);
                            ub.appendAnnouncement(a);
                            status = new StatusMessage(Status.Success);
                        }  else status = new StatusMessage(Status.InvalidRequest, "Announcement already exists.");
                    } else status = new StatusMessage(Status.InvalidRequest, "Invalid linked announcement detected, please re-check.");
                } else status = new StatusMessage(Status.InvalidRequest, "Attempt to write on wrong board.");
            } else status = new StatusMessage(Status.NotFound, "Board for this user not found. Forgot to register?");

            return new ACKPayload(DPAServer.this.keyPair.getPublic(), Operation.POST, Instant.now(), status, DPAServer.this.keyPair.getPrivate());
        }

        private DecryptedPayload handlePostGeneralPrepare(PostGeneralPreparePayload p) {
            synchronized (generalWriteId) {
                StatusMessage status;
                int writeId = p.getMsgId();
                logger.info("User " + p.getSenderKey().hashCode() + " prepared post in General Board with " + writeId + " message ID!");
                if (writeId < DPAServer.this.getGeneralWriteId()) {
                    status = new StatusMessage(Status.OldID, "Board has newer messages.");
                    return new LastTimestampPayload(DPAServer.this.keyPair.getPublic(), Instant.now(), status,
                            DPAServer.this.getGeneralWriteId(), DPAServer.this.keyPair.getPrivate());
                } else {
                    if (nextAnnouncer == null || nextAnnouncer != p.getSenderKey()) {
                        status = new StatusMessage(Status.PostInProgress, "Another post is in progress.");
                    }
                    else {
                        nextAnnouncer = p.getSenderKey();
                        status = new StatusMessage(Status.Success);
                    }
                    return new ACKPayload(DPAServer.this.keyPair.getPublic(), Operation.POST_GENERAL_PREPARE, Instant.now(),
                            status, DPAServer.this.keyPair.getPrivate());
                }
            }
        }

        private DecryptedPayload handlePostGeneral(PostPayload p) {
            synchronized (generalWriteId) {
                StatusMessage status;
                int writeId = p.getMsgId();
                logger.info("User " + p.getSenderKey().hashCode() + " attempted to post in General Board with " + writeId + " message ID!");
                if (writeId < DPAServer.this.getGeneralWriteId()) {
                    status = new StatusMessage(Status.OldID, "Board has newer messages.");
                    return new LastTimestampPayload(DPAServer.this.keyPair.getPublic(), Instant.now(), status,
                            DPAServer.this.getGeneralWriteId(), DPAServer.this.keyPair.getPrivate());
                }
                else {
                    Announcement a = new Announcement(p.getData(), p.getSenderKey(), p.getLinkedAnnouncements(), p.getTimestamp(), p.getMsgId());
                    boolean success = announcementDAO.safeInsert(a);
                    //boolean allExist = announcementDAO.allExist(p.getLinkedAnnouncements());
                    if (success) {
                        generalWriteId.incrementAndGet();
                        nextAnnouncer = null;
                        general.appendAnnouncement(a);
                        status = new StatusMessage(Status.Success);
                    }
                    else status = new StatusMessage(Status.InvalidRequest, "This announcement already exists.");
                    return new ACKPayload(DPAServer.this.keyPair.getPublic(), Operation.POST_GENERAL, Instant.now(),
                            status, DPAServer.this.keyPair.getPrivate());
                }
            }
        }

        private DecryptedPayload handleRead(ReadPayload p) {
            logger.info("User " + p.getSenderKey().hashCode() + " attempted to read User " + p.getBoardToReadFrom().hashCode() + " board!");
            PublicKey boardKey = p.getBoardToReadFrom();
            Optional<UserBoard> optUB = getUserBoard(boardKey);
            //Add user to listener list
            DPAServer.this.listenerMap.get(boardKey).add(p.getSenderKey());
            StatusMessage statusMessage;
            List<Announcement> announcements = new ArrayList<>();
            if (optUB.isEmpty()) {
                statusMessage = new StatusMessage(Status.NotFound, "The board associated with this key doesn't exist.");
            } else {
                UserBoard board = optUB.get();
                try {
                    announcements = board.getNAnnouncements(p);
                    statusMessage = new StatusMessage(Status.Success);
                } catch (IllegalArgumentException e) {
                    statusMessage = new StatusMessage(Status.InvalidRequest, "Attempt to read wrong user board.");
                }
            }
            return new AnnouncementsPayload(DPAServer.this.keyPair.getPublic(), Operation.READ, Instant.now(),
                    statusMessage, announcements, DPAServer.this.keyPair.getPrivate());

        }

        private DecryptedPayload handleReadGeneral(ReadPayload p) {
            logger.info("User " + p.getSenderKey().hashCode() + " attempted to read from general board.");
            List<Announcement> announcements = general.getNAnnouncements(p);
            return new AnnouncementsPayload(DPAServer.this.keyPair.getPublic(), Operation.READ_GENERAL, Instant.now(),
                    new StatusMessage(Status.Success), announcements, DPAServer.this.keyPair.getPrivate());
        }

        private DecryptedPayload handleWriteBack(WriteBackPayload p) {
            AnnouncementsPayload read = p.getData();
            // announcements that were read by user that sent this WriteBackPayload
            List<Announcement> announcements = read.getAnnouncements();
            StatusMessage status;
            if (announcements.size() == 0) {
                status = new StatusMessage(Status.Success, "No announcements added");
                return new ACKPayload(DPAServer.this.keyPair.getPublic(), Operation.WRITE_BACK, Instant.now(),
                        status, DPAServer.this.keyPair.getPrivate());
            }
            // check if all announcements have the same key (belong to the same board)
            boolean allSameKey = announcements.stream().map(Announcement::getCreatorId).distinct().count() == 1;
            if (! allSameKey) {
                status = new StatusMessage(Status.InvalidRequest, "Inconsistent announcements. Announcements belong to different boards");
                return new ACKPayload(DPAServer.this.keyPair.getPublic(), Operation.WRITE_BACK, Instant.now(),
                        status, DPAServer.this.keyPair.getPrivate());
            }

            PublicKey boardKey = announcements.get(0).getCreatorId();
            Optional<UserBoard> userBoardOpt = getUserBoard(boardKey);
            int inserted = 0, rejectedAlreadyExists = 0, rejectedInvalidLinkedAnnouncements = 0;
            if (userBoardOpt.isPresent()) {
                UserBoard userBoard = userBoardOpt.get();
                for (Announcement a : announcements) {
                    boolean success;
                    // check if related announcements exist
                    boolean allExists = announcementDAO.allExist(a.getReferred());
                    if (allExists) {
                        success = announcementDAO.safeInsert(a);
                        if (success) {
                            userBoard.appendAnnouncement(a);
                            inserted++;
                        } else rejectedAlreadyExists++;
                    } else rejectedInvalidLinkedAnnouncements++;
                }
            } else {
                status = new StatusMessage(Status.InvalidRequest, "This user isn't registered in the system");
                return new ACKPayload(DPAServer.this.keyPair.getPublic(), Operation.WRITE_BACK, Instant.now(),
                        status, DPAServer.this.keyPair.getPrivate());
            }
            status = new StatusMessage(Status.Success, "Inserted: " + inserted +
                    ", already in db: " + rejectedAlreadyExists + ", invalid linked announcements: " + rejectedInvalidLinkedAnnouncements);
            return new ACKPayload(DPAServer.this.keyPair.getPublic(), Operation.WRITE_BACK, Instant.now(),
                    status, DPAServer.this.keyPair.getPrivate());
        }

        private DecryptedPayload handleRegister(RegisterPayload p){

            String userName = p.getData();
            StatusMessage status;
            if (userDAO.exists("username", userName)) {
                status = new StatusMessage(Status.InvalidRequest, "Username already taken.");
            } else if (userDAO.exists("publicKey", p.getSenderKey())) {
                status = new StatusMessage(Status.InvalidRequest, "Key already assigned to a User.");
            } else {
                User u = new User(p.getSenderKey(), userName);
                status = new StatusMessage(Status.Success);
                userDAO.persist(u);
                UserBoard userBoard = new UserBoard(u.getPublicKey());
                allBoards.put(u.getPublicKey(), userBoard);
                userBoardDAO.persist(userBoard);
            }
            return new ACKPayload(DPAServer.this.keyPair.getPublic(), Operation.REGISTER, Instant.now(),
                    status, DPAServer.this.keyPair.getPrivate());
        }

        private DecryptedPayload handleGetLastTimestamp(GetLastTimestampPayload p) {
            logger.info("User " + p.getSenderKey().hashCode() + " attempted to get last timestamp (" + generalWriteId.get() + ") from general board.");
            return new LastTimestampPayload(DPAServer.this.keyPair.getPublic(), Instant.now(), new StatusMessage(Status.Success),
                    DPAServer.this.getGeneralWriteId(), DPAServer.this.keyPair.getPrivate());
        }
    }

    private DecryptedPayload defaultErrorMessage(Status status, String errorMsg, Operation o, PublicKey receiverKey) {
        return new ACKPayload(DPAServer.this.keyPair.getPublic(), o, Instant.now(),
                new StatusMessage(status, errorMsg), DPAServer.this.keyPair.getPrivate());
    }

    public int getGeneralWriteId() {
        return generalWriteId.get();
    }
    public static int getPort() {
        return port;
    }
    public static int getBasePort() {
        return BASE_PORT;
    }
    public void broadcastPost(){

    }
}