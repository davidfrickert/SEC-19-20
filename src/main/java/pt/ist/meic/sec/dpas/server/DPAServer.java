package pt.ist.meic.sec.dpas.server;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.Status;
import pt.ist.meic.sec.dpas.common.StatusMessage;
import pt.ist.meic.sec.dpas.common.model.*;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.ACKPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.AnnouncementsPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.EncryptedPayloadReply;
import pt.ist.meic.sec.dpas.common.payloads.requests.PostPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.ReadPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.RegisterPayload;
import pt.ist.meic.sec.dpas.common.utils.dao.AnnouncementDAO;
import pt.ist.meic.sec.dpas.common.utils.dao.DAO;
import pt.ist.meic.sec.dpas.common.utils.dao.UserDAO;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public class DPAServer {
    private final static Logger logger = Logger.getLogger(DPAServer.class);
    private static final String KEYSTORE_PATH = "keys/private/server/keystore1.p12";
    private static final String KEYSTORE_ALIAS = "server1";

    private Map<PublicKey, UserBoard> allBoards;
    private Board general;

    private static ServerSocket server;
    private static int port = 9876;

    private KeyPair keyPair;

    private DAO<UserBoard, Long> userBoardDAO = new DAO<>(UserBoard.class);
    private DAO<GeneralBoard, Long> generalBoardDAO = new DAO<>(GeneralBoard.class);
    private AnnouncementDAO announcementDAO = new AnnouncementDAO();
    private UserDAO userDAO = new UserDAO();

    public DPAServer() {
        try{
            FileInputStream is = new FileInputStream(KEYSTORE_PATH);

            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(is, "server".toCharArray());

            Key key = keystore.getKey(KEYSTORE_ALIAS, "server".toCharArray());
            if (key instanceof PrivateKey) {
                // Get certificate of public key
                Certificate cert = keystore.getCertificate(KEYSTORE_ALIAS);

                // Get public key
                PublicKey publicKey = cert.getPublicKey();

                // Return a key pair
                this.keyPair = new KeyPair(publicKey, (PrivateKey) key);
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
            }
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
                ServerThread newServerThread = new ServerThread(inSoc);
                newServerThread.start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) throws IOException {
       DPAServer s = new DPAServer();
       s.listen();
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
                outStream = new ObjectOutputStream(socket.getOutputStream());
                inStream = new ObjectInputStream(socket.getInputStream());
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                while (!isInterrupted()) {
                    // all operations send EncryptedPayload, so, read and cast
                    EncryptedPayload ep = (EncryptedPayload) inStream.readObject();
                    // decrypt with server privatekey
                    try {
                        DecryptedPayload dp = ep.decrypt(DPAServer.this.keyPair.getPrivate());

                        boolean correctSignature = dp.verifySignature(ep, ep.getSenderKey());

                        if (!correctSignature) {
                            logger.warn("Received " + dp.getOperation() + " with bad signature from " + dp.getSenderKey().hashCode());
                            Operation o = dp.getOperation();
                            EncryptedPayload e = switch (o) {
                                case REGISTER:
                                case POST:
                                case POST_GENERAL:
                                    yield defaultErrorMessage(Status.InvalidRequest, "Invalid Signature.", o, dp.getSenderKey());
                                case READ:
                                case READ_GENERAL:
                                    yield new AnnouncementsPayload(DPAServer.this.keyPair.getPublic(), o, Instant.now(),
                                            new StatusMessage(Status.InvalidRequest, "Invalid Signature."), new ArrayList<>())
                                            .encrypt(dp.getSenderKey(), DPAServer.this.keyPair.getPrivate());
                            };
                            outStream.writeObject(e);
                        } else {
                            logger.info("Received " + dp.getOperation() + " with correct signature from " + dp.getSenderKey().hashCode());
                            // handle regular logic
                            EncryptedPayload e = switch (dp.getOperation()) {
                                case REGISTER -> handleRegister((RegisterPayload) dp);
                                case POST -> handlePost((PostPayload) dp);
                                case POST_GENERAL -> handlePostGeneral((PostPayload) dp);
                                case READ -> handleRead((ReadPayload) dp);
                                case READ_GENERAL -> handleReadGeneral((ReadPayload) dp);
                            };
                            outStream.writeObject(e);
                        }
                    } catch (MissingDataException e) {
                        if (ep.getSenderKey() != null) {
                            outStream.writeObject(defaultErrorMessage(Status.MissingData,"Missing data", Operation.READ, ep.getSenderKey()));
                        } else {
                            this.close();
                            this.interrupt();
                        }
                    }
                }
            } catch (ClassNotFoundException | IOException e) {
                e.printStackTrace();
            }


        }

        private EncryptedPayloadReply handlePost(PostPayload p) {
            System.out.println(p.getTimestamp());
            Announcement a = new Announcement(p.getData(), p.getSenderKey(), p.getLinkedAnnouncements(), p.getTimestamp());
            Optional<UserBoard> optUB = getUserBoard(p.getSenderKey());
            boolean success;
            StatusMessage status;

            if (optUB.isPresent()) {
                UserBoard ub = optUB.get();
                if (ub.announcementCanBePosted(a)) {
                    success = announcementDAO.safeInsert(a);
                    if (success) {
                        ub.appendAnnouncement(a);
                        status = new StatusMessage(Status.Success);
                    }
                    else status = new StatusMessage(Status.InvalidRequest, "Announcement already exists.");
                } else status = new StatusMessage(Status.InvalidRequest, "Attempt to write on wrong board.");
            } else status = new StatusMessage(Status.NotFound, "Board for this user not found. Forgot to register?");

            return new ACKPayload(DPAServer.this.keyPair.getPublic(), Operation.POST, Instant.now(), status)
                    .encrypt(p.getSenderKey(), DPAServer.this.keyPair.getPrivate());
        }

        private EncryptedPayloadReply handlePostGeneral(PostPayload p) {
            Announcement a = new Announcement(p.getData(), p.getSenderKey(), p.getLinkedAnnouncements(), p.getTimestamp());
            boolean success = announcementDAO.safeInsert(a);
            StatusMessage status;
            if (success) {
                general.appendAnnouncement(a);
                status = new StatusMessage(Status.Success);
            }
            else status = new StatusMessage(Status.InvalidRequest, "This announcement already exists.");
            return new ACKPayload(DPAServer.this.keyPair.getPublic(), Operation.POST_GENERAL, Instant.now(),
                    status).encrypt(p.getSenderKey(), DPAServer.this.keyPair.getPrivate());
        }

        private EncryptedPayloadReply handleRead(ReadPayload p) {
            logger.info("User " + p.getSenderKey().hashCode() + " attempted to read User " + p.getBoardToReadFrom().hashCode() + " board!");
            PublicKey boardKey = p.getBoardToReadFrom();
            Optional<UserBoard> optUB = getUserBoard(boardKey);
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
                    statusMessage, announcements).encrypt(p.getSenderKey(), DPAServer.this.keyPair.getPrivate());

        }

        private EncryptedPayloadReply handleReadGeneral(ReadPayload p) {
            logger.info("User " + p.getSenderKey().hashCode() + " attempted to read from general board.");
            List<Announcement> announcements = general.getNAnnouncements(p);
            return new AnnouncementsPayload(DPAServer.this.keyPair.getPublic(), Operation.READ_GENERAL, Instant.now(),
                    new StatusMessage(Status.Success), announcements).encrypt(p.getSenderKey(), DPAServer.this.keyPair.getPrivate());
        }

        private EncryptedPayloadReply handleRegister(RegisterPayload p){
            String userName = p.getData();
            StatusMessage status;
            if (userDAO.exists(userName)) {
                status = new StatusMessage(Status.InvalidRequest, "Username already taken.");
            } else {
                User u = new User(p.getSenderKey(), userName);
                status = new StatusMessage(Status.Success);
                userDAO.persist(u);
                UserBoard userBoard = new UserBoard(u.getPublicKey());
                userBoardDAO.persist(userBoard);
            }
            return new ACKPayload(DPAServer.this.keyPair.getPublic(), Operation.REGISTER, Instant.now(),
                    status)
                    .encrypt(p.getSenderKey(), DPAServer.this.keyPair.getPrivate());
        }

    }

    private EncryptedPayload defaultErrorMessage(Status status, String errorMsg, Operation o, PublicKey receiverKey) {
        return new ACKPayload(DPAServer.this.keyPair.getPublic(), o, Instant.now(),
                new StatusMessage(status, errorMsg))
                .encrypt(receiverKey, DPAServer.this.keyPair.getPrivate());
    }



    public static int getPort() {
        return port;
    }
}
