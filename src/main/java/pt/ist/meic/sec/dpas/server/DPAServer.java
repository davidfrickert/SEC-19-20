package pt.ist.meic.sec.dpas.server;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.Status;
import pt.ist.meic.sec.dpas.common.StatusMessage;
import pt.ist.meic.sec.dpas.common.model.Announcement;
import pt.ist.meic.sec.dpas.common.model.Board;
import pt.ist.meic.sec.dpas.common.model.GeneralBoard;
import pt.ist.meic.sec.dpas.common.model.UserBoard;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.ACKPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.AnnouncementsPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.EncryptedPayloadReply;
import pt.ist.meic.sec.dpas.common.payloads.requests.PostPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.ReadPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.RegisterPayload;
import pt.ist.meic.sec.dpas.common.utils.dao.DAO;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static pt.ist.meic.sec.dpas.common.utils.KeyManager.*;

public class DPAServer {
    private final static Logger logger = Logger.getLogger(DPAServer.class);

    private List<PublicKey> clientPKs;
    private Map<PublicKey, UserBoard> allBoards;
    private Board general;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private static ServerSocket server;
    private static int port = 9876;

    private DAO<UserBoard, Long> userBoardDAO = new DAO<>(UserBoard.class);
    private DAO<GeneralBoard, Long> generalBoardDAO = new DAO<>(GeneralBoard.class);
    private DAO<Announcement, BigInteger> announcementDAO = new DAO<>(Announcement.class);


    public DPAServer() throws IOException {
        this.clientPKs = loadPublicKeys();
        this.privateKey = loadPrivateKey("keys/private/priv-server.der");
        this.publicKey = loadPublicKey("keys/public/pub-server.der");
        server = new ServerSocket(port);

        initBoards();

    }

    // loads boards from db and if they dont exists creates them
    // not persisting new boards yet.
    private void initBoards() {
        initUserBoards();
        initGeneralBoard();
    }

    private void initUserBoards() {
        Map<PublicKey, UserBoard> boards = userBoardDAO.findAllAsStream().collect(Collectors.toMap(
                UserBoard::getOwner, u -> u));

        for (PublicKey id : clientPKs) {
            if (! boards.containsKey(id)) {
                UserBoard u = new UserBoard(id);
                userBoardDAO.persist(u);
                boards.put(id, u);
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

        public void run() {
            try{
                outStream = new ObjectOutputStream(socket.getOutputStream());
                inStream = new ObjectInputStream(socket.getInputStream());

                while (!isInterrupted()) {
                    // all operations send EncryptedPayload, so, read and cast
                    EncryptedPayload ep = (EncryptedPayload) inStream.readObject();
                    // decrypt with server privatekey
                    DecryptedPayload dp = ep.decrypt(DPAServer.this.privateKey);
                    boolean correctSignature = dp.verifySignature(ep, ep.getSenderKey());

                    if (!correctSignature) {
                        // handle logic for tampering attempt?
                        logger.warn("Received " + dp.getOperation() + " with bad signature from " + dp.getSenderKey().hashCode());

                        EncryptedPayload e = switch (dp.getOperation()) {
                            case REGISTER:
                                // do something about register in db or whatever.. and then return msg
                                yield null;
                            case POST:
                                yield new ACKPayload(DPAServer.this.publicKey, Operation.POST, Instant.now(),
                                    new StatusMessage(Status.InvalidRequest, "Message Tampered."))
                                        .encrypt(dp.getSenderKey(), DPAServer.this.privateKey);
                            case POST_GENERAL:
                                yield null;
                            case READ:
                            case READ_GENERAL:
                                yield null;
                        };
                        outStream.writeObject(e);
                    } else {
                        logger.info("Received " + dp.getOperation() + " with correct signature from " + dp.getSenderKey().hashCode());
                        // handle regular logic
                        EncryptedPayload e = switch (dp.getOperation()) {
                            case REGISTER:
                                // do something about register in db or whatever.. and then return msg
                                yield new ACKPayload(DPAServer.this.publicKey, Operation.REGISTER, Instant.now(),
                                    new StatusMessage(Status.Success, "OK")).encrypt(dp.getSenderKey(), DPAServer.this.privateKey);
                            case POST:
                                yield handlePost((PostPayload) dp);
                            case POST_GENERAL:
                                yield handlePostGeneral((PostPayload) dp);
                            case READ:
                                yield handleRead((ReadPayload) dp);
                            case READ_GENERAL:
                                yield handleReadGeneral((ReadPayload) dp);
                        };
                        outStream.writeObject(e);
                    }
                }

            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
        }

        private EncryptedPayloadReply handlePost(PostPayload p) {
            Announcement a = new Announcement(p.getData(), p.getSenderKey(), p.getLinkedAnnouncements());
            announcementDAO.persist(a);
            allBoards.get(p.getSenderKey()).appendAnnouncement(a);
            return new ACKPayload(DPAServer.this.publicKey, Operation.POST, Instant.now(),
                    new StatusMessage(Status.Success)).encrypt(p.getSenderKey(), DPAServer.this.privateKey);
        }

        private EncryptedPayloadReply handlePostGeneral(PostPayload p) {
            Announcement a = new Announcement(p.getData(), p.getSenderKey(), p.getLinkedAnnouncements());
            announcementDAO.persist(a);
            general.appendAnnouncement(a);
            return new ACKPayload(DPAServer.this.publicKey, Operation.POST_GENERAL, Instant.now(),
                    new StatusMessage(Status.Success)).encrypt(p.getSenderKey(), DPAServer.this.privateKey);
        }

        private EncryptedPayloadReply handleRead(ReadPayload p) {
            logger.info("User " + p.getSenderKey().hashCode() + " attempted to read User " + p.getBoardToReadFrom().hashCode() + " board!");
            PublicKey boardKey = p.getBoardToReadFrom();
            UserBoard board = allBoards.get(boardKey);
            List<Announcement> announcements = board.getNAnnouncements(p.getData().intValue());
            return new AnnouncementsPayload(DPAServer.this.publicKey, Operation.READ, Instant.now(),
                    new StatusMessage(Status.Success), announcements).encrypt(p.getSenderKey(), DPAServer.this.privateKey);
        }

        private EncryptedPayloadReply handleReadGeneral(ReadPayload p) {
            return null;

        }

        private EncryptedPayloadReply handleRegister(RegisterPayload p) {
            return null;

        }

    }

    public static int getPort() {
        return port;
    }
}
