package pt.ist.meic.sec.dpas.server;

import org.apache.log4j.Logger;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.boot.Metadata;
import org.hibernate.boot.MetadataSources;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
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
import pt.ist.meic.sec.dpas.common.payloads.requests.PostPayload;

import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static pt.ist.meic.sec.dpas.common.utils.KeyManager.*;

public class DPAServer {
    private final static Logger logger = Logger.getLogger(DPAServer.class);

    private List<PublicKey> clientPKs = new ArrayList<>();
    private Map<PublicKey, UserBoard> allBoards;
    private Board general;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private static ServerSocket server;
    private static int port = 9876;

    private SessionFactory sf;

    public DPAServer() throws IOException {
        loadPublicKeys();
        this.privateKey = loadPrivateKey("keys/private/priv-server.der");
        this.publicKey = loadPublicKey("keys/public/pub-server.der");
        server = new ServerSocket(port);
        StandardServiceRegistry ssr = new StandardServiceRegistryBuilder().configure("hibernate.cfg.xml").build();
        Metadata meta = new MetadataSources(ssr).getMetadataBuilder().build();
        sf = meta.getSessionFactoryBuilder().build();
        initBoards();

    }

    // loads boards from db and if they dont exists creates them
    // not persisting new boards yet.
    private void initBoards() {
        Session s = openSession();
        CriteriaBuilder cb = s.getCriteriaBuilder();
        CriteriaQuery<UserBoard> c = cb.createQuery(UserBoard.class);
        c.from(UserBoard.class);
        Map<PublicKey, UserBoard> boards = s.createQuery(c).getResultStream().collect(Collectors.toMap(
                UserBoard::getOwner, u -> u));
        for (PublicKey id : clientPKs) {
            if (! boards.containsKey(id)) {
                UserBoard u = new UserBoard(id);

                boards.put(id, u);
            }
        }
        this.allBoards = boards;
        s.close();
        Session s2 = openSession();
        CriteriaBuilder cb2 = s.getCriteriaBuilder();
        CriteriaQuery<GeneralBoard> c2 = cb.createQuery(GeneralBoard.class);
        c.from(GeneralBoard.class);
        List<GeneralBoard> general = s2.createQuery(c2).getResultStream().collect(Collectors.toList());
        GeneralBoard generalBoard = null;
        if (general.isEmpty()) {
            generalBoard = new GeneralBoard();
        } else {
            generalBoard = general.get(0);
        }
        this.general = generalBoard;
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
                    } else {
                        // handle regular logic
                        EncryptedPayload e = switch (dp.getOperation()) {
                            case REGISTER:
                                // do something about register in db or whatever.. and then return msg
                                yield new ACKPayload(DPAServer.this.publicKey, Operation.REGISTER, Instant.now(),
                                    new StatusMessage(Status.Success, "OK")).encrypt(dp.getSenderKey(), DPAServer.this.privateKey);
                            case POST:
                                PostPayload p = (PostPayload) dp;
                                saveAnnouncement(p.getData(), p.getSenderKey(), p.getLinkedAnnouncements());
                                yield new ACKPayload(DPAServer.this.publicKey, Operation.REGISTER, Instant.now(),
                                        new StatusMessage(Status.Success, "OK")).encrypt(dp.getSenderKey(), DPAServer.this.privateKey);
                            case POST_GENERAL:
                            case READ:
                            case READ_GENERAL:
                                yield null;
                        };
                        outStream.writeObject(e);
                    }
                }

            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
        }

        public void saveAnnouncement(String a, PublicKey owner, List<BigInteger> linked) {
            Session sess = openSession();
            Transaction t = sess.beginTransaction();
            Announcement announcement = new Announcement(a, owner, linked);
            sess.save(announcement);
            t.commit();
            sess.close();
            DPAServer.this.allBoards.get(owner).appendAnnouncement(announcement);
        }

    }

    public Session openSession() {
        return sf.openSession();
    }

    public static int getPort() {
        return port;
    }
}
