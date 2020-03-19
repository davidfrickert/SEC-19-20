package pt.ist.meic.sec.dpas.server;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import static pt.ist.meic.sec.dpas.common.utils.KeyManager.*;

public class DPAServer {
    private final static Logger logger = Logger.getLogger(DPAServer.class);

    private List<PublicKey> clientPKs = new ArrayList<>();
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private static ServerSocket server;
    private static int port = 9876;

    public DPAServer() throws IOException {
        loadPublicKeys();
        this.privateKey = loadPrivateKey("keys/private/priv-server.der");
        this.publicKey = loadPublicKey("keys/public/pub-server.der");
        server = new ServerSocket(port);
    }

    public PublicKey getPublicKey(int index) {
        return this.clientPKs.get(index);
    }

    public void listen() {
        while(true) {
            try {
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
                    }
                }

            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }



}
