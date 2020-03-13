package pt.ist.meic.sec.dpas.server;

import org.apache.log4j.Logger;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.ArrayList;
import java.util.List;

public class DPAServer {
    private final static Logger logger = Logger.getLogger(DPAServer.class);

    private List<PublicKey> clientPKs = new ArrayList<>();
    // to remove
    private List<PrivateKey> clientPriv = new ArrayList<>();
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private static ServerSocket server;
    private static int port = 9876;

    public DPAServer() throws IOException {
        //oadPublicKeys();
        //this.privateKey = loadPrivateKey("keys/private/priv-server.der");
        //this.publicKey = loadPublicKey("keys/public/pub-server.der");
        server = new ServerSocket(port);
    }

    private PrivateKey getPrivateKey(int index) {
        return this.clientPriv.get(index);
    }

    public PublicKey getPublicKey(int index) {
        return this.clientPKs.get(index);
    }

    public static void main(String[] args) throws IOException {

       DPAServer s = new DPAServer();

        //receive multiple clients
        while(true) {
            try {
                Socket inSoc = server.accept();
                ServerThread newServerThread = new ServerThread(inSoc);
                newServerThread.start();
            }
            catch (IOException e) {
                e.printStackTrace();
            }

        }

       /**
       String data = "Olá";
       List<Integer> links = Arrays.asList(1, 2, 3);

       byte[] encryptedData = Crypto.encryptBytes(data.getBytes(),  s.publicKey, true);
       PublicKey idKey = s.getPublicKey(0);
       byte[] encryptedOperation = Crypto.encryptBytes(Operation.POST.name().getBytes(), s.publicKey, true);
       byte[] encryptedLinkedAnnouncements = Crypto.encryptBytes(ArrayUtils.listToBytes(links), s.publicKey, false);

       byte[] originalData = ArrayUtils.merge(data.getBytes(), s.getPublicKey(0).getEncoded(),
               Operation.POST.name().getBytes(), ArrayUtils.listToBytes(links));

       byte[] signature = Crypto.sign(originalData, s.getPrivateKey(0));

       EncryptedPayload p = new EncryptedPayload(encryptedData, idKey, encryptedOperation, encryptedLinkedAnnouncements,
               signature);
       p.decrypt(s.privateKey, idKey);
        */
    }

    static class ServerThread extends Thread {

        private Socket socket = null;
        private ObjectOutputStream outStream = null;
        private ObjectInputStream inStream = null;

        ServerThread(Socket inSoc) {
            socket = inSoc;
        }

        public void run() {
            try{
                outStream = new ObjectOutputStream(socket.getOutputStream());
                inStream = new ObjectInputStream(socket.getInputStream());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }



}
