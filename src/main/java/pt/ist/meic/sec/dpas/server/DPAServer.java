package pt.ist.meic.sec.dpas.server;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.utils.Crypto;
import pt.ist.meic.sec.dpas.common.payloads.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
        loadPublicKeys();
        this.privateKey = loadPrivateKey("keys/private/priv-server.der");
        this.publicKey = loadPublicKey("keys/public/pub-server.der");
        server = new ServerSocket(port);
    }

    private void loadPublicKeys() {


        try (Stream<Path> walk = Files.walk(Paths.get("keys/public/clients"))) {

            List<String> result = walk.filter(Files::isRegularFile).map(Path::toString).collect(Collectors.toList());
            clientPKs.addAll(result.stream().map(this::loadPublicKey).collect(Collectors.toList()));
        } catch (IOException e) {
            e.printStackTrace();
        }

        // to remove
        try (Stream<Path> walk = Files.walk(Paths.get("keys/private/clients"))) {

            List<String> result = walk.filter(Files::isRegularFile).map(Path::toString).collect(Collectors.toList());
            clientPriv.addAll(result.stream().map(this::loadPrivateKey).collect(Collectors.toList()));
        } catch (IOException e) {
            e.printStackTrace();
        }
        //

    }

    /**
     * Loads private key file
     *
     * @param path - path of server private key
     * @return PrivateKey
     */

    private PrivateKey loadPrivateKey(String path)  {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(path));
            PKCS8EncodedKeySpec spec =
                    new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            logger.info("Private key loaded from file '" + path + "'");
            return kf.generatePrivate(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.info("Failed to load private key from file '" + path + "'. " + e.getClass().getSimpleName() + " - " + e.getMessage());
            throw new IllegalStateException();
        }
    }

    /**
     * Loads public key file
     *
     * @param path - path of server public key
     * @return PublicKey
     */

    public PublicKey loadPublicKey(String path) {
        try {
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(Files.readAllBytes(Paths.get(path)));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            logger.info("Public key loaded from file '" + path + "'");
            return keyFactory.generatePublic(publicSpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.info("Failed to load public key from file '" + path + "'. " + e.getClass().getSimpleName() + " - " + e.getMessage());
            throw new IllegalStateException();
        }
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
    }



}
