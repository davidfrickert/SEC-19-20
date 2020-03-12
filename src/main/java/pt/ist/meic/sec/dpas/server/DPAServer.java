package pt.ist.meic.sec.dpas.server;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;
import pt.ist.meic.sec.dpas.common.utils.Crypto;
import pt.ist.meic.sec.dpas.common.utils.KeyManager;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
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

    public DPAServer() {
        loadPublicKeys();
        this.privateKey = KeyManager.loadPrivateKey("keys/private/priv-server.der");
        this.publicKey = KeyManager.loadPublicKey("keys/public/pub-server.der");
    }

    private void loadPublicKeys() {


        try (Stream<Path> walk = Files.walk(Paths.get("keys/public/clients"))) {
            List<String> result = walk.filter(Files::isRegularFile).map(Path::toString).collect(Collectors.toList());
            clientPKs.addAll(result.stream().map(KeyManager::loadPublicKey).collect(Collectors.toList()));
        } catch (IOException e) {
            e.printStackTrace();
        }

        // to remove
        try (Stream<Path> walk = Files.walk(Paths.get("keys/private/clients"))) {
            List<String> result = walk.filter(Files::isRegularFile).map(Path::toString).collect(Collectors.toList());
            clientPriv.addAll(result.stream().map(KeyManager::loadPrivateKey).collect(Collectors.toList()));
        } catch (IOException e) {
            e.printStackTrace();
        }
        //

    }


    private PrivateKey getPrivateKey(int index) {
        return this.clientPriv.get(index);
    }

    public PublicKey getPublicKey(int index) {
        return this.clientPKs.get(index);
    }

    public static void main(String[] args) {
       DPAServer s = new DPAServer();

       String data = "Olá";
       List<Integer> linkedAnnouncementIds = Arrays.asList(1, 2, 3);
       Instant timestamp = Instant.now();

       byte[] encryptedData = Crypto.encryptBytes(data.getBytes(),  s.publicKey, true);
       PublicKey idKey = s.getPublicKey(0);
       byte[] encryptedOperation = Crypto.encryptBytes(Operation.POST.name().getBytes(), s.publicKey, true);
       byte[] encryptedLinkedAnnouncements = Crypto.encryptBytes(ArrayUtils.listToBytes(linkedAnnouncementIds), s.publicKey, false);
       byte[] encryptedTimestamp = Crypto.encryptBytes(timestamp.toString().getBytes(), s.publicKey, true);

       byte[] originalData = ArrayUtils.merge(data.getBytes(), ArrayUtils.listToBytes(linkedAnnouncementIds),
               idKey.getEncoded(), Operation.POST.name().getBytes(), timestamp.toString().getBytes());

       byte[] signature = Crypto.sign(originalData, s.getPrivateKey(0));

       EncryptedPayload p = new EncryptedPayload(encryptedData, idKey, encryptedOperation, encryptedLinkedAnnouncements,
               encryptedTimestamp, signature);
       p.decrypt(s.privateKey, idKey);
    }






}
