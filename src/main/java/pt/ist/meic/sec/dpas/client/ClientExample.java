package pt.ist.meic.sec.dpas.client;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Status;
import pt.ist.meic.sec.dpas.common.model.Announcement;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.ACKPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.AnnouncementsPayload;
import pt.ist.meic.sec.dpas.common.utils.exceptions.IncorrectSignatureException;
import pt.ist.meic.sec.dpas.server.DPAServer;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class ClientExample {
    private final static Logger logger = Logger.getLogger(ClientExample.class);
    private static final String KEYSTORE_ALIAS = "client";

    private KeyPair keyPair;

    private ClientLibrary library;

    private String username;

    public ClientExample(String username, String keyPath, String keyStorePassword) {

        this.username = username;

        try{
            FileInputStream is = new FileInputStream(keyPath);

            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(is, keyStorePassword.toCharArray());

            Key key = keystore.getKey(KEYSTORE_ALIAS, keyStorePassword.toCharArray());
            if (key instanceof PrivateKey) {
                // Get certificate of public key
                Certificate cert = keystore.getCertificate(KEYSTORE_ALIAS);

                // Get public key
                PublicKey publicKey = cert.getPublicKey();

                // Return a key pair
                this.keyPair = new KeyPair(publicKey, (PrivateKey) key);
            }
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            e.printStackTrace();
            throw new IllegalStateException("Problems with keystore, client not starting.");
        }

        InetAddress host;
        try {
            host = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
        library = new ClientLibrary();
        library.start(host.getHostName(), DPAServer.getPort());
    }

    public void input(InputStream src) {
        System.out.println("Welcome to DPAS! Your public key is:" +
                parsePublicKeyToString(getPublicKey()));
        System.out.println("Possible operations: ");
        System.out.println("  register");
        System.out.println("  post <message>");
        System.out.println("  read <public key of board> <number of announcements to read>");
        System.out.println("  postgeneral <message>");
        System.out.println("  readgeneral <number of announcements to read>");
        Scanner sc = new Scanner(src);
        String line;
        String[] split;
        System.out.print(">>");
        while(true) {
            line = sc.nextLine();
            split = line.split(" ");
            if (split[0].equals("quit")) {
                System.out.print("Sure you want to leave? (Y = Yes, N = No) ");
                String conf = sc.nextLine();
                if(conf.equals("Y")) {
                    System.exit(0);
                }
            }
            // sends sentPayload
            try {
                EncryptedPayload sentPayload = doAction(line);
                Pair<DecryptedPayload, EncryptedPayload> response = getResponseOrRetry(sentPayload);
                if (response == null) {
                    System.out.println("Failure sending this request");
                } else {
                    processResponse(response.getLeft());
                }
            } catch (ArrayIndexOutOfBoundsException ie) {
                System.out.println("wrong syntax");
            }
            System.out.print(">>");
        }
    }

    public Pair<DecryptedPayload, EncryptedPayload> getResponseOrRetry(EncryptedPayload e) {
        int max_attempts = 10, attempts = 0;
        while (attempts < max_attempts) {
            try {
                return getResponse();
            } catch (SocketTimeoutException | IncorrectSignatureException ste) {
                attempts++;
                System.out.println("Failure... Retrying. Retry Count: " + attempts);
                library.write(e);
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ex) {
                    ex.printStackTrace();
                }
            }
        }
        System.out.println("Max Retries reached (" + max_attempts + ").");
        return null;
    }

    public Optional<Pair<DecryptedPayload, EncryptedPayload>> doActionAndReceiveReply(String command) {
        EncryptedPayload sent = doAction(command);
        return Optional.ofNullable(getResponseOrRetry(sent));
    }

    public EncryptedPayload doAction(String command) {
        String[] data = command.split(" ");
        String action = data[0];
        EncryptedPayload sentPayload = switch (action.toLowerCase()) {
            case "register" -> library.register(username, keyPair.getPublic(), keyPair.getPrivate());
            case "post" -> {
                String announcement = getAnnouncement(data);
                LinkedHashSet<String> prevAnnouncements = getPreviousAnnouncement(data);
                yield library.post(keyPair.getPublic(), announcement, prevAnnouncements, keyPair.getPrivate());
            }
            case "postgeneral" -> {
                String announcementGeneral = getAnnouncement(data);
                LinkedHashSet<String> prevAnnouncementsGen = getPreviousAnnouncement(data);
                yield library.postGeneral(keyPair.getPublic(), announcementGeneral, prevAnnouncementsGen, keyPair.getPrivate());
            }
            case "read" -> {
                BigInteger nAnnounce = BigInteger.valueOf(Integer.parseInt(data[2]));
                PublicKey boardKey = parseStringToPublicKey(data[1]);
                yield library.read(keyPair.getPublic(), boardKey, nAnnounce, keyPair.getPrivate());
            }
            case "readgeneral" -> {
                BigInteger nAnnounceGen = BigInteger.valueOf(Integer.parseInt(data[1]));
                yield library.readGeneral(nAnnounceGen, keyPair.getPublic(), keyPair.getPrivate());
            }
            default -> {
                logger.info("Invalid input, possibles are: register, post, postgeneral, read, readgeneral (case is not relevant)");
                yield null;
            }
        };
        return sentPayload;
    }

    /**
     * This method will listen for server answer to the client's requests
     * @return Pair<DecryptedPayload, EncryptedPayload> Encrypted and Decrypted payload that server sent.
     */

    public Pair<DecryptedPayload, EncryptedPayload> getResponse() throws SocketTimeoutException, IncorrectSignatureException {
        return library.receiveReply(this.keyPair.getPrivate());
    }

    public EncryptedPayload getEncryptedResponse() throws SocketTimeoutException, IncorrectSignatureException {
        return getResponse().getRight();
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }


    public static void main(String[] args) throws IOException {

        //program must be initialized with a username
        String username, keyStorePath, ksPassword;
        if(args.length != 3){
            System.out.println("ERROR: Wrong number of parameters.");
            System.out.println("Correct usage: java ClientExample <username> <keyStore path> <keyStore password>");
            System.exit(-1);
        } else {
            username = args[0];
            keyStorePath = args[1];
            ksPassword = args[2];
            ClientExample c = new ClientExample(username, keyStorePath, ksPassword);
            c.input(System.in);
        }
    }

    private static String getAnnouncement(String[] line) {
        StringBuilder sb = new StringBuilder();
        boolean found = false;
        for(int i = 1; i < line.length && !found; i++){
            if(!line[i].equals("|")){
                sb.append(line[i]).append(" ");
            } else {
                found = true;
            }
        }
        // remove last " "
        sb.setLength(sb.length() - 1);
        return sb.toString();
    }

    private static LinkedHashSet<String> getPreviousAnnouncement(String[] line) {
        List<String> result = new ArrayList<>();
        boolean found = false;
        for(int i = 1; i < line.length; i++){
            if(line[i].equals("|")){
                found = true;
                continue;
            }

            if(found){
                result.add(line[i]);
            }
        }
        //return ArrayUtils.bytesToSet(ArrayUtils.objectToBytes(new HashSet<>(result)));
        return new LinkedHashSet<>(result);
    }

    public ClientLibrary getLibrary() {
        return library;
    }

    private void processResponse(DecryptedPayload response){
        if(((ACKPayload) response).getStatus().getStatus().equals(Status.Success)){
            switch (response.getOperation()){
                case REGISTER:
                    System.out.println("Registered with success!");
                    break;
                case POST:
                case POST_GENERAL:
                    System.out.println("Message posted with success!");
                    break;
                case READ:
                case READ_GENERAL:
                    List<Announcement> aList = ((AnnouncementsPayload) response).getAnnouncements();
                    System.out.println("Read successful!");
                    System.out.println("Read " + aList.size() + " announcements.");
                    for (Announcement announcement : aList) {
                        System.out.println("Hash: " + announcement.getHash());
                        System.out.println("Message: " + announcement.getMessage());
                        System.out.println("Posted by: " +
                                parsePublicKeyToString(announcement.getOwnerKey()));
                        System.out.println("At: " + announcement.getReceivedTime());
                        System.out.println("Linked: " + announcement.getReferred());
                    }
                    break;
            }
        } else {
            System.out.println("Something went wrong");
            System.out.println(((ACKPayload) response).getStatus().toString());
        }
    }

    public boolean validateReply(EncryptedPayload ep) {

        boolean correctSignature = ep.verifySignature(this.keyPair.getPrivate());
        if (! correctSignature) {
            logger.info("bad sign");
            return false;
        } else {
            logger.info("Received reply correctly!");
            return true;
        }
    }

    private PublicKey parseStringToPublicKey(String s){
        PublicKey pubKey = null;
        try{
            byte[] publicBytes = Base64.decodeBase64(s);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            pubKey = keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return pubKey;

    }

    private String parsePublicKeyToString(PublicKey k){
        return java.util.Base64.getEncoder().encodeToString(k.getEncoded());
    }
}
