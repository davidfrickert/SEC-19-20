package pt.ist.meic.sec.dpas.client;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.utils.KeyManager;
import pt.ist.meic.sec.dpas.server.DPAServer;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class ClientExample {
    private final static Logger logger = Logger.getLogger(ClientExample.class);

    private PrivateKey privateKey;
    private PublicKey publicKey;

    private ClientLibrary library;

    private String username;

    public ClientExample(String username) throws IOException {

        this.username = username;

        privateKey = KeyManager.loadPrivateKey("keys/private/clients/private1.der");
        publicKey = KeyManager.loadPublicKey("keys/public/clients/pub1.der");

        InetAddress host = InetAddress.getLocalHost();
        library = new ClientLibrary();
        library.start(host.getHostName(), DPAServer.getPort());
    }

    public void input(InputStream src) {
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
            doAction(line);

            System.out.print(">>");
        }
    }

    public Pair<EncryptedPayload, EncryptedPayload> doAction(String command) {
        String[] data = command.split(" ");
        String action = data[0];
        return switch (action.toLowerCase()) {
            case "register" -> library.register(username, publicKey, privateKey);
            case "post" -> {
                String announcement = getAnnouncement(data);
                List<BigInteger> prevAnnouncements = getPreviousAnnouncement(data);
                yield library.post(publicKey, announcement, prevAnnouncements, privateKey);
            }
            case "postgeneral" -> {
                String announcementGeneral = getAnnouncement(data);
                List<BigInteger> prevAnnouncementsGen = getPreviousAnnouncement(data);
                yield library.postGeneral(publicKey, announcementGeneral, prevAnnouncementsGen, privateKey);
            }
            case "read" -> {
                BigInteger nAnnounce = BigInteger.valueOf(Integer.parseInt(data[1]));
                PublicKey boardKey = KeyManager.loadPublicKey(data[2]);
                yield library.read(publicKey, boardKey, nAnnounce, privateKey);
            }
            case "readgeneral" -> {
                BigInteger nAnnounceGen = BigInteger.valueOf(Integer.parseInt(data[1]));
                yield library.readGeneral(nAnnounceGen, publicKey, privateKey);
            }
            default -> {
                logger.info("Invalid input, possibles are: register, post, postgeneral, read, readgeneral (case is not relevant)");
                yield null;
            }
        };
    }

    public static void main(String[] args) throws IOException {

        //program must be initialized with a username
        String username;
        if(args.length != 1){
            System.out.println("ERROR: Wrong number of parameters.");
            System.out.println("Correct usage: java ClientExample <username>");
            System.exit(-1);
        } else {
            username = args[0];
            ClientExample c = new ClientExample(username);
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
        return sb.toString();
    }

    private static List<BigInteger> getPreviousAnnouncement(String[] line) {
        List<BigInteger> result = new ArrayList<>();
        boolean found = false;
        for(int i = 1; i < line.length; i++){
            if(line[i].equals("|")){
                found = true;
                continue;
            }

            if(found){
                result.add(BigInteger.valueOf(Integer.parseInt(line[i])));
            }
        }
        return result;
    }

}
