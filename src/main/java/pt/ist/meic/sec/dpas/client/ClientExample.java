package pt.ist.meic.sec.dpas.client;

import pt.ist.meic.sec.dpas.common.utils.KeyManager;
import pt.ist.meic.sec.dpas.client.ClientLibrary;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class ClientExample {

    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static PublicKey serverKey;

    public static void main(String[] args) throws IOException {

        // not dynamic (yet)
        privateKey = KeyManager.loadPrivateKey("keys/private/clients/private1.der");
        publicKey = KeyManager.loadPublicKey("keys/public/clients/public1.der");

        InetAddress host = InetAddress.getLocalHost();
        ClientLibrary library = new ClientLibrary();
        library.start(host.getHostName(), 9999);

        //do actions
        Scanner sc = new Scanner(System.in);
        String line;
        String[] split;
        Boolean quit = false;
        System.out.print(">>");
        while(!quit) {
            line = sc.nextLine();
            split = line.split(" ");

            switch(split[0]) {
                case "register":
                    library.register(publicKey, privateKey);
                    break;
                case "post":
                    String announcement = getAnnouncement(split);
                    List<BigInteger> prevAnnouncements = getPreviousAnnouncement(split);
                    library.post(publicKey, announcement, prevAnnouncements, privateKey);
                    break;
                case "postGeneral":
                    String announcementGeneral = getAnnouncement(split);
                    List<BigInteger> prevAnnouncementsGen = getPreviousAnnouncement(split);
                    library.postGeneral(publicKey,announcementGeneral, prevAnnouncementsGen, privateKey);
                    break;
                case "read":
                    BigInteger nAnnounce = BigInteger.valueOf(Integer.parseInt(split[1]));
                    library.read(publicKey, nAnnounce, privateKey);
                    break;
                case "readGeneral":
                    BigInteger nAnnounceGen = BigInteger.valueOf(Integer.parseInt(split[1]));
                    library.readGeneral(nAnnounceGen, privateKey);
                    break;
                case "quit":
                    System.out.print("Sure you want to leave? (Y = Yes, N = No) ");
                    String conf = sc.nextLine();
                    if(conf.equals("Y")) {
                        quit = true;
                        System.exit(0);
                    }
                    break;
            }

            System.out.print(">>");
        }
    }

    private static String getAnnouncement(String[] line) {
        StringBuilder sb = new StringBuilder();
        boolean found = false;
        for(int i = 1; i < line.length && !found; i++){
            if(!line[i].equals("|")){
                sb.append(line[i] + " ");
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
            }

            if(found){
                result.add(BigInteger.valueOf(Integer.parseInt(line[i])));
            }
        }
        return result;
    }

}
