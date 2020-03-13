package pt.ist.meic.sec.dpas.client;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class ClientExample {

    public static void main(String[] args) throws IOException {

        InetAddress host = InetAddress.getLocalHost();
        Socket socket = null;
        ObjectOutputStream oos = null;
        ObjectInputStream ois = null;

        //establish socket connection to server
        socket = new Socket(host.getHostName(), 9876);


    }

}
