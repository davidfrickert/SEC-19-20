package pt.ist.meic.sec.dpas.server;

import java.util.ArrayList;
import java.util.List;

public class ServerLauncher {
    private static List<DPAServer> serverList = new ArrayList<>();
    private static List<Thread> threadList = new ArrayList<>();

    public static void main(String[] args) {
        DPAServer s1 = new DPAServer(9876, "keys/private/server/keystore1.p12", "server");
        serverList.add(s1);

        for (DPAServer s : serverList) {
            {
                Thread serverThread = new Thread (s::listen);
                serverThread.start();
                threadList.add(serverThread);
            }
        }
    }

    // Return a server port (first one working?)
    public static int getServerPort() {
        return serverList.get(1).getPort();
    }
}
