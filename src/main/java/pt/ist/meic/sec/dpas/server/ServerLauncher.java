package pt.ist.meic.sec.dpas.server;

import java.util.ArrayList;
import java.util.List;

public class ServerLauncher {
    private static ServerLauncher sl = null;

    public List<LauncherThread> threadList = new ArrayList<>();
    public int launched = 0;

    public ServerLauncher() {
        LauncherThread t1 = new LauncherThread(8080, "keys/private/server/keystore1.p12", "server");
        LauncherThread t2 = new LauncherThread(8081, "keys/private/server/keystore1.p12", "server");
        LauncherThread t3 = new LauncherThread(8082, "keys/private/server/keystore1.p12", "server");
        LauncherThread t4 = new LauncherThread(8083, "keys/private/server/keystore1.p12", "server");
        LauncherThread t5 = new LauncherThread(8084, "keys/private/server/keystore1.p12", "server");

        threadList.add(t1);
        threadList.add(t2);
        threadList.add(t3);
        threadList.add(t4);
        threadList.add(t5);
    }

    public void start() {
        try {
            for (LauncherThread t: threadList) {
                t.start();
                launched++;
                Thread.sleep(3000);
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static ServerLauncher launchInstance() {
        sl = new ServerLauncher();
        return sl;
    }

    public static ServerLauncher getInstance() {
        return sl;
    }

    class LauncherThread extends Thread {

        public int port;
        public String path;
        public String password;
        public DPAServer s;
        public Thread t;

        public LauncherThread(int serverPort, String keyPath, String keyStorePassword) {
            this.port = serverPort;
            this.path = keyPath;
            this.password = keyStorePassword;
        }
        public void run() {
            s = new DPAServer(port, path, password);
            t = new Thread (s::listen);
            t.start();
        }
    }

    public static void main(String[] args) {

        ServerLauncher sl = ServerLauncher.launchInstance();
        sl.start();
    }
}
