package pt.ist.meic.sec.dpas.server;

import java.util.ArrayList;
import java.util.List;

public class ServerLauncher {
    private static ServerLauncher sl = null;

    public List<LauncherThread> threadList = new ArrayList<>();
    public int launched = 0;

    public ServerLauncher() {
        LauncherThread t1 = new LauncherThread(35000, "keys/private/server/keystore1.p12", "server1");
        LauncherThread t2 = new LauncherThread(35001, "keys/private/server/keystore2.p12", "server2");
        LauncherThread t3 = new LauncherThread(35002, "keys/private/server/keystore3.p12", "server3");
        LauncherThread t4 = new LauncherThread(35003, "keys/private/server/keystore4.p12", "server4");
        LauncherThread t5 = new LauncherThread(35004, "keys/private/server/keystore5.p12", "server5");

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

    static class LauncherThread extends Thread {

        public int port;
        public String path;
        public String password;
        public DPAServer s;

        public LauncherThread(int serverPort, String keyPath, String keyStorePassword) {
            this.port = serverPort;
            this.path = keyPath;
            this.password = keyStorePassword;
        }
        public void run() {
            s = new DPAServer(port, path, password);
            s.listen();
        }
    }

    public static void main(String[] args) {

        ServerLauncher sl = ServerLauncher.launchInstance();
        sl.start();
    }
}
