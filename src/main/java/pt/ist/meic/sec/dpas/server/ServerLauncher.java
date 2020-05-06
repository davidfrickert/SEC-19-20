package pt.ist.meic.sec.dpas.server;

import java.util.ArrayList;
import java.util.List;

public class ServerLauncher {
    public List<LauncherThread> threadList = new ArrayList<>();

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
                Thread.sleep(3000);
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

//    public ServerLauncher() {
//        DPAServer s1 = new DPAServer(8080, "keys/private/server/keystore1.p12", "server");
//        DPAServer s2 = new DPAServer(8081, "keys/private/server/keystore1.p12", "server");
//        DPAServer s3 = new DPAServer(8082, "keys/private/server/keystore1.p12", "server");
//        DPAServer s4 = new DPAServer(8083, "keys/private/server/keystore1.p12", "server");
//        DPAServer s5 = new DPAServer(8084, "keys/private/server/keystore1.p12", "server");
//        DPAServer s6 = new DPAServer(8085, "keys/private/server/keystore1.p12", "server");
//        DPAServer s7 = new DPAServer(8086, "keys/private/server/keystore1.p12", "server");
//        DPAServer s8 = new DPAServer(8087, "keys/private/server/keystore1.p12", "server");
//        DPAServer s9 = new DPAServer(8088, "keys/private/server/keystore1.p12", "server");
//        DPAServer s10 = new DPAServer(8089, "keys/private/server/keystore1.p12", "server");
//
//        serverList.add(s1);
//        serverList.add(s2);
//        serverList.add(s3);
//        serverList.add(s4);
//        serverList.add(s5);
//        serverList.add(s6);
//        serverList.add(s7);
//        serverList.add(s8);
//        serverList.add(s9);
//        serverList.add(s10);
//
//    }
//
//    public void start() {
//        for (DPAServer s : serverList) {
//            {
//                Thread serverThread = new Thread (s::listen);
//                serverThread.start();
//                threadList.add(serverThread);
//            }
//        }
//    }

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

        ServerLauncher sl = new ServerLauncher();
        sl.start();
    }
}
