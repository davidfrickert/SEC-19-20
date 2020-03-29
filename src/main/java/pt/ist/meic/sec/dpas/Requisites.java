package pt.ist.meic.sec.dpas;

import org.apache.commons.lang3.tuple.Pair;
import org.testng.annotations.Test;
import pt.ist.meic.sec.dpas.client.ClientExample;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.server.DPAServer;

@Test
public class Requisites {

    private DPAServer s = new DPAServer();

    {
        Thread serverThread = new Thread (s::listen);
        serverThread.start();
    }

    ClientExample c1 = new ClientExample("test1", "keys/private/clients/1.p12", "client1");
    ClientExample c2 = new ClientExample("test2", "keys/private/clients/2.p12", "client2");

    public void generalboard() {
        String command1 = "postgeneral hello world";
        String command2 = "readgeneral 1";
        String command3 = "postgeneral hello void | 0";
        String command4 = "readgeneral 2";

        c1.doAction(command1);
        c1.doAction(command2);
        c2.doAction(command3);
        Pair<EncryptedPayload, EncryptedPayload> sentAndReceived = c2.doAction(command4);

    }
}
