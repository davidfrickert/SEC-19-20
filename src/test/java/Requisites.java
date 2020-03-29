import org.apache.commons.lang3.tuple.Pair;
import org.testng.annotations.Test;
import pt.ist.meic.sec.dpas.client.ClientExample;
import pt.ist.meic.sec.dpas.common.Status;
import pt.ist.meic.sec.dpas.common.model.Announcement;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.ACKPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.AnnouncementsPayload;
import pt.ist.meic.sec.dpas.server.DPAServer;

import java.net.SocketTimeoutException;

import static org.testng.Assert.assertEquals;

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
        String command2 = "postgeneral hello void | 0";
        String command3 = "readgeneral 2";

        try {
            c1.doAction(command1);
            ACKPayload received1 = (ACKPayload) c1.getResponse().getLeft();
            assertEquals(received1.getStatus().getStatus(), Status.Success);

            c2.doAction(command2);
            ACKPayload received2 = (ACKPayload) c2.getResponse().getLeft();
            assertEquals(received2.getStatus().getStatus(), Status.Success);

            c2.doAction(command3);
            AnnouncementsPayload received3 = (AnnouncementsPayload) c2.getResponse().getLeft();
            assertEquals(received3.getAnnouncements().size(), 2);

            assertEquals(received3.getAnnouncements().get(0).getOwnerKey(), c1.getPublicKey());
            assertEquals(received3.getAnnouncements().get(0).getMessage(), "hello world ");

            assertEquals(received3.getAnnouncements().get(1).getOwnerKey(), c2.getPublicKey());
            assertEquals(received3.getAnnouncements().get(1).getMessage(), "hello void ");

        } catch (SocketTimeoutException e) {
            e.printStackTrace();
        }

    }
}
