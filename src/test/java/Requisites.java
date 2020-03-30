import org.testng.annotations.Test;
import pt.ist.meic.sec.dpas.client.ClientExample;
import pt.ist.meic.sec.dpas.common.Status;
import pt.ist.meic.sec.dpas.common.payloads.reply.ACKPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.AnnouncementsPayload;
import pt.ist.meic.sec.dpas.server.DPAServer;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

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
            ACKPayload received1 = (ACKPayload) c1.doActionAndReceiveReply(command1).get().getLeft();
            assertEquals(received1.getStatus().getStatus(), Status.Success);

            ACKPayload received2 = (ACKPayload) c2.doActionAndReceiveReply(command2).get().getLeft();
            assertEquals(received2.getStatus().getStatus(), Status.Success);

            AnnouncementsPayload received3 = (AnnouncementsPayload) c2.doActionAndReceiveReply(command3).get().getLeft();
            assertEquals(received3.getAnnouncements().size(), 2);

            assertEquals(received3.getAnnouncements().get(0).getOwnerKey(), c1.getPublicKey());
            assertEquals(received3.getAnnouncements().get(0).getMessage(), "hello world ");

            assertEquals(received3.getAnnouncements().get(1).getOwnerKey(), c2.getPublicKey());
            assertEquals(received3.getAnnouncements().get(1).getMessage(), "hello void ");

        } catch (NullPointerException e) {
            e.printStackTrace();
            fail();
        }

    }
}
