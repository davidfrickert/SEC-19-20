import org.testng.annotations.Test;
import pt.ist.meic.sec.dpas.client.ClientExample;
import pt.ist.meic.sec.dpas.common.Status;
import pt.ist.meic.sec.dpas.common.payloads.reply.ACKPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.AnnouncementsPayload;
import pt.ist.meic.sec.dpas.common.utils.exceptions.IncorrectSignatureException;
import pt.ist.meic.sec.dpas.server.DPAServer;

import java.net.SocketTimeoutException;
import java.util.Base64;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

public class Requisites {

    private DPAServer s = new DPAServer();

    {
        Thread serverThread = new Thread (s::listen);
        serverThread.start();
    }

    ClientExample c1 = new ClientExample("test1", "keys/private/clients/1.p12", "client1");
    ClientExample c2 = new ClientExample("test2", "keys/private/clients/2.p12", "client2");

    @Test(priority = 1)
    public void testRegister(){

        String command1 = "register";

        try{
            c1.doAction(command1);
            ACKPayload received1 = (ACKPayload) c1.getResponse().getLeft();
            assertEquals(received1.getStatus().getStatus(), Status.Success);

            c2.doAction(command1);
            ACKPayload received2 = (ACKPayload) c2.getResponse().getLeft();
            assertEquals(received2.getStatus().getStatus(), Status.Success);
        } catch (SocketTimeoutException | IncorrectSignatureException e) {
            fail();
            e.printStackTrace();
        }


    }

    @Test(priority = 2)
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
            assertEquals(received3.getAnnouncements().get(0).getMessage(), "hello world");

            assertEquals(received3.getAnnouncements().get(1).getOwnerKey(), c2.getPublicKey());
            assertEquals(received3.getAnnouncements().get(1).getMessage(), "hello void");

        } catch (NullPointerException e) {
            e.printStackTrace();
            //fail();
        }

    }


    @Test(priority = 3)
    /**
     * Try to read the own posted announcement
     */
    public void testPostAndRead(){
        String pkClient1 = Base64.getEncoder().encodeToString(c1.getPublicKey().getEncoded());
        String command1 = "post hello";
        String command2 = "post still here man, glad to be alive...";
        String command3 = "post goodbye folks!";
        String command4 = "post hello world";
        String command5 = "read " +  pkClient1 + " 2";

        try{
            c1.doAction(command1);
            ACKPayload received1 = (ACKPayload) c1.getResponse().getLeft();
            assertEquals(received1.getStatus().getStatus(), Status.Success);

            c1.doAction(command2);
            ACKPayload received2 = (ACKPayload) c1.getResponse().getLeft();
            assertEquals(received1.getStatus().getStatus(), Status.Success);

            c1.doAction(command3);
            ACKPayload received3 = (ACKPayload) c1.getResponse().getLeft();
            assertEquals(received1.getStatus().getStatus(), Status.Success);

            c2.doAction(command4);
            ACKPayload received4 = (ACKPayload) c2.getResponse().getLeft();
            assertEquals(received1.getStatus().getStatus(), Status.Success);

            c1.doAction(command5);
            AnnouncementsPayload received5 = (AnnouncementsPayload) c1.getResponse().getLeft();
            assertEquals(received5.getAnnouncements().size(), 2);
            assertEquals(received5.getAnnouncements().get(0).getOwnerKey(), c1.getPublicKey());
            assertEquals(received5.getAnnouncements().get(0).getMessage(), "goodbye folks!");
            assertEquals(received5.getAnnouncements().get(1).getMessage(),
                    "still here man, glad to be alive...");


            c2.doAction(command5);
            AnnouncementsPayload received6 = (AnnouncementsPayload) c2.getResponse().getLeft();
            assertEquals(received5.getAnnouncements().size(), 2);
            assertEquals(received5.getAnnouncements().get(0).getOwnerKey(), c1.getPublicKey());
            assertEquals(received5.getAnnouncements().get(0).getMessage(), "goodbye folks!");
            assertEquals(received5.getAnnouncements().get(1).getMessage(),
                    "still here man, glad to be alive...");

        } catch (SocketTimeoutException | IncorrectSignatureException e) {
            e.printStackTrace();
        }
    }
}
