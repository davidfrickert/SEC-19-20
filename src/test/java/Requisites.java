import org.testng.annotations.Test;
import pt.ist.meic.sec.dpas.client.ClientExample;
import pt.ist.meic.sec.dpas.common.Status;
import pt.ist.meic.sec.dpas.common.payloads.reply.ACKPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.AnnouncementsPayload;
import pt.ist.meic.sec.dpas.common.utils.exceptions.IncorrectSignatureException;
import pt.ist.meic.sec.dpas.common.utils.exceptions.QuorumNotReachedException;
import pt.ist.meic.sec.dpas.server.DPAServer;

import java.util.Base64;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

public class Requisites {

    private DPAServer s = new DPAServer(9876, "keys/private/server/keystore1.p12", "server");

    {
        Thread serverThread = new Thread (s::listen);
        serverThread.start();
    }

    ClientExample c1 = new ClientExample("test1", "keys/private/clients/1.p12", "client1", 9876);
    ClientExample c2 = new ClientExample("test2", "keys/private/clients/2.p12", "client2", 9876);

    @Test(priority = 1)
    public void testRegister(){

        String command1 = "register";

        try{
            c1.doAction(command1);
            ACKPayload received1 = (ACKPayload) c1.getResponse();
            assertEquals(received1.getStatus().getStatus(), Status.Success);

            c2.doAction(command1);
            ACKPayload received2 = (ACKPayload) c2.getResponse();
            assertEquals(received2.getStatus().getStatus(), Status.Success);
        } catch (QuorumNotReachedException | IncorrectSignatureException e) {
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
            ACKPayload received1 = (ACKPayload) c1.doActionAndReceiveReply(command1).get();
            assertEquals(received1.getStatus().getStatus(), Status.Success);

            ACKPayload received2 = (ACKPayload) c2.doActionAndReceiveReply(command2).get();
            assertEquals(received2.getStatus().getStatus(), Status.Success);

            AnnouncementsPayload received3 = (AnnouncementsPayload) c2.doActionAndReceiveReply(command3).get();
            assertEquals(received3.getAnnouncements().size(), 2);

            assertEquals(received3.getAnnouncements().get(0).getOwnerKey(), c2.getPublicKey());
            assertEquals(received3.getAnnouncements().get(0).getMessage(), "hello void");


            assertEquals(received3.getAnnouncements().get(1).getOwnerKey(), c1.getPublicKey());
            assertEquals(received3.getAnnouncements().get(1).getMessage(), "hello world");

        } catch (NullPointerException e) {
            fail();
            e.printStackTrace();
        }

    }


    @Test(priority = 3)
    public void testPostAndRead(){
        String pkClient1 = Base64.getEncoder().encodeToString(c1.getPublicKey().getEncoded());
        String pkClient2 = Base64.getEncoder().encodeToString(c2.getPublicKey().getEncoded());
        String command1 = "post hello";
        String command2 = "post still here man, glad to be alive...";
        String command3 = "post goodbye folks!";
        String command4 = "post hello world";
        String command5 = "read " +  pkClient1 + " 2";
        String command6 = "read " +  pkClient1 + " 0";
        String command7 = "read " +  pkClient2 + " 2";
        String command9 = "post wrong reference | 100000";

        try{
            //Client 1 post
            c1.doAction(command1);
            ACKPayload received1 = (ACKPayload) c1.getResponse();
            assertEquals(received1.getStatus().getStatus(), Status.Success);

            //Client 1 post
            c1.doAction(command2);
            ACKPayload received2 = (ACKPayload) c1.getResponse();
            assertEquals(received2.getStatus().getStatus(), Status.Success);

            //Client 1 post
            c1.doAction(command3);
            ACKPayload received3 = (ACKPayload) c1.getResponse();
            assertEquals(received3.getStatus().getStatus(), Status.Success);

            //Client 2 post
            c2.doAction(command4);
            ACKPayload received4 = (ACKPayload) c2.getResponse();
            assertEquals(received4.getStatus().getStatus(), Status.Success);

            //Client 1 read his own last 2 posts
            c1.doAction(command5);
            AnnouncementsPayload received5 = (AnnouncementsPayload) c1.getResponse();
            assertEquals(received5.getAnnouncements().size(), 2);
            assertEquals(received5.getAnnouncements().get(0).getOwnerKey(), c1.getPublicKey());
            assertEquals(received5.getAnnouncements().get(0).getMessage(), "goodbye folks!");
            assertEquals(received5.getAnnouncements().get(1).getMessage(),
                    "still here man, glad to be alive...");

            //Client 2 read Client 1 all posts
            c2.doAction(command6);
            AnnouncementsPayload received6 = (AnnouncementsPayload) c2.getResponse();
            assertEquals(received6.getAnnouncements().size(), 3);
            assertEquals(received6.getAnnouncements().get(0).getOwnerKey(), c1.getPublicKey());
            assertEquals(received6.getAnnouncements().get(0).getMessage(), "goodbye folks!");
            assertEquals(received6.getAnnouncements().get(1).getMessage(),
                    "still here man, glad to be alive...");

            //Client 1 read more posts than Client 2 actually have
            c1.doAction(command7);
            AnnouncementsPayload received7 = (AnnouncementsPayload) c1.getResponse();
            assertEquals(received7.getAnnouncements().size(), 1);
            assertEquals(received7.getAnnouncements().get(0).getOwnerKey(), c2.getPublicKey());
            assertEquals(received7.getAnnouncements().get(0).getMessage(), "hello world");

            //Client 2 post reference his other post
            String c2LastPostID = received7.getAnnouncements().get(0).getId().toString();
            String command8 = "post references | " + c2LastPostID;
            c2.doAction(command8);
            ACKPayload received8 = (ACKPayload) c2.getResponse();
            assertEquals(received8.getStatus().getStatus(), Status.Success);

            //Client 1 reads Client 2 annoucnemt that has a reference to another one
            c1.doAction(command7);
            AnnouncementsPayload received9 = (AnnouncementsPayload) c1.getResponse();
            assertEquals(received9.getAnnouncements().size(), 2);
            assertEquals(received9.getAnnouncements().get(0).getOwnerKey(), c2.getPublicKey());
            assertEquals(received9.getAnnouncements().get(0).getMessage(), "references");
            assertEquals(received9.getAnnouncements().get(0).getReferred().iterator().next().intValue(), 6);
            assertEquals(received9.getAnnouncements().get(1).getMessage(), "hello world");

            //Client 1 posts an invalid announcement because of a wrong reference
            c1.doAction(command9);
            ACKPayload received10 = (ACKPayload) c1.getResponse();
            assertEquals(received10.getStatus().getStatus(), Status.InvalidRequest);

            //Client 1 posts a multiple reference announcement with one from him and another from
            //Client 2
            String c1LastPostID = received5.getAnnouncements().get(0).getId().toString();
            String command10 = "post multiple reference | " + c1LastPostID + " " + c2LastPostID;
            c1.doAction(command10);
            ACKPayload received11 = (ACKPayload) c1.getResponse();
            assertEquals(received11.getStatus().getStatus(), Status.Success);

        } catch (QuorumNotReachedException | IncorrectSignatureException e) {
            fail();
            e.printStackTrace();
        }
    }
}
