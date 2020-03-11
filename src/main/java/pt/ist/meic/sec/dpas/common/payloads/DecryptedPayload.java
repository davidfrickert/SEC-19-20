package pt.ist.meic.sec.dpas.common.payloads;

import pt.ist.meic.sec.dpas.common.Operation;

import java.security.PublicKey;
import java.util.List;

public abstract class DecryptedPayload {
    private final PublicKey senderKey;
    private final Operation operation;
    private final List<Integer> linkedAnnouncements;

    /*
    public DecryptedPayload(byte[] data, PublicKey auth, Operation op, List<Integer> links) {
        this.data = data;
        this.auth = auth;
        this.op = op;
        this.links = links;
    }
     */
    public DecryptedPayload(PublicKey auth, Operation op, List<Integer> links) {
        this.senderKey = auth;
        this.operation = op;
        this.linkedAnnouncements = links;
    }

    public abstract Object getData();

    public abstract byte[] asBytes();

    public PublicKey getSenderKey() {
        return senderKey;
    }

    public Operation getOperation() {
        return operation;
    }

    public List<Integer> getLinkedAnnouncements() {
        return linkedAnnouncements;
    }
}
