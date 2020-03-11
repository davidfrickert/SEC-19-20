package pt.ist.meic.sec.dpas.common.payloads;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;
import pt.ist.meic.sec.dpas.common.Operation;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.List;

public class ReadPayload extends DecryptedPayload {
    private final static Logger logger = Logger.getLogger(ReadPayload.class);

    private BigInteger nAnnouncements;

    public ReadPayload(BigInteger nAnnouncements, PublicKey auth, Operation op, List<Integer> links) {
        super(auth, op, links);
        this.nAnnouncements = nAnnouncements;
    }

    public byte[] asBytes() {
        return ArrayUtils.merge(nAnnouncements.toByteArray(), this.getSenderKey().getEncoded(),
                this.getOperation().name().getBytes(), ArrayUtils.listToBytes(this.getLinkedAnnouncements()));
    }

    public BigInteger getData() {
        return nAnnouncements;
    }

}
