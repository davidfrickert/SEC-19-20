package pt.ist.meic.sec.dpas.common.payloads;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public class ReadPayload extends DecryptedPayload {
    private final static Logger logger = Logger.getLogger(ReadPayload.class);

    private BigInteger nAnnouncements;

    public ReadPayload(BigInteger nAnnouncements, PublicKey auth, Operation op, Instant timestamp) {
        super(auth, op,  timestamp);
        this.nAnnouncements = nAnnouncements;
        logger.info("Created - " + op + ", " + nAnnouncements + ", " + timestamp + ", " + auth.hashCode());
    }

    public byte[] asBytes() {
        return ArrayUtils.merge(nAnnouncements.toByteArray(), super.asBytes());
    }

    @Override
    public EncryptedPayload encrypt(PublicKey receiverKey, PrivateKey senderKey) {
       return null;
    }

    public BigInteger getData() {
        return nAnnouncements;
    }

}
