package pt.ist.meic.sec.dpas.common.payloads.requests;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;
import pt.ist.meic.sec.dpas.common.utils.Crypto;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public class ReadPayload extends DecryptedPayload {
    private final static Logger logger = Logger.getLogger(ReadPayload.class);

    private final BigInteger nAnnouncements;

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
        byte[] encryptedData = Crypto.encryptBytes(nAnnouncements.toByteArray(),  receiverKey);
        PublicKey idKey = this.getSenderKey();
        byte[] encryptedOperation = Crypto.encryptBytes(this.getOperation().name().getBytes(), receiverKey);
        byte[] encryptedTimestamp = Crypto.encryptBytes(this.getTimestamp().toString().getBytes(), receiverKey);

        byte[] originalData = this.asBytes();

        byte[] signature = Crypto.sign(originalData, senderKey);

        return new EncryptedPayloadRequest(idKey, encryptedOperation, encryptedTimestamp, signature, encryptedData,
                null);
    }

    public BigInteger getData() {
        return nAnnouncements;
    }

}
