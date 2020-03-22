package pt.ist.meic.sec.dpas.common.payloads.requests;

import org.apache.commons.lang3.tuple.Pair;
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

    private final Pair<PublicKey, BigInteger> data;

    public ReadPayload(BigInteger nAnnouncements, PublicKey senderKey, PublicKey desiredBoardKey, Operation op, Instant timestamp) {
        super(senderKey, op,  timestamp);
        this.data = Pair.of(desiredBoardKey, nAnnouncements);
        //logger.info("Created - " + op + ", " + nAnnouncements + ", " + timestamp + ", " + auth.hashCode());
    }

    public ReadPayload(Pair<PublicKey, BigInteger> boardKeyAndNumberOfAnnouncements, PublicKey senderKey, Operation op, Instant timestamp) {
        super(senderKey, op,  timestamp);
        this.data = boardKeyAndNumberOfAnnouncements;
        //logger.info("Created - " + op + ", " + nAnnouncements + ", " + timestamp + ", " + auth.hashCode());
    }

    public byte[] asBytes() {
        return ArrayUtils.merge(ArrayUtils.objectToBytes(this.data), super.asBytes());
    }


    @Override
    public EncryptedPayload encrypt(PublicKey receiverKey, PrivateKey senderKey) {
        byte[] encryptedData = Crypto.encryptBytes(ArrayUtils.objectToBytes(this.data),  receiverKey);
        PublicKey idKey = this.getSenderKey();
        byte[] encryptedOperation = Crypto.encryptBytes(this.getOperation().name().getBytes(), receiverKey);
        byte[] encryptedTimestamp = Crypto.encryptBytes(this.getTimestamp().toString().getBytes(), receiverKey);
        byte[] originalData = this.asBytes();

        byte[] signature = Crypto.sign(originalData, senderKey);

        return new EncryptedPayloadRequest(idKey, encryptedOperation, encryptedTimestamp, signature, encryptedData,
                null);
    }

    public Pair<PublicKey, BigInteger> getData() {
        return data;
    }

    @Override
    public String toString() {
        return "ReadPayload{" +
                "nAnnouncements=" + data +
                ", senderKey=" + getSenderKey().hashCode() +
                ", operation=" + getOperation() +
                ", timestamp=" + getTimestamp() +
                '}';
    }
}
