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
    private final PublicKey boardToReadFrom;

    public ReadPayload(BigInteger nAnnouncements, PublicKey senderKey, PublicKey boardToReadFrom, Operation op, Instant timestamp) {
        super(senderKey, op,  timestamp);
        this.nAnnouncements = nAnnouncements;
        this.boardToReadFrom = boardToReadFrom;
        //logger.info("Created - " + op + ", " + nAnnouncements + ", " + timestamp + ", " + auth.hashCode());
    }

    public byte[] asBytes() {
        byte[] key = boardToReadFrom != null ? boardToReadFrom.getEncoded() : new byte[0];
        return ArrayUtils.merge(key, ArrayUtils.objectToBytes(nAnnouncements), super.asBytes());
    }


    @Override
    public EncryptedPayload encrypt(PublicKey receiverKey, PrivateKey senderKey) {
        byte[] encryptedData = Crypto.encryptBytes(ArrayUtils.objectToBytes(this.nAnnouncements),  receiverKey);
        PublicKey idKey = this.getSenderKey();
        byte[] encryptedOperation = Crypto.encryptBytes(this.getOperation().name().getBytes(), receiverKey);
        byte[] encryptedTimestamp = Crypto.encryptBytes(this.getTimestamp().toString().getBytes(), receiverKey);
        byte[] originalData = this.asBytes();

        byte[] signature = Crypto.sign(originalData, senderKey);

        return new EncryptedPayloadRead(idKey, boardToReadFrom, encryptedOperation, encryptedTimestamp, signature,
                encryptedData);
    }

    public BigInteger getData() {
        return nAnnouncements;
    }

    public PublicKey getBoardToReadFrom() {
        return boardToReadFrom;
    }

    @Override
    public String toString() {
        return "ReadPayload{" +
                "nAnnouncements=" + nAnnouncements +
                ", senderKey=" + getSenderKey().hashCode() +
                ", operation=" + getOperation() +
                ", timestamp=" + getTimestamp() +
                '}';
    }
}
