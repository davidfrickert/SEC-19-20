package pt.ist.meic.sec.dpas.common;

import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;

import java.io.Serializable;
import java.util.Optional;

public class StatusMessage implements Serializable {
    private Status status;
    private String message;

    public StatusMessage(Status s) {
        this.status = s;
    }

    public StatusMessage(Status s, String message) {
        this.status = s;
        this.message = message;
    }

    public Status getStatus() {
        return status;
    }

    public Optional<String> getMessage() {
        return Optional.ofNullable(message);
    }

    public byte[] asBytes() {
        return ArrayUtils.objectToBytes(this);
    }

    public static StatusMessage fromBytes(byte[] bytes) {
        return ArrayUtils.bytesToGeneric(bytes);
    }

    @Override
    public String toString() {
        return "StatusMessage{" +
                "status=" + status +
                ", message='" + message + '\'' +
                '}';
    }
}
