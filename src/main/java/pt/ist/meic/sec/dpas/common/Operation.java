package pt.ist.meic.sec.dpas.common;

import java.util.Random;

public enum Operation {
    REGISTER,
    POST,
    POST_GENERAL,
    READ,
    READ_GENERAL,
    WRITE_BACK,
    GET_LAST_TIMESTAMP,
    VALUE,
    ACK,
    POST_GENERAL_PREPARE,
    READ_COMPLETED;

    public static Operation fromBytes(byte[] bytes) {
        return Operation.valueOf(new String(bytes));
    }

    public static Operation random() {
        return Operation.values()[new Random().nextInt(Operation.values().length)];
    }
}
