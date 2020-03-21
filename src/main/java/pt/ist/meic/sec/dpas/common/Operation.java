package pt.ist.meic.sec.dpas.common;

import java.util.Random;

public enum Operation {
    REGISTER,
    POST,
    POST_GENERAL,
    READ,
    READ_GENERAL;

    public static Operation fromBytes(byte[] bytes) {
        return Operation.valueOf(new String(bytes));
    }

    public static Operation random() {
        return Operation.values()[new Random().nextInt(Operation.values().length)];
    }
}
