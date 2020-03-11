package pt.ist.meic.sec.dpas.common;

public enum Operation {
    REGISTER,
    POST,
    POST_GENERAL,
    READ,
    READ_GENERAL;

    public static Operation fromBytes(byte[] bytes) {
        return Operation.valueOf(new String(bytes));
    }
}
