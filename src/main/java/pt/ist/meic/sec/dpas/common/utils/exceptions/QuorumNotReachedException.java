package pt.ist.meic.sec.dpas.common.utils.exceptions;

import java.io.IOException;

public class QuorumNotReachedException extends IOException {
    public QuorumNotReachedException(String errorMessage) {
        super(errorMessage);
    }
}