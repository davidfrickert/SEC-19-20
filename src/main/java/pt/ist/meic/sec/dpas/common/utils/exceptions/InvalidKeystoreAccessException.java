package pt.ist.meic.sec.dpas.common.utils.exceptions;

import java.io.IOException;

public class InvalidKeystoreAccessException extends IOException {
    public InvalidKeystoreAccessException(String errorMessage) {
        super(errorMessage);
    }
}