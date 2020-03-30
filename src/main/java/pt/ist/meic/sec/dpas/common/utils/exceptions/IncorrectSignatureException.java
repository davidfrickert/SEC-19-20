package pt.ist.meic.sec.dpas.common.utils.exceptions;

import java.security.SignatureException;

public class IncorrectSignatureException extends SignatureException {
    public IncorrectSignatureException(String errorMessage) {
        super(errorMessage);
    }
}
