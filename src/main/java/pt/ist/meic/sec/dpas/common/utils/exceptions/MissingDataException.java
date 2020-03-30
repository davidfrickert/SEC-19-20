package pt.ist.meic.sec.dpas.common.utils.exceptions;

import java.io.IOException;

public class MissingDataException extends IOException {
    public MissingDataException(String errorMessage) {
        super(errorMessage);
    }
}
