package pt.ist.meic.sec.dpas.common;

public enum Status {
    Success,
    InvalidRequest,
    OldID,
    Unauthorized,
    PostInProgress,
    NotFound,
    MissingData,
    InvalidSignature,
    NotFresh
}
