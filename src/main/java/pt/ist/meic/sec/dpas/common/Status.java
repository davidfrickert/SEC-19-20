package pt.ist.meic.sec.dpas.common;

public enum Status {
    Success(200),
    InvalidRequest(400),
    Unauthorized(401),
    NotFound(404)
    ;

    private int code;

    Status(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

}
