package pt.ist.meic.sec.dpas.client.register;

import java.util.List;

public class MultipleAtomicRegister<T> {
    private int ackNumber;
    private int writeId;
    private boolean writing;
    private T readVal;
    private List<SingleAtomicRegister<T>> registers;

    public void write(){
        writeId++;
        writing = true;
        for(SingleAtomicRegister<T> register : registers) {
            register.write();
        }
    }
}
