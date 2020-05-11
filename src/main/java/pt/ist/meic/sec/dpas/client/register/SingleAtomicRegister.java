package pt.ist.meic.sec.dpas.client.register;

public class SingleAtomicRegister<T> {

    private int atomicWriteId;
    // ts
    private int atomicReadId;
    private T atomicReadValue;
    private RegularRegister regularRegister;

    public void write() {
        atomicWriteId++;
        regularRegister.write();
    }
}
