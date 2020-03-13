package pt.ist.meic.sec.dpas.common.utils;

import java.io.*;
import java.util.Arrays;
import java.util.List;

public class ArrayUtils {

    public static  byte[] merge(byte[] ...arrays) {
        int totalSize = Arrays.stream(arrays).map(b -> b.length).reduce(0, Integer::sum);

        byte[] merged = null;
        int len = 0;

        for (byte[] array : arrays) {
            if (merged == null) {
                merged = Arrays.copyOf(array, totalSize);
                len = array.length;
            } else {
                System.arraycopy(array, 0, merged, len, array.length);
                len += array.length;
            }
        }
        return merged;
    }

    public static <T extends Serializable> byte[] listToBytes(List<T> list) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(list);
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            throw new IllegalStateException();
        }
    }

    public static <T extends Serializable> List<T> bytesToList(byte[] bytes) {
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
            ObjectInputStream ois = new ObjectInputStream(bis);
            return (List<T>) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            throw new IllegalStateException();
        }
    }
}
