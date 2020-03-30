package pt.ist.meic.sec.dpas.common.utils;

import java.io.*;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

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

    public static <T> byte[] objectToBytes(T object) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(object);
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            throw new IllegalStateException();
        }
    }

    public static Object bytesToObject(byte[] bytes) {
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
            ObjectInputStream ois = new ObjectInputStream(bis);
            return ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            throw new IllegalStateException();
        }
    }

    public static <T> List<T> bytesToList(byte[] bytes) {
        return (List<T>) bytesToObject(bytes);
    }

    public static <T> T bytesToGeneric(byte[] bytes) {
        return (T) bytesToObject(bytes);
    }

    public static boolean anyIsNull(Object... array) {
        return Stream.of(array).anyMatch(Objects::isNull);
    }
}
