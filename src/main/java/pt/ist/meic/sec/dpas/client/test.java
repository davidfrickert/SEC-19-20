package pt.ist.meic.sec.dpas.client;

import java.io.IOException;

public class test {
    public static void main(String[] args) throws IOException {
        int n = 8;
        int f = (n - 1) / 2;
        int q = (int) Math.ceil((n + f) / 2.);
        System.out.println(n);
        System.out.println(f);
        System.out.println(q);
    }
}
