package org.example;

import java.io.File;
import java.security.MessageDigest;
import java.util.Scanner;

/**
 * Программа для тестирования KuznyechikCipher.
 * Команды:
 *   gen <file> <sizeBytes>           - создать файл со случайными данными
 *   enc <in> <out>                   - зашифровать (введи пароль)
 *   dec <in> <out>                   - расшифровать (введи пароль)
 *   compare-hash <file>              - вывести SHA3-256 хеш (для проверки)
 */
public class Main {

    private static void generateTestFile(File file, long sizeBytes) throws Exception {
        final int chunk = 8192;
        byte[] buf = new byte[chunk];
        int v = 0xC0FFEE;
        long written = 0;
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(file, false)) {
            while (written < sizeBytes) {
                int toWrite = (int) Math.min(chunk, sizeBytes - written);
                for (int i = 0; i < toWrite; i++) {
                    v = v * 1664525 + 1013904223;
                    buf[i] = (byte) (v >>> 16);
                }
                fos.write(buf, 0, toWrite);
                written += toWrite;
            }
        }
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }

    private static byte[] sha3_256(File f) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA3-256");
        try (java.io.FileInputStream fis = new java.io.FileInputStream(f)) {
            byte[] buf = new byte[8192];
            int read;
            while ((read = fis.read(buf)) != -1) md.update(buf, 0, read);
            return md.digest();
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java org.example.MainKuznyechik <gen|enc|dec|compare-hash> ...");
            System.exit(2);
        }
        String cmd = args[0];
        switch (cmd) {
            case "gen": {
                File f = new File(args[1]);
                long size = Long.parseLong(args[2]);
                generateTestFile(f, size);
                System.out.println("Generated: " + f.getAbsolutePath() + " (" + size + " bytes)");
                break;
            }
            case "enc": {
                File in = new File(args[1]);
                File out = new File(args[2]);
                System.out.print("Password: ");
                char[] pwd = System.console() != null ? System.console().readPassword() : (new Scanner(System.in)).nextLine().toCharArray();
                long t0 = System.nanoTime();
                KuznyechikCipher.encryptFile(in, out, pwd);
                long t1 = System.nanoTime();
                System.out.println("Encrypted to: " + out.getAbsolutePath());
                System.out.printf("Time: %.3f ms%n", (t1 - t0) / 1e6);
                java.util.Arrays.fill(pwd, '\0');
                break;
            }
            case "dec": {
                File in = new File(args[1]);
                File out = new File(args[2]);
                System.out.print("Password: ");
                char[] pwd = System.console() != null ? System.console().readPassword() : (new Scanner(System.in)).nextLine().toCharArray();
                long t0 = System.nanoTime();
                KuznyechikCipher.decryptFile(in, out, pwd);
                long t1 = System.nanoTime();
                System.out.println("Decrypted to: " + out.getAbsolutePath());
                System.out.printf("Time: %.3f ms%n", (t1 - t0) / 1e6);
                java.util.Arrays.fill(pwd, '\0');
                break;
            }
            case "compare-hash": {
                File f = new File(args[1]);
                byte[] h = sha3_256(f);
                System.out.println("SHA3-256: " + bytesToHex(h));
                break;
            }
            default:
                System.err.println("Unknown command");
        }
    }
}
