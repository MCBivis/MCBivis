package org.example;

import java.io.*;

/**
 * Консольный интерфейс для SHA3FileHasher.
 * Команды:
 *   hash <file>
 *   compare <file>
 *   gen <file> <sizeBytes>
 */
public class Main {

    private static void generateTestFile(File file, long sizeBytes) throws IOException {
        byte[] buf = new byte[8192];
        int v = 0xC0FFEE;
        long written = 0;
        try (FileOutputStream fos = new FileOutputStream(file, false)) {
            while (written < sizeBytes) {
                int toWrite = (int) Math.min(buf.length, sizeBytes - written);
                for (int i = 0; i < toWrite; i++) {
                    v = v * 1664525 + 1013904223;
                    buf[i] = (byte) (v >>> 16);
                }
                fos.write(buf, 0, toWrite);
                written += toWrite;
            }
        }
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java Main <hash|compare|gen> ...");
            System.exit(2);
        }

        String cmd = args[0];
        try {
            switch (cmd) {
                case "hash": {
                    File f = new File(args[1]);
                    long t0 = System.nanoTime();
                    byte[] digest = SHA3FileHasher.computeSHA3_256(f);
                    long t1 = System.nanoTime();
                    System.out.println("SHA3-256: " + SHA3FileHasher.bytesToHex(digest));
                    System.out.printf("Time: %.3f ms%n", (t1 - t0) / 1e6);
                    break;
                }
                case "compare": {
                    File f = new File(args[1]);
                    byte[] ours = SHA3FileHasher.computeSHA3_256(f);
                    byte[] ref = SHA3FileHasher.computeReferenceSHA3_256(f);
                    System.out.println("Our SHA3-256 : " + SHA3FileHasher.bytesToHex(ours));
                    System.out.println("Ref SHA3-256 : " + SHA3FileHasher.bytesToHex(ref));
                    System.out.println("Equal        : " + SHA3FileHasher.secureEquals(ours, ref));
                    break;
                }
                case "gen": {
                    File f = new File(args[1]);
                    long size = Long.parseLong(args[2]);
                    generateTestFile(f, size);
                    System.out.println("Generated file: " + f.getAbsolutePath() + " (" + size + " bytes)");
                    break;
                }
                default:
                    System.err.println("Unknown command.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
