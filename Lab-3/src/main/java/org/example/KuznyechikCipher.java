package org.example;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Шифрование и расшифровка файлов с использованием алгоритма Кузнечик (ГОСТ Р 34.12-2015) в режиме CBC.
 * Ключ получается из пароля через PBKDF2 (HMAC-SHA256, 200000 итераций).
 * Дополняется по схеме PKCS#7.
 *
 * Формат выходного файла:
 *  [длина соли][соль][длина IV][IV][шифртекст]
 */
public final class KuznyechikCipher {

    private static final int SALT = 16;   // размер соли
    private static final int IV = 16;     // размер вектора инициализации
    private static final int KEYLEN = KuznyechikEngine.keySize();
    private static final int BLOCK = KuznyechikEngine.blockSize();
    private static final int ITER = 200_000;

    /** Генерация случайных байтов */
    private static byte[] randomBytes(int n) {
        SecureRandom sr = new SecureRandom();
        byte[] b = new byte[n];
        sr.nextBytes(b);
        return b;
    }

    /** Получение ключа из пароля и соли через PBKDF2 */
    private static byte[] deriveKey(char[] pass, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(pass, salt, ITER, KEYLEN * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        try {
            return skf.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    /** Добавление PKCS7-паддинга */
    private static byte[] pad(byte[] data, int len) {
        int toPad = BLOCK - (len % BLOCK);
        if (toPad == 0) toPad = BLOCK;
        byte[] out = new byte[len + toPad];
        System.arraycopy(data, 0, out, 0, len);
        Arrays.fill(out, len, out.length, (byte) toPad);
        return out;
    }

    /** Удаление PKCS7-паддинга */
    private static int unpad(byte[] block) throws IOException {
        if (block.length % BLOCK != 0) throw new IOException("Неверная длина");
        int p = block[block.length - 1] & 0xFF;
        if (p < 1 || p > BLOCK) throw new IOException("Ошибка паддинга");
        for (int i = block.length - p; i < block.length; i++)
            if ((block[i] & 0xFF) != p) throw new IOException("Ошибка паддинга");
        return block.length - p;
    }

    /** Шифрование файла */
    public static void encryptFile(File inFile, File outFile, char[] pass) throws Exception {
        if (inFile == null || outFile == null || pass == null) throw new IllegalArgumentException("null");
        if (!inFile.isFile()) throw new IllegalArgumentException("Некорректный входной файл");

        byte[] salt = randomBytes(SALT);
        byte[] iv = randomBytes(IV);
        byte[] key = deriveKey(pass, salt);
        KuznyechikEngine eng = new KuznyechikEngine(key);

        try (FileInputStream fis = new FileInputStream(inFile);
             FileOutputStream fos = new FileOutputStream(outFile)) {

            fos.write((byte) SALT); fos.write(salt);
            fos.write((byte) IV); fos.write(iv);

            byte[] prev = Arrays.copyOf(iv, BLOCK);
            byte[] rem = new byte[0];
            byte[] buf = new byte[4096];
            int r;
            while ((r = fis.read(buf)) != -1) {
                int total = rem.length + r;
                byte[] chunk = new byte[total];
                System.arraycopy(rem, 0, chunk, 0, rem.length);
                System.arraycopy(buf, 0, chunk, rem.length, r);

                int blocks = total / BLOCK;
                int remain = total % BLOCK;

                for (int off = 0; off < blocks * BLOCK; off += BLOCK) {
                    byte[] block = Arrays.copyOfRange(chunk, off, off + BLOCK);
                    for (int i = 0; i < BLOCK; i++) block[i] ^= prev[i];
                    byte[] enc = eng.encryptBlock(block);
                    fos.write(enc);
                    prev = enc;
                }
                rem = Arrays.copyOfRange(chunk, blocks * BLOCK, total);
            }

            byte[] toWrite = pad(rem, rem.length);
            for (int off = 0; off < toWrite.length; off += BLOCK) {
                byte[] block = Arrays.copyOfRange(toWrite, off, off + BLOCK);
                for (int i = 0; i < BLOCK; i++) block[i] ^= prev[i];
                byte[] enc = eng.encryptBlock(block);
                fos.write(enc);
                prev = enc;
            }
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    /** Расшифровка файла */
    public static void decryptFile(File inFile, File outFile, char[] pass) throws Exception {
        if (inFile == null || outFile == null || pass == null) throw new IllegalArgumentException("null");
        if (!inFile.isFile()) throw new IllegalArgumentException("Некорректный входной файл");

        try (FileInputStream fis = new FileInputStream(inFile)) {
            int sl = fis.read(); if (sl <= 0 || sl > 64) throw new IOException("Ошибка соли");
            byte[] salt = new byte[sl]; if (fis.read(salt) != sl) throw new IOException("Ошибка чтения соли");
            int il = fis.read(); if (il <= 0 || il > 64) throw new IOException("Ошибка IV");
            byte[] iv = new byte[il]; if (fis.read(iv) != il) throw new IOException("Ошибка чтения IV");

            byte[] key = deriveKey(pass, salt);
            KuznyechikEngine eng = new KuznyechikEngine(key);

            try (FileOutputStream fos = new FileOutputStream(outFile)) {
                byte[] prev = Arrays.copyOf(iv, BLOCK);
                byte[] cur = new byte[BLOCK];

                int r = readBlockExactly(fis, cur);
                if (r == -1) throw new IOException("Слишком короткий шифртекст");

                while (true) {
                    byte[] next = new byte[BLOCK];
                    int rn = readBlockExactly(fis, next);

                    byte[] dec = eng.decryptBlock(cur);
                    for (int i = 0; i < BLOCK; i++) dec[i] ^= prev[i];

                    if (rn == -1) {
                        int actual = unpad(dec);
                        fos.write(dec, 0, actual);
                        break;
                    } else {
                        fos.write(dec, 0, BLOCK);
                        prev = Arrays.copyOf(cur, BLOCK);
                        System.arraycopy(next, 0, cur, 0, BLOCK);
                    }
                }
            } finally {
                Arrays.fill(key, (byte) 0);
            }
        }
    }

    /** Читает ровно BLOCK байт, возвращает -1 при EOF до начала блока. */
    private static int readBlockExactly(InputStream is, byte[] buf) throws IOException {
        int off = 0;
        while (off < buf.length) {
            int r = is.read(buf, off, buf.length - off);
            if (r == -1) return off == 0 ? -1 : -2;
            off += r;
        }
        return buf.length;
    }
}
