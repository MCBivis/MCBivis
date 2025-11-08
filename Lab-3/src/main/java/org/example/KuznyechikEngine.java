package org.example;

import java.util.Arrays;

/**
 * KuznyechikEngine — реализация блочного шифра ГОСТ Р 34.12-2015 (Кузнечик).
 *
 * Использование:
 *   new KuznyechikEngine(ключ_32_байта)
 *   byte[] enc = encryptBlock(plain16)
 *   byte[] dec = decryptBlock(cipher16)
 *
 * Реализованы:
 *  - S-бокс и обратный S-бокс
 *  - Преобразования R и L, а также их обратные
 *  - Расписание ключей по алгоритму F с константами C_i = L(Vec(i))
 */
public final class KuznyechikEngine {

    private static final int BLOCK = 16;
    private static final int KEY_BYTES = 32;
    private static final int ROUNDS = 10;

    // S-бокс из стандарта
    private static final byte[] S = new byte[] {
            (byte)0xFC,(byte)0xEE,(byte)0xDD,(byte)0x11,(byte)0xCF,(byte)0x6E,(byte)0x31,(byte)0x16,
            (byte)0xFB,(byte)0xC4,(byte)0xFA,(byte)0xDA,(byte)0x23,(byte)0xC5,(byte)0x04,(byte)0x4D,
            (byte)0xE9,(byte)0x77,(byte)0xF0,(byte)0xDB,(byte)0x93,(byte)0x2E,(byte)0x99,(byte)0xBA,
            (byte)0x17,(byte)0x36,(byte)0xF1,(byte)0xBB,(byte)0x14,(byte)0xCD,(byte)0x5F,(byte)0xC1,
            (byte)0xF9,(byte)0x18,(byte)0x65,(byte)0x5A,(byte)0xE2,(byte)0x5C,(byte)0xEF,(byte)0x21,
            (byte)0x81,(byte)0x1C,(byte)0x3C,(byte)0x42,(byte)0x8B,(byte)0x01,(byte)0x8E,(byte)0x4F,
            (byte)0x05,(byte)0x84,(byte)0x02,(byte)0xAE,(byte)0xE3,(byte)0x6A,(byte)0x8F,(byte)0xA0,
            (byte)0x06,(byte)0x0B,(byte)0xED,(byte)0x98,(byte)0x7F,(byte)0xD4,(byte)0xD3,(byte)0x1F,
            (byte)0xEB,(byte)0x34,(byte)0x2C,(byte)0x51,(byte)0xEA,(byte)0xC8,(byte)0x48,(byte)0xAB,
            (byte)0xF2,(byte)0x2A,(byte)0x68,(byte)0xA2,(byte)0xFD,(byte)0x3A,(byte)0xCE,(byte)0xCC,
            (byte)0xB5,(byte)0x70,(byte)0x0E,(byte)0x56,(byte)0x08,(byte)0x0C,(byte)0x76,(byte)0x12,
            (byte)0xBF,(byte)0x72,(byte)0x13,(byte)0x47,(byte)0x9C,(byte)0xB7,(byte)0x5D,(byte)0x87,
            (byte)0x15,(byte)0xA1,(byte)0x96,(byte)0x29,(byte)0x10,(byte)0x7B,(byte)0x9A,(byte)0xC7,
            (byte)0xF3,(byte)0x91,(byte)0x78,(byte)0x6F,(byte)0x9D,(byte)0x9E,(byte)0xB2,(byte)0xB1,
            (byte)0x32,(byte)0x75,(byte)0x19,(byte)0x3D,(byte)0xFF,(byte)0x35,(byte)0x8A,(byte)0x7E,
            (byte)0x6D,(byte)0x54,(byte)0xC6,(byte)0x80,(byte)0xC3,(byte)0xBD,(byte)0x0D,(byte)0x57,
            (byte)0xDF,(byte)0xF5,(byte)0x24,(byte)0xA9,(byte)0x3E,(byte)0xA8,(byte)0x43,(byte)0xC9,
            (byte)0xD7,(byte)0x79,(byte)0xD6,(byte)0xF6,(byte)0x7C,(byte)0x22,(byte)0xB9,(byte)0x03,
            (byte)0xE0,(byte)0x0F,(byte)0xEC,(byte)0xDE,(byte)0x7A,(byte)0x94,(byte)0xB0,(byte)0xBC,
            (byte)0xDC,(byte)0xE8,(byte)0x28,(byte)0x50,(byte)0x4E,(byte)0x33,(byte)0x0A,(byte)0x4A,
            (byte)0xA7,(byte)0x97,(byte)0x60,(byte)0x73,(byte)0x1E,(byte)0x00,(byte)0x62,(byte)0x44,
            (byte)0x1A,(byte)0xB8,(byte)0x38,(byte)0x82,(byte)0x64,(byte)0x9F,(byte)0x26,(byte)0x41,
            (byte)0xAD,(byte)0x45,(byte)0x46,(byte)0x92,(byte)0x27,(byte)0x5E,(byte)0x55,(byte)0x2F,
            (byte)0x8C,(byte)0xA3,(byte)0xA5,(byte)0x7D,(byte)0x69,(byte)0xD5,(byte)0x95,(byte)0x3B,
            (byte)0x07,(byte)0x58,(byte)0xB3,(byte)0x40,(byte)0x86,(byte)0xAC,(byte)0x1D,(byte)0xF7,
            (byte)0x30,(byte)0x37,(byte)0x6B,(byte)0xE4,(byte)0x88,(byte)0xD9,(byte)0xE7,(byte)0x89,
            (byte)0xE1,(byte)0x1B,(byte)0x83,(byte)0x49,(byte)0x4C,(byte)0x3F,(byte)0xF8,(byte)0xFE,
            (byte)0x8D,(byte)0x53,(byte)0xAA,(byte)0x90,(byte)0xCA,(byte)0xD8,(byte)0x85,(byte)0x61,
            (byte)0x20,(byte)0x71,(byte)0x67,(byte)0xA4,(byte)0x2D,(byte)0x2B,(byte)0x09,(byte)0x5B,
            (byte)0xCB,(byte)0x9B,(byte)0x25,(byte)0xD0,(byte)0xBE,(byte)0xE5,(byte)0x6C,(byte)0x52,
            (byte)0x59,(byte)0xA6,(byte)0x74,(byte)0xD2,(byte)0xE6,(byte)0xF4,(byte)0xB4,(byte)0xC0,
            (byte)0xD1,(byte)0x66,(byte)0xAF,(byte)0xC2,(byte)0x39,(byte)0x4B,(byte)0x63,(byte)0xB6
    };

    // Обратный S-бокс
    private static final byte[] Si = new byte[256];

    // Коэффициенты для линейного преобразования L
    private static final int[] LCOEF = new int[] {
            0x01,0x94,0x20,0x85,0x10,0xC2,0xC0,0x01,0xFB,0x01,0xC0,0xC2,0x10,0x85,0x20,0x94
    };

    // Многочлен для редукции: x^8+x^7+x^6+x+1
    private static final int GFRED = 0x1C3;

    static {
        for (int i = 0; i < 256; i++) Si[S[i] & 0xFF] = (byte) i;
    }

    // Ключи раундов K1..K10
    private final byte[][] K = new byte[ROUNDS][BLOCK];

    public KuznyechikEngine(byte[] master) {
        if (master == null || master.length != KEY_BYTES)
            throw new IllegalArgumentException("Ключ должен быть 32 байта");
        keySchedule(Arrays.copyOf(master, KEY_BYTES));
        Arrays.fill(master, (byte) 0);
    }

    public static int blockSize() { return BLOCK; }
    public static int keySize() { return KEY_BYTES; }

    /** Шифрование одного блока (16 байт). */
    public byte[] encryptBlock(byte[] in) {
        if (in == null || in.length != BLOCK)
            throw new IllegalArgumentException("Блок должен быть 16 байт");
        byte[] a = Arrays.copyOf(in, BLOCK);
        for (int i = 0; i < ROUNDS - 1; i++) {
            xorInplace(a, K[i]);
            subBytesInplace(a);
            linearInplace(a);
        }
        xorInplace(a, K[ROUNDS - 1]);
        return a;
    }

    /** Расшифрование одного блока (16 байт). */
    public byte[] decryptBlock(byte[] in) {
        if (in == null || in.length != BLOCK)
            throw new IllegalArgumentException("Блок должен быть 16 байт");
        byte[] a = Arrays.copyOf(in, BLOCK);
        xorInplace(a, K[ROUNDS - 1]);
        for (int i = ROUNDS - 2; i >= 0; i--) {
            invLinearInplace(a);
            invSubBytesInplace(a);
            xorInplace(a, K[i]);
        }
        return a;
    }

    // --- Вспомогательные методы ---

    private static void xorInplace(byte[] a, byte[] b) {
        for (int i = 0; i < BLOCK; i++) a[i] ^= b[i];
    }

    private static void subBytesInplace(byte[] a) {
        for (int i = 0; i < BLOCK; i++) a[i] = S[a[i] & 0xFF];
    }

    private static void invSubBytesInplace(byte[] a) {
        for (int i = 0; i < BLOCK; i++) a[i] = Si[a[i] & 0xFF];
    }

    private static void linearInplace(byte[] a) {
        for (int i = 0; i < 16; i++) rTransform(a);
    }

    private static void invLinearInplace(byte[] a) {
        for (int i = 0; i < 16; i++) invRTransform(a);
    }

    /** Преобразование R. */
    private static void rTransform(byte[] a) {
        byte new0 = lValue(a);
        for (int i = BLOCK - 1; i >= 1; i--) a[i] = a[i - 1];
        a[0] = new0;
    }

    /** Обратное преобразование R⁻¹. */
    private static void invRTransform(byte[] a) {
        byte[] tmp = new byte[BLOCK];
        System.arraycopy(a, 1, tmp, 0, BLOCK - 1);
        int acc = 0;
        for (int k = 0; k < BLOCK - 1; k++)
            acc ^= gfMul(tmp[k] & 0xFF, LCOEF[BLOCK - 1 - k]);
        tmp[15] = (byte) (((a[0] & 0xFF) ^ acc) & 0xFF);
        System.arraycopy(tmp, 0, a, 0, BLOCK);
    }

    /** Вычисление l(a0..a15). */
    private static byte lValue(byte[] st) {
        int acc = 0;
        for (int i = 0; i < BLOCK; i++)
            acc ^= gfMul(st[BLOCK - 1 - i] & 0xFF, LCOEF[i]);
        return (byte) acc;
    }

    /** Умножение в поле GF(2^8) с редукцией по полиному GFRED. */
    private static int gfMul(int a, int b) {
        int res = 0;
        int aa = a & 0xFF, bb = b & 0xFF;
        while (bb != 0) {
            if ((bb & 1) != 0) res ^= aa;
            bb >>>= 1;
            aa <<= 1;
            if ((aa & 0x100) != 0) aa ^= GFRED;
            aa &= 0xFF;
        }
        return res;
    }

    /** Генерация раундовых ключей. */
    private void keySchedule(byte[] master) {
        byte[] k1 = Arrays.copyOfRange(master, 0, 16);
        byte[] k2 = Arrays.copyOfRange(master, 16, 32);

        byte[][] C = new byte[32][BLOCK];
        for (int i = 0; i < 32; i++) {
            byte[] v = new byte[BLOCK];
            v[0] = (byte) (i + 1);
            linearInplace(v);
            C[i] = v;
        }

        byte[] A = k1, B = k2;

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 8; j++) {
                byte[] tmp = Arrays.copyOf(A, BLOCK);
                xorInplace(tmp, C[i * 8 + j]);
                subBytesInplace(tmp);
                linearInplace(tmp);
                for (int t = 0; t < BLOCK; t++) tmp[t] ^= B[t];
                B = A;
                A = tmp;
            }
            K[2 * i] = Arrays.copyOf(A, BLOCK);
            K[2 * i + 1] = Arrays.copyOf(B, BLOCK);
        }
        Arrays.fill(master, (byte) 0);
    }
}
