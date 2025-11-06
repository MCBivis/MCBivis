package org.example;

import java.io.*;
import java.security.*;
import java.util.Arrays;

/**
 * Реализация хеш-функции SHA3-256 (Keccak).
 */
public class SHA3FileHasher {

    /** Длина выходного хеша (256 бит). */
    private static final int OUTPUT_LENGTH_BYTES = 32;

    /** Размер блока (rate) для SHA3-256 = 1088 бит = 136 байт. */
    private static final int RATE_BYTES = 136;

    /** Размер состояния Keccak в 64-битных "дорожках". */
    private static final int STATE_LANES = 25;

    /** Количество раундов Keccak-f[1600]. */
    private static final int KECCAK_ROUNDS = 24;

    /** Константы раундов Keccak-f. */
    private static final long[] ROUND_CONSTANTS = new long[]{
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L,
            0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
            0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    /** Смещения ρ-функции (rotation offsets). */
    private static final int[][] RHO_OFFSETS = {
            {0, 36, 3, 41, 18},
            {1, 44, 10, 45, 2},
            {62, 6, 43, 15, 61},
            {28, 55, 25, 21, 56},
            {27, 20, 39, 8, 14}
    };

    /**
     * Основной метод вычисления SHA3-256 для файла.
     * Обрабатывает данные потоково и применяет паддинг Keccak (pad10*1).
     */
    public static byte[] computeSHA3_256(File file) throws IOException {
        // Проверка корректности аргументов
        if (file == null) throw new IllegalArgumentException("file is null");
        if (!file.exists() || !file.isFile()) throw new IllegalArgumentException("invalid file");

        // Инициализация состояния Keccak (25 64-битных слов = 1600 бит)
        long[] state = new long[STATE_LANES];
        Arrays.fill(state, 0L);

        // Буфер для чтения данных из файла
        byte[] buffer = new byte[RATE_BYTES];
        try (FileInputStream fis = new FileInputStream(file)) {
            boolean lastWasFull = false;
            int read;

            // Последовательная обработка блоков
            while ((read = fis.read(buffer)) != -1) {
                if (read == RATE_BYTES) {
                    // Полный блок — сразу обрабатываем
                    xorBlockToState(state, buffer, RATE_BYTES);
                    keccakF1600(state);
                    lastWasFull = true;
                } else {
                    // Последний неполный блок
                    byte[] last = Arrays.copyOf(buffer, read);
                    byte[] padded = pad10star1(last, RATE_BYTES);
                    xorBlockToState(state, padded, RATE_BYTES);
                    keccakF1600(state);
                    zeroize(padded);
                    zeroize(last);
                    lastWasFull = false;
                    break;
                }
            }

            // Обработка особых случаев (пустой файл и кратная длина)
            if (file.length() == 0) {
                byte[] padded = pad10star1(new byte[0], RATE_BYTES);
                xorBlockToState(state, padded, RATE_BYTES);
                keccakF1600(state);
                zeroize(padded);
            } else if (lastWasFull) {
                byte[] padded = pad10star1(new byte[0], RATE_BYTES);
                xorBlockToState(state, padded, RATE_BYTES);
                keccakF1600(state);
                zeroize(padded);
            }

        } finally {
            // Безопасное обнуление временного буфера
            zeroize(buffer);
        }

        // Этап выжимки (squeezing) для получения выходного хеша
        byte[] digest = new byte[OUTPUT_LENGTH_BYTES];
        int outOffset = 0;
        byte[] blockOut = new byte[RATE_BYTES];

        while (outOffset < OUTPUT_LENGTH_BYTES) {
            stateToBytes(state, blockOut, RATE_BYTES);
            int toCopy = Math.min(RATE_BYTES, OUTPUT_LENGTH_BYTES - outOffset);
            System.arraycopy(blockOut, 0, digest, outOffset, toCopy);
            outOffset += toCopy;
            if (outOffset < OUTPUT_LENGTH_BYTES) keccakF1600(state);
        }

        // Очистка состояния
        Arrays.fill(state, 0L);
        zeroize(blockOut);
        return digest;
    }

    /** Побайтовое XOR сложение блока с состоянием (в LE порядке). */
    private static void xorBlockToState(long[] state, byte[] in, int rateBytes) {
        int idx = 0;
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                int laneIndex = 5 * y + x;
                if (idx + 8 <= rateBytes) {
                    state[laneIndex] ^= toLongLE(in, idx);
                    idx += 8;
                } else {
                    int remain = Math.min(8, rateBytes - idx);
                    long lane = 0L;
                    for (int i = 0; i < remain; i++)
                        lane |= ((in[idx + i] & 0xFFL) << (8 * i));
                    state[laneIndex] ^= lane;
                    return;
                }
            }
        }
    }

    /** Преобразует состояние Keccak обратно в байты (для выжимки). */
    private static void stateToBytes(long[] state, byte[] out, int rateBytes) {
        int idx = 0;
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                int laneIndex = 5 * y + x;
                if (idx + 8 <= rateBytes) {
                    fromLongLE(state[laneIndex], out, idx);
                    idx += 8;
                } else {
                    int remain = Math.min(8, rateBytes - idx);
                    long lane = state[laneIndex];
                    for (int i = 0; i < remain; i++)
                        out[idx + i] = (byte) ((lane >>> (8 * i)) & 0xFF);
                    return;
                }
            }
        }
    }

    /** Паддинг Keccak: добавляет биты 0x06 и завершающий 0x80. */
    private static byte[] pad10star1(byte[] block, int rateBytes) {
        byte[] padded = new byte[rateBytes];
        System.arraycopy(block, 0, padded, 0, block.length);
        padded[block.length] = 0x06;        // битовое начало 0b00000110
        padded[rateBytes - 1] |= 0x80;      // завершающий бит 1
        return padded;
    }

    /**
     * Основная перестановка Keccak-f[1600].
     * Состоит из шагов θ, ρ, π, χ, ι.
     */
    private static void keccakF1600(long[] A) {
        long[] C = new long[5];
        long[] D = new long[5];
        long[][] B = new long[5][5];

        for (int round = 0; round < KECCAK_ROUNDS; round++) {
            // Θ: выравнивание по столбцам
            for (int x = 0; x < 5; x++)
                C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
            for (int x = 0; x < 5; x++)
                D[x] = C[(x + 4) % 5] ^ Long.rotateLeft(C[(x + 1) % 5], 1);
            for (int i = 0; i < 25; i++)
                A[i] ^= D[i % 5];

            // ρ и π: вращение и перестановка координат
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    int newX = y;
                    int newY = (2 * x + 3 * y) % 5;
                    int srcIndex = 5 * y + x;
                    B[newX][newY] = Long.rotateLeft(A[srcIndex], RHO_OFFSETS[x][y]);
                }
            }

            // χ: нелинейное преобразование
            for (int x = 0; x < 5; x++)
                for (int y = 0; y < 5; y++)
                    A[5 * y + x] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]);

            // ι: добавление константы раунда
            A[0] ^= ROUND_CONSTANTS[round];
        }
    }

    /** Преобразование 8 байт little-endian в long. */
    private static long toLongLE(byte[] b, int off) {
        return ((b[off] & 0xFFL)) |
                ((b[off + 1] & 0xFFL) << 8) |
                ((b[off + 2] & 0xFFL) << 16) |
                ((b[off + 3] & 0xFFL) << 24) |
                ((b[off + 4] & 0xFFL) << 32) |
                ((b[off + 5] & 0xFFL) << 40) |
                ((b[off + 6] & 0xFFL) << 48) |
                ((b[off + 7] & 0xFFL) << 56);
    }

    /** Преобразование long в 8 байт little-endian. */
    private static void fromLongLE(long v, byte[] out, int off) {
        for (int i = 0; i < 8; i++) out[off + i] = (byte) (v >>> (8 * i));
    }

    /** Безопасное обнуление массива (zeroization). */
    private static void zeroize(byte[] a) {
        if (a != null) Arrays.fill(a, (byte) 0);
    }

    /** Сравнение с эталонным SHA3-256 из стандартной библиотеки Java. */
    public static byte[] computeReferenceSHA3_256(File file)
            throws IOException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA3-256");
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buf = new byte[8192];
            int read;
            while ((read = fis.read(buf)) != -1) md.update(buf, 0, read);
            return md.digest();
        }
    }

    /** Перевод байтов в шестнадцатеричную строку. */
    public static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }

    /** Постоянновременное сравнение массивов для защиты от атак по времени. */
    public static boolean secureEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= (a[i] ^ b[i]);
        return diff == 0;
    }
}
