package org.nick.passman.sim;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class PasswordManagerApplet extends Applet {

    private static final short OFFSET_ZERO = 0;

    private static final byte CLA = (byte) 0x80;
    private static final byte INS_GET_STATUS = (byte) 0x1;
    private static final byte INS_GEN_RANDOM = (byte) 0x2;
    private static final byte INS_GEN_KEY = (byte) 0x03;
    private static final byte INS_ENCRYPT = (byte) 0x4;
    private static final byte INS_DECRYPT = (byte) 0x5;
    private static final byte INS_CLEAR = (byte) 0x6;

    // in bytes
    // AES 128
    private static final short KEY_LENGTH = 128 / 8;
    private static final short AES_BLOCK_LEN = 16;
    // nonce || short ctr
    private static final short PRNG_NONCE_LEN = AES_BLOCK_LEN - 2;

    private static final short MAX_DATA_LEN = (short) 208;
    // IV(16) + ENCRYPTED DATA
    private static final short MAX_ENCYPTED_DATA_LEN = (short) (MAX_DATA_LEN + 2 * AES_BLOCK_LEN);

    // AES 128
    private byte[] keyBytes;
    private boolean keysGenerated = false;
    // AES PRNG
    private byte[] prngKey;
    private byte[] prngNonce;
    private short prngCounter;

    // transient
    // for AES
    private byte[] iv;
    private byte[] cbcV;
    private byte[] cbcNextV;
    private byte[] cipherBuff;
    private byte[] roundKeysBuff;

    private JavaCardAES aesCipher;

    private PasswordManagerApplet(byte[] bArray, short bOffset, byte bLength) {
        keyBytes = new byte[KEY_LENGTH];
        // XXX sample values for easier testing
        // always initialize from install parameters!
        prngKey = new byte[] { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
                0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
        prngNonce = new byte[] { 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa,
                0xb, 0xc, 0xd, 0xe, 0xf };
        if (bArray != null) {
            short Li = bArray[bOffset];
            short Lc = bArray[(short) (bOffset + Li + 1)];
            short seedLength = bArray[(short) (bOffset + Li + Lc + 2)];
            if (seedLength > 0) {
                if (seedLength != (KEY_LENGTH + PRNG_NONCE_LEN)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }

                short seedOffset = (short) (bOffset + Li + Lc + 3);
                Util.arrayCopy(bArray, seedOffset, prngKey, OFFSET_ZERO,
                        KEY_LENGTH);
                Util.arrayCopy(bArray, (short) (seedOffset + KEY_LENGTH),
                        prngNonce, OFFSET_ZERO, PRNG_NONCE_LEN);
            }
        }
        prngCounter = 0;

        iv = JCSystem.makeTransientByteArray(AES_BLOCK_LEN,
                JCSystem.CLEAR_ON_DESELECT);
        cbcV = JCSystem.makeTransientByteArray(AES_BLOCK_LEN,
                JCSystem.CLEAR_ON_DESELECT);
        cbcNextV = JCSystem.makeTransientByteArray(AES_BLOCK_LEN,
                JCSystem.CLEAR_ON_DESELECT);
        // account for padding
        cipherBuff = JCSystem.makeTransientByteArray(
                (short) (MAX_DATA_LEN + AES_BLOCK_LEN),
                JCSystem.CLEAR_ON_DESELECT);
        roundKeysBuff = JCSystem.makeTransientByteArray(
                (short) (AES_BLOCK_LEN * 11), JCSystem.CLEAR_ON_DESELECT);

        aesCipher = new JavaCardAES();
    }

    public static void install(byte bArray[], short bOffset, byte bLength)
            throws ISOException {
        new PasswordManagerApplet(bArray, bOffset, bLength).register();
    }

    public void process(APDU apdu) throws ISOException {
        byte[] buff = apdu.getBuffer();

        if (selectingApplet()) {
            return;
        }

        // account for logical channels
        if (((byte) (buff[ISO7816.OFFSET_CLA] & (byte) 0xFC)) != CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buff[ISO7816.OFFSET_INS]) {
        case INS_GET_STATUS:
            getInitStatus(apdu);
            break;
        case INS_GEN_RANDOM:
            prng(apdu);
            break;
        case INS_GEN_KEY:
            generateKeys(apdu);
            break;
        case INS_ENCRYPT:
            encrypt(apdu);
            break;
        case INS_DECRYPT:
            decrypt(apdu);
            break;
        case INS_CLEAR:
            clear(apdu);
            break;

        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void getInitStatus(APDU apdu) {
        byte[] buff = apdu.getBuffer();
        buff[0] = keysGenerated ? (byte) 0x01 : (byte) 0x00;
        apdu.setOutgoingAndSend(OFFSET_ZERO, (short) 1);
    }

    private void prng(APDU apdu) {
        byte[] buff = apdu.getBuffer();

        prng(buff, OFFSET_ZERO, AES_BLOCK_LEN);

        apdu.setOutgoingAndSend(OFFSET_ZERO, AES_BLOCK_LEN);
    }

    // use RandomData.getInstance(ALG_SECURE_RANDOM) on real cards!
    private void prng(byte[] buff, short offset, short len) {
        if (len > AES_BLOCK_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopyNonAtomic(prngNonce, OFFSET_ZERO, cipherBuff,
                OFFSET_ZERO, (short) prngNonce.length);
        Util.setShort(cipherBuff, (short) (AES_BLOCK_LEN - 2), prngCounter);

        try {
            aesCipher.RoundKeysSchedule(prngKey, (short) 0, roundKeysBuff);

            // encrypts in place
            boolean success = aesCipher.AESEncryptBlock(cipherBuff,
                    OFFSET_ZERO, roundKeysBuff);
            if (!success) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            prngCounter++;

            Util.arrayCopyNonAtomic(cipherBuff, OFFSET_ZERO, buff, offset, len);
        } finally {
            clearCipherState();
        }
    }

    private void generateKeys(APDU apdu) {
        if (keysGenerated) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        try {
            JCSystem.beginTransaction();
            prng(keyBytes, OFFSET_ZERO, KEY_LENGTH);
            keysGenerated = true;
        } finally {
            JCSystem.commitTransaction();
        }
    }

    private void encrypt(APDU apdu) {
        if (!keysGenerated) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buff = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        if (len > MAX_DATA_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        prng(iv, OFFSET_ZERO, AES_BLOCK_LEN);
        initAes();

        try {
            aesCipher.RoundKeysSchedule(keyBytes, (short) 0, roundKeysBuff);

            short offset = Util.arrayCopyNonAtomic(buff, ISO7816.OFFSET_CDATA,
                    cipherBuff, OFFSET_ZERO, len);
            short padSize = addPadding(cipherBuff, offset, len);
            short paddedLen = (short) (len + padSize);
            short blocks = (short) (paddedLen / AES_BLOCK_LEN);

            for (short i = 0; i < blocks; i++) {
                short cipherOffset = (short) (i * AES_BLOCK_LEN);
                for (short j = 0; j < AES_BLOCK_LEN; j++) {
                    cbcV[j] ^= cipherBuff[(short) (cipherOffset + j)];
                }

                // encrypts in place
                boolean success = aesCipher.AESEncryptBlock(cbcV, OFFSET_ZERO,
                        roundKeysBuff);
                if (!success) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                Util.arrayCopyNonAtomic(cbcV, OFFSET_ZERO, cipherBuff,
                        cipherOffset, AES_BLOCK_LEN);
            }

            offset = Util.arrayCopyNonAtomic(iv, OFFSET_ZERO, buff,
                    OFFSET_ZERO, AES_BLOCK_LEN);
            offset = Util.arrayCopyNonAtomic(cipherBuff, OFFSET_ZERO, buff,
                    AES_BLOCK_LEN, paddedLen);
            apdu.setOutgoingAndSend(OFFSET_ZERO,
                    (short) (AES_BLOCK_LEN + paddedLen));
        } finally {
            clearCipherState();
        }
    }

    private void clearCipherState() {
        Util.arrayFillNonAtomic(roundKeysBuff, OFFSET_ZERO,
                (short) roundKeysBuff.length, (byte) 0x0);
        Util.arrayFillNonAtomic(cipherBuff, OFFSET_ZERO,
                (short) cipherBuff.length, (byte) 0x0);
        Util.arrayFillNonAtomic(cbcNextV, OFFSET_ZERO, (short) cbcNextV.length,
                (byte) 0);
        Util.arrayFillNonAtomic(cbcV, OFFSET_ZERO, (short) cbcV.length,
                (byte) 0);
    }

    private void decrypt(APDU apdu) {
        if (!keysGenerated) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buff = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        if (len % AES_BLOCK_LEN != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (len > MAX_ENCYPTED_DATA_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopyNonAtomic(buff, ISO7816.OFFSET_CDATA, iv, OFFSET_ZERO,
                AES_BLOCK_LEN);
        initAes();

        try {
            aesCipher.RoundKeysSchedule(keyBytes, (short) 0, roundKeysBuff);

            short cipherLen = (short) (len - AES_BLOCK_LEN);
            Util.arrayCopyNonAtomic(buff,
                    (short) (ISO7816.OFFSET_CDATA + AES_BLOCK_LEN), cipherBuff,
                    OFFSET_ZERO, cipherLen);
            short blocks = (short) (cipherLen / AES_BLOCK_LEN);

            for (short i = 0; i < blocks; i++) {
                short cipherOffset = (short) (i * AES_BLOCK_LEN);
                Util.arrayCopyNonAtomic(cipherBuff, cipherOffset, cbcNextV,
                        OFFSET_ZERO, AES_BLOCK_LEN);
                aesCipher.AESDecryptBlock(cipherBuff, cipherOffset,
                        roundKeysBuff);
                // XOR output w/ cbcV
                for (short j = 0; j < AES_BLOCK_LEN; j++) {
                    cipherBuff[(short) (cipherOffset + j)] ^= cbcV[j];
                }

                // swap
                byte[] tmp = cbcV;
                cbcV = cbcNextV;
                cbcNextV = tmp;
            }

            short plainLen = (short) (cipherLen - padCount(cipherBuff,
                    cipherLen));
            Util.arrayCopyNonAtomic(cipherBuff, OFFSET_ZERO, buff, OFFSET_ZERO,
                    plainLen);
            apdu.setOutgoingAndSend(OFFSET_ZERO, plainLen);
        } finally {
            clearCipherState();
        }
    }

    private void initAes() {
        Util.arrayCopyNonAtomic(iv, OFFSET_ZERO, cbcV, OFFSET_ZERO,
                (short) iv.length);
        Util.arrayFillNonAtomic(cbcNextV, OFFSET_ZERO, (short) cbcNextV.length,
                (byte) 0);
        Util.arrayFillNonAtomic(roundKeysBuff, OFFSET_ZERO,
                (short) roundKeysBuff.length, (byte) 0);
    }

    private static short addPadding(byte[] in, short start, short len) {
        short unpaddedBlockLen = 0;
        if (len % AES_BLOCK_LEN != 0) {
            short blocks = len < AES_BLOCK_LEN ? (short) 1
                    : (short) (len / AES_BLOCK_LEN);
            unpaddedBlockLen = len < AES_BLOCK_LEN ? len
                    : (short) (len - blocks * AES_BLOCK_LEN);
        }
        byte code = (byte) (AES_BLOCK_LEN - unpaddedBlockLen);

        for (short i = 0; i < code; i++) {
            in[(short) (start + i)] = code;
        }

        return code;
    }

    private static short padCount(byte[] in, short len) {
        short count = (short) (in[(short) (len - 1)] & 0xff);

        if (count > len || count == 0) {
            // corrupted pad block
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        for (short i = 1; i <= count; i++) {
            if (in[(short) (len - i)] != count) {
                // corrupted pad block
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
        }

        return count;
    }

    private void clear(APDU apdu) {
        try {
            JCSystem.beginTransaction();
            for (short i = 0; i < KEY_LENGTH; i++) {
                keyBytes[i] = 0;
            }

            keysGenerated = false;
            prngCounter = 0;
        } finally {
            JCSystem.commitTransaction();
        }
    }

}
