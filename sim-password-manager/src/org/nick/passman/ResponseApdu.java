package org.nick.passman;


import java.util.Arrays;


public class ResponseApdu {

    private static final byte SW1_BYTES_REMAINING = 0x61;

    private byte[] data;
    private byte sw1;
    private byte sw2;
    private short sw;

    public ResponseApdu(byte[] raw) {
        this.data = getData(raw);
        this.sw = getStatus(raw);
        this.sw1 = raw[raw.length - 2];
        this.sw2 = raw[raw.length - 1];
    }

    public ResponseApdu(byte[] data, byte sw1, byte sw2, short sw) {
        this.data = data.clone();
        this.sw1 = sw1;
        this.sw2 = sw2;
        this.sw = sw;
    }

    public byte[] getData() {
        return data == null ? new byte[0] : data.clone();
    }

    public byte getSW1() {
        return sw1;
    }

    public byte getSW2() {
        return sw2;
    }

    public short getSW() {
        return sw;
    }

    @Override
    public String toString() {
        String swStr = String.format("%02X", sw);
        if (data != null) {
            return String.format("%s %s", Hex.toHex(data), swStr);
        }

        return String.format("%s", swStr);
    }

    public static byte[] getData(byte[] responseApdu) {
        if (responseApdu.length <= 2) {
            return null;
        }

        return Arrays.copyOf(responseApdu, responseApdu.length - 2);
    }

    public static short getStatus(byte[] responseApdu) {
        int len = responseApdu.length;
        return (short) ((responseApdu[len - 2] << 8) | (0xff & responseApdu[len - 1]));
    }


    public boolean isDataRemaining() {
        return getSW1() == SW1_BYTES_REMAINING;
    }

    public byte getRemainingDataLength() {
        if (!isDataRemaining()) {
            return 0;
        }

        return getSW2();
    }

}
