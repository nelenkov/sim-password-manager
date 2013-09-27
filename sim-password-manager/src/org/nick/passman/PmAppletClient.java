package org.nick.passman;

import static org.nick.passman.Hex.fromHex;
import static org.nick.passman.Hex.toHex;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import org.simalliance.openmobileapi.Channel;
import org.simalliance.openmobileapi.Session;

import android.util.Base64;
import android.util.Log;

public class PmAppletClient {

    private static final String TAG = PmAppletClient.class.getSimpleName();
    private static final boolean DEBUG = true;

    private static final short SW_SUCCESS = (short) 0x9000;

    private static final String APPLET_AID = "73 69 6d 70 61 73 73 6d 61 6e 01";

    private static final byte CLA = (byte) 0x80;
    private static final byte INS_GET_STATUS = (byte) 0x1;
    private static final byte INS_GEN_RANDOM = (byte) 0x2;
    private static final byte INS_GEN_KEY = (byte) 0x03;
    private static final byte INS_ENCRYPT = (byte) 0x4;
    private static final byte INS_DECRYPT = (byte) 0x5;
    private static final byte INS_CLEAR = (byte) 0x6;

    private static final String GET_RESPONSE_CMD = "00 C0 00 00 ";

    private static final String GET_STATUS_CMD = "80 01 00 00 00 01";
    private static final String GENERATE_KEYS_CMD = "80 03 00 00 00 00";
    private static final String ENCRYPT_CMD = "80 04 00 00 ";
    private static final String DECRYPT_CMD = "80 05 00 00 ";
    private static final String CLEAR_CMD = "80 06 00 00 00 00";


    private Session session;
    private Channel channel;

    public PmAppletClient(Session session) {
        this.session = session;
    }

    public void connect() throws IOException {
        channel = session.openLogicalChannel(fromHex(APPLET_AID));
    }

    public void disconnect() {
        if (channel != null) {
            channel.close();
        }
    }

    private void init() throws IOException {
        if (channel == null || channel.isClosed()) {
            connect();
        }
    }

    public boolean isInitialized() throws IOException {
        init();

        ResponseApdu rapdu = transmit(fromHex(GET_STATUS_CMD));
        checkSw(rapdu);

        return rapdu.getData()[0] == 1;
    }

    public void generateKeys() throws IOException {
        init();

        ResponseApdu rapdu = transmit(fromHex(GENERATE_KEYS_CMD));
        checkSw(rapdu);
    }

    private void checkSw(ResponseApdu rapdu) {
        if (rapdu.getSW() != SW_SUCCESS) {
            throw new AppletException(rapdu.getSW());
        }
    }


    public byte[] encrypt(byte[] data) throws IOException {
        init();

        String cmdStr = ENCRYPT_CMD + String.format("%02x", data.length)
                + toHex(data) + "00";
        ResponseApdu rapdu = transmit(fromHex(cmdStr));
        checkSw(rapdu);

        return rapdu.getData();
    }

    public byte[] encrypt(String str) throws IOException {
        try {
            return encrypt(str.trim().getBytes("ASCII"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public String encryptStr(String str) throws IOException {
        try {
            return Base64.encodeToString(encrypt(str.trim().getBytes("ASCII")),
                    Base64.NO_WRAP);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] decrypt(byte[] data) throws IOException {
        init();

        String cmdStr = DECRYPT_CMD
                + String.format("%02x", (byte) (data.length & 0xff))
                + toHex(data) + "00";
        ResponseApdu rapdu = transmit(fromHex(cmdStr));
        checkSw(rapdu);

        return rapdu.getData();
    }

    public byte[] decrypt(String base64) throws IOException {
        return decrypt(Base64.decode(base64.trim(), Base64.NO_WRAP));
    }

    public String decryptStr(byte[] encrypted) throws IOException {
        return new String(decrypt(encrypted), "ASCII");
    }

    public String decryptStr(String base64) throws IOException {
        try {
            return new String(decrypt(Base64.decode(base64.trim(),
                    Base64.NO_WRAP)), "ASCII");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public void clear() throws IOException {
        init();

        ResponseApdu rapdu = transmit(fromHex(CLEAR_CMD));
        checkSw(rapdu);
    }

    private ResponseApdu transmit(byte[] cmd) throws IOException {
        log(cmd);
        ResponseApdu response = new ResponseApdu(channel.transmit(cmd));
        log(response);

        while (response.isDataRemaining()) {
            cmd = fromHex(GET_RESPONSE_CMD
                    + String.format("%02x",
                            (byte) (response.getRemainingDataLength() & 0xff)));
            log(cmd);
            response = new ResponseApdu(channel.transmit(cmd));
            log(response);
        }

        return response;
    }

    private static void log(byte[] cmd) {
        if (DEBUG) {
            Log.d(TAG, String.format("--> %s", Hex.toHex(cmd)));
        }
    }

    private static void log(ResponseApdu response) {
        if (DEBUG) {
            Log.d(TAG, String.format("<-- %s", response.toString()));
        }
    }
}
