package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

class RawInsertionPoint implements IScannerInsertionPoint {
    private byte[] prefix;
    private byte[] suffix;
    private String baseValue;
    private String name;

    RawInsertionPoint(byte[] req, String name, int start, int end) {
        this.name = name;
        this.prefix = Arrays.copyOfRange(req, 0, start);
        this.suffix = Arrays.copyOfRange(req, end, req.length);
        baseValue = new String(Arrays.copyOfRange(req, start, end));
    }


    @Override
    public String getInsertionPointName() {
        return name;
    }

    @Override
    public String getBaseValue() {
        return baseValue;
    }

    @Override
    public byte[] buildRequest(byte[] payload) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(prefix);
            outputStream.write(payload);
            outputStream.write(suffix);
        } catch (IOException e) {

        }

        return Utilities.fixContentLength(outputStream.toByteArray());
    }

    @Override
    public int[] getPayloadOffsets(byte[] payload) {
        return new int[]{prefix.length, prefix.length + payload.length};
    }

    @Override
    public byte getInsertionPointType() {
        return IScannerInsertionPoint.INS_EXTENSION_PROVIDED;
    }
}
