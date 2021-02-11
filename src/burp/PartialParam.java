package burp;

class PartialParam implements IParameter {

    int valueStart, valueEnd;
    private String name;
    private byte type;
    private String value;

    PartialParam(String name, int valueStart, int valueEnd) {
        this(name, valueStart, valueEnd, IParameter.PARAM_COOKIE, null);
    }

    PartialParam(String name, int valueStart, int valueEnd, String fakeValue) {
        this(name, valueStart, valueEnd, IParameter.PARAM_COOKIE, null);
    }

    PartialParam(String name, int valueStart, int valueEnd, byte type) {
        this(name, valueStart, valueEnd, type, null);
    }

    PartialParam(String name, int valueStart, int valueEnd, byte type, String fakeValue) {
        this.name = name;
        this.valueStart = valueStart;
        this.valueEnd = valueEnd;
        this.type = type;
        this.value = fakeValue;
    }



    @Override
    public byte getType() {
        return type;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getValue() {
        return value;
    }

    @Override
    public int getNameStart() {
        return 0;
    }

    @Override
    public int getNameEnd() {
        return 0;
    }

    @Override
    public int getValueStart() {
        return valueStart;
    }

    @Override
    public int getValueEnd() {
        return valueEnd;
    }
}

