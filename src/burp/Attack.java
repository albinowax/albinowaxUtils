package burp;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

/**
 * Created by james on 24/11/2016.
 */
class Attack {
    final static int UNINITIALISED = -1;
    final static int DYNAMIC = -2;
    final static int INCALCULABLE = -3;

    private Resp firstRequest;
    private HashMap<String, Object> firstFingerprint;

    HashMap<String, Object> getLastPrint() {
        return lastPrint;
    }

    private HashMap<String, Object> lastPrint;

    Resp getLastRequest() {
        return lastRequest;
    }

    private Resp lastRequest;

    private String[] keys = new String[]{Utilities.globalSettings.getString("canary"), "\",\"", "true", "false", "\"\"", "[]", "</html>", "error", "exception", "invalid", "warning", "stack", "sql syntax", "divisor", "divide", "ora-", "division", "infinity", "<script", "<div"};

    String payload;
    private Probe probe;
    private String anchor;
    private HashMap<String, Object> fingerprint;

    private IResponseKeywords responseKeywords = Utilities.helpers.analyzeResponseKeywords(Arrays.asList(keys));
    private IResponseVariations responseDetails = Utilities.helpers.analyzeResponseVariations();

    // todo add response end?
    private int responseReflections = UNINITIALISED;

    public Attack(Resp req, Probe probe, String payload, String anchor) {
        this.firstRequest = req;
        this.lastRequest = req;
        this.probe = probe;
        this.payload = payload;
        this.anchor = anchor;
        add(req, anchor);
        firstFingerprint = fingerprint;
        this.lastPrint = fingerprint;
    }

    public Attack(Resp req) {
        this.firstRequest = req;
        this.lastRequest = req;
        add(req, "");
        firstFingerprint = fingerprint;
        this.lastPrint = fingerprint;
    }

    public Attack() {}


    public HashMap<String, Object> getPrint() {
        return fingerprint;
    }

    public HashMap<String, Object> getFirstPrint() {
        return firstFingerprint;
    }

    public Resp getFirstRequest() {
        return firstRequest;
    }

    private void regeneratePrint() {
        HashMap<String, Object> generatedPrint = new HashMap<>();
        List<String> keys = responseKeywords.getInvariantKeywords();
        for (String key : keys) {
            generatedPrint.put(key, responseKeywords.getKeywordCount(key, 0));
        }

        keys = responseDetails.getInvariantAttributes();
        for (String key : keys) {
            generatedPrint.put(key, responseDetails.getAttributeValue(key, 0));

        }

        if (responseReflections != DYNAMIC) {
            generatedPrint.put("input_reflections", responseReflections);
        }

        fingerprint = generatedPrint;
    }

    Probe getProbe() {
        return probe;
    }

    private Attack add(Resp resp, String anchor) {
        assert (firstRequest != null);


        byte[] response = Utilities.filterResponse(resp.getReq().getResponse());
        responseKeywords.updateWith(response);
        responseDetails.updateWith(response);

        if(anchor.equals("")) {
            responseReflections = INCALCULABLE;
        }
        else {
            int reflections = Utilities.countMatches(response, anchor.getBytes());
            if (responseReflections == UNINITIALISED) {
                responseReflections = reflections;
            } else if (responseReflections != reflections && responseReflections != INCALCULABLE) {
                responseReflections = DYNAMIC;
            }
        }

        regeneratePrint();

        return this;
    }

    Attack addAttack(Attack attack) {
        if(firstRequest == null) {
            firstRequest = attack.firstRequest;
            anchor = attack.anchor;
            probe = attack.getProbe();
            payload = attack.payload;
            add(attack.getFirstRequest(), anchor);
            firstFingerprint = fingerprint;
        }

        //add(attack.firstRequest.getResponse(), anchor);
        HashMap<String, Object> generatedPrint = new HashMap<>();
        HashMap<String, Object> inputPrint = attack.getPrint();
        for (String key: inputPrint.keySet()) {
            if (fingerprint.containsKey(key)) {
                if (fingerprint.get(key).equals(inputPrint.get(key))) {
                    generatedPrint.put(key, fingerprint.get(key));
                }
            }
        }

        fingerprint = generatedPrint;
        lastRequest = attack.lastRequest;
        this.lastPrint = attack.getPrint();

        return this;
    }

}
