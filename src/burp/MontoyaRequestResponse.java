package burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

public class MontoyaRequestResponse implements HttpRequestResponse {

    HttpRequestResponse requestResponse;
    TimingData time;
    Long elapsedTime = 0L;

    public boolean timedOut() {
        return timedOut;
    }

    boolean timedOut = false;

    public MontoyaRequestResponse(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;
        if (requestResponse.timingData().isPresent()) {
            time = requestResponse.timingData().get();
        } else {
            setTime(0);
        }
    }

    @Override
    public HttpRequest request() {
        return requestResponse.request();
    }

    @Override
    public HttpResponse response() {
        return requestResponse.response();
    }

    @Override
    public boolean hasResponse() {
        return requestResponse.hasResponse();
    }

    @Override
    public Annotations annotations() {
        return requestResponse.annotations();
    }

    @Override
    public Optional<TimingData> timingData() {
        return Optional.of(time);
    }

    public void setTime(long time) {
        this.time = new TimeLog(time);
    }

    public void setElapsedTime(long elapsedTime) {
        if (status() == 0) {
            //int requestTimeout = Utilities.globalSettings.getInt("timeout") * 1000;
            long requestTimeout = Utilities.burpTimeout;
            if (elapsedTime > requestTimeout) {
                timedOut = true;
            }
        }
        this.elapsedTime = elapsedTime;
    }

    public long elapsedTime() {
        return elapsedTime;
    }

    @Override
    public String url() {
        return requestResponse.url();
    }

    @Override
    public HttpService httpService() {
        return requestResponse.httpService();
    }

    @Override
    public ContentType contentType() {
        return requestResponse.contentType();
    }

    @Override
    public short statusCode() {
        return status();
    }

    public short status() {
        if (requestResponse.hasResponse()) {
            return requestResponse.response().statusCode();
        } else {
            return 0;
        }
    }

    public short nestedStatus() {
        short topStatus = status();
        if (topStatus != 100) {
            return 0;
        }
        String body = requestResponse.response().bodyToString();
        if (!body.startsWith("HTTP/")) {
            return 0;
        }
        short nestedStatus = 0;
        try {
            nestedStatus = Short.parseShort(body.substring(9, 12));
        } catch (NumberFormatException e) {
            return 0;
        }
        return nestedStatus;
    }

    public int server() {
        int serverCode = 0;
        if (response().hasHeader("Server") && response().headerValue("Server").length() > 3) {
            serverCode = response().headerValue("Server").substring(0, 3).hashCode();
        }
        return serverCode;
    }

    public int serverStatus() {
        short status = status();
        if (status != 0) {
            return (server() + status);
        }
        return status;
    }

    @Override
    public List<Marker> requestMarkers() {
        return requestResponse.requestMarkers();
    }

    @Override
    public List<Marker> responseMarkers() {
        return requestResponse.responseMarkers();
    }

    @Override
    public boolean contains(String searchTerm, boolean caseSensitive) {
        return requestResponse.contains(searchTerm, caseSensitive);
    }

    @Override
    public boolean contains(Pattern pattern) {
        return requestResponse.contains(pattern);
    }

    @Override
    public HttpRequestResponse copyToTempFile() {
        return requestResponse.copyToTempFile();
    }

    @Override
    public HttpRequestResponse withAnnotations(Annotations annotations) {
        return requestResponse.withAnnotations(annotations);
    }

    @Override
    public HttpRequestResponse withRequestMarkers(List<Marker> requestMarkers) {
        return requestResponse.withRequestMarkers(requestMarkers);
    }

    @Override
    public HttpRequestResponse withRequestMarkers(Marker... requestMarkers) {
        return requestResponse.withRequestMarkers(requestMarkers);
    }

    @Override
    public HttpRequestResponse withResponseMarkers(List<Marker> responseMarkers) {
        return requestResponse.withResponseMarkers(responseMarkers);
    }

    @Override
    public HttpRequestResponse withResponseMarkers(Marker... responseMarkers) {
        return requestResponse.withResponseMarkers(responseMarkers);
    }
}

class TimeLog implements TimingData {
    Duration time;
    ZonedDateTime timeSent;
    public TimeLog(long time) {
        this.timeSent = ZonedDateTime.now(); // this is horribly inaccurate
        this.time = Duration.of(time, ChronoUnit.MICROS);
    }

    @Override
    public Duration timeBetweenRequestSentAndStartOfResponse() {
        return time;
    }

    @Override
    public Duration timeBetweenRequestSentAndEndOfResponse() {
        return time;
    }

    @Override
    public ZonedDateTime timeRequestSent() {
        return timeSent;
    }
}
