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

    public MontoyaRequestResponse(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;
        if (requestResponse.timingData().isPresent()) {
            time = requestResponse.timingData().get();
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
        return requestResponse.statusCode();
    }

    public short status() {
        if (requestResponse.hasResponse()) {
            return requestResponse.response().statusCode();
        } else {
            return 0;
        }
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
