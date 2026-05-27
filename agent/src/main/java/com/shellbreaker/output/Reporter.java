package com.shellbreaker.output;

import com.shellbreaker.agent.AgentConfig;
import com.shellbreaker.rules.ScanResult;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.logging.Logger;

/**
 * Reports detection events via HTTP POST (to shellbreaker API) and log file.
 *
 * The JSON payload is compatible with the existing detections.jsonl format used
 * by the shellbreaker detector service, so Splunk dashboards need no changes.
 */
public class Reporter {

    private static final Logger LOG = Logger.getLogger("ShellBreaker.Reporter");

    private final AgentConfig cfg;

    public Reporter(AgentConfig cfg) {
        this.cfg = cfg;
    }

    public void report(ScanResult result) {
        String json = buildJson(result);
        LOG.info("[ShellBreaker] " + result);
        sendHttp(json);
    }

    // -----------------------------------------------------------------------
    // JSON builder — minimal, no external deps
    // -----------------------------------------------------------------------

    private String buildJson(ScanResult r) {
        String rules = r.getRules().stream()
            .map(s -> "\"" + escapeJson(s) + "\"")
            .reduce("", (a, b) -> a.isEmpty() ? b : a + "," + b);

        String stack = "";
        if (r.getCallStack() != null) {
            stack = r.getCallStack().stream()
                .map(s -> "\"" + escapeJson(s) + "\"")
                .reduce("", (a, b) -> a.isEmpty() ? b : a + "," + b);
        }

        Instant now = Instant.now();
        return "{"
            + "\"ts\":"              + now.getEpochSecond()                + ","
            + "\"timestamp_iso\":\"" + now.toString()                      + "\","
            + "\"source\":\"agent\","
            + "\"class_name\":\""    + escapeJson(r.getClassName())        + "\","
            + "\"verdict\":\""       + verdictFor(r)                       + "\","
            + "\"tier\":\""          + r.getRisk().name()                  + "\","
            + "\"rule_score\":"      + r.getScore()                        + ","
            + "\"rule_hits\":["      + rules                               + "],"
            + "\"class_loader\":\""  + escapeJson(r.getClassLoaderInfo())  + "\","
            + "\"thread_name\":\""   + escapeJson(nvl(r.getThreadName()))  + "\","
            + "\"codesource_url\":\"" + escapeJson(nvl(r.getCodeSourceUrl())) + "\","
            + "\"trigger_hook\":\""  + escapeJson(nvl(r.getTriggerHook())) + "\","
            + "\"call_stack\":["     + stack                               + "],"
            + "\"extracted_path\":"  + jsonStr(r.getExtractedPath())
            + "}";
    }

    private static String nvl(String s) { return s != null ? s : ""; }

    private static String verdictFor(ScanResult r) {
        switch (r.getRisk()) {
            case HIGH:   return "WEBSHELL";
            case MEDIUM: return "WEBSHELL";
            default:     return "BENIGN";
        }
    }

    private static String jsonStr(String s) {
        return s == null ? "null" : "\"" + escapeJson(s) + "\"";
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r");
    }

    // -----------------------------------------------------------------------
    // HTTP POST
    // -----------------------------------------------------------------------

    private void sendHttp(String json) {
        String url = cfg.getReportUrl();
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(json.getBytes(StandardCharsets.UTF_8));
            }

            int code = conn.getResponseCode();
            if (code != 200 && code != 204) {
                LOG.warning("[Reporter] POST " + url + " → HTTP " + code);
            }
        } catch (Exception e) {
            // Non-fatal — agent detection still happened; just couldn't send
            LOG.warning("[Reporter] Could not POST to " + url + ": " + e.getMessage());
        }
    }
}
