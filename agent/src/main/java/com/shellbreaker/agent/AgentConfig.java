package com.shellbreaker.agent;

import java.util.HashMap;
import java.util.Map;

/**
 * Parses the agent argument string: "key=val,key=val,..."
 *
 * Accepted keys:
 *   report_url   — where to POST detection events (default: http://localhost:8081/agent-report)
 *   extract_dir  — directory to dump extracted class bytecode (default: /tmp/shellbreaker)
 *   min_score    — minimum rule score to trigger extraction (default: 2)
 *   verbose      — log every scanned class (default: false)
 *   scan_loaded  — during agentmain, retransform already-loaded classes (default: true)
 */
public class AgentConfig {

    private final String reportUrl;
    private final String extractDir;
    private final int    minScore;
    private final boolean verbose;
    private final boolean scanLoaded;

    private AgentConfig(Map<String, String> m) {
        this.reportUrl  = m.getOrDefault("report_url",  "http://localhost:8081/agent-report");
        this.extractDir = m.getOrDefault("extract_dir", "/tmp/shellbreaker");
        this.minScore   = Integer.parseInt(m.getOrDefault("min_score", "2"));
        this.verbose    = Boolean.parseBoolean(m.getOrDefault("verbose", "false"));
        this.scanLoaded = Boolean.parseBoolean(m.getOrDefault("scan_loaded", "true"));
    }

    public static AgentConfig parse(String args) {
        Map<String, String> m = new HashMap<>();
        if (args != null && !args.isBlank()) {
            for (String part : args.split(",")) {
                int eq = part.indexOf('=');
                if (eq > 0) {
                    m.put(part.substring(0, eq).trim(), part.substring(eq + 1).trim());
                }
            }
        }
        return new AgentConfig(m);
    }

    public String getReportUrl()  { return reportUrl; }
    public String getExtractDir() { return extractDir; }
    public int    getMinScore()   { return minScore; }
    public boolean isVerbose()    { return verbose; }
    public boolean isScanLoaded() { return scanLoaded; }
}
