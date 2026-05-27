package com.shellbreaker.rules;

import java.util.List;

public class ScanResult {

    public enum Risk { NONE, LOW, MEDIUM, HIGH }

    private final String       className;
    private final Risk         risk;
    private final int          score;
    private final List<String> rules;
    private final String       classLoaderInfo;
    private String             extractedPath;   // set after class is dumped to disk
    private String             threadName;
    private List<String>       callStack;
    private String             codeSourceUrl;
    private String             triggerHook;

    public ScanResult(String className, Risk risk, int score,
                      List<String> rules, String classLoaderInfo) {
        this.className      = className;
        this.risk           = risk;
        this.score          = score;
        this.rules          = rules;
        this.classLoaderInfo = classLoaderInfo;
    }

    public String       getClassName()      { return className; }
    public Risk         getRisk()           { return risk; }
    public int          getScore()          { return score; }
    public List<String> getRules()          { return rules; }
    public String       getClassLoaderInfo(){ return classLoaderInfo; }
    public String       getExtractedPath()  { return extractedPath; }
    public void         setExtractedPath(String p) { this.extractedPath = p; }

    public String       getThreadName()     { return threadName; }
    public void         setThreadName(String t) { this.threadName = t; }

    public List<String> getCallStack()      { return callStack; }
    public void         setCallStack(List<String> cs) { this.callStack = cs; }

    public String       getCodeSourceUrl()  { return codeSourceUrl; }
    public void         setCodeSourceUrl(String u) { this.codeSourceUrl = u; }

    public String       getTriggerHook()    { return triggerHook; }
    public void         setTriggerHook(String h) { this.triggerHook = h; }

    public boolean isSuspicious() { return risk != Risk.NONE; }

    @Override
    public String toString() {
        return String.format("[%s score=%d] %s | rules=%s | loader=%s | path=%s",
            risk, score, className, rules, classLoaderInfo, extractedPath);
    }
}
