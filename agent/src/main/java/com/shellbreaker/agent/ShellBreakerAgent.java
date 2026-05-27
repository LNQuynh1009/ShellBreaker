package com.shellbreaker.agent;

import com.shellbreaker.output.Reporter;

import java.lang.instrument.Instrumentation;
import java.util.logging.Logger;

/**
 * ShellBreaker Java Agent entry point.
 *
 * premain  — loaded at JVM startup via: -javaagent:shellbreaker-agent.jar=<args>
 *            Registers a ClassFileTransformer that intercepts every class load.
 *
 * agentmain — attached at runtime via the Attach API (see AttachMain).
 *             Same as premain, but also retransforms already-loaded classes
 *             so classes injected before attach are still caught.
 *
 * Agent args (comma-separated key=value):
 *   report_url   — POST detections here  (default: http://localhost:8081/agent-report)
 *   extract_dir  — dump class bytecode   (default: /tmp/shellbreaker)
 *   min_score    — minimum rule score    (default: 2)
 *   verbose      — log every scan        (default: false)
 *   scan_loaded  — retransform existing classes in agentmain mode (default: true)
 */
public class ShellBreakerAgent {

    private static final Logger LOG = Logger.getLogger("ShellBreakerAgent");

    /** "premain" or "agentmain" — set before any transformer fires. */
    private static volatile String TRIGGER_HOOK = "premain";

    public static String getTriggerHook() { return TRIGGER_HOOK; }

    /** Called at JVM startup: -javaagent:shellbreaker-agent.jar=<args> */
    public static void premain(String args, Instrumentation inst) {
        TRIGGER_HOOK = "premain";
        LOG.info("[ShellBreaker] premain — monitoring class loads from startup");
        start(args, inst, false);
    }

    /** Called at runtime via Attach API (agentmain mode) */
    public static void agentmain(String args, Instrumentation inst) {
        TRIGGER_HOOK = "agentmain";
        LOG.info("[ShellBreaker] agentmain — attached to live JVM");
        start(args, inst, true);
    }

    private static void start(String args, Instrumentation inst, boolean lateAttach) {
        AgentConfig cfg      = AgentConfig.parse(args);
        Reporter    reporter = new Reporter(cfg);
        ClassScanner scanner = new ClassScanner(reporter, cfg);

        // true = can retransform (needed for agentmain to scan already-loaded classes)
        inst.addTransformer(scanner, true);

        LOG.info("[ShellBreaker] Transformer registered");
        LOG.info("[ShellBreaker]   report_url  = " + cfg.getReportUrl());
        LOG.info("[ShellBreaker]   extract_dir = " + cfg.getExtractDir());
        LOG.info("[ShellBreaker]   min_score   = " + cfg.getMinScore());

        if (lateAttach && cfg.isScanLoaded()) {
            // Scan classes already in the JVM before we attached.
            // This is the critical agentmain capability — catching shells
            // injected before the agent was loaded.
            new Thread(() -> {
                try {
                    Thread.sleep(200); // brief pause for transformer to register fully
                    scanner.scanAlreadyLoaded(inst.getAllLoadedClasses(), inst);
                } catch (InterruptedException ignored) {}
            }, "shellbreaker-scan-loaded").start();
        }
    }
}
