package com.shellbreaker.agent;

import com.shellbreaker.output.ClassExtractor;
import com.shellbreaker.output.Reporter;
import com.shellbreaker.rules.RuleEngine;
import com.shellbreaker.rules.ScanResult;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Core detection component — registered as a ClassFileTransformer.
 *
 * For every class loaded (premain) or retransformed (agentmain):
 *  1. Skip bootstrap / JDK / well-known framework packages
 *  2. Apply rule engine on raw bytecode
 *  3. If score >= minScore: extract bytecode to disk + report
 *
 * Returns null (never modifies bytecode — passive observation only).
 */
public class ClassScanner implements ClassFileTransformer {

    private static final Logger LOG = Logger.getLogger("ShellBreaker.Scanner");

    // Packages to skip entirely — server/JDK internals, not webshell territory.
    // We scan webapp/user-defined class packages only.
    private static final List<String> SKIP_PREFIXES = List.of(
        // JDK / JVM internals
        "java/", "javax/", "jakarta/", "sun/", "com/sun/", "jdk/",
        "org/w3c/", "org/xml/", "org/ietf/", "org/jcp/",
        // Tomcat / Spring / common frameworks that load legitimately
        "org/apache/",
        "org/springframework/",
        "org/hibernate/",
        "org/slf4j/",
        "ch/qos/",
        "com/fasterxml/",
        "io/netty/",
        // Our own classes
        "com/shellbreaker/shaded/",
        "com/shellbreaker/"
    );

    private final Reporter       reporter;
    private final ClassExtractor extractor;
    private final AgentConfig    cfg;
    // Dedup: don't re-scan the same (name, loaderIdentity) pair
    private final Set<String>    seen = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public ClassScanner(Reporter reporter, AgentConfig cfg) {
        this.reporter  = reporter;
        this.extractor = new ClassExtractor(cfg.getExtractDir());
        this.cfg       = cfg;
    }

    @Override
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {
        if (className == null || shouldSkip(className)) {
            return null;
        }

        // Dedup key: class name + loader identity
        String key = className + "@" + System.identityHashCode(loader);
        if (!seen.add(key)) {
            return null;
        }

        if (cfg.isVerbose()) {
            LOG.info("[Scan] " + className);
        }

        ScanResult result = RuleEngine.scan(className, classfileBuffer, loader, protectionDomain);

        if (result.getScore() >= cfg.getMinScore()) {
            // Capture thread context at injection time
            Thread current = Thread.currentThread();
            result.setThreadName(current.getName());
            result.setCallStack(captureStack(current));

            // CodeSource URL — null means dynamically defined (no backing file/JAR)
            String csUrl = "null";
            if (protectionDomain != null) {
                CodeSource cs = protectionDomain.getCodeSource();
                if (cs != null) {
                    URL loc = cs.getLocation();
                    if (loc != null) csUrl = loc.toString();
                }
            }
            result.setCodeSourceUrl(csUrl);
            result.setTriggerHook(ShellBreakerAgent.getTriggerHook());

            // Extract bytecode BEFORE returning — this is the copagent approach:
            // the transform() callback has the raw bytes even for in-memory classes
            String path = extractor.extract(className, classfileBuffer);
            result.setExtractedPath(path);
            reporter.report(result);
        }

        return null; // never modify the bytecode
    }

    /**
     * Called during agentmain to retransform already-loaded classes.
     * Filters to non-bootstrap app classes only, then triggers transform() on each.
     */
    public void scanAlreadyLoaded(Class<?>[] allClasses, Instrumentation inst) {
        LOG.info("[Scanner] Scanning " + allClasses.length + " already-loaded classes...");

        List<Class<?>> candidates = new ArrayList<>();
        for (Class<?> clazz : allClasses) {
            String internalName = clazz.getName().replace('.', '/');
            if (!shouldSkip(internalName) && clazz.getClassLoader() != null) {
                candidates.add(clazz);
            }
        }

        LOG.info("[Scanner] Retransforming " + candidates.size() + " app classes");

        // Retransform in batches to cap memory usage
        int batchSize = 100;
        for (int i = 0; i < candidates.size(); i += batchSize) {
            List<Class<?>> batch = candidates.subList(i, Math.min(i + batchSize, candidates.size()));
            try {
                inst.retransformClasses(batch.toArray(new Class[0]));
            } catch (Exception e) {
                LOG.warning("[Scanner] Retransform batch failed: " + e.getMessage());
            }
        }

        LOG.info("[Scanner] Already-loaded class scan complete.");
    }

    private static boolean shouldSkip(String className) {
        for (String prefix : SKIP_PREFIXES) {
            if (className.startsWith(prefix)) return true;
        }
        return false;
    }

    /** Capture top 12 non-JVM-internal stack frames from the calling thread. */
    private static List<String> captureStack(Thread t) {
        StackTraceElement[] frames = t.getStackTrace();
        List<String> out = new ArrayList<>(12);
        for (StackTraceElement f : frames) {
            String cls = f.getClassName();
            if (cls.startsWith("java.") || cls.startsWith("sun.")
                    || cls.startsWith("jdk.") || cls.startsWith("com.shellbreaker.")) {
                continue;
            }
            out.add(f.toString());
            if (out.size() >= 12) break;
        }
        return out;
    }
}
