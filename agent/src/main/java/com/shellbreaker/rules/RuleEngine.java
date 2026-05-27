package com.shellbreaker.rules;

import org.objectweb.asm.ClassReader;

import java.net.URL;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Score-based rule engine for in-process memory webshell detection.
 *
 * Mirrors the Python rule layer in 05_inference_api.py but operates directly
 * on raw JVM bytecode via ASM (no javap subprocess).  Scores and tier names
 * match the Python side so the combined verdict is consistent.
 *
 * Baseline: copagent (LandGrey/copagent) — interface checks + classloader analysis.
 * Extended: Jakarta EE, Spring WebSocket, Tomcat Valve, RMI, dynamic Proxy,
 *           ProtectionDomain/CodeSource heuristics, BCEL/Javassist detection.
 */
public class RuleEngine {

    private static final Logger LOG = Logger.getLogger("ShellBreaker.Rules");

    // -----------------------------------------------------------------------
    // Injection interfaces — JVM internal form
    // -----------------------------------------------------------------------
    private static final Set<String> IFACES_SCORE3 = new HashSet<>();
    private static final Set<String> IFACES_SCORE2 = new HashSet<>();
    private static final Set<String> SUPER_SCORE3  = new HashSet<>();
    private static final Set<String> NAME_KEYWORDS = new HashSet<>();

    static {
        // Servlet 4 (javax.*) — Tomcat 9
        for (String s : new String[]{
            "javax/servlet/Filter", "javax/servlet/Servlet",
            "javax/servlet/http/HttpServlet",
            "javax/servlet/ServletRequestListener",
            "javax/servlet/http/HttpSessionListener",
            "javax/servlet/ServletContextListener",
            // Servlet 5+ (jakarta.*) — Tomcat 10+
            "jakarta/servlet/Filter", "jakarta/servlet/Servlet",
            "jakarta/servlet/http/HttpServlet",
            "jakarta/servlet/ServletContextListener",
            "jakarta/servlet/http/HttpSessionListener",
            // Tomcat pipeline injection (valve + executor)
            "org/apache/catalina/Valve",
            "org/apache/catalina/valves/ValveBase",
            "org/apache/catalina/Executor",
            // Spring interceptors
            "org/springframework/web/servlet/HandlerInterceptor",
            // Java Agent injection via ClassFileTransformer
            "java/lang/instrument/ClassFileTransformer"
        }) IFACES_SCORE3.add(s);

        // WebSocket / Netty (score: 2)
        for (String s : new String[]{
            "javax/websocket/Endpoint",
            "javax/websocket/server/ServerEndpointConfig$Configurator",
            "org/springframework/web/socket/WebSocketHandler",
            "io/netty/channel/ChannelHandler",
            "io/netty/channel/ChannelInboundHandler"
        }) IFACES_SCORE2.add(s);

        // Dangerous superclasses (score: 3)
        for (String s : new String[]{
            "javax/servlet/http/HttpServlet",
            "jakarta/servlet/http/HttpServlet",
            "org/apache/catalina/valves/ValveBase",
            "java/rmi/server/UnicastRemoteObject"
        }) SUPER_SCORE3.add(s);

        // Suspicious name keywords (score: 2, one match only)
        for (String s : new String[]{
            "shell", "cmd", "exec", "backdoor", "payload", "webshell",
            "memshell", "inject", "exploit", "hack", "evil",
            "godzilla", "behinder", "regeorg", "icescorpion", "antsword"
        }) NAME_KEYWORDS.add(s);
    }

    // -----------------------------------------------------------------------
    // Main entry point
    // -----------------------------------------------------------------------

    /**
     * Analyse a class being loaded or retransformed.
     *
     * @param className        JVM internal name ("com/evil/Shell")
     * @param bytecode         raw class bytes from ClassFileTransformer
     * @param loader           ClassLoader (null = bootstrap)
     * @param protectionDomain may be null
     */
    public static ScanResult scan(String className, byte[] bytecode,
                                   ClassLoader loader, ProtectionDomain protectionDomain) {
        List<String> rules = new ArrayList<>();
        int score = 0;

        // 1. Parse bytecode with ASM
        BytecodeVisitor bv = new BytecodeVisitor();
        try {
            new ClassReader(bytecode).accept(bv, 0); // 0 = include all attributes (SourceFile)
        } catch (Exception e) {
            rules.add("malformed_bytecode");
            score += 2;
        }

        // 2. Injection interface matching
        for (String iface : bv.interfaces) {
            if (IFACES_SCORE3.contains(iface)) {
                rules.add("iface:" + last(iface));
                score += 3;
            } else if (IFACES_SCORE2.contains(iface)) {
                rules.add("iface:" + last(iface));
                score += 2;
            }
        }

        // 3. Dangerous superclass
        if (SUPER_SCORE3.contains(bv.superName)) {
            rules.add("super:" + last(bv.superName));
            score += 3;
        }

        // 4. Dangerous API calls (from ASM MethodVisitor)
        for (String call : bv.dangerCalls) {
            String method = call.substring(call.lastIndexOf('.') + 1);
            rules.add("api:" + method);
            score += dangerScore(call);
        }

        // 5. Dynamic Proxy usage (Spring interceptor injection pattern)
        if (bv.hasReflectProxy) {
            rules.add("api:reflect_proxy");
            score += 2;
        }

        // 6. Missing SourceFile — generated/obfuscated class
        boolean isInner = className.contains("$");
        if (!bv.hasSourceFile && !isInner) {
            rules.add("no_source_attr");
            score += 1;
        }

        // 7. Suspicious class name (check simple name only)
        String simpleName = last(className).toLowerCase();
        for (String kw : NAME_KEYWORDS) {
            if (simpleName.contains(kw)) {
                rules.add("name:" + kw);
                score += 2;
                break;
            }
        }

        // 8. Obfuscated short name (1–3 chars, not inner class)
        if (simpleName.length() <= 3 && !isInner) {
            rules.add("name:obfuscated_short");
            score += 1;
        }

        // 9. ClassLoader heuristics — copagent approach
        //    Skip if score is 0 to avoid noisy false positives
        if (loader != null && score > 0) {
            String loaderName = loader.getClass().getName();

            // 9a. No backing resource: class is not in any JAR on this ClassLoader
            //     Pure in-memory classes have no URL backing them
            URL resource = loader.getResource(className + ".class");
            if (resource == null) {
                rules.add("no_backing_file");
                score += 3;
            }

            // 9b. Dynamic bytecode-generating classloader
            if (loaderName.contains("Groovy") || loaderName.contains("javassist")
                    || loaderName.contains("Unsafe") || loaderName.contains("BCEL")) {
                rules.add("dynamic_loader");
                score += 2;
            }
        }

        // 10. No CodeSource location — dynamically defined (not from a file/JAR)
        if (protectionDomain != null && score > 0) {
            CodeSource cs = protectionDomain.getCodeSource();
            if (cs == null || cs.getLocation() == null) {
                rules.add("no_code_source");
                score += 2;
            }
        }

        // 11. Handler method names in suspicious class (informational, no score)
        if (!bv.handlerMethods.isEmpty() && score > 0) {
            rules.add("handler:" + String.join("+", bv.handlerMethods));
        }

        // Determine risk tier (mirrors Python rule_check tiers)
        ScanResult.Risk risk;
        if (score >= 6) {
            risk = ScanResult.Risk.HIGH;
        } else if (score >= 2) {
            risk = ScanResult.Risk.MEDIUM;
        } else {
            risk = ScanResult.Risk.NONE;
        }

        String loaderInfo = loader != null ? loader.getClass().getSimpleName() + "@"
                + Integer.toHexString(System.identityHashCode(loader)) : "bootstrap";

        return new ScanResult(className, risk, score, rules, loaderInfo);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static String last(String internalName) {
        int i = internalName.lastIndexOf('/');
        return i >= 0 ? internalName.substring(i + 1) : internalName;
    }

    private static int dangerScore(String call) {
        String lower = call.toLowerCase();
        if (lower.endsWith(".exec") || lower.contains("processbuilder")
                || lower.contains("defineclass") || lower.endsWith(".getruntime")) return 3;
        if (lower.contains("setcontextclassloader") || lower.contains("urlclassloader")
                || lower.contains("scriptengine") || lower.contains("groovy")
                || lower.contains("javassist") || lower.contains("compiler")
                || lower.contains("bcel")) return 2;
        return 1; // invoke, setAccessible, etc.
    }
}
