package com.shellbreaker.rules;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * ASM ClassVisitor that collects detection signals from raw bytecode.
 *
 * Signals gathered:
 *  - superclass and interfaces (for injection-interface matching)
 *  - presence of SourceFile debug attribute
 *  - dangerous invocation targets seen in any method body
 *  - HTTP handler method names present (doFilter, service, doGet, etc.)
 *  - dynamic Proxy.newProxyInstance usage
 *
 * Derived from copagent (LandGrey) + c0ny1 scanner — uses ASM instead of
 * javap so it works in-process without spawning a subprocess.
 */
public class BytecodeVisitor extends ClassVisitor {

    // -----------------------------------------------------------------------
    // Dangerous call table: owner → set of method names
    // Using Map<String,Set<String>> avoids the Set<String[]> equality trap.
    // -----------------------------------------------------------------------
    private static final Map<String, Set<String>> DANGER_CALLS = buildDangerCalls();

    private static Map<String, Set<String>> buildDangerCalls() {
        Map<String, Set<String>> m = new HashMap<>();
        // Command execution
        add(m, "java/lang/Runtime",                  "exec", "getRuntime");
        add(m, "java/lang/ProcessBuilder",            "<init>", "start");
        // Class definition (dynamic classloading)
        add(m, "java/lang/ClassLoader",              "defineClass");
        add(m, "sun/misc/Unsafe",                    "defineClass", "defineAnonymousClass");
        add(m, "jdk/internal/misc/Unsafe",           "defineAnonymousClass");
        // Reflection / access bypass
        add(m, "java/lang/reflect/Method",           "invoke");
        add(m, "java/lang/reflect/AccessibleObject", "setAccessible");
        // ClassLoader manipulation
        add(m, "java/lang/Thread",                   "getContextClassLoader", "setContextClassLoader");
        add(m, "java/net/URLClassLoader",             "<init>");
        // Script engine code execution
        add(m, "javax/script/ScriptEngine",          "eval");
        // Dynamic bytecode generation frameworks
        add(m, "groovy/lang/GroovyClassLoader",      "parseClass");
        add(m, "javax/tools/JavaCompiler",           "getTask");
        add(m, "org/apache/bcel/classfile/JavaClass","getBytes");
        add(m, "javassist/ClassPool",                "makeClass");
        add(m, "javassist/CtClass",                  "toBytecode");
        return m;
    }

    private static void add(Map<String, Set<String>> m, String owner, String... methods) {
        Set<String> s = m.computeIfAbsent(owner, k -> new HashSet<>());
        for (String method : methods) s.add(method);
    }

    // HTTP handler methods — presence in a suspicious class increases confidence
    private static final Set<String> HANDLER_METHODS = new HashSet<>();
    static {
        for (String n : new String[]{
            "doFilter", "service", "doGet", "doPost", "doPut", "doDelete",
            "doHead", "doOptions", "invoke", "handle", "execute",
            "transform", "agentmain", "premain"
        }) HANDLER_METHODS.add(n);
    }

    // Collected results — dangerCalls is a LinkedHashSet to dedup repeated calls
    // (e.g. Method.invoke called 20 times should count as one signal, not 20)
    String           superName;
    List<String>     interfaces     = new ArrayList<>();
    boolean          hasSourceFile  = false;
    java.util.LinkedHashSet<String> dangerCalls = new java.util.LinkedHashSet<>();
    List<String>     handlerMethods = new ArrayList<>();
    boolean          hasReflectProxy = false;

    public BytecodeVisitor() {
        super(Opcodes.ASM9);
    }

    @Override
    public void visit(int version, int access, String name, String signature,
                      String superName, String[] interfaces) {
        this.superName = superName == null ? "" : superName;
        if (interfaces != null) {
            for (String i : interfaces) this.interfaces.add(i);
        }
    }

    @Override
    public void visitSource(String source, String debug) {
        hasSourceFile = (source != null);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor,
                                     String signature, String[] exceptions) {
        if (HANDLER_METHODS.contains(name)) {
            handlerMethods.add(name);
        }
        return new MethodVisitor(Opcodes.ASM9) {
            @Override
            public void visitMethodInsn(int opcode, String owner, String mname,
                                        String descriptor, boolean isInterface) {
                Set<String> methods = DANGER_CALLS.get(owner);
                if (methods != null && methods.contains(mname)) {
                    dangerCalls.add(owner.replace('/', '.') + "." + mname);
                }
                if ("java/lang/reflect/Proxy".equals(owner) && "newProxyInstance".equals(mname)) {
                    hasReflectProxy = true;
                }
            }
        };
    }
}
