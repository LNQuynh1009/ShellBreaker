package com.shellbreaker.attach;

import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;

import java.io.File;
import java.util.List;

/**
 * Standalone CLI for agentmain attach — can attach ShellBreaker to a running JVM.
 *
 * Usage:
 *   # Attach by PID:
 *   java -jar shellbreaker-agent.jar <pid> [agent-args]
 *
 *   # List running JVMs:
 *   java -jar shellbreaker-agent.jar --list
 *
 *   # Attach to first JVM whose display name matches pattern:
 *   java -jar shellbreaker-agent.jar --match tomcat [agent-args]
 *
 * Example:
 *   java -jar shellbreaker-agent.jar 1234 \
 *       report_url=http://shellbreaker:8081/agent-report,extract_dir=/extracted
 *
 * Requires: JDK (not just JRE) — needs com.sun.tools.attach module.
 * Docker: run inside the Tomcat container, or share PID namespace.
 */
public class AttachMain {

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || "--help".equals(args[0]) || "-h".equals(args[0])) {
            printUsage();
            return;
        }

        if ("--list".equals(args[0])) {
            listJvms();
            return;
        }

        String agentJar = resolveAgentJar();
        String agentArgs = args.length > 1 ? args[1] : "";

        if ("--match".equals(args[0])) {
            if (args.length < 2) { System.err.println("--match requires a pattern"); System.exit(1); }
            String pattern = args[1];
            agentArgs = args.length > 2 ? args[2] : "";
            attachByMatch(agentJar, pattern, agentArgs);
        } else {
            // args[0] is a PID
            String pid = args[0];
            attach(agentJar, pid, agentArgs);
        }
    }

    private static void attach(String agentJar, String pid, String agentArgs) throws Exception {
        System.out.println("[AttachMain] Attaching to PID " + pid + " ...");
        VirtualMachine vm = VirtualMachine.attach(pid);
        try {
            vm.loadAgent(agentJar, agentArgs);
            System.out.println("[AttachMain] Agent loaded. PID=" + pid);
        } finally {
            vm.detach();
        }
    }

    private static void attachByMatch(String agentJar, String pattern, String agentArgs) throws Exception {
        List<VirtualMachineDescriptor> vms = VirtualMachine.list();
        for (VirtualMachineDescriptor desc : vms) {
            if (desc.displayName().toLowerCase().contains(pattern.toLowerCase())) {
                System.out.println("[AttachMain] Matched JVM: " + desc.id() + " — " + desc.displayName());
                attach(agentJar, desc.id(), agentArgs);
                return;
            }
        }
        System.err.println("[AttachMain] No JVM found matching: " + pattern);
        System.exit(1);
    }

    private static void listJvms() {
        List<VirtualMachineDescriptor> vms = VirtualMachine.list();
        System.out.println("Running JVMs:");
        for (VirtualMachineDescriptor desc : vms) {
            System.out.printf("  PID=%-8s  %s%n", desc.id(), desc.displayName());
        }
    }

    private static String resolveAgentJar() {
        // When running as Main-Class of the fat JAR, __FILE__ is this JAR
        try {
            File jar = new File(AttachMain.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI());
            return jar.getAbsolutePath();
        } catch (Exception e) {
            throw new RuntimeException("Cannot resolve agent JAR path: " + e.getMessage(), e);
        }
    }

    private static void printUsage() {
        System.out.println("ShellBreaker Agent Attacher");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java -jar shellbreaker-agent.jar <pid> [agent-args]");
        System.out.println("  java -jar shellbreaker-agent.jar --match <pattern> [agent-args]");
        System.out.println("  java -jar shellbreaker-agent.jar --list");
        System.out.println();
        System.out.println("Agent args (comma-separated key=value):");
        System.out.println("  report_url=http://shellbreaker:8081/agent-report");
        System.out.println("  extract_dir=/tmp/shellbreaker");
        System.out.println("  min_score=2");
        System.out.println("  verbose=false");
        System.out.println("  scan_loaded=true");
        System.out.println();
        System.out.println("Example:");
        System.out.println("  java -jar shellbreaker-agent.jar --match Bootstrap \\");
        System.out.println("      report_url=http://localhost:8081/agent-report,verbose=true");
    }
}
