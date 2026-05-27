package com.shellbreaker.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Logger;

/**
 * Dumps raw bytecode of a detected class to disk.
 *
 * Approach from copagent (LandGrey): the ClassFileTransformer receives the
 * raw bytecode before the JVM defines the class, so even purely in-memory
 * webshells (never written to disk by the attacker) can be extracted here.
 *
 * Output path: <extractDir>/<package>/<ClassName>_<timestamp>.class
 * The shellbreaker detector service watches extractDir and runs ML on these files.
 */
public class ClassExtractor {

    private static final Logger LOG = Logger.getLogger("ShellBreaker.Extractor");

    private final Path extractRoot;

    public ClassExtractor(String extractDir) {
        this.extractRoot = Paths.get(extractDir);
    }

    /**
     * Write bytecode to disk.
     *
     * @param className JVM internal name ("com/evil/Shell")
     * @param bytecode  raw class bytes
     * @return absolute path of written file, or null on failure
     */
    public String extract(String className, byte[] bytecode) {
        try {
            // Preserve package structure so standard tools (javap, decompilers) work
            Path dir  = extractRoot.resolve(packageDir(className));
            Files.createDirectories(dir);

            String simpleName = simpleName(className);
            String fname      = simpleName + "_" + System.currentTimeMillis() + ".class";
            Path   outPath    = dir.resolve(fname);

            Files.write(outPath, bytecode);
            LOG.info("[Extract] Dumped " + className + " → " + outPath);
            return outPath.toString();
        } catch (IOException e) {
            LOG.warning("[Extract] Failed to dump " + className + ": " + e.getMessage());
            return null;
        }
    }

    private static String packageDir(String className) {
        int slash = className.lastIndexOf('/');
        return slash > 0 ? className.substring(0, slash) : ".";
    }

    private static String simpleName(String className) {
        int slash = className.lastIndexOf('/');
        return slash >= 0 ? className.substring(slash + 1) : className;
    }
}
