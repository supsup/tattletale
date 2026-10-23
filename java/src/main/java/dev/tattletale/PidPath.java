package dev.tattletale;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;

/**
 * The kernel's executable path for a pid: libproc's proc_pidpath, the call Python makes through
 * ctypes, made here through the JDK's own Foreign Function API (java.lang.foreign, no third-party
 * code). ProcessHandle.info().command() is the fallback only: on macOS it reads KERN_PROCARGS2,
 * which is refused for other users' processes (every root daemon comes back empty) and returns
 * the exec path as typed (".../Support//cloudphotod"), so it would key programs differently from
 * the Python version that shares the same database.
 */
final class PidPath {
    private PidPath() {}

    private static final MethodHandle PROC_PIDPATH = load();

    @SuppressWarnings("restricted")
    private static MethodHandle load() {
        try {
            Linker linker = Linker.nativeLinker();
            SymbolLookup lib = SymbolLookup.libraryLookup("/usr/lib/libproc.dylib", Arena.global());
            MemorySegment fn = lib.find("proc_pidpath").orElseThrow();
            return linker.downcallHandle(fn, FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
        } catch (Throwable t) {
            return null;
        }
    }

    static boolean nativeAvailable() {
        return PROC_PIDPATH != null;
    }

    /** The path, or null if it cannot be read (as Python's pid_path). */
    static String of(long pid) {
        if (PROC_PIDPATH != null) {
            try (Arena a = Arena.ofConfined()) {
                MemorySegment buf = a.allocate(4096);
                int n = (int) PROC_PIDPATH.invokeExact((int) pid, buf, 4096);
                if (n <= 0) return null;
                byte[] b = buf.asSlice(0, n).toArray(ValueLayout.JAVA_BYTE);
                int z = 0;
                while (z < b.length && b[z] != 0) z++;
                return new String(b, 0, z, StandardCharsets.UTF_8);
            } catch (Throwable t) {
                // fall through to ProcessHandle
            }
        }
        return ProcessHandle.of(pid).flatMap(h -> h.info().command()).orElse(null);
    }
}
