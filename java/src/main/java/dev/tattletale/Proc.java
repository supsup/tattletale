package dev.tattletale;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** subprocess.run(cmd, capture_output=True, text=True[, timeout=...]) for the read-only tools. */
final class Proc {
    private Proc() {}

    /** subprocess.TimeoutExpired; the main loop reports it as a failed check, as Python does. */
    static final class Timeout extends Exception {
        private static final long serialVersionUID = 1L;

        Timeout(List<String> cmd, long seconds) {
            super("Command " + Py.repr(cmd) + " timed out after " + seconds + " seconds");
        }
    }

    record Result(int code, String out, String err) {}

    /** Run and wait; timeoutSeconds <= 0 waits forever. stdin is not inherited. */
    static Result run(List<String> cmd, long timeoutSeconds) throws IOException, Timeout {
        return run(cmd, timeoutSeconds, false);
    }

    static Result collector(List<String> cmd, long timeoutSeconds) throws IOException, Timeout {
        return run(cmd, timeoutSeconds, true);
    }

    static ProcessBuilder builder(List<String> cmd, boolean collector) {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        if (collector) collectorEnvironment(pb);
        pb.redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null")));
        return pb;
    }

    static void collectorEnvironment(ProcessBuilder pb) { pb.environment().put("LC_ALL", "C"); }

    private static Result run(List<String> cmd, long timeoutSeconds, boolean collector) throws IOException, Timeout {
        ProcessBuilder pb = builder(cmd, collector);
        Process p;
        try {
            p = pb.start();
        } catch (IOException e) {
            // Python: FileNotFoundError: [Errno 2] No such file or directory: 'lsof'
            throw new IOException(Py.oserror(e, cmd.get(0)), e);
        }
        Reader out = new Reader(p.getInputStream());
        Reader err = new Reader(p.getErrorStream());
        out.start();
        err.start();
        try {
            if (timeoutSeconds > 0) {
                if (!p.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                    p.destroyForcibly();
                    p.waitFor();
                    throw new Timeout(cmd, timeoutSeconds);
                }
            } else p.waitFor();
            out.join();
            err.join();
        } catch (InterruptedException e) {
            p.destroyForcibly();
            Thread.currentThread().interrupt();
            throw new IOException("interrupted", e);
        }
        if (out.failure != null || err.failure != null) throw new IOException("collector-stream");
        try {
            return new Result(p.exitValue(), collector ? strictText(out.bytes()) : text(out.bytes()),
                    collector ? strictText(err.bytes()) : text(err.bytes()));
        } catch (java.nio.charset.CharacterCodingException e) { throw new IOException("collector-decode", e); }
    }

    static Result run(List<String> cmd) throws IOException, Timeout {
        return run(cmd, 0);
    }

    /** Text mode decoding with universal newlines, as subprocess(text=True) gives. */
    static String text(byte[] b) {
        return newlines(new String(b, StandardCharsets.UTF_8));
    }

    static String strictText(byte[] b) throws java.nio.charset.CharacterCodingException {
        return newlines(StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(b)).toString());
    }

    private static String newlines(String s) {
        if (s.indexOf('\r') < 0) return s;
        return s.replace("\r\n", "\n").replace('\r', '\n');
    }

    static final class Reader extends Thread {
        private final InputStream in;
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        IOException failure;

        Reader(InputStream in) {
            this.in = in;
            setDaemon(true);
        }

        @Override
        public void run() {
            try (in) {
                in.transferTo(buf);
            } catch (IOException e) {
                failure = e;
            }
        }

        byte[] bytes() {
            return buf.toByteArray();
        }
    }
}
