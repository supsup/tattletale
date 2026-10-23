package dev.tattletale;

import java.io.IOException;
import java.net.InetAddress;
import java.util.*;

/** Current watcher-epoch health, deliberately not persisted in SQLite schema 1. */
final class CollectionHealth {
    static final List<String> KEYS = List.of("processes", "listeners", "startup", "crontab");
    private final Map<String, Map<String, Object>> entries = new LinkedHashMap<>();
    CollectionHealth() {
        for (String key : KEYS) {
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("lastAttempt", null); e.put("lastSuccess", null); e.put("status", "unknown"); e.put("error", null);
            entries.put(key, e);
        }
    }
    synchronized void attempt(String key, String time) { entries.get(key).put("lastAttempt", time); }
    synchronized void success(String key, String time) {
        Map<String,Object> e=entries.get(key); e.put("lastSuccess",time); e.put("status","ok"); e.put("error",null);
    }
    synchronized void fail(String key, String code) {
        Map<String,Object> e=entries.get(key); e.put("status","degraded"); e.put("error",code);
    }
    synchronized Map<String,Object> snapshot() {
        Map<String,Object> out=new LinkedHashMap<>();
        entries.forEach((k,v)->out.put(k,new LinkedHashMap<>(v))); return out;
    }
    static final class Rejected extends IOException {
        private static final long serialVersionUID=1L;
        final String code;
        Rejected(String code) { super(code); this.code=code; }
    }
    static String command(String tool, Proc.Result r) throws Rejected {
        if (tool.equals("lsof") && ((r.code()==0 && r.err().isEmpty()) ||
                (r.code()==1 && r.out().isEmpty() && r.err().isEmpty()))) return r.out().isEmpty()?"ok-empty":"ok";
        if (tool.equals("crontab")) {
            if (r.code()==0 && r.err().isEmpty()) return r.out().isEmpty()?"ok-empty":"ok";
            if (r.code()==1 && r.out().isEmpty() && r.err().matches("(?:crontab: )?no crontab for [^\\s\\r\\n]+\\n?")) return "ok-absent";
        }
        if (tool.equals("ps") && r.code()==0 && r.err().isEmpty()) return r.out().isBlank()?"ok-empty":"ok";
        throw new Rejected(tool+"-command");
    }
    static String ioError(IOException e) {
        return e instanceof java.nio.charset.CharacterCodingException || e.getCause() instanceof java.nio.charset.CharacterCodingException
                ? "collection-parse" : "collection-io";
    }
    /** Literal parsing only: ofLiteral never performs name resolution or interface lookup. */
    static String bindScope(String host) {
        if (host==null || host.isEmpty()) return "unknown";
        if (host.equals("*")) return "wildcard";
        if (host.startsWith("[") || host.endsWith("]")) {
            if (!host.startsWith("[") || !host.endsWith("]")) return "unknown";
            host=host.substring(1,host.length()-1);
            if(!host.contains(":")) return "unknown";
        }
        if(host.indexOf('[')>=0 || host.indexOf(']')>=0) return "unknown";
        int z=host.indexOf('%');
        if (z>=0) {
            if (!host.contains(":") || !host.substring(z+1).matches("[A-Za-z0-9_.-]+")) return "unknown";
            host=host.substring(0,z);
        }
        if (!host.contains(":") || host.contains(".")) {
            String ipv4=host.substring(host.lastIndexOf(':')+1);
            String[] parts=ipv4.split("\\.",-1); if(parts.length!=4) return "unknown";
            for(String p:parts) if(!p.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(p)>255) return "unknown";
        }
        try {
            InetAddress address=InetAddress.ofLiteral(host);
            if(address.isAnyLocalAddress()) return "wildcard";
            return address.isLoopbackAddress()?"loopback":"non-loopback";
        } catch(IllegalArgumentException e) { return "unknown"; }
    }
}
