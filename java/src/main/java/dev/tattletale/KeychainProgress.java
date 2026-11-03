package dev.tattletale;

import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** One stream worker's interval progress; malformed evidence cannot become ok-zero. */
final class KeychainProgress {
    long count;
    String error;
    Map<?,?> line(byte[] raw) {
        try {
            String text=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString();
            Object parsed=Json.parseStrict(text);
            if(!(parsed instanceof Map<?,?> ev) || !(ev.get("processID") instanceof Long pid) || pid<=0 || pid>2147483647
                    || !(ev.get("processImagePath") instanceof String path) || !path.startsWith("/") || !Watch.STREAM_PROCS.contains(Py.basename(path))
                    || (ev.containsKey("eventMessage") && !(ev.get("eventMessage") instanceof String)))throw new IllegalArgumentException("stream-record");
            count++;return ev;
        }catch(java.nio.charset.CharacterCodingException | Json.ParseError | IllegalArgumentException | StackOverflowError e){error="keychain-malformed";return null;}
    }
    record Cycle(Long count,String error) {}
    Cycle cycle(boolean alive,boolean partial) {
        String why=!alive?"keychain-ended":partial?"keychain-partial":error;
        Cycle result=new Cycle(why==null?count:null,why);count=0;error=null;return result;
    }
}
