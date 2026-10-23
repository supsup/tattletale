package dev.tattletale;
import java.util.*;
/** Page/database publication, separate from the four collectors and reset on each watcher epoch. */
final class PublicationHealth {
    private Map<String,Object> value=new LinkedHashMap<>();
    PublicationHealth(){value.put("lastAttempt",null);value.put("lastSuccess",null);value.put("status","unknown");value.put("error",null);}
    synchronized void attempt(String time){value.put("lastAttempt",time);}
    synchronized void fail(String code){value.put("status","degraded");value.put("error",code);}
    synchronized Map<String,Object> snapshot(){return new LinkedHashMap<>(value);}
    synchronized Map<String,Object> success(String time){Map<String,Object> m=snapshot();m.put("lastSuccess",time);m.put("status","ok");m.put("error",null);return m;}
    synchronized void adopt(Map<String,Object> accepted){value=new LinkedHashMap<>(accepted);}
}
