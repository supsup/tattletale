package dev.tattletale;
import java.nio.file.*;
import java.io.IOException;
import java.util.List;
/** Runs only two synthetic shell commands through an untouched default Watch.sources. */
public final class DefaultSourcesProbe {
 public static void main(String[] args)throws Exception {
  Path d=Path.of(args[0]);Files.createDirectory(d);
  Watch w=new Watch(d.resolve("log").toString(),d.resolve("db").toString(),30,300,List.of(),false,100000,1,3,d.resolve("absent-map").toString(),0,0,d.resolve("absent-page").toString());
  try {
   Watch.Sources actualDefault=w.sources;
   if(!actualDefault.run(List.of("/bin/sh","-c","printf '%s' \"$LC_ALL\""),2).out().equals("C"))throw new AssertionError("default source inherited conflicting locale");
   boolean strict=false;try{actualDefault.run(List.of("/bin/sh","-c","printf '\\377'"),2);}catch(IOException e){strict=CollectionHealth.ioError(e).equals("collection-parse");}
   if(!strict)throw new AssertionError("default source accepted malformed UTF8");
   System.out.println("DEFAULT_SOURCE_STRICT_AND_C");
  } finally {w.db.close();}
 }
}
