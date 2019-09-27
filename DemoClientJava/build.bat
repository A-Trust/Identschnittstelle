cls

rem set JAVAPATH=c:\Program Files\Java\jdk-11.0.2\bin
set JAVAPATH=c:\Program Files\Java\openjdk-12.0.1\bin
set CLASSPATH="./;./lib/*;"


"%JAVAPATH%\javac.exe" -classpath %CLASSPATH% IdentRecord.java
"%JAVAPATH%\java.exe" -classpath %CLASSPATH% IdentRecord
