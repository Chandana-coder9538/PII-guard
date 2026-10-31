@echo off
rem Same as: mvnw spring-boot:run  (works from any folder, even paths with spaces)
cd /d "%~dp0"
call mvnw.cmd spring-boot:run "-Dspring-boot.run.jvmArguments=-Dnet.bytebuddy.experimental=true" %*
