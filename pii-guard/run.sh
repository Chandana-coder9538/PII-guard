#!/bin/sh
# Same as: ./mvnw spring-boot:run  (works from any folder, extra args are passed through)
cd "$(dirname "$0")"
exec ./mvnw spring-boot:run "-Dspring-boot.run.jvmArguments=-Dnet.bytebuddy.experimental=true" "$@"
