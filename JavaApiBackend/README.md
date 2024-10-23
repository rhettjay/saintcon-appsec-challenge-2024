# Java Backend API

## Function
This is a Java Spring application to handle the REST API for the IRC chat application. Restrictions described in the application should be enforced.
It should be noted that for the purposes of this challenge, the server is intended to run on `localhost` OR `irc.local`. You should treat these as possible hostnames for the server.

## Vulnerabilities
There are 6 vulnerabilities:
- JAVA_EASY_A (SQL injection)
- JAVA_EASY_B
- JAVA_MODERATE_A
- JAVA_MODERATE_B
- JAVA_MODERATE_C
- JAVA_HARD
- JAVA_INSANE

## In-scope files
- `src/main/java/community/saintcon/appsec/*.java` (including all subdirectories, like `utils/`).

## Exclusions
- Config files. Don't worry about prod vs local configurations, etc. Worry about the stuff in the Java files, as indicated by the scope above.