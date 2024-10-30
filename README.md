> [!IMPORTANT]
> This is a [detached fork](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/detaching-a-fork) of the [saintcon-appsec-challenge-2024](https://github.com/smanesse/saintcon-appsec-challenge-2024). It is detached in order to prevent disturbing the upstream repo with our pushes / PRs as it is unlikely any of the revisions we introduce will be of benefit to them. All credit to this repo goes to creators of the original repository.
# SAINTCON 2024 AppSec Challenge

**Please read this README thoroughly. It will answer many of your questions.**

## Basic info
This web application consists of several smaller components, each written in a different langauge. Hopefully you will encounter a language you are familiar with.

More information about each service can be found in their respective README files. These will contain really, really helpful information, like the number of vulns in the service and what is in or out of scope.

It should be noted that for the purposes of this challenge, the server is intended to run on `localhost` OR `irc.local`. You should treat these as possible hostnames for the server.

## Prerequisites
- Python
- Docker
- a few gigs of disk space for docker images
- A Linux OS, or a willingness to deal with any possible issues that may arise on Windows/Mac when running tests locally


## Running
Services run in docker on localhost. Don't expose ports or run code natively, you don't want to run vulnerable code on your host machine.

You can visit the vulnerable website at `http://localhost:42101`.

To run all services:

```
docker compose up --build -d
```

To run a specific service:
```
docker-compose up --build -d <service name from docker-compose.yml>
```

To stop services:

```
docker compose down
```

To rebuild a specific service (for faster iteration):
```
docker compose up --build <service name from docker-compose.yml>
```
For example, `docker compose up --build java-api` would restart/rebuild my Java service without restarting all other services.

To complete nuke all running services:
```
docker compose down -t 1 -v --remove-orphans --rmi local
```

It is a good idea to read through `docker-compose.yml` to understand which services run on which ports, in case you'd like to test them directly instead of through the nginx proxy.

It's also a good idea to periodically run `docker system prune --volumes` to remove dangling containers/images and save on disk space.



## Testing

Services must be stopped before running unit tests.

Linux (recommended) or Mac:

`./runtests.sh`

Windows:

`.\runtests.bat` or `.\runtests.ps1`

Note that the local tests my be flaky on Windows, and we didn't test at all on Mac. Everything should still *work* fine with writing code and running the web application though.

Note that the final commit on the repo changes tests to use environment-variable-defined IP addresses instead of hostnames to resolve an issue with Docker's DNS stack on Windows and Mac. This makes the unit tests slightly different than what is on the test harness, but signficantly speeds up local testing on those operating systems.

## Submitting
Run `python3 make_package.py` and submit the resulting `appsec-submission.zip` to https://appsec.saintcon.community. You'll need to create an account first.

Submissions that do not pass unit tests will not be scored for vulnerabilities.

Files you change outside of those listed in scope (as referenced in README files and fully enumerated in `allowed_files.txt`) will not be included in your submission. Limit your changes to those files.
