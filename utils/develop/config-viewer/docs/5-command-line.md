# Command line

On the computer the viewer runs on, in the folder of `panosphp-viewer`:

| Command | What it does |
|---|---|
| `./panosphp-viewer start` | start; the first time: questions (port, HTTPS) and the one-time code |
| `./panosphp-viewer stop` / `restart` | stop (data stays) / restart |
| `./panosphp-viewer status` | containers, address, licence, plug-ins |
| `./panosphp-viewer logs [web\|service\|jobs\|proxy]` | the last lines of the log |
| `./panosphp-viewer setup` | the questions again, then `restart` |
| `./panosphp-viewer update` | newer version (from the internet, or `images.tar.gz` of an air-gap bundle) |
| `./panosphp-viewer user add <name> admin` | the first administrator without a browser - only while there is none |
| `./panosphp-viewer user list` | users |
| `./panosphp-viewer projects <user>` | projects of a user |
| `./panosphp-viewer token list <user> <project>` | API tokens of a project (never the secret) |
| `./panosphp-viewer license [<file>]` | show / install the licence |
| `./panosphp-viewer plugin [<file.ppp>]` | list / add licensed plug-ins |

**Users, passwords, projects and API tokens are changed only in the browser** - by an administrator (Account → Users)
or, for tokens, by the user in the project. Whoever can run commands on this computer can not reset a password or make
himself an administrator. A try is refused, written into the audit log and shown to the administrators after their
next login.

Settings are in `.env` next to the script, plug-ins in `plugins/`. All data (users, projects, versions, licence) is in
the Docker volume `panosphp-viewer-data` - `stop` and `update` keep it.
