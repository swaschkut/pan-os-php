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
| `./panosphp-viewer user add <name> [admin]` | new user, password shown once |
| `./panosphp-viewer user list` / `user delete <name>` | users |
| `./panosphp-viewer password <user>` | new password, shown once |
| `./panosphp-viewer projects <user>` / `project add <user> <name>` | projects of a user / new project |
| `./panosphp-viewer token <user> <project> [read\|write] [days]` | API token for scripts, shown once |
| `./panosphp-viewer token list <user> <project>` | tokens of a project |
| `./panosphp-viewer license [<file>]` | show / install the licence |
| `./panosphp-viewer plugin [<file.ppp>]` | list / add licensed plug-ins |

Settings are in `.env` next to the script, plug-ins in `plugins/`. All data (users, projects, versions, licence) is in
the Docker volume `panosphp-viewer-data` - `stop` and `update` keep it.
