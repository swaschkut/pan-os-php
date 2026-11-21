# First steps

The config viewer shows and changes PAN-OS / Panorama configurations in the browser, runs playbooks and statistics,
and - with a licence - migrates configurations of other vendors.

## A new installation

1. On the computer the viewer runs on: `./panosphp-viewer start`. The first time it shows a **one-time code**.
2. Open the address it shows. The login page offers **New installation: create the administrator**.
3. Enter the code, a user name and a password (10+ characters). You are logged in as administrator.

The code works once. Lost it: `./panosphp-viewer status` shows it again as long as there is no administrator. Without a browser:
`./panosphp-viewer user add <name> admin` creates the administrator and shows its password.

## After that

- **Account**: change your password; as administrator: users, licence, plug-ins, audit log.
- **Projects**: create a project, upload a configuration (XML), open it. More: [Users and projects](2-users-and-projects.md).
- **Runs**: statistics, playbooks, migration - see [Runs and scripts](3-runs-and-scripts.md).

## Forgot the password

An administrator gives a new one under **Account → Users** (**New password**, shown once). There is no way around
it on the command line, also not for the administrator.

**Have two administrators.** When the only administrator forgets the password, nobody can get in any more - the only
way out is a new start without the data (`./panosphp-viewer stop`, `docker volume rm panosphp-viewer-data`,
`./panosphp-viewer start`).
