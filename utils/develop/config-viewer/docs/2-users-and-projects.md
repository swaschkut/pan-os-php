# Users and projects

## Users

Administrators manage users under **Account → Users (admin)**: name, password, and whether the user is an
administrator, and **New password** for a user who forgot it (shown once). Not on the command line: there, only
`./panosphp-viewer user list`, and `user add <name> admin` for the very first administrator.

An administrator manages users, the licence and plug-ins. What a user sees in a project is set in the project.

## Projects

A project holds configuration versions, project files (playbooks, BP JSON, configurations of other vendors), runs and
its members. Who creates a project is its **owner**.

| Permission | May |
|---|---|
| read | open versions, look at objects, download |
| write | also change, save, upload, start runs |
| owner | also members, API tokens of everybody, audit log of the project |

Under **Members** the owner can limit a member to some object types (e.g. address, service) and to some locations
(device groups, templates, vsys). Such a member can not download or upload whole versions and can not start runs.

## Versions

Every upload, every save and every run result that is taken over makes a new **version** - nothing is overwritten.
Changes in the viewer are kept automatically (autosave) until they are saved or discarded.
