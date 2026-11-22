# Licences and plug-ins

Everything described in the other pages works without a licence. **Licensed plug-ins** (e.g. migration of other
vendors) come as a package file `<name>.ppp` and need a licence.

1. Put the package into the folder `plugins/` next to `panosphp-viewer`: `./panosphp-viewer plugin migration.ppp`
2. Install the licence: **Account → Licence** (paste the text or choose the file), or `./panosphp-viewer license <file>`
3. **Account → Plug-ins** shows the plug-in as **on** - its runs appear in the projects.

A licence names the customer, the end date and the licensed features. 30 days before the end it shows a warning; after
the end there are 14 days of grace, then the licensed plug-ins are locked. Basic features and all data stay.

| Shown | Meaning |
|---|---|
| not licensed: no licence installed | install the licence |
| … does not hold the feature … | the licence is for other plug-ins, or it ended |
| … key of this release … | a newer plug-in version: a renewed licence is needed |
| signed with an unknown key | the pan-os-php version of this installation is too old for the licence: `./panosphp-viewer update` |
