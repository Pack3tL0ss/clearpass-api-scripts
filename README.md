# ClearPass API Scripts

- [ClearPass API Scripts](#clearpass-api-scripts)
  - [Setup](#setup)
  - [Current Tools](#current-tools)
  - [Certificate Sync](#certificate-sync)
  - [xml-import-builder](#xml-import-builder)

> Development is generally done in Ubuntu, scripts should work on other environments, but not necessarily tested.

------

A collection (of 2 currently) of Aruba ClearPass API Scripts

Visit [the official Aruba GitHub](https://github.com/aruba/) for additional tools from the Aruba Automation Team.

------

## Setup

Clone The Repo
`git clone https://github.com/Pack3tL0ss/cppm-api-scripts.git`

Setup the Virtual Environment

```bash
export DEB_PYTHON_INSTALL_LAYOUT='deb'  # on POSIX / *NIX based system

cd cppm-api-scripts
python3 -m virtualenv venv

# Activate the venv
. venv/bin/activate # Linux
venv\Scripts\activate # Windows

# install requirements
python3 -m pip install -U pip
python3 -m pip install -r requirements.txt
```

> If the `python3 -m virtualenv venv` results in a no module found error, you need to install virtualenv: `python3 -m pip install virtualenv`

Define configuration in config.yaml

```bash
cp config.yaml.example config.yaml
```

Then use nano or your editor of preference to populate values in config.yaml (i.e. `nano config.yaml`)

These scripts interact with the ClearPass API, so an API client needs to be configured for the scripts to use in the ClearPass Guest interface.

>The `in`, `out`, and `log` directories are ignored by git.  The scripts will look for any input files in the `in` directory, will send any generated reports/output to `out` and will log to the `log` directory.

------

## Current Tools

------

### Certificate Sync

This Script is used to Update ClearPass' https certificate with one from a provider such as LetsEncrypt

#### Setup:

Complete the [common setup](#setup), and ensure required entries are populated in `config.yaml`.  You can copy or use `config.yaml.example` as a reference.

#### Example Flow:

- You use an existing solution/tool (not this script) to do automatic renewal with LetsEncrypt (or similar) provider.
- You run this script either by triggering it from the tool used to do the auto-renewal or periodically via CRON or the like (or manually).
- cppm-certsync will compare the expiration of the certificate on each server in the CPPM cluster to the certificate specified in the config and available to the script in the Filesystem.
- If the new cert has an expiration beyond that of the cert currently in CPPM, the script will start a webserver, then send an API request to CPPM instructing it to download/import the new cert and use as it's https certificate.
- If an update occurred, or was attempted, but resulted in an error a notification can be sent (via PushBullet).  If no update was required, no notification is sent.

#### Prerequisites/Requirements:

- An API Client Configured in ClearPass Guest Interface, and appropriate configuration in this scripts config.yaml
- The root/signing cert needs to be imported/enabled in the Trusted Certs in ClearPass (as with any https cert you would import).
  - Clearpass Policy Manager -> Administration -> Certificates -> Trust List
- The Auto-Renewal with LetsEncrypt or the like is handled by a different tool, the certificate needs to be available to whatever host runs cppm-synccerts (i.e. a mounted NAS drive).
- ClearPass is instructed to import the certificate via the API, it does so by reaching out to a web-server and downloading the file.  This script starts a webserver which by default listens on port 8080 (cofnigurable), so that port would need to be available and allowed on the host this script runs on.

>!!! **All servers in the cluster will be sent the same certificate** It's common to use a single certificate for all servers in a CPPM cluster, with the fqdn of the Cluster VIP as the CN, and the FQDNs of each individual server/alias in the SAN.  The script will get a list of all of the Servers in the cluster, and verify/update the https certificate on each of them using the same certificate (specified in the config).

#### API Client Permissions:

Create an Operator Profile in the ClearPass Guest interface, name it something specific to acme and assign the following Operator Privilages:

- API Services -> Custom
  - Allow API Access -> Allow Access
- Platform -> Custom
  - Import Configuration -> Read Only
- Policy Manager -> Custom
  - Certificates -> Read, Write, Delete

Create an api client in the ClearPass Guest interface

- Client ID -> acme (or whatever you want to name it), take note of this for your config.yaml
- Enable API client
- Operating mode -> ClearPass REST API
- Operator Profile -> (the profile you created above)
- Grant Type -> Client Credentials, if you know what you are doing you can use a different grant type.
- Client Secret, take note of this for your config.yaml

#### Working Example (this is how it's done in my lab):

- pfSense handles certificate renewals for all hosts in my lab (via acme package available in package manager).
- That tool has an option to run a script/perform an action after any renewal
- The shell script below is what runs.

```bash
#!/bin/tcsh

# -- // Verify NAS (omv) is mounted \\ --
set mounted=`mount | grep -c FileDump`
if ($mounted == 0) then
    mount 10.0.30.30:/export/FileDump /media/FileDump/
endif
sleep 5

# -- // Certificate Conversions (Generate pfx) \\ --
openssl pkcs12 -export -out /conf/acme/securelogin.arubalab.net.pfx -inkey /conf/acme/securelogin.arubalab.net.key -in /conf/acme/securelogin.arubalab.net.crt -password pass:reD@cted\!\!
openssl pkcs12 -export -out /conf/acme/plex.arubalab.net.p12 -inkey /conf/acme/plex.arubalab.net.key -in /conf/acme/plex.arubalab.net.crt -password pass:reD@cted\!\!
openssl pkcs12 -export -out /conf/acme/cppm.arubalab.net.p12 -inkey /conf/acme/cppm.arubalab.net.key -in /conf/acme/cppm.arubalab.net.fullchain -password pass:reD@cted\!\!

# -- // Copy Certificates to NAS \\ --
(cp /conf/acme/* /media/FileDump/certificates/LetsEncrypt/ >> /root/mv_certs.log) >>& /root/mv_certs.log
umount /media/FileDump/

# -- // Send a Notification via PushBullet \\ --
curl -u "Redacted-pushbullet-api-key:" https://api.pushbullet.com/v2/pushes -d type=note -d title="LetsEncrypt" -d body="Certificate Renewed by pfsense acme package" >/dev/null

# -- // Kick off cppm-certsync running on NAS to Sync https certs with CPPM \\ --
ssh -t wade@omv "clearpass-api-scripts/venv/bin/python3 clearpass-api-scripts/cppm-certsync.py"
```

You can see from the comments in the script above how the flow works.

> One key note, to ssh from pfSense to my NAS.  Certificate Authentication is in use, so no password has to be sent, which allows the remote command to run from this script without prompt.
The PushBullet Notification is redundant in the case of ClearPass, but I have other certificates that also use this same script.  That piece is obviously optional.

You can also run this script manually: `./cppm-certsync.py`

------

### xml-import-builder

This script was built to aid in role/role-mapping/and enforcement-policy creation.

> Note: Currently this tool has some configuration in the script itself (GLOBAL Variables near the top of the script.)

**The Use Case:**

Customer had an export that included 2 pertinent columns of data: AD Group and Cisco ASA/EasyConnect VPN Tunnel they were authorized to access based on that AD Group.

The export was converted to csv and cleaned, up.  Header line was stripped out (the script doesn't try to detect the header).

**Roles and Role Mapping are created with the following rules:**

- User is member of X ad-group
- Radius:Cisco-ASA Tunnel Group Name = Tunnel Group Name associated with the AD Group (sent in the Radius Request)

Enforcement Policy is created with rules:

- if Tips Role = *assigned from role mapping* then Allow Access Profile (send Radius Accept.)

**USAGE:**
You can specify `in_file` in the CPPM section of the configuration, or as the first argument when running the script.  Command line argument will be honored and `in_file` in config will be ignored if both are populated.
API access is still required as some queries are done to gather data to populate the xml import.

> Note the script also has a function and logic to creat the roles and role-mapping via the Rest API, those are commented out, as xml was going to be required for the enforcement anyway.
