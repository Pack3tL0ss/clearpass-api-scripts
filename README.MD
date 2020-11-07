# ClearPass API Scripts

- [ClearPass API Scripts](#clearpass-api-scripts)
  - [Setup](#setup)
  - [Current Tools](#current-tools)
  - [Certificate Sync](#certificate-sync)

> Development is generally done in Ubuntu, scripts should work on other environments, but not necessarily tested.

------

A collection (of 1 currently) of Aruba ClearPass API Scripts

Visit [the official Aruba GitHub](https://github.com/aruba/) for additional tools from the Aruba Automation Team.

------

## Setup

Clone The Repo
`git clone https://github.com/Pack3tL0ss/cppm-api-scripts.git`

Setup the Virtual Environment

```bash
cd cppm-api-scripts
python3 -m virtualenv venv
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

> If the `python3 -m virtualenv venv` results in a no module found error, you need to install virtualenv: `python3 -m pip install virtualenv`

Define configuration in config.yaml

```bash
cp config.yaml.example config.yaml
```

Then use nano or your editor of preference to populate values in config.yaml (i.e. `nano config.yaml`)

These scripts interact with the ClearPass API, so an API client needs to be configured for the scripts to use in the ClearPass Guest interface.

------

## Current Tools

------

## Certificate Sync

This Script is used to Update ClearPass' https certificate with one from a provider such as LetsEncrypt

Setup:

Complete the [common setup](#setup), and ensure required entries are populated in `config.yaml`.  You can copy or use `config.yaml.example` as a reference.

Example Flow:

- You use an existing solution/tool (not this script) to do automatic renewal with LetsEncrypt (or similar) provider.
- You run this script either by triggering it from the tool used to do the auto-renewal or periodically via CRON or the like (or manually).
- cppm-certsync will compare the expiration of the certificate on each server in the CPPM cluster to the certificate specified in the config and available to the script in the Filesystem.
- If the new cert has an expiration beyond that of the cert currently in CPPM, the script will start a webserver, then send an API request to CPPM instructing it to download/import the new cert and use as it's https certificate.
- If an update occurred, or was attempted, but resulted in an error a notification can be sent (via PushBullet).  If no update was required, no notification is sent.

Prerequisites/Requirements:

- The root/signing cert needs to be imported/enabled in the Trusted Certs in ClearPass (as with any https cert you would import).
- The Auto-Renewal with LetsEncrypt or the like is handled by a different tool, the certificate needs to be available to whatever host runs cppm-synccerts (i.e. a mounted NAS drive).

>!!! **All servers in the cluster will be sent the same certificate** It's common to use a single certificate for all servers in a CPPM cluster, with the fqdn of the Cluster VIP as the CN, and the FQDNs of each individual server/alias in the SAN.  The script will get a list of all of the Servers in the cluster, and verify/update the https certificate on each of them using the same certificate (specified in the config).

Working Example (this is how it's done in my lab):

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
cp /conf/acme/* /media/FileDump/certificates/LetsEncrypt/
umount /media/FileDump/

# -- // Send a Notification via PushBullet \\ --
curl -u "Redacted-pushbullet-api-key:" https://api.pushbullet.com/v2/pushes -d type=note -d title="LetsEncrypt" -d body="Certificate Renewed by pfsense acme package" >/dev/null

# -- // Kick off cppm-certsync running on NAS to Sync https certs with CPPM \\ --
ssh -t wade@omv "clearpass-api-scripts/venv/bin/python3 clearpass-api-scripts/cppm-certsync.py"
```

You can see from the comments in the script above how the flow works.
> One key note, to ssh from pfSense to my NAS.  Certificate Authentication is in use, so no password has to be sent, which allows the remote command to run from this script without prompt.
The PushBullet Notification is redundant in the case of ClearPass, but I have other certificates that also use this same script.  That piece is obviously optional.
