# Operation without internet (M7, P4)

## A local mirror

    efactl update-mirror-set --url https://mirror.example.lan/el9

With a mirror set, eFa-next takes its updates only from there.

- **What the mirror is:** a copy of `https://repo.efa-next.eu/el9`, with the same files: `latest.json`, a folder per release
  with its packages, and the signed `SHA256SUMS`.
- **What is checked:** eFa-next checks the signature of the eFa-next repository key exactly as with the repository itself. A
  mirror cannot slip in other packages.
- **Going back:** an empty `--url` goes back to the repository and the GitHub mirror.

## Signed bundles

For a network without any connection.

1. On an eFa-next host with internet, `efactl offline-bundle-make` packs one file into `/var/lib/eFa/offline`:
   - the packages of the newest release (checked against its signed `SHA256SUMS`);
   - the ClamAV signatures of the host;
   - the maps of the threat feeds.

   It signs the list of all files and their checksums with its own Ed25519 key, and shows the public key.
2. On the isolated host, trust that key once: `efactl offline-trust-set --key <public key>`.
3. Copy the file to the isolated host (to `/var/tmp`, `/media` or `/mnt`). Apply it with
   `efactl offline-bundle-apply --file ... --confirm yes`.

The bundle is applied only when the signature of its list fits the trusted key and every file fits its checksum; otherwise
nothing is applied. Then:
- each ClamAV file must be taken by `sigtool`;
- each package must carry a valid signature of the eFa-next key (`rpm -K`), because dnf does not check local packages by
  default;
- the packages are installed with dnf, without repositories.

Each bundle that is made, applied or refused goes into the audit log.

## Old signatures

When the virus signatures are older than 3 days, the dashboard says so: check freshclam, or apply a bundle.
`efactl offline-status` shows their age, the mirror and the trusted key.
