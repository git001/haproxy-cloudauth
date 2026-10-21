# Security policy

## Supported versions

Only the latest release receives security fixes. The packages and the image
of a release ship their own AWS-LC, curl and OpenTelemetry libraries, which are
updated with the releases.

## Reporting a vulnerability

Please do not report vulnerabilities in public issues. Report them privately,
either with the [private vulnerability reporting][report] of GitHub, or by mail
to Aleksandar Lazic <al-haproxy@none.at>.

[report]: https://github.com/git001/haproxy-cloudauth/security/advisories/new

Please include the affected version, the configuration needed to reproduce the
issue, and its impact. You will get an answer within days. The fix is
published in a release with a GitHub security advisory, which credits the
reporter unless asked otherwise.

Vulnerabilities of HAProxy itself are reported to the HAProxy project, see
<https://www.haproxy.org/#secu>, and the ones of the shipped libraries to their
projects. The release with the fixed versions follows their publication.

## Vulnerability monitoring

The packages and the image are rebuilt and scanned every week, against the
current packages of the distributions, with their SBOMs. The results are in
the code scanning alerts of the repository.

## Verifying the releases

Each release provides, for every package and for the image:

- a CycloneDX and an SPDX SBOM, which lists the shipped libraries too;
- a SLSA build provenance attestation and an SBOM attestation, signed with
  Sigstore by the GitHub workflow which built them;
- the SHA256SUMS file of all the files, signed with Sigstore
  (`SHA256SUMS.sigstore.json`), and with GPG when the RPM packages are signed.

The image is signed with cosign, keyless. See the release notes for the
commands verifying them.
