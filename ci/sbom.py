#!/usr/bin/env python3
#
# Writes the CycloneDX SBOM of a haproxy-cloudauth build: the sources built
# from their repositories (HAProxy, the filters, AWS-LC, the OpenTelemetry C
# wrapper), the libraries built by the OpenTelemetry bundle, which no scanner
# identifies since they are not installed by a package manager, and the
# libraries of the distribution the shipped binaries are linked with.
#
#   sbom.py <prefix> <haproxy binary> <libdir> <version> <output>
#
# <prefix> holds share/haproxy-cloudauth/sources and third_party_release (see
# build-deps.sh), <libdir> the shipped libraries. A shipped library which is not
# known here is an error, so that a new dependency is never left out. Runs with
# Python 3.6 (RHEL 8). The timestamp is SOURCE_DATE_EPOCH when it is set, and
# the serial number is derived from the contents, so that the SBOM, and thus the
# package, only changes with its contents.

import datetime
import glob
import json
import os
import re
import subprocess
import sys
import uuid

LICENSES = {
    "haproxy": "GPL-2.0-or-later AND LGPL-2.1-or-later",
    "haproxy-cloudauth": "GPL-2.0-or-later AND LGPL-2.1-or-later",
    "haproxy-opentelemetry": "GPL-2.0-only",
    "aws-lc": "(Apache-2.0 OR ISC) AND ISC AND OpenSSL",
    "opentelemetry-c-wrapper": "Apache-2.0",
    "opentelemetry-cpp": "Apache-2.0",
    "opentelemetry-proto": "Apache-2.0",
    "curl": "curl",
    "abseil": "Apache-2.0",
    "grpc": "Apache-2.0",
    "protobuf": "BSD-3-Clause",
    "c-ares": "MIT",
    "re2": "BSD-3-Clause",
    "rapidyaml": "MIT",
    "c4core": "MIT",
    "nlohmann-json": "MIT",
}

REPOS = {
    "opentelemetry-cpp": "https://github.com/open-telemetry/opentelemetry-cpp",
    "opentelemetry-proto": "https://github.com/open-telemetry/opentelemetry-proto",
    "curl": "https://github.com/curl/curl",
    "abseil": "https://github.com/abseil/abseil-cpp",
    "grpc": "https://github.com/grpc/grpc",
    "protobuf": "https://github.com/protocolbuffers/protobuf",
    "c-ares": "https://github.com/c-ares/c-ares",
    "re2": "https://github.com/google/re2",
    "rapidyaml": "https://github.com/biojppm/rapidyaml",
    "c4core": "https://github.com/biojppm/c4core",
    "nlohmann-json": "https://github.com/nlohmann/json",
}

# CPE vendor:product, for the matching of the vulnerability databases
CPES = {
    "haproxy": "haproxy:haproxy",
    "curl": "haxx:curl",
    "c-ares": "c-ares:c-ares",
    "grpc": "grpc:grpc",
    "protobuf": "google:protobuf",
    "re2": "google:re2",
    "nlohmann-json": "nlohmann:json",
}

# The shipped libraries, by the beginning of their names
LIBRARIES = [
    ("libcrypto.", "aws-lc"), ("libssl.", "aws-lc"),
    ("libcurl.", "curl"),
    ("libopentelemetry-c-wrapper.", "opentelemetry-c-wrapper"),
    ("libopentelemetry_", "opentelemetry-cpp"),
    ("libabsl_", "abseil"),
    ("libgrpc", "grpc"), ("libgpr.", "grpc"), ("libupb", "grpc"),
    ("libaddress_sorting.", "grpc"),
    ("libprotobuf", "protobuf"), ("libprotoc.", "protobuf"),
    ("libutf8_", "protobuf"),
    ("libcares.", "c-ares"),
    ("libre2.", "re2"),
    ("libryml.", "rapidyaml"),
    ("libc4core.", "c4core"),
]

# The libraries compiled into the shipped ones (headers only)
COMPILED_IN = ["nlohmann-json", "opentelemetry-proto"]


def run(*args):
    return subprocess.check_output(args, universal_newlines=True)


def run_ok(*args):
    try:
        return subprocess.check_output(args, universal_newlines=True,
                                       stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, OSError):
        return None


def os_release():
    info = {}
    with open("/etc/os-release") as f:
        for line in f:
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                info[k] = v.strip('"')
    return info


def cmake_version(prefix, name):
    """Version of the cmake package <name> installed in <prefix>"""
    for path in glob.glob(os.path.join(prefix, "lib*", "cmake", name, "*[Vv]ersion.cmake")):
        with open(path) as f:
            m = re.search(r'set\(PACKAGE_VERSION "([^"]+)"\)', f.read())
        if m:
            return m.group(1)
    return None


def component(name, version, ref=None, commit=None, repo=None):
    comp = {
        "bom-ref": "%s@%s" % (name, version),
        "type": "library",
        "name": name,
        "version": version,
        "licenses": [{"expression": LICENSES[name]}],
    }
    repo = repo or REPOS.get(name)
    if repo:
        repo = re.sub(r"\.git$", "", repo)
        comp["externalReferences"] = [{"type": "vcs", "url": repo}]
        m = re.match(r"https://github\.com/([^/]+)/([^/]+)$", repo)
        if m:
            comp["purl"] = "pkg:github/%s/%s@%s" % (m.group(1), m.group(2), ref or version)
    if name in CPES:
        comp["cpe"] = "cpe:2.3:a:%s:%s:*:*:*:*:*:*:*" % (CPES[name], version)
    if commit:
        comp["properties"] = [{"name": "haproxy-cloudauth:commit", "value": commit}]
    return comp


def system_package(path, osr):
    """Package of the distribution owning the file <path>, as a component"""
    candidates = [path, os.path.realpath(path)]
    for p in list(candidates):
        if p.startswith("/usr/lib"):
            candidates.append(p[len("/usr"):])
        elif p.startswith("/lib"):
            candidates.append("/usr" + p)
    for p in candidates:
        out = run_ok("rpm", "-qf", "--qf", "%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n", p)
        if out:
            name, version, arch = out.splitlines()[0].split()
            purl = "pkg:rpm/%s/%s@%s?arch=%s&distro=%s-%s" % (
                osr["ID"], name, version, arch, osr["ID"], osr["VERSION_ID"])
            break
        out = run_ok("dpkg", "-S", p)
        if out:
            pkg = out.splitlines()[0].split(":", 1)[0]
            name = pkg
            version = run("dpkg-query", "-W", "-f", "${Version}", pkg)
            arch = run("dpkg-query", "-W", "-f", "${Architecture}", pkg)
            purl = "pkg:deb/%s/%s@%s?arch=%s&distro=%s-%s" % (
                osr["ID"], name, version, arch, osr["ID"], osr["VERSION_ID"])
            break
    else:
        sys.exit("no package owns %s" % path)
    return {
        "bom-ref": purl,
        "type": "library",
        "name": name,
        "version": version,
        "purl": purl,
    }


def main():
    prefix, binary, libdir, version, output = sys.argv[1:6]
    osr = os_release()
    share = os.path.join(prefix, "share", "haproxy-cloudauth")
    commit = os.environ.get("CLOUDAUTH_COMMIT", "")

    components = {}

    # the sources built from their repositories: name repo ref commit
    with open(os.path.join(share, "sources")) as f:
        for line in f:
            name, repo, ref, sha = line.split()
            comp = component(name, ref.lstrip("v"), ref, sha, repo)
            if name == "haproxy":
                # the version of a development tree is the one HAProxy reports
                comp["version"] = run(binary, "-v").split()[2]
                comp["bom-ref"] = "haproxy@" + comp["version"]
                comp["purl"] = re.sub(r"@.*", "@" + sha, comp["purl"])
                comp["cpe"] = "cpe:2.3:a:haproxy:haproxy:%s:*:*:*:*:*:*:*" % comp["version"].split("-")[0]
            components[name] = comp

    # the filter itself, whose sources are not cloned
    components["haproxy-cloudauth"] = component(
        "haproxy-cloudauth", version, commit or version, commit or None,
        "https://github.com/git001/haproxy-cloudauth")

    # the libraries built by the SDK, pinned in third_party_release
    pinned = {}
    with open(os.path.join(share, "third_party_release")) as f:
        for line in f:
            m = re.match(r"^([\w-]+)=(\S+)", line)
            if m:
                pinned[m.group(1)] = m.group(2)

    def bundled(name):
        if name in components:
            return
        if name == "opentelemetry-cpp":
            ver = cmake_version(prefix, "opentelemetry-cpp")
            ref = "v" + ver
        elif name == "curl":
            ref = pinned["curl"]
            ver = ref[len("curl-"):].replace("_", ".")
        elif name in ("abseil", "grpc", "protobuf", "nlohmann-json", "opentelemetry-proto"):
            ref = pinned[name]
            ver = ref.lstrip("v")
        elif name == "rapidyaml":
            ref = pinned["ryml"]
            ver = ref.lstrip("v")
        else:
            # the dependencies of gRPC and rapidyaml, built from their trees
            ver = cmake_version(prefix, {"c-ares": "c-ares", "re2": "re2", "c4core": "c4core"}[name])
            ref = ver
        if not ver:
            sys.exit("no version found for %s" % name)
        components[name] = component(name, ver, ref)

    shipped = sorted(os.path.basename(p) for p in glob.glob(os.path.join(libdir, "*.so*")))
    for lib in shipped:
        for start, name in LIBRARIES:
            if lib.startswith(start):
                bundled(name)
                break
        else:
            sys.exit("unknown shipped library %s, see ci/sbom.py" % lib)
    for name in COMPILED_IN:
        bundled(name)

    # the libraries of the distribution the shipped binaries are linked with
    elves = [binary] + [os.path.join(libdir, l) for l in shipped
                        if not os.path.islink(os.path.join(libdir, l))]
    needed = set()
    for elf in elves:
        for line in run("readelf", "-d", elf).splitlines():
            m = re.search(r"\(NEEDED\).*\[(.+)\]", line)
            if m and m.group(1) not in shipped:
                needed.add(m.group(1))
    cache = {}
    for line in run("ldconfig", "-p").splitlines():
        m = re.match(r"\s+(\S+) \(libc6,x86-64[^)]*\) => (\S+)", line)
        if m and m.group(1) not in cache:
            cache[m.group(1)] = m.group(2)
    system = {}
    for soname in sorted(needed):
        if soname not in cache:
            sys.exit("library %s not found" % soname)
        comp = system_package(cache[soname], osr)
        system[comp["bom-ref"]] = comp

    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    when = datetime.datetime.utcfromtimestamp(int(epoch)) if epoch else datetime.datetime.utcnow()
    main_ref = "haproxy-cloudauth-package@" + version
    all_components = sorted(components.values(), key=lambda c: c["name"]) + \
        sorted(system.values(), key=lambda c: c["name"])
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(
            uuid.NAMESPACE_URL, json.dumps([version, all_components], sort_keys=True))),
        "version": 1,
        "metadata": {
            "timestamp": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "ci/sbom.py",
                                      "group": "haproxy-cloudauth"}]},
            "component": {
                "bom-ref": main_ref,
                "type": "application",
                "name": "haproxy-cloudauth",
                "version": version,
                "description": "HAProxy with the cloudauth and the OpenTelemetry filters, for %s %s"
                               % (osr["ID"], osr["VERSION_ID"]),
                "licenses": [{"expression": LICENSES["haproxy-cloudauth"]}],
                "externalReferences": [{"type": "vcs",
                                        "url": "https://github.com/git001/haproxy-cloudauth"}],
            },
            "supplier": {"name": "Aleksandar Lazic",
                         "url": ["https://github.com/git001/haproxy-cloudauth"]},
        },
        "components": all_components,
        "dependencies": [{"ref": main_ref,
                          "dependsOn": [c["bom-ref"] for c in all_components]}],
    }
    with open(output, "w") as f:
        json.dump(bom, f, indent=2, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
