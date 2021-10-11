#!/usr/bin/python
# encoding: utf-8
#
# Copyright 2020 Armin Briegel.
#
# based on Greg Neagle's 'installinstallmacos.py'
# https://github.com/munki/macadmin-scripts/blob/main/installinstallmacos.py
#
# with many thanks to Greg Neagle for the original script and lots of advice
# and Mike Lynn for helping me figure out the software update catalog
# Graham R Pugh for figurung out the 11.1 download
# see his combined version of mine and Greg's script here:
# https://github.com/grahampugh/erase-install/tree/pkg

#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""fetch-full-installer.py
A tool to download the a pkg installer for the Install macOS app from Apple's
softwareupdate servers"""

# Python 3 compatibility shims
from __future__ import absolute_import, division, print_function, unicode_literals

import argparse
import gzip
import os
import plistlib
import subprocess
import sys
import logging
import json
from datetime import datetime

try:
    # python 2
    from urllib.parse import urlsplit
except ImportError:
    # python 3
    from urlparse import urlsplit
from xml.dom import minidom
from xml.parsers.expat import ExpatError
import xattr


DEFAULT_SUCATALOGS = {
    "17": "https://swscan.apple.com/content/catalogs/others/"
    "index-10.13-10.12-10.11-10.10-10.9"
    "-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog",
    "18": "https://swscan.apple.com/content/catalogs/others/"
    "index-10.14-10.13-10.12-10.11-10.10-10.9"
    "-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog",
    "19": "https://swscan.apple.com/content/catalogs/others/"
    "index-10.15-10.14-10.13-10.12-10.11-10.10-10.9"
    "-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog",
    "20": "https://swscan.apple.com/content/catalogs/others/"
    "index-11-10.15-10.14-10.13-10.12-10.11-10.10-10.9"
    "-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog",
}

SEED_CATALOGS_PLIST = (
    "/System/Library/PrivateFrameworks/Seeding.framework/Versions/Current/"
    "Resources/SeedCatalogs.plist"
)

WORKING_DIR = "/tmp"


def get_logger():
    logger = logging.getLogger(os.path.basename(__file__))
    logger.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )
    logger.addHandler(handler)

    return logger


log = get_logger()


def get_input(prompt=None):
    """Python 2 and 3 wrapper for raw_input/input"""
    try:
        return raw_input(prompt)
    except NameError:
        # raw_input doesn't exist in Python 3
        return input(prompt)


def read_plist(filepath):
    """Wrapper for the differences between Python 2 and Python 3's plistlib"""
    try:
        with open(filepath, "rb") as fileobj:
            return plistlib.load(fileobj)
    except AttributeError:
        # plistlib module doesn't have a load function (as in Python 2)
        return plistlib.readPlist(filepath)


def read_plist_from_string(bytestring):
    """Wrapper for the differences between Python 2 and Python 3's plistlib"""
    try:
        return plistlib.loads(bytestring)
    except AttributeError:
        # plistlib module doesn't have a load function (as in Python 2)
        return plistlib.readPlistFromString(bytestring)


def get_seeding_program(sucatalog_url):
    """Returns a seeding program name based on the sucatalog_url"""
    try:
        seed_catalogs = read_plist(SEED_CATALOGS_PLIST)
        for key, value in seed_catalogs.items():
            if sucatalog_url == value:
                return key
        return ""
    except (OSError, IOError, ExpatError, AttributeError, KeyError) as err:
        log.warn(err)
        return ""


def get_seed_catalog(seedname="DeveloperSeed"):
    """Returns the developer seed sucatalog"""
    try:
        seed_catalogs = read_plist(SEED_CATALOGS_PLIST)
        return seed_catalogs.get(seedname)
    except (OSError, IOError, ExpatError, AttributeError, KeyError) as err:
        log.warn(err)
        return ""


def get_seeding_programs():
    """Returns the list of seeding program names"""
    try:
        seed_catalogs = read_plist(SEED_CATALOGS_PLIST)
        return list(seed_catalogs.keys())
    except (OSError, IOError, ExpatError, AttributeError, KeyError) as err:
        log.warn(err)
        return ""


def get_default_catalog():
    """Returns the default softwareupdate catalog for the current OS"""
    darwin_major = os.uname()[2].split(".")[0]
    return DEFAULT_SUCATALOGS.get(darwin_major)


class ReplicationError(Exception):
    """A custom error when replication fails"""

    pass


def content_length(full_url):
    try:
        output = subprocess.check_output(
            ["/usr/bin/curl", "--silent", "--head", "-i", "-fL", full_url]
        )

        for line in output.splitlines():
            if line.strip().startswith("Content-Length:"):
                return int(line.split(":")[-1].strip())

        return None
    except subprocess.CalledProcessError as err:
        raise ReplicationError(err)


def replicate_url(
    full_url, dest=None, default_workdir=None, show_progress=False, ignore_cache=False
):
    """Downloads a URL and stores it in the same relative path on our
    filesystem. Returns a path to the replicated file."""

    if default_workdir is None:
        default_workdir = WORKING_DIR

    if dest is None:
        dest = os.path.normpath(urlsplit(full_url)[2].lstrip("/"))

    if not dest.startswith("/"):
        dest = os.path.join(default_workdir, dest)

    if show_progress:
        options = "-fL"
    else:
        options = "-sfL"

    filename = dest.split("/")[-1]
    curl_cmd = ["/usr/bin/curl", options, "--create-dirs", "-o", dest]

    if not full_url.endswith(".gz"):
        # stupid hack for stupid Apple behavior where it sometimes returns
        # compressed files even when not asked for
        curl_cmd.append("--compressed")

    if ignore_cache and os.path.exists(dest):
        os.remove(dest)

    if not ignore_cache and os.path.exists(dest):
        remote_bytes = content_length(full_url)
        cached_bytes = os.path.getsize(dest)
        if remote_bytes == cached_bytes:
            log.info("%s is cached - skipping download." % (filename))
            return dest
        elif remote_bytes < cached_bytes:
            os.remove(dest)
        else:
            log.info(
                "%s is partially cached - resuming download from %s..."
                % (filename, full_url)
            )
            curl_cmd.extend(["-C", "-"])
    else:
        log.info("%s is required - downloading from %s..." % (filename, full_url))

    curl_cmd.append(full_url)

    try:
        subprocess.check_call(curl_cmd)
    except subprocess.CalledProcessError as err:
        raise ReplicationError(err)

    return dest


def parse_server_metadata(filename):
    """Parses a softwareupdate server metadata file, looking for information
    of interest.
    Returns a dictionary containing title, version, and description."""
    title = ""
    vers = ""
    try:
        md_plist = read_plist(filename)
    except (OSError, IOError, ExpatError) as err:
        log.error("Error reading %s: %s" % (filename, err))
        return {}
    vers = md_plist.get("CFBundleShortVersionString", "")
    localization = md_plist.get("localization", {})
    preferred_localization = localization.get("English") or localization.get("en")
    if preferred_localization:
        title = preferred_localization.get("title", "")

    metadata = {}
    metadata["title"] = title
    metadata["version"] = vers
    return metadata


def get_server_metadata(catalog, product_key, ignore_cache=False):
    """Replicate ServerMetaData"""
    try:
        url = catalog["Products"][product_key]["ServerMetadataURL"]
        try:
            smd_path = replicate_url(url, ignore_cache=ignore_cache)
            return smd_path
        except ReplicationError as err:
            log.warn("Could not replicate %s: %s" % (url, err))
            return None
    except KeyError:
        # log.info('Malformed catalog.')
        return None


def parse_dist(filename):
    """Parses a softwareupdate dist file, returning a dict of info of
    interest"""
    dist_info = {}
    try:
        dom = minidom.parse(filename)
    except ExpatError:
        log.warn("Invalid XML in %s" % filename)
        return dist_info
    except IOError as err:
        log.warn("Error reading %s: %s" % (filename, err))
        return dist_info

    titles = dom.getElementsByTagName("title")
    if titles:
        dist_info["title_from_dist"] = titles[0].firstChild.wholeText

    auxinfos = dom.getElementsByTagName("auxinfo")
    if not auxinfos:
        return dist_info
    auxinfo = auxinfos[0]
    key = None
    value = None
    children = auxinfo.childNodes
    # handle the possibility that keys from auxinfo may be nested
    # within a 'dict' element
    dict_nodes = [
        n
        for n in auxinfo.childNodes
        if n.nodeType == n.ELEMENT_NODE and n.tagName == "dict"
    ]
    if dict_nodes:
        children = dict_nodes[0].childNodes
    for node in children:
        if node.nodeType == node.ELEMENT_NODE and node.tagName == "key":
            key = node.firstChild.wholeText
        if node.nodeType == node.ELEMENT_NODE and node.tagName == "string":
            value = node.firstChild.wholeText
        if key and value:
            dist_info[key] = value
            key = None
            value = None
    return dist_info


def download_and_parse_sucatalog(sucatalog, ignore_cache=False):
    """Downloads and returns a parsed softwareupdate catalog"""
    try:
        localcatalogpath = replicate_url(sucatalog, ignore_cache=ignore_cache)
    except ReplicationError as err:
        log.error("Could not replicate %s: %s" % (sucatalog, err))
        sys.exit(1)
    if os.path.splitext(localcatalogpath)[1] == ".gz":
        with gzip.open(localcatalogpath) as the_file:
            content = the_file.read()
            try:
                catalog = read_plist_from_string(content)
                return catalog
            except ExpatError as err:
                log.info("Error reading %s: %s" % (localcatalogpath, err))
                sys.exit(1)
    else:
        try:
            catalog = read_plist(localcatalogpath)
            return catalog
        except (OSError, IOError, ExpatError) as err:
            log.error("Error reading %s: %s" % (localcatalogpath, err))
            sys.exit(1)


def get_installassistant_pkgs(product):
    with_auto = filter(
        lambda pkg: pkg["URL"].endswith("InstallAssistant.pkg")
        or pkg["URL"].endswith("InstallAssistantAuto.pkg"),
        filter(lambda pkg: pkg.get("URL"), product["Packages"]),
    )

    return (
        filter(lambda pkg: pkg["URL"].endswith("InstallAssistant.pkg"), with_auto)
        or with_auto
    )


def find_mac_os_installers(
    catalog, shared_support_only=False, pkg_installers_only=False
):
    """Return a list of product identifiers for what appear to be macOS
    installers"""
    mac_os_installer_products = []
    if "Products" in catalog:
        for product_key in catalog["Products"].keys():
            product = catalog["Products"][product_key]
            installassistant_ids = product.get("ExtendedMetaInfo", {}).get(
                "InstallAssistantPackageIdentifiers"
            )
            if installassistant_ids is None:
                continue

            if (
                installassistant_ids.get("SharedSupport") or not shared_support_only
            ) and (get_installassistant_pkgs(product) or not pkg_installers_only):
                mac_os_installer_products.append(product_key)

    return mac_os_installer_products


def os_installer_product_info(catalog, ignore_cache=False, pkg_installers_only=False):
    """Returns a dict of info about products that look like macOS installers"""
    product_info = {}
    installer_products = find_mac_os_installers(
        catalog, pkg_installers_only=pkg_installers_only
    )
    for product_key in installer_products:
        product_info[product_key] = {}
        filename = get_server_metadata(catalog, product_key)
        if filename:
            product_info[product_key] = parse_server_metadata(filename)
        else:
            log.warn("No server metadata for %s" % product_key)
            product_info[product_key]["title"] = None
            product_info[product_key]["version"] = None

        product = catalog["Products"][product_key]
        product_info[product_key]["PostDate"] = product["PostDate"]
        distributions = product["Distributions"]
        dist_url = distributions.get("English") or distributions.get("en")
        try:
            dist_path = replicate_url(
                dist_url, show_progress=False, ignore_cache=ignore_cache
            )
        except ReplicationError as err:
            log.warn("Could not replicate %s: %s" % (dist_url, err))
        else:
            dist_info = parse_dist(dist_path)
            product_info[product_key]["DistributionPath"] = dist_path
            product_info[product_key].update(dist_info)
            if not product_info[product_key]["title"]:
                product_info[product_key]["title"] = dist_info.get("title_from_dist")
            if not product_info[product_key]["version"]:
                product_info[product_key]["version"] = dist_info.get("VERSION")

    return product_info


def replicate_product(catalog, product_id, show_progress=False, ignore_cache=False):
    """Downloads all the packages for a product"""
    product = catalog["Products"][product_id]

    for package in product.get("Packages", []):
        # TO-DO: Check 'Size' attribute and make sure
        # we have enough space on the target
        # filesystem before attempting to download
        if "URL" in package:
            try:
                replicate_url(
                    package["URL"],
                    show_progress=show_progress,
                    ignore_cache=ignore_cache,
                )
            except ReplicationError as err:
                log.error("Could not replicate %s: %s" % (package["URL"], err))
                sys.exit(1)
        if "MetadataURL" in package:
            try:
                replicate_url(
                    package["MetadataURL"],
                    ignore_cache=ignore_cache,
                )
            except ReplicationError as err:
                log.error("Could not replicate %s: %s" % (package["MetadataURL"], err))
                sys.exit(1)


def interactive_product_selection(options, product_info):
    def select_product_id(raw_answer):
        if not raw_answer:
            return None

        try:
            index = int(raw_answer) - 1
            assert index >= 0
            return options[index]
        except (ValueError, IndexError, AssertionError):
            print("Invalid selection. Please try again.")
            return None

    print(
        "%2s %14s %10s %8s %11s  %s"
        % ("#", "ProductID", "Version", "Build", "Post Date", "Title")
    )
    for index, product_id in enumerate(options):
        print(
            "%2s %14s %10s %8s %11s  %s"
            % (
                index + 1,
                product_id,
                product_info[product_id].get("version", "UNKNOWN"),
                product_info[product_id].get("BUILD", "UNKNOWN"),
                product_info[product_id]["PostDate"].strftime("%Y-%m-%d"),
                product_info[product_id]["title"],
            )
        )

    product_id = None
    while product_id is None:
        product_id = select_product_id(
            get_input("\nChoose a product to download (1-%s): " % len(options))
        )

    return product_id


def install_product(dist_path, target_vol):
    """Install a product to a target volume.
    Returns a boolean to indicate success or failure."""
    # set CM_BUILD env var to make Installer bypass eligibilty checks
    # when installing packages (for machine-specific OS builds)
    os.environ["CM_BUILD"] = "CM_BUILD"
    cmd = ["/usr/sbin/installer", "-pkg", dist_path, "-target", target_vol]
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as err:
        log.warn(err)
        return False
    else:
        # Apple postinstall script bug ends up copying files to a path like
        # /tmp/dmg.T9ak1HApplications
        path = target_vol + "Applications"
        if os.path.exists(path):
            log.info("Working around a very dumb Apple bug")
            subprocess.check_call(
                ["/usr/bin/ditto", path, os.path.join(target_vol, "Applications")]
            )
            subprocess.check_call(["/bin/rm", "-r", path])
        return True


def make_sparse_image(volume_name, output_path):
    """Make a sparse disk image we can install a product to"""
    cmd = [
        "/usr/bin/hdiutil",
        "create",
        "-size",
        "16g",
        "-fs",
        "HFS+",
        "-volname",
        volume_name,
        "-type",
        "SPARSE",
        "-plist",
        output_path,
    ]
    try:
        output = subprocess.check_output(cmd)
    except subprocess.CalledProcessError as err:
        log.error(err)
        sys.exit(1)
    try:
        return read_plist_from_string(output)[0]
    except IndexError as err:
        log.error("Unexpected output from hdiutil: %s" % output)
        sys.exit(1)
    except ExpatError as err:
        log.error("Malformed output from hdiutil: %s" % output)
        log.error(err)
        sys.exit(1)


def mountdmg(dmgpath):
    """
    Attempts to mount the dmg at dmgpath and returns first mountpoint
    """
    mountpoints = []
    dmgname = os.path.basename(dmgpath)
    cmd = [
        "/usr/bin/hdiutil",
        "attach",
        dmgpath,
        "-mountRandom",
        "/tmp",
        "-nobrowse",
        "-plist",
        "-owners",
        "on",
    ]
    proc = subprocess.Popen(
        cmd, bufsize=-1, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    (pliststr, err) = proc.communicate()
    if proc.returncode:
        log.error('Error: "%s" while mounting %s.' % (err, dmgname))
        return None
    if pliststr:
        plist = read_plist_from_string(pliststr)
        for entity in plist["system-entities"]:
            if "mount-point" in entity:
                mountpoints.append(entity["mount-point"])

    return mountpoints[0]


def unmountdmg(mountpoint):
    """
    Unmounts the dmg at mountpoint
    """
    proc = subprocess.Popen(
        ["/usr/bin/hdiutil", "detach", mountpoint],
        bufsize=-1,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    (dummy_output, err) = proc.communicate()
    if proc.returncode:
        log.warn("Polite unmount failed: %s" % err)
        log.warn("Attempting to force unmount %s" % mountpoint)
        # try forcing the unmount
        retcode = subprocess.call(["/usr/bin/hdiutil", "detach", mountpoint, "-force"])
        if retcode:
            log.warn("Failed to unmount %s" % mountpoint)


def find_installer_app(mountpoint):
    """Returns the path to the Install macOS app on the mountpoint"""
    applications_dir = os.path.join(mountpoint, "Applications")
    for item in os.listdir(applications_dir):
        if item.endswith(".app"):
            return os.path.join(applications_dir, item)
    return None


def make_compressed_dmg(app_path, diskimagepath):
    """Returns path to newly-created compressed r/o disk image containing
    Install macOS.app"""

    cmd = [
        "/usr/bin/hdiutil",
        "create",
        "-fs",
        "HFS+",
        "-srcfolder",
        app_path,
        diskimagepath,
    ]
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as err:
        log.warn(err)
    else:
        log.info("Disk image created at: %s" % diskimagepath)


def installinstallmacos(
    catalog,
    su_catalog_url,
    product_id,
    product_info,
    show_progress=False,
    ignore_cache=False,
):
    macos_version = product_info.get("version", "UNKNOWN")
    volname = "Install_macOS_%s-%s" % (
        macos_version,
        product_info["BUILD"],
    )
    downloaded_artifact = os.path.join(WORKING_DIR, volname + ".dmg")
    if os.path.exists(downloaded_artifact):
        if ignore_cache:
            os.remove(downloaded_artifact)
        else:
            log.info(
                "Read-only compressed dmg containing installer app is already cached."
            )
            return downloaded_artifact

    replicate_product(
        catalog,
        product_id,
        show_progress=show_progress,
        ignore_cache=ignore_cache,
    )

    sparse_diskimage_path = os.path.join(WORKING_DIR, volname + ".sparseimage")
    if os.path.exists(sparse_diskimage_path):
        os.unlink(sparse_diskimage_path)

    log.info("Making empty sparseimage...")
    sparse_diskimage_path = make_sparse_image(volname, sparse_diskimage_path)

    mountpoint = mountdmg(sparse_diskimage_path)
    if not mountpoint or not os.path.exists(mountpoint):
        log.error("Failed to mount downloaded diskimage!")
        sys.exit(1)

    try:
        err = None
        log.info("Installing product to mounted image...")
        success = install_product(product_info["DistributionPath"], mountpoint)
        if not success:
            log.error("Product installation failed.")
            sys.exit(1)

        installer_app = find_installer_app(mountpoint)
        if not installer_app:
            log.error("No installer .app found in downloaded artifact!")
            sys.exit(1)

        seeding_program = get_seeding_program(su_catalog_url)
        if seeding_program:
            log.info(
                "Adding seeding program %s extended attribute to app" % seeding_program
            )
            xattr.setxattr(installer_app, "SeedProgram", seeding_program)

        log.info(
            "Creating read-only compressed dmg containing %s..."
            % (os.path.basename(installer_app))
        )
        make_compressed_dmg(installer_app, downloaded_artifact)
    except Exception as err:
        log.error("Unexpected error:")
        log.error(err)
    except SystemExit as err:
        print("Goodbye!")
    finally:
        unmountdmg(mountpoint)
        os.unlink(sparse_diskimage_path)
        if err:
            sys.exit(1)

    return downloaded_artifact


def main():
    """Do the main thing here"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--seedprogram",
        default="",
        help="Which Seed Program catalog to use. Valid values "
        "are %s." % ", ".join(get_seeding_programs()),
    )
    parser.add_argument(
        "--catalogurl",
        default="",
        help="Software Update catalog URL. This option "
        "overrides any seedprogram option.",
    )
    parser.add_argument(
        "--workdir",
        metavar="path_to_working_dir",
        default=".",
        help="Path to working directory on a volume with over "
        "10G of available space. Defaults to current working "
        "directory.",
    )
    parser.add_argument(
        "--ignore-cache",
        action="store_true",
        help="Ignore any previously cached files.",
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Download the latest version with no user interaction.",
    )
    parser.add_argument(
        "--open-with-finder",
        action="store_true",
        help="Open installer pkg with finder once complete.",
    )
    parser.add_argument(
        "--show-progress", action="store_true", help="Show curl progress."
    )
    parser.add_argument(
        "--write-receipt",
        action="store_true",
        help="Write receipt on successful download.",
    )
    parser.add_argument(
        "--version",
        default="",
        help="Only find installers for version. With --latest, download the latest for version.",
    )
    parser.add_argument(
        "--pkg-installers-only",
        action="store_true",
        help="Only consider and download macOS installers with a full InstallAssistant.pkg. If false, .dmg installers are also considered for download.",
    )
    args = parser.parse_args()

    current_dir = os.getcwd()

    if args.catalogurl:
        su_catalog_url = args.catalogurl
    elif args.seedprogram:
        su_catalog_url = get_seed_catalog(args.seedprogram)
        if not su_catalog_url:
            log.error(
                "Could not find a catalog url for seed program %s" % args.seedprogram,
                file=sys.stderr,
            )
            log.error(
                "Valid seeding programs are: %s" % ", ".join(get_seeding_programs()),
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        su_catalog_url = get_default_catalog()
        if not su_catalog_url:
            log.error(
                "Could not find a default catalog url for this OS version.",
                file=sys.stderr,
            )
            sys.exit(1)

    global WORKING_DIR
    WORKING_DIR = args.workdir

    log.info("Searching catalog: " + su_catalog_url)

    # download sucatalog and look for products that are for macOS installers
    catalog = download_and_parse_sucatalog(
        su_catalog_url, ignore_cache=args.ignore_cache
    )

    # log.info(catalog)
    product_info = os_installer_product_info(
        catalog,
        ignore_cache=args.ignore_cache,
        pkg_installers_only=args.pkg_installers_only,
    )

    # sort the list by release date
    sorted_product_info = filter(
        lambda pid: not args.version or product_info[pid]["version"] == args.version,
        sorted(product_info, key=lambda k: product_info[k]["PostDate"], reverse=True),
    )

    if not sorted_product_info:
        log.error(
            "No macOS installer products found in the sucatalog for version: "
            + args.version
            if args.version
            else "any"
        )
        sys.exit(1)

    log.info("Found %s installers." % (str(len(product_info))))

    if args.latest or len(sorted_product_info) == 1:
        product_id = sorted_product_info[0]
    else:
        product_id = interactive_product_selection(sorted_product_info, product_info)

    selected_product_info = product_info[product_id]
    macos_version = selected_product_info.get("version", "UNKNOWN")

    log.info(
        "Selected installer: %14s %10s %8s %11s  %s"
        % (
            product_id,
            macos_version,
            selected_product_info.get("BUILD", "UNKNOWN"),
            selected_product_info["PostDate"].strftime("%Y-%m-%d"),
            selected_product_info["title"],
        )
    )

    # determine the InstallAssistant pkg url
    package_url = get_installassistant_pkgs(catalog["Products"][product_id])[0]["URL"]

    if package_url.endswith("InstallAssistantAuto.pkg"):
        if args.pkg_installers_only:
            log.error(
                "Specified macOS installer does not have standalone InstallAssistant.pkg, and --pkg-installers-only was specified. Will not installinstallmacos. Exiting."
            )
            sys.exit(1)

        artifact_type = "dmg"
        expected_size = 0

        downloaded_artifact = installinstallmacos(
            catalog,
            su_catalog_url,
            product_id,
            selected_product_info,
            show_progress=args.show_progress,
            ignore_cache=args.ignore_cache,
        )

    else:
        artifact_type = "pkg"
        pkg_name = "InstallAssistant-%s-%s.pkg" % (
            macos_version,
            selected_product_info["BUILD"],
        )

        downloaded_artifact = os.path.join(WORKING_DIR, pkg_name)
        expected_size = content_length(package_url)

        replicate_url(
            package_url,
            dest=downloaded_artifact,
            show_progress=args.show_progress,
            ignore_cache=args.ignore_cache,
        )

    log.info("Cached %s installer at %s." % (artifact_type, downloaded_artifact))

    receipt = "org.macadmins.fetched.macos.installer.%s" % (macos_version)
    receipt_path = os.path.join("/var/db/receipts", receipt + ".bom")
    metadata_path = os.path.join("/opt/gusto/macos-installers", receipt + ".plist")
    old_metadata_path = os.path.join("/var/db/receipts", receipt + ".plist")

    if os.path.exists(old_metadata_path):
        os.remove(old_metadata_path)

    # we arbitrarily expect the artifact to be at least 5gb otherwise we assume something broke
    if (
        not os.path.exists(downloaded_artifact)
        or os.path.getsize(downloaded_artifact) < 5368709120
    ):
        if os.path.exists(metadata_path):
            os.remove(metadata_path)

        if os.path.exists(receipt_path):
            os.remove(receipt_path)

        log.error(
            downloaded_artifact
            + " was not found or is too small! Something went quite wrong."
        )
        sys.exit(1)

    if args.write_receipt:
        metadata = {
            "CacheDate": str(datetime.now()),
            "InstallPrefixPath": WORKING_DIR,
            "InstallProcessName": "fetch-macos-installer.py",
            "ArtifactFileName": downloaded_artifact,
            "PackageVersion": macos_version,
            "ArtifactType": artifact_type,
            "ArtifactSize": expected_size,
        }

        with open(receipt_path, "wb+") as f:
            f.write("")

        try:
            plistlib.writePlist(metadata, metadata_path)
        except AttributeError:
            with open(metadata_path, "wb+") as f:
                plistlib.dump(metadata, f)

    if args.open_with_finder:
        # reveal in Finder
        open_cmd = ["open", "-R", downloaded_artifact]
        subprocess.check_call(open_cmd)

    sys.exit(0)


if __name__ == "__main__":
    main()
