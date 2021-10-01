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
        log.warn(err, file=sys.stderr)
        return ""


def get_seed_catalog(seedname="DeveloperSeed"):
    """Returns the developer seed sucatalog"""
    try:
        seed_catalogs = read_plist(SEED_CATALOGS_PLIST)
        return seed_catalogs.get(seedname)
    except (OSError, IOError, ExpatError, AttributeError, KeyError) as err:
        log.warn(err, file=sys.stderr)
        return ""


def get_seeding_programs():
    """Returns the list of seeding program names"""
    try:
        seed_catalogs = read_plist(SEED_CATALOGS_PLIST)
        return list(seed_catalogs.keys())
    except (OSError, IOError, ExpatError, AttributeError, KeyError) as err:
        log.warn(err, file=sys.stderr)
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
            ["/usr/bin/curl", "--head", "-i", "-fL", full_url]
        )

        for line in output.splitlines():
            if line.strip().startswith("Content-Length:"):
                return int(line.split(":")[-1].strip())

        return None
    except subprocess.CalledProcessError as err:
        raise ReplicationError(err)


def replicate_url(full_url, dest=None, show_progress=False, ignore_cache=False):
    """Downloads a URL and stores it in the same relative path on our
    filesystem. Returns a path to the replicated file."""

    if dest is None:
        dest = os.path.normpath(urlsplit(full_url)[2].lstrip("/"))

    if not dest.startswith("/"):
        dest = os.path.join(WORKING_DIR, dest)

    if show_progress:
        options = "-fL"
    else:
        options = "-sfL"

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
            log.info("Skipping download: %s is cached." % (dest))
            return dest
        elif remote_bytes < cached_bytes:
            os.remove(dest)
        else:
            curl_cmd.extend(["-C", "-"])

    curl_cmd.append(full_url)
    log.info("Downloading %s from %s..." % (dest, full_url))

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
        log.error("Error reading %s: %s" % (filename, err), file=sys.stderr)
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
            log.warn("Could not replicate %s: %s" % (url, err), file=sys.stderr)
            return None
    except KeyError:
        # log.info('Malformed catalog.', file=sys.stderr)
        return None


def parse_dist(filename):
    """Parses a softwareupdate dist file, returning a dict of info of
    interest"""
    dist_info = {}
    try:
        dom = minidom.parse(filename)
    except ExpatError:
        log.warn("Invalid XML in %s" % filename, file=sys.stderr)
        return dist_info
    except IOError as err:
        log.warn("Error reading %s: %s" % (filename, err), file=sys.stderr)
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
        log.error("Could not replicate %s: %s" % (sucatalog, err), file=sys.stderr)
        exit(-1)
    if os.path.splitext(localcatalogpath)[1] == ".gz":
        with gzip.open(localcatalogpath) as the_file:
            content = the_file.read()
            try:
                catalog = read_plist_from_string(content)
                return catalog
            except ExpatError as err:
                log.info(
                    "Error reading %s: %s" % (localcatalogpath, err), file=sys.stderr
                )
                exit(-1)
    else:
        try:
            catalog = read_plist(localcatalogpath)
            return catalog
        except (OSError, IOError, ExpatError) as err:
            log.error("Error reading %s: %s" % (localcatalogpath, err), file=sys.stderr)
            exit(-1)


def find_mac_os_installers(catalog, installassistant_pkg_only=False):
    """Return a list of product identifiers for what appear to be macOS
    installers"""
    mac_os_installer_products = []
    if "Products" in catalog:
        for product_key in catalog["Products"].keys():
            product = catalog["Products"][product_key]
            try:
                if product["ExtendedMetaInfo"]["InstallAssistantPackageIdentifiers"]:
                    if product["ExtendedMetaInfo"][
                        "InstallAssistantPackageIdentifiers"
                    ]["SharedSupport"]:
                        mac_os_installer_products.append(product_key)
            except KeyError:
                continue
    return mac_os_installer_products


def os_installer_product_info(catalog, ignore_cache=False):
    """Returns a dict of info about products that look like macOS installers"""
    product_info = {}
    installer_products = find_mac_os_installers(catalog)
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
            log.warn("Could not replicate %s: %s" % (dist_url, err), file=sys.stderr)
        else:
            dist_info = parse_dist(dist_path)
            product_info[product_key]["DistributionPath"] = dist_path
            product_info[product_key].update(dist_info)
            if not product_info[product_key]["title"]:
                product_info[product_key]["title"] = dist_info.get("title_from_dist")
            if not product_info[product_key]["version"]:
                product_info[product_key]["version"] = dist_info.get("VERSION")

    return product_info


def replicate_product(catalog, product_id, ignore_cache=False):
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
                    show_progress=True,
                    ignore_cache=ignore_cache,
                    attempt_resume=(not ignore_cache),
                )
            except ReplicationError as err:
                log.error(
                    "Could not replicate %s: %s" % (package["URL"], err),
                    file=sys.stderr,
                )
                exit(-1)
        if "MetadataURL" in package:
            try:
                replicate_url(package["MetadataURL"], ignore_cache=ignore_cache)
            except ReplicationError as err:
                log.error(
                    "Could not replicate %s: %s" % (package["MetadataURL"], err),
                    file=sys.stderr,
                )
                exit(-1)


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
        help="Download the latest version with no user interaction.",
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
            exit(-1)
    else:
        su_catalog_url = get_default_catalog()
        if not su_catalog_url:
            log.error(
                "Could not find a default catalog url for this OS version.",
                file=sys.stderr,
            )
            exit(-1)

    global WORKING_DIR
    WORKING_DIR = args.workdir

    # download sucatalog and look for products that are for macOS installers
    catalog = download_and_parse_sucatalog(
        su_catalog_url, ignore_cache=args.ignore_cache
    )

    # log.info(catalog)
    product_info = os_installer_product_info(catalog, ignore_cache=args.ignore_cache)

    if not product_info:
        log.error(
            "No macOS installer products found in the sucatalog.", file=sys.stderr
        )
        exit(-1)

    if len(product_info) > 1:
        # display a menu of choices (some seed catalogs have multiple installers)
        log.info(
            "%2s %14s %10s %8s %11s  %s"
            % ("#", "ProductID", "Version", "Build", "Post Date", "Title")
        )
        # sort the list by release date
        sorted_product_info = sorted(
            product_info, key=lambda k: product_info[k]["PostDate"], reverse=True
        )

        if args.latest:
            product_id = sorted_product_info[0]
        elif args.version:
            found_version = False
            for index, product_id in enumerate(sorted_product_info):
                if product_info[product_id]["version"] == args.version:
                    found_version = True
                    break
            if found_version != True:
                log.error("Couldn't find version, Exiting.")
                exit(1)
        else:
            for index, product_id in enumerate(sorted_product_info):
                log.info(
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
            answer = get_input(
                "\nChoose a product to download (1-%s): " % len(product_info)
            )
            try:
                index = int(answer) - 1
                if index < 0:
                    raise ValueError
                product_id = sorted_product_info[index]
            except (ValueError, IndexError):
                log.warn("Exiting.")
                exit(0)
    else:  # only one product found
        product_id = list(product_info.keys())[0]
        log.info("Found a single installer:")

    product = catalog["Products"][product_id]

    log.info(
        "%14s %10s %8s %11s  %s"
        % (
            product_id,
            product_info[product_id].get("version", "UNKNOWN"),
            product_info[product_id].get("BUILD", "UNKNOWN"),
            product_info[product_id]["PostDate"].strftime("%Y-%m-%d"),
            product_info[product_id]["title"],
        )
    )

    # determine the InstallAssistant pkg url
    for package in product["Packages"]:
        package_url = package["URL"]
        if package_url.endswith("InstallAssistant.pkg"):
            break

    # log.info("Package URL is %s" % package_url)
    pkg_name = "InstallAssistant-%s-%s.pkg" % (
        product_info[product_id]["version"],
        product_info[product_id]["BUILD"],
    )

    downloaded_pkg = os.path.join(args.workdir, pkg_name)
    replicate_url(
        package_url,
        dest=downloaded_pkg,
        show_progress=args.show_progress,
        ignore_cache=args.ignore_cache,
    )

    if args.open_with_finder:
        # reveal in Finder
        open_cmd = ["open", "-R", downloaded_pkg]
        subprocess.check_call(open_cmd)

    if args.write_receipt:
        receipt = "fetched.%.installer.bom" % (product_info[product_id]["version"])
        with open(os.path.join("/var/db/receipts", receipt), "wb+") as f:
            f.write("")


if __name__ == "__main__":
    main()
