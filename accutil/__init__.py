from re import compile as re_compile
from json import dumps
from pathlib import Path
from argparse import ArgumentParser
from os import scandir, remove
from hashlib import md5 as _md5
from uuid import uuid4
from configparser import ConfigParser
from os import curdir, environ, fsencode
from os.path import expanduser
from multiprocessing.pool import ThreadPool

import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder


__author__ = "Brian Balsamo"
__email__ = "balsamo@uchicago.edu"
__company__ = "The University of Chicago Library"
__publication__ = ""
__version__ = "0.0.1dev"


def launch():
    """
    entry point launch hook
    """
    app = AccUtil()
    app.main()


def rscandir(path="."):
    for entry in scandir(path):
        yield entry
        if entry.is_dir():
            yield from rscandir(entry.path)


def sanitize_path(some_path):
    return bytes(some_path).hex()


def md5(path, buff=1024*1000*8):
    hasher = _md5()
    with open(path, 'rb') as f:
        data = f.read(buff)
        while data:
            hasher.update(data)
            data = f.read(buff)
    return hasher.hexdigest()


def mint_acc(acc_endpoint):
    acc_create_response = requests.post(
        acc_endpoint
    )
    acc_create_response.raise_for_status()
    acc_create_json = acc_create_response.json()
    return acc_create_json['Minted'][0]['identifier']


def check_acc_exists(acc_endpoint, acc_id):
    target_acc_url = acc_endpoint+acc_id + "/"
    return requests.head(target_acc_url).status_code == 200


def get_config(config_file=None):
    """
    Grab the config CLI --> env var --> typical locations
    """
    config = ConfigParser()
    if config_file:
        config.read(config_file)
        return config
    elif environ.get("ACCUTIL_CONFIG"):
        config.read(environ.get("ACCUTIL_CONFIG"))
        return config
    for x in [
        curdir,
        expanduser("~"),
        str(Path(expanduser("~"), ".config")),
        str(Path(expanduser("~"), ".config", "accutil")),
        "/etc", str(Path("/etc", "accutil"))
    ]:
        if Path(x, "accutil.conf").is_file():
            config.read(str(Path(x, "accutil.conf")))
            return config
    return ConfigParser()


def ingest_file(*args):
    path = args[0]
    ingress_url = args[1]
    acc_id = args[2]
    buffer_location = args[3]
    buff = args[4]
    root = args[5]
    running_buffer_delete = args[6]
    # Start building the data dict we're going to throw at the endpoint.
    data = {}
    data['accession_id'] = acc_id
    # Compute our originalName from the path, considering it relative to a
    # root if one was provided
    if root is not None:
        originalName = path.relative_to(root)
    else:
        originalName = path
    # TODO: Need to do byte escaping here in the callback
    data['name'] = sanitize_path(fsencode(originalName))

    # If a buffer location is specified, copy the file to there straight
    # away so we don't stress the original media. Then confirm the copy if
    # possible (otherwise emit a warning) and work with that copy from
    # there.
    # TODO: Handling of partial reads?
    precomputed_md5 = None
    if buffer_location is not None:
        tmp_path = str(Path(buffer_location, uuid4().hex))
        with open(path, 'rb') as src:
            with open(tmp_path, 'wb') as dst:
                d = src.read(buff)
                while d:
                    dst.write(d)
                    d = src.read(buff)
        precomputed_md5 = md5(tmp_path, buff)
        if not precomputed_md5 == md5(path, buff):
            print("Emit a warning about a bad copy from origin media here.")
        path = Path(tmp_path)

    # Re-use our hash of the buffer location if we have it precomputed.
    if precomputed_md5:
        data['md5'] = precomputed_md5
    else:
        data['md5'] = md5(path, buff)

    # Package up our open file object
    with open(path, "rb") as fd:
        data['file'] = ('file', fd)
        ingress_post_multipart_encoder = MultipartEncoder(data)
        # Ship the whole package off to the ingress microservice
        resp = requests.post(
            ingress_url,
            data=ingress_post_multipart_encoder,
            headers={"Content-Type":
                     ingress_post_multipart_encoder.content_type},
            stream=True
        )

    # Be sure what we got back is a-okay
    resp.raise_for_status()
    resp_json = resp.json()

    # If we made a "new" accession, store the minted acc id for future files
    # processed as a part of this run.
    if resp_json['acc_output'].get('acc_mint'):
        acc_id = \
            resp_json['acc_output']['acc_mint']['Minted'][0]['identifier']

    # If we buffered the file into safe storage somewhere in addition to the
    # origin media remove it now
    if buffer_location is not None and running_buffer_delete:
        remove(path)
    return resp_json


class AccUtil:
    def main(self):
        # Instantiate boilerplate parser
        parser = ArgumentParser(
            description="The UChicago LDR Tool Suite utility " +
            "for ingesting material into the library digital repository."
        )
        parser.add_argument(
            "target", help="The file/directory that " +
            "needs to be ingested.",
            type=str, action='store'
        )
        parser.add_argument(
            "accession_id", help="The identifier of the accession " +
            "the ingested material belongs to, or 'new' to mint a new " +
            "accession identifier and apply it",
            type=str, action='store'
        )
        parser.add_argument(
            "--running_buffer_delete",
            help="If this argument is passed individual files will be " +
            "deleted out of the buffer after they are POST'd to the " +
            "ingress endpoint. If it isn't _you must clean up your " +
            "buffer location manually_. If the location you are addressing " +
            "is bigger than your buffering location, not passing this " +
            "argument can result in your disk being filled.",
            action='store_true', default=None
        )
        parser.add_argument(
            "--buffer_location", help="A location on disk to save " +
            "files briefly* from outside media to operate on. If not " +
            "specified the application will read straight from the outside " +
            "multiple times.", type=str, action='store', default=None
        )
        parser.add_argument(
            "--buff", help="How much data to load into RAM in one go for " +
            "various operations. Currently the maximum for this should be " +
            "~2*n bits in RAM, with n specified in this arg.",
            type=int, action='store', default=None
        )
        # TODO: Generate some kind of receipt for this to read
        parser.add_argument(
            "--resume", "-r", help="Resume a previously " +
            "started run.",
            action='store_true'
        )
        parser.add_argument(
            "--source_root", help="The root of the  " +
            "directory that needs to be staged.",
            type=str, action='store',
            default=None
        )
        parser.add_argument(
            "--filter_pattern", help="Regexes to " +
            "use to exclude files whose rel paths match.",
            action='append', default=[]
        )
        parser.add_argument(
            "--ingress_url", help="The url of the ingress service.",
            action='store', default=None
        )
        parser.add_argument(
            "--accessions_url", help="The url of the accessions idnest.",
            action='store', default=None
        )
        # Parse arguments into args namespace
        args = parser.parse_args()

        # App code
        config = get_config()

        # Argument handling
        target = Path(args.target)
        self.root = args.source_root
        self.filters = [re_compile(x) for x in args.filter_pattern]
        self.acc_id = args.accession_id
        if args.ingress_url:
            self.ingress_url = args.ingress_url
        elif config["DEFAULT"].get("INGRESS_URL"):
            self.ingress_url = config["DEFAULT"].get("INGRESS_URL")
        else:
            raise RuntimeError("No ingress url specified at CLI or in a conf!")

        if args.accessions_url:
            self.acc_endpoint = args.accessions_url
        elif config["DEFAULT"].get("ACCESSIONS_URL"):
            self.acc_endpoint = config["DEFAULT"].get("ACCESSIONS_URL")
        else:
            raise RuntimeError("No ingress url specified at CLI or in a conf!")

        if args.buffer_location:
            self.buffer_location = args.buffer_location
        elif config["DEFAULT"].get("BUFFER_LOCATION"):
            self.buffer_location = config["DEFAULT"].get("BUFFER_LOCATION")
        else:
            self.buffer_location = None

        if isinstance(args.running_buffer_delete, bool):
            self.running_buffer_delete = args.running_buffer_delete
        elif isinstance(config["DEFAULT"].getboolean(
                "RUNNING_BUFFER_DELETE"), bool):
            self.running_buffer_delete = config["DEFAULT"].getboolean(
                "RUNNING_BUFFER_DELETE")
        else:
            self.running_buffer_delete = False

        if isinstance(args.buff, int):
            self.buff = args.buff
        elif isinstance(config["DEFAULT"].getint("BUFF"), int):
            self.buff = config["DEFAULT"].getint("BUFF")
        else:
            self.buff = 1024*1000*8

        # Real work

        # If our acc id is given as "new" create a new one, check to be sure it
        # exists regardless and if it doesn't raise an error
        if self.acc_id == "new":
            self.acc_id = mint_acc(self.acc_endpoint)
        if not check_acc_exists(self.acc_endpoint, self.acc_id):
            raise RuntimeError("That acc doesn't exist! " +
                               "(or there was a problem creating a new " +
                               "accession identifier)")

        if target.is_file():
            r = self.ingest_file(str(target))
        elif target.is_dir():
            r = self.ingest_dir(
                str(target), args.source_root,
                [re_compile(x) for x in args.filter_pattern]
            )
        else:
            raise ValueError("Thats not a file or a dir!")
        # TODO: Clean up output
        print(dumps(r, indent=4))

    def ingest_file(self, path):
        return ingest_file(
            path, self.ingress_url, self.acc_id,
            self.buffer_location, self.buff, self.root,
            self.running_buffer_delete
        )

    def ingest_dir(self, path, root=None, filters=[]):
        # Enforce filters, delegate to the ingest_file() method
        file_list = []
        for x in rscandir(path):
            if x.is_file():
                skip = False
                for f in filters:
                    if f.match(x.path):
                        skip = True
                if skip:
                    continue
                file_list.append(x.path)
        pool = ThreadPool(50)
        p_result = pool.map(self.ingest_file, file_list)

        return p_result


if __name__ == "__main__":
    launch()
