from re import compile as re_compile
from json import dumps
from pathlib import Path
from argparse import ArgumentParser
from os import scandir, remove
from hashlib import md5 as _md5
from uuid import uuid4
from configparser import ConfigParser
from os import curdir, environ
from os.path import expanduser

import requests


__author__ = "Brian Balsamo"
__email__ = "balsamo@uchicago.edu"
__company__ = "The University of Chicago Library"
__publication__ = ""
__version__ = "0.0.1dev"


# TODO
# Thread the POSTs

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


def sanitize_name(some_path):
    return some_path


def md5(path, buff=1024*1000*8):
    hasher = _md5()
    with open(path, 'rb') as f:
        data = f.read(buff)
        while data:
            hasher.update(data)
            data = f.read(buff)
    return hasher.hexdigest()


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
        # Parse arguments into args namespace
        args = parser.parse_args()

        # App code
        config = get_config()

        # Argument handling
        target = Path(args.target)
        self.filters = [re_compile(x) for x in args.filter_pattern]
        self.acc_id = args.accession_id
        if args.ingress_url:
            self.ingress_url = args.ingress_url
        elif config["DEFAULT"].get("INGRESS_URL"):
            self.ingress_url = config["DEFAULT"].get("INGRESS_URL")
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
        if target.is_file():
            r = self.ingest_file(target, args.source_root)
        elif target.is_dir():
            r = self.ingest_dir(
                target, args.source_root,
                [re_compile(x) for x in args.filter_pattern]
            )
        else:
            raise ValueError("Thats not a file or a dir!")
        # TODO: Clean up output
        print(dumps(r, indent=4))

    def ingest_file(self, path, root=None):
        # Start building the data dict we're going to throw at the endpoint.
        data = {}
        data['accession_id'] = self.acc_id
        # Compute our originalName from the path, considering it relative to a
        # root if one was provided
        if root is not None:
            originalName = str(path.relative_to(root))
        else:
            originalName = str(path)
        # TODO: Need to do byte escaping here in the callback
        data['originalName'] = sanitize_name(originalName)

        # If a buffer location is specified, copy the file to there straight
        # away so we don't stress the original media. Then confirm the copy if
        # possible (otherwise emit a warning) and work with that copy from
        # there.
        # TODO: Handling of partial reads?
        precomputed_md5 = None
        if self.buffer_location is not None:
            tmp_path = str(Path(self.buffer_location, uuid4().hex))
            with open(str(path), 'rb') as src:
                with open(tmp_path, 'wb') as dst:
                    d = src.read(self.buff)
                    while d:
                        dst.write(d)
                        d = src.read(self.buff)
            precomputed_md5 = md5(tmp_path, self.buff)
            if not precomputed_md5 == md5(str(path), self.buff):
                print("Emit a warning about a bad copy from origin media here.")
            path = Path(tmp_path)

        # Re-use our hash of the buffer location if we have it precomputed.
        if precomputed_md5:
            data['md5'] = precomputed_md5
        else:
            data['md5'] = md5(str(path), self.buff)

        # Package up our open file opbject
        files = {'file': open(str(path), 'rb')}

        # Ship the whole package off to the ingress microservice
        resp = requests.post(
            self.ingress_url,
            data=data,
            files=files
        )

        # Be sure what we got back is a-okay
        resp.raise_for_status()
        resp_json = resp.json()

        # If we made a "new" accession, store the minted acc id for future files
        # processed as a part of this run.
        if resp_json['acc_output'].get('acc_mint'):
            self.acc_id = \
                resp_json['acc_output']['acc_mint']['Minted'][0]['identifier']

        # If we buffered the file into safe storage somewhere in addition to the
        # origin media remove it now
        if self.buffer_location is not None and self.running_buffer_delete:
            print("Removing {}".format(str(path)))
            remove(str(path))
        return resp_json

    def ingest_dir(self, path, root=None, filters=[]):
        # Enforce filters, delegate to the ingest_file() method
        r = []
        for x in rscandir(str(path)):
            if x.is_file():
                skip = False
                for f in filters:
                    if f.match(x.path):
                        skip = True
                if skip:
                    continue
                r.append(self.ingest_file(Path(x.path), root=root))
        return r


if __name__ == "__main__":
    launch()
