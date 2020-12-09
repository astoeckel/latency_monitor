#!/usr/bin/env python3

#  Latency Monitor
#  Copyright (C) 2020  Andreas Stöckel
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Affero General Public License as
#  published by the Free Software Foundation, either version 3 of the
#  License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Affero General Public License for more details.
#
#  You should have received a copy of the GNU Affero General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.

import json, os, random, re, shlex, sys, time

import http.server
import http.client

import select

import logging
logger = logging.getLogger(__name__)

import socketserver
socketserver.TCPServer.allow_reuse_address = True

import threading

################################################################################
# Helper functions                                                             #
################################################################################


def mimetype(filename):
    """
    Returns the mime type based on the file extension.
    """
    MIME_MAP = {
        "woff2": "font/woff2",
        "html": "text/html; charset=utf-8",
        "js": "text/javascript; charset=utf-8",
        "json": "application/json",
        "manifest": "application/manifest+json",
        "css": "text/css; charset=utf-8",
        "svg": "image/svg+xml",
        "ico": "image/x-icon",
        "png": "image/png",
    }

    # Get the file extension
    ext = (filename.split(".")[-1]).lower()
    if ext in MIME_MAP:
        return MIME_MAP[ext]

    # Otherwise, return a safe default MIME type
    return "application/octet-stream"


def escape(text):
    return (text.replace('&', '&amp;').replace('<', '&lt;').replace(
        '>', '&gt;').replace('"', '&quot;').replace("'", '&#39;'))


###############################################################################
# Client program                                                              #
###############################################################################


def main_client():
    """
    This program acts as a simple echo server on the remote server. It simply
    reads the incoming json message from stdin, adds a local timestamp and
    writes it back out to stdout. Please perserve the "#CLIENT_BEGIN#" and
    "#CLIENT_END" comments exactly as they are in the code. The code between
    these comments should be a self-contained Python program.
    """
    #CLIENT_BEGIN#
    import time, json, sys
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            break
        response = {"crt": time.monotonic()}
        try:
            data = json.loads(str(line, "utf-8"))
            if not isinstance(data, dict):
                response = {"error": "Invalid message"}
            else:
                response.update(data)
        except json.decoder.JSONDecodeError as e:
            response = {"error": str(e)}
        sys.stdout.buffer.write(
            json.dumps(response, sort_keys=True).encode("utf-8") + b"\n")
        sys.stdout.buffer.flush()
    #CLIENT_END#
    return 0


def get_main_client_as_arg():
    """
    Extracts the code of the function "main_client" above and returns an array
    that can be passed to subprocess.run() to execute this code in a separate
    Python 3 interpreter.
    """
    with open(__file__, 'r') as f:
        lines = []
        in_code = False
        indent = 0
        while True:
            line = f.readline()
            if not line:
                break
            if in_code and (line.strip() == "#CLIENT_END#"):
                in_code = False
            if in_code:
                lines.append(line[indent:])
            if (not in_code) and (line.strip() == "#CLIENT_BEGIN#"):
                in_code = True
                indent = 0
                for i in range(len(line)):
                    if line[i] == " ":
                        indent += 1
                    else:
                        break
        return [
            "/usr/bin/env", "python3", "-u", "-c",
            shlex.quote("".join(lines))
        ]


###############################################################################
# Webserver Request Handlers                                                  #
###############################################################################


def _handle_fs(document_root, static_filename=None):
    """
    Creates a handler that resolves a file in the virtual filesystem.
    """

    # Get the canonical document root
    document_root = os.path.realpath(document_root)

    def _handler(req, query=None, match=None, head=False):
        # If no static_filename has been specified, check whether the
        # user-provided file is stored in the file system
        filename = None
        if static_filename:
            if not os.path.isabs(static_filename):
                filename = os.path.join(document_root, static_filename)
            else:
                filename = static_filename
        elif match:
            filename = os.path.join(document_root, match.group(0)[1:])

        # If no file has been found, return
        if (not filename) or (not os.path.isfile(filename)):
            return False

        # If the file path was assembled from user input, make sure the file is
        # truely a child of the document root
        filename = os.path.realpath(filename)
        if (not static_filename) and (not filename.startswith(document_root)):
            return False

        # Send the header
        req.send_response(200)

        # Force caching of non-html files
        if filename.endswith(".woff2"):
            req.send_header('Cache-control', 'public,max-age=31536000')
        elif not filename.endswith(".html"):
            req.send_header('Cache-control', 'public,max-age=86400')

        # Set the correct content type
        req.send_header('Content-type', mimetype(filename))
        req.end_headers()
        if head:
            return True

        # Dump the file
        with open(filename, 'rb') as f:
            req.wfile.write(f.read())
        return True

    return _handler


def _handle_error(code, msg=None):
    ERROR_PAGE = '''<!doctype html>
<head><title>{code} {msg}</title></head>
<body><center><h1>{code} {msg}</h1></center>
<hr><center>{name}</center></body>'''

    # If no message is given, try to lookup the correct status code
    if msg is None:
        msg = http.client.responses[code]

    def _handler(req, query=None, match=None, head=False):
        # Send the header
        req.send_response(code)
        req.send_header("Content-type", "text/html; charset=utf-8")
        req.end_headers()
        if head:
            return True

        # Generate the actual HTML
        req.wfile.write(
            ERROR_PAGE.format(code=code,
                              msg=escape(msg),
                              name=os.path.basename(__file__)).encode('utf-8'))
        return True

    return _handler


def _handle_index():
    def _handler(req, query=None, match=None, head=False):
        # Send the response header
        req.send_response(200)
        req.send_header('Content-type', 'text/html; charset=utf-8')
        req.end_headers()
        if head:
            return True

        req.wfile.write(
            INDEX_HTML.format(js=INDEX_JS, css=INDEX_CSS).encode("utf-8"))

    return _handler


def _handle_data(logfile):
    def _handler(req, query=None, match=None, head=False):
        # Send the response header
        req.send_response(200)
        req.send_header('Content-type', 'application/json')
        req.end_headers()
        if head:
            return True

        with open(logfile, 'rb') as f:
            req.wfile.write(b'[')
            first = True
            while True:
                line = f.readline()
                if not line:
                    break
                if not first:
                    req.wfile.write(b',\n ')
                req.wfile.write(line[:-1])
                first = False
            req.wfile.write(b']\n')
        return True

    return _handler


def _handle_endpoints(endpoints):
    def _handler(req, query=None, match=None, head=False):
        # Send the response header
        req.send_response(200)
        req.send_header('Content-type', 'application/json')
        req.end_headers()
        if head:
            return True

        req.wfile.write(json.dumps(endpoints).encode('utf-8'))

    return _handler


def _handle_time():
    def _handler(req, query=None, match=None, head=False):
        # Send the response header
        req.send_response(200)
        req.send_header('Content-type', 'application/json')
        req.end_headers()
        if head:
            return True

        req.wfile.write(
            json.dumps({
                "monotonic": time.monotonic(),
                "unix": time.time()
            }).encode('utf-8'))

    return _handler


def _handle_interval(interval):
    def _handler(req, query=None, match=None, head=False):
        # Send the response header
        req.send_response(200)
        req.send_header('Content-type', 'application/json')
        req.end_headers()
        if head:
            return True

        req.wfile.write(json.dumps(interval).encode('utf-8'))

    return _handler


###############################################################################
# Webserver Request Router                                                    #
###############################################################################


class Route:
    def __init__(self, method, path, callback):
        self.method = method.upper()
        self.path = re.compile(path)
        self.callback = callback

    def exec_on_match(self, req, method, head, path, query):
        if (self.method == "*") or (method == self.method) or head:
            match = self.path.match(path)
            if match:
                return self.callback(req, query, match, head)
        return False


class Router:
    def __init__(self, routes):
        self.routes = routes

    @staticmethod
    def _parse_path(path):
        from urllib.parse import parse_qs

        # Reject malicious paths
        if (len(path) == 0) or (path[0] != '/') or (".." in path):
            return None, None

        # Parse the query string
        query = {}
        if "?" in path:
            path, query = path.split("?", 1)
            query = parse_qs(query)

        return path, query

    def exec(self, req):
        # Fetch the method and the path, reject malformed paths
        method = req.command.upper()
        head = method == "HEAD"
        path, query = self._parse_path(req.path)
        if path is None:
            _handle_error(404)(req, None, head)
            return False
        logger.debug("Router request for path=%s, query=%s", path, repr(query))

        # Try to execute the request
        for route in self.routes:
            if route is None:
                continue
            res = route.exec_on_match(req, method, head, path, query)
            if res or (res is None):
                return True

        # No route matched, issue a 404 error
        _handle_error(404)(req, None, head)
        return False


def _construct_http_server_class(args):
    root = os.path.join(os.path.dirname(__file__), "static")

    router = Router([
        Route("GET", r"^/api/data$", _handle_data(args.logfile)),
        Route("GET", r"^/api/endpoints$", _handle_endpoints(args.endpoints)),
        Route("GET", r"^/api/interval$", _handle_endpoints(args.interval)),
        Route("GET", r"^/api/time$", _handle_time()),
        Route("GET", r"^/(index.html?)?$", _handle_fs(root, "index.html")),
        Route("GET", r"^/(.*)$", _handle_fs(root)),
    ])

    class Server(http.server.BaseHTTPRequestHandler):
        def do_HEAD(self):
            router.exec(self)

        def do_POST(self):
            router.exec(self)

        def do_GET(self):
            router.exec(self)

    return Server


###############################################################################
# Data collection                                                             #
###############################################################################


class Endpoint:
    def __init__(self, idx, ssh_endpoint):
        # Copy the given index
        self._idx = idx

        # Local sequence number
        self._seq_per_connection = 0
        self._seq_connection = 0

        # Split the given "ssh_endpoint" parameters according to shell lexical
        # rules
        self._ssh_endpoint = ssh_endpoint
        self._args = ["ssh"
                      ] + shlex.split(ssh_endpoint) + get_main_client_as_arg()

        # Initialize all other local variables
        self._process = None
        self._stdout_pipe_in, self._stdout_pipe_out = None, None
        self._stderr_pipe_in, self._stderr_pipe_out = None, None
        self._stdin_pipe_in, self._stdin_pipe_out = None, None

        # Timestamps indicating when the last write was
        self._last_write = None

        # Initialize the standard out and standard err buffers
        self._stdout_buf = b""
        self._stderr_buf = b""

    @property
    def name(self):
        return self._ssh_endpoint

    @property
    def idx(self):
        return self._idx

    def increment_seq(self):
        self._seq_per_connection += 1
        return self._seq_per_connection - 1

    def connection_seq(self):
        return self._seq_connection

    @property
    def is_open(self):
        if self._process:
            return self._process.poll() is None
        else:
            return False

    def time_till_next_write(self, ts, interval):
        if not self.is_open:
            # If this endpoint is not open, don't care
            return interval
        elif self._last_write is None:
            # If we did not write to this endpoint at all, we should immediately
            # schedule a write
            return 0.0
        return interval - (ts - self._last_write)

    def open(self):
        import subprocess

        # Abort if the process is still open
        if self.is_open:
            return

        # Make sure that all pipes are closed
        self.close()

        # Create the pipes to communicate with the subprocess
        self._stdout_pipe_in, self._stdout_pipe_out = os.pipe()
        self._stderr_pipe_in, self._stderr_pipe_out = os.pipe()
        self._stdin_pipe_in, self._stdin_pipe_out = os.pipe()

        # Run the process
        logger.debug("Connecting to endpoint %s", self._ssh_endpoint)
        self._process = subprocess.Popen(
            self._args,
            shell=False,
            stdout=self._stdout_pipe_out,
            stderr=self._stderr_pipe_out,
            stdin=self._stdin_pipe_in,
        )

        # Reset the standard out and standard in buffers
        self._stdout_buf = b""
        self._stderr_buf = b""

        # Reset the timestamps
        self._last_write = None

        # Reset the per-connection sequence number and increment the connection
        # number
        self._seq_per_connection = 0
        self._seq_connection += 1

    def close(self):
        # Close the standard in pipe
        if self._stdin_pipe_out:
            os.close(self._stdin_pipe_out)
            self._stdin_pipe_out = None

        # Terminate the process
        if self._process:
            # Try to nicely terminate the process
            self._process.terminate()
            try:
                self._process.wait(timeout=5.0)
            except TimeoutExpired:
                # If being nice didn't work, force-kill the process
                logger.info("Forcefully terminating the child process...")
                self._process.kill()
                self._process.wait()
            finally:
                self._process = None

        # Close all other pipes that may still be open
        for pipe in [
                "_stdout_pipe_out", "_stdout_pipe_in", "_stdin_pipe_out",
                "_stdin_pipe_in", "_stderr_pipe_out", "_stderr_pipe_in"
        ]:
            if not getattr(self, pipe) is None:
                os.close(getattr(self, pipe))
                setattr(self, pipe, None)

    @property
    def write_fds(self):
        return {"stdin": self._stdin_pipe_out}

    @property
    def read_fds(self):
        return {
            "stdout": self._stdout_pipe_in,
            "stderr": self._stderr_pipe_in,
        }

    def _read(self, fd, bufname):
        buf = os.read(fd, 4096)
        if len(buf) <= 0:
            return []

        setattr(self, bufname, getattr(self, bufname) + buf)
        lines = getattr(self, bufname).split(b"\n")
        res = []
        for line in lines[:-1]:
            res.append(str(line, "utf-8"))
        setattr(self, bufname, lines[-1])
        return res

    def read_from_stdout(self):
        return self._read(self._stdout_pipe_in, "_stdout_buf")

    def read_from_stderr(self):
        return self._read(self._stderr_pipe_in, "_stderr_buf")

    def write_to_stdin(self, buf):
        os.write(self._stdin_pipe_out, buf)
        self._last_write = time.monotonic()


done = False


def collect(seq, interval, endpoints):
    """
    This is the heart of the program. This function establishes a connection
    to the given SSH endpoints and sends a (non-icmp) ping message to each of
    them in the given interval.
    """

    res = []

    # Try to connect to endpoints that are not active
    offs = 0
    for i, endpoint in enumerate(endpoints):
        if not endpoint.is_open:
            # Attempt to open the connection to the endpoint
            endpoint.open()

            # Compute a virtual last write depending on the index. This will
            # ensure that the pings are spread out through time
            ts = time.monotonic() - (len(endpoints) -
                                     i) * interval / len(endpoints)
            endpoint._last_write = ts

    # Fetch the next time a read or write is due; collect all read and write fds
    ts = time.monotonic()
    timeout = interval
    read_fds, write_fds, fdmap = [], [], {}
    for endpoint in endpoints:
        endpoint_timeout = endpoint.time_till_next_write(ts, interval)
        if endpoint_timeout <= 0.0:
            for type_, fd in endpoint.write_fds.items():
                fdmap[fd] = (type_, endpoint)
            write_fds.append(fd)
        for type_, fd in endpoint.read_fds.items():
            fdmap[fd] = (type_, endpoint)
            read_fds.append(fd)
        timeout = max(10e-3, min(timeout, endpoint_timeout))

    # Wait for a message from the subprocess or wait for the write pipe to
    # become free
    read_fds, write_fds, _ = select.select(read_fds, write_fds, [], timeout)
    for read_fd in read_fds:
        type_, endpoint = fdmap[read_fd]
        if type_ == "stdout":
            lines = endpoint.read_from_stdout()
            for line in lines:
                if (len(line) >= 2) and (line[0] == '{') and (line[-1] == '}'):
                    try:
                        data = json.loads(line)
                    except json.decoder.JSONDecodeError:
                        data = {}
                    if "error" in data:
                        logger.error("[error from %s]", endpoint.name,
                                     data["error"])
                    if (("i" in data) and ("cs" in data) and ("gs" in data)
                            and ("ls" in data) and ("sst" in data)
                            and ("crt" in data) and isinstance(data["i"], int)
                            and isinstance(data["cs"], int)
                            and isinstance(data["gs"], int)
                            and isinstance(data["ls"], int)
                            and isinstance(data["sst"], float)
                            and isinstance(data["crt"], float)):
                        data.update({"srt": time.monotonic()})
                        res.append(data)
                else:
                    logger.debug("[stdout from %s] %s", endpoint.name, line)
        elif type_ == "stderr":
            lines = endpoint.read_from_stderr()
            for line in lines:
                logger.info("[stderr from %s] %s", endpoint.name, line)
    for write_fd in write_fds:
        type_, endpoint = fdmap[write_fd]
        obj = {
            "gs": seq[0],
            "ls": endpoint.increment_seq(),
            "cs": endpoint.connection_seq(),
            "i": endpoint.idx,
            "sst": time.monotonic()
        }
        endpoint.write_to_stdin((json.dumps(obj) + "\n").encode("utf-8"))
        seq[0] += 1

    return res


def main_collection_thread(logfile, interval, ssh_endpoints):
    global done

    # Construct the endpoints datastructure that holds information about all of
    # the individual connections
    endpoints = []
    for i, ssh_endpoint in enumerate(ssh_endpoints):
        endpoints.append(Endpoint(i, ssh_endpoint))

    # Collect information until the "done" flag is set
    seq = [0]
    if os.path.exists(logfile):
        i = 1
        while os.path.isfile(logfile + "." + str(i)):
            i += 1
        os.rename(logfile, logfile + "." + str(i))
    with open(logfile, 'w') as f:
        while not done:
            objs = collect(seq, interval, endpoints)
            for obj in objs:
                f.write(json.dumps(obj, sort_keys=True) + "\n")
            if len(objs) > 0:
                f.flush()

    # Close all still open endpoints
    for endpoint in endpoints:
        endpoint.close()


###############################################################################
# Server main program                                                         #
###############################################################################


def main_server_construct_argparse():
    import argparse

    parser = argparse.ArgumentParser(
        description=
        "Simple latency monitor for multiple targets. Reconstructs both the incoming and outgoing latency and displays the results as a webpage."
    )
    parser.add_argument(
        "--bind",
        default="127.0.0.1",
        type=str,
        required=False,
        help="Network address to bind the server to. This script should only "
        "be used in conjunction with a reverse proxy such as NGINX.")
    parser.add_argument("--port",
                        default=45699,
                        type=int,
                        required=False,
                        help="Network port to bind the server to.")
    parser.add_argument("--interval",
                        default=1.0,
                        type=float,
                        required=False,
                        help="Ping interval in seconds.")
    parser.add_argument("--verbose",
                        action="store_true",
                        help="If specified, sets the log level to \"DEBUG\".")
    parser.add_argument("--logfile",
                        default="/tmp/pingmonitor.log",
                        help="File to which the collected data is written")
    parser.add_argument(
        'endpoints',
        type=str,
        nargs='+',
        help=
        'List of SSH ednpoints. These parameters are passed in verbatim to SSH; i.e., you can specify "user@host -p 2222" to connect to a server on a specific SSH port.'
    )

    return parser


def main_server(argv):
    global done

    # Parse the arguments
    args = main_server_construct_argparse().parse_args(argv)

    # Increase the verbosity
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Make sure the parsed arguments are valid
    if args.interval <= 0.0:
        print("Interval must be strictly positive.")
        return 1

    # Run the data collection in a separate thread
    collection_thread = threading.Thread(target=main_collection_thread,
                                         args=(args.logfile, args.interval,
                                               args.endpoints))
    collection_thread.start()

    # Run the webserver from the main thread
    Server = _construct_http_server_class(args)
    httpd = socketserver.TCPServer((args.bind, args.port), Server)
    # Wait for the webserver to exit
    logger.info("Serving on http://{}:{}/".format(args.bind, args.port))
    try:
        while True:
            httpd.handle_request()
    except KeyboardInterrupt:
        pass

    # Wait for the collection thread
    logger.info("Waiting for the collection thread to finish")
    done = True
    collection_thread.join()

    return 0


###############################################################################
# Main entry point                                                            #
###############################################################################


def main():
    """
    Either runs the client or server program depending on the second parameter.
    """
    if len(sys.argv) >= 2:
        if sys.argv[1] == "client":
            return main_client()
        elif sys.argv[1] == "server":
            return main_server(sys.argv[2:])
    return main_server(sys.argv[1:])


if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(format='[%(levelname)s] %(message)s',
                        level=logging.INFO)

    sys.exit(main())

