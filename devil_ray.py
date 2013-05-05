#!/usr/bin/env python2.7

import base64
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import cStringIO
import hashlib
import hmac
from itertools import chain, ifilter, imap
import sys
from time import gmtime, strftime
import urllib2
from urlparse import urlparse
import yaml

DEBUG = False

CONFIG = None

CHUNK_SIZE = 4096

# From http://docs.python.org/2/library/time.html
def rfc_2822_now():
  return strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())

def is_amz_key(key):
  return key.startswith("x-amz-")

def prepare_headers(headers):
  if not headers:
    return
  for key in headers.keys():
    key = key.lower()
    if is_amz_key(key):
      yield (key, headers[key])

def Status(Error):

  def __init__(code):
    self.code = code

class Handler(BaseHTTPRequestHandler):

  def _debug(self):
    self.send_response(200)
    self.end_headers()
    self.wfile.close()
    print("BEGIN")
    print(self._s3_url())
    headers = self._s3_headers()
    for key in headers.keys():
      print("%s: %s" % (key, headers[key]))
    print("END\n")

  def do_GET(self):
    if DEBUG:
      self._debug()
      return
    try:
      req = urllib2.Request(self._s3_url(), None, self._s3_headers())
    except Status as status:
      self.send_response(status.code)
      self.end_headers()
      self.wfile.close()
      return
    try:
      resp = urllib2.urlopen(req)
    except urllib2.HTTPError as err:
      resp = err
    self.send_response(resp.getcode())
    resp_headers = resp.info()
    for key in resp_headers.keys():
      # TODO support transfer-encoding: chunked
      if key.lower() != "transfer-encoding":
        self.send_header(key, resp_headers.get(key))
    self.end_headers()
    # TODO read and write in parallel?
    chunk = None
    while chunk != "":
      chunk = resp.read(CHUNK_SIZE)
      self.wfile.write(chunk)
    self.wfile.close()
    resp.close()

  def _s3_url(self):
    if not self.path.startswith("/"):
      raise Status(400)
    parts = self.path[1:].split("/", 1)
    if len(parts) == 0:
      domain = "s3.amazonaws.com"
    else:
      domain = parts[0] + ".s3.amazonaws.com"
    if len(parts) < 2:
      path = ""
    else:
      path = parts[1]
    return "http://" + domain + "/" + path

  def _s3_headers(self):
    date = rfc_2822_now()
    headers = {}
    # Date header
    headers["date"] = date
    # Headers from the request
    for key in self.headers:
      if key.lower() != "host":
        headers[key] = self.headers[key]
    # Headers from the config file
    c_headers = CONFIG["headers"]
    if c_headers:
      for key in c_headers:
        headers[key] = c_headers[key]
    # Authorization header
    # TODO pass the existing headers down into self._hmac so it doesn't
    # have to iterate over all the separate header sources again
    auth_value = "AWS %s:%s" % (CONFIG["key"]["id"], self._hmac(date))
    headers["Authorization"] = auth_value
    return headers

  def _hmac(self, date):
    with open(CONFIG["key"]["secret_file"], "r") as secret:
      h = hmac.new(secret.read().strip(), self._canonical(date), hashlib.sha1)
      secret.close()
      return base64.b64encode(h.digest())

  def _canonical(self, date):
    buffer = cStringIO.StringIO()
    buffer.write(self.command)
    buffer.write("\n")
    buffer.write(self.headers.get("Content-MD5", ""))
    buffer.write("\n")
    buffer.write(self.headers.get("Content-Type", ""))
    buffer.write("\n")
    buffer.write(self.headers.get("Date", date))
    buffer.write("\n")
    self._canonical_amz_headers(buffer)
    self._canonical_resource(buffer)
    value = buffer.getvalue()
    buffer.close()
    return value

  def _canonical_resource(self, buffer):
    buffer.write(self.path)
    # TODO
    # Handle sub-resources

  def _canonical_amz_headers(self, buffer):
    # TODO
    # Handle continuation lines
    # Handle multiple headers with the same key
    config_headers = prepare_headers(CONFIG["headers"])
    request_headers = prepare_headers(self.headers)
    headers = list(chain(config_headers, request_headers))
    headers.sort()
    for (key, value) in headers:
      buffer.write(key)
      buffer.write(":")
      buffer.write(value)
      buffer.write("\n")

def load_yaml(path):
  with open(path, "r") as handle:
    return yaml.safe_load(handle)

def main():
  global CONFIG 
  CONFIG = load_yaml("s3.yaml")
  listen = (CONFIG["listen"]["address"], CONFIG["listen"]["port"])
  server = HTTPServer(listen, Handler)
  # TODO handle simultaneous requests?
  while True:
    print("Ready for a request...")
    server.handle_request()

if __name__ == "__main__":
  main()

