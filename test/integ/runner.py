"""
Starts and stops test instances for integration tests.
"""

import os
import sys
import time
import signal
import tempfile
import subprocess

from stem.util import term

# number of seconds before we time out our attempt to start a tor instance
TOR_INIT_TIMEOUT = 30

BASIC_TORRC = """# configuration for stem integration tests
DataDirectory %s
ControlPort 1111
"""

class Runner:
  def __init__(self):
    self._test_dir = tempfile.mktemp("-stem-integ")
    self._torrc_contents = BASIC_TORRC % self._test_dir
    self._tor_process = None
  
  def run_setup(self):
    """
    Makes a temporary directory for the runtime resources of our integ tests.
    
    Raises:
      OSError if unsuccessful
    """
    
    print term.format("Setting up a test instance...", term.Color.BLUE, term.Attr.BOLD)
    
    # makes a temporary directory for the runtime resources of our integ test
    try:
      sys.stdout.write(term.format("  making test directory (%s)... " % self._test_dir, term.Color.BLUE, term.Attr.BOLD))
      os.makedirs(self._test_dir)
      sys.stdout.write(term.format("done\n", term.Color.BLUE, term.Attr.BOLD))
    except OSError, exc:
      sys.stdout.write(term.format("failed (%s)\n" % exc, term.Color.RED, term.Attr.BOLD))
      raise exc
    
    # writes our testing torrc
    torrc_dst = os.path.join(self._test_dir, "torrc")
    try:
      sys.stdout.write(term.format("  writing torrc (%s)... " % torrc_dst, term.Color.BLUE, term.Attr.BOLD))
      
      torrc_file = open(torrc_dst, "w")
      torrc_file.write(self._torrc_contents)
      torrc_file.close()
      
      sys.stdout.write(term.format("done\n", term.Color.BLUE, term.Attr.BOLD))
      
      for line in self._torrc_contents.strip().split("\n"):
        print term.format("    %s" % line.strip(), term.Color.BLUE)
    except Exception, exc:
      sys.stdout.write(term.format("failed (%s)\n" % exc, term.Color.RED, term.Attr.BOLD))
      raise exc
    finally:
      print # extra newline
  
  def start(self):
    """
    Initializes a tor process. This blocks until initialization completes or we
    error out.
    
    Raises:
      OSError if we either fail to create the tor process or reached a timeout
      without success
    """
    
    print term.format("Starting tor...", term.Color.BLUE, term.Attr.BOLD)
    start_time = time.time()
    
    try:
      # terminate our previous instance before continuing if we had one
      if self._tor_process: self._tor_process.kill()
      
      # double check that we have a torrc to work with
      torrc_dst = os.path.join(self._test_dir, "torrc")
      if not os.path.exists(torrc_dst):
        raise OSError("torrc doesn't exist (%s)" % torrc_dst)
      
      # starts a tor subprocess, raising an OSError if it fails
      self._tor_process = subprocess.Popen(["tor", "-f", torrc_dst], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
      
      # time ourselves out if we reach TOR_INIT_TIMEOUT
      def timeout_handler(signum, frame):
        # terminates the uninitialized tor process and raise on timeout
        self._tor_process.kill()
        raise OSError("reached a %i second timeout without success" % TOR_INIT_TIMEOUT)
      
      signal.signal(signal.SIGALRM, timeout_handler)
      signal.alarm(TOR_INIT_TIMEOUT)
      
      while True:
        init_line = self._tor_process.stdout.readline().strip()
        
        # this will provide empty results if the process is terminated
        if not init_line:
          self._tor_process.kill() # ... but best make sure
          raise OSError("process terminated")
        
        print term.format("  %s" % init_line, term.Color.BLUE)
        
        # return the process if we're done with bootstrapping
        if init_line.endswith("Bootstrapped 100%: Done."):
          print term.format("  done (%i seconds)" % (time.time() - start_time), term.Color.BLUE, term.Attr.BOLD)
          return
    except OSError, exc:
      print term.format("  failed to start tor: %s" % exc, term.Color.RED, term.Attr.BOLD)
      raise exc
    finally:
      print # extra newline
  
  def stop(self):
    """
    Terminates our tor instance.
    """
    
    if self._tor_process:
      sys.stdout.write(term.format("Shutting down tor... ", term.Color.BLUE, term.Attr.BOLD))
      self._tor_process.kill()
      sys.stdout.write(term.format("done\n", term.Color.BLUE, term.Attr.BOLD))
      print # extra newline

