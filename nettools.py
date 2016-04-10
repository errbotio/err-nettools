import dns.resolver
import gzip
import IPy
import logging
import os
import queue
import socket
import threading
import whois

from errbot import arg_botcmd, botcmd, BotPlugin
from subprocess import Popen, PIPE, STDOUT
try:
    from urllib.request import urlretrieve
except ImportError:
    # Python 2
    from urllib import urlretrieve
try:
    import GeoIP
except ImportError as e:
    log = logging.getLogger('errbot.plugins.nettools')
    log.exception("Couldn't import GeoIP, disabling GeoIP functionality (try `pip install geoip`)")
    GeoIP = None


FLAGS = 'http://media.xfire.com/images/flags/%s.gif'
RESULT = """\
     City: %(city)s [%(postal_code)s]
   Region: %(region_name)s [%(region)s]
  Country: %(country_name)s
Time Zone: %(time_zone)s
Longitude: %(longitude)f
 Latitude: %(latitude)f
"""
RBL_OK = 1
RBL_LISTED = 2
RBL_ERROR = 4


def is_valid_ipaddress(address):
    try:
        IPy.IP(address)
    except ValueError:
        return False
    return True


class ThreadedRBLLookup(threading.Thread):
    """
    This class implements a threaded worker which takes RBL addresses
    from in_queue, checks the given address against them and returns
    the result to out_queue.

    Results are always put on the out_queue as a 3-element tuple,
    the first value being the address of the rbl itself, the second
    element being one of the RBL status constants and the third item
    being the reason (or the exception in case of an error).
    """
    def __init__(self, address, in_queue, out_queue):
        threading.Thread.__init__(self)
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.addr = address
        self.log = logging.getLogger('errbot.plugins.nettools.%s' % self.name)
        self.log.debug("RBL worker ready")

    def run(self):
        while True:
            try:
                rbl = self.in_queue.get(timeout=5)
            except queue.Empty:
                self.log.debug("Queue empty, shutting down")
                return

            reverse = IPy.IP(self.addr).reverseName().rstrip("in-addr.arpa").rstrip("ip6.arpa")
            lookup_addr = "%s.%s." % (reverse, rbl)
            try:
                self.log.debug("Checking %s for %s (query addr: %s)", rbl, reverse, lookup_addr)
                response = socket.gethostbyname(lookup_addr)
            except Exception as e:
                # -2: Name or service not known
                # -3: Temporary failure in name resolution
                if e.errno in (-2, -3):
                    self.log.debug("%s not listed in %s", self.addr, rbl)
                    self.out_queue.put((rbl, RBL_OK, None))
                else:
                    self.log.warning("Lookup of %s failed with: %s", lookup_addr, e)
                    self.out_queue.put((rbl, RBL_ERROR, e))
            else:
                self.log.debug("%s listed in %s: %s", self.addr, rbl, response)
                txt_records = dns.resolver.query(lookup_addr, "TXT")
                reason = ", ".join([r.to_text() for r in txt_records])
                self.out_queue.put((rbl, RBL_LISTED, reason))


class Nettools(BotPlugin):
    """Various tools to query info about IPs, networks and domain names"""

    def activate(self):
        self.gi = None
        if GeoIP is not None:
            threading.Thread(target=self.init_geoip).start()

        rblfile = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "rbls.txt"), 'r')
        self.rbl_list = [l.strip() for l in rblfile]
        rblfile.close()

        super(Nettools, self).activate()

    def deactivate(self):
        self.gi = None
        super(Nettools, self).deactivate()

    def init_geoip(self):
        """Initialize the GeoIP database, downloading it first if needed."""
        GEOIP_DB = os.path.join(self.bot_config.BOT_DATA_DIR, 'GeoLiteCity.dat')
        if not os.path.exists(GEOIP_DB + '.gz'):
            self.log.info('Downloading the GeoIP database')
            urlretrieve("http://www.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz", GEOIP_DB + '.gz')
        if not os.path.exists(GEOIP_DB):
            self.log.info('Gunzipping the GeoIP database')
            with open(GEOIP_DB, 'w+b') as f:
                f.write(gzip.open(GEOIP_DB + '.gz').read())
        self.gi = GeoIP.open(GEOIP_DB, GeoIP.GEOIP_STANDARD)

    def execute(self, cmd, args):
        """Execute a command and return it's result
        Args:
            cmd: A string pointing to the executable to run
            args: A list of arguments to pass to the executable
        Returns: String containing output
        """
        try:
            return Popen([cmd] + args, stdout=PIPE, stderr=STDOUT).communicate()[0].decode('utf-8')
        except OSError as e:
            self.log.exception(e)
            return "Failed to run {0}: {1}".format(cmd, e)

    @arg_botcmd("address", help="a hostname or IP address to look up", unpack_args=False)
    def geoip(self, mess, args):
        """
        Display geographical information about the given hostname or IP address.
        """
        if GeoIP is None:
            return "Sorry, I cannot do that. geoip isn't available because the GeoIP module couldn't be initialized."
        if self.gi is None:
            return "The GeoIP database isn't available right now. Please try again later."

        if is_valid_ipaddress(args.address):
            result = self.gi.record_by_addr(args.address)
        else:
            result = self.gi.record_by_name(args.address)
        if result is None:
            return "Couldn't find any record for %s" % args.address
        return RESULT % result

    @arg_botcmd("domain", help="the domainname or IP address to perform a whois query on", unpack_args=False)
    def whois(self, mess, args):
        """
        Display whois information about a given IP/domainname.
        """
        domain = whois.query(args.domain)
        return '\n'.join(['%25s : %s' % (k, v) for k, v in domain.__dict__.items()])

    @botcmd(template="codeblock")
    def dig(self, mess, args):
        """Call 'dig'"""
        return {'code': self.execute('dig', args.split())}

    @botcmd(template="codeblock")
    def nslookup(self, mess, args):
        """Call 'nslookup'"""
        args = args.split()
        if len(args) < 1 or args[0] in ('-', '-interactive'):
            # Passing no arguments, or with first argument beginning with - or -interactive
            # to nslookup causes it to hang due to dropping into interactive mode.
            # Using self.send() here avoids the template.
            self.send(
                identifier=mess.frm,
                in_reply_to=mess,
                text="Sorry, interactive mode is not supported"
            )
            return
        else:
            return {'code': self.execute('nslookup', args)}

    @botcmd(template="codeblock")
    def host(self, mess, args):
        """Call 'host'"""
        return {'code': self.execute('host', args.split())}

    @arg_botcmd("-t", "--threads", type=int, default=5, help="number of threads to use for lookup")
    @arg_botcmd("address", help="a hostname or IP address to look up", unpack_args=False)
    def check_rbl(self, mess, args):
        """
        Perform an RBL lookup for a given hostname or IP address.
        """
        addr = args.address
        if not is_valid_ipaddress(args.address):
            try:
                addr = socket.gethostbyname(args.address)
                yield "Resolved {host} to {ip}".format(host=args.address, ip=addr)
            except Exception as e:
                yield "Couldn't resolve {host}: {e!s}".format(host=args.address, e=e)
                return

        num_rbls = len(self.rbl_list)
        yield "Checking {count} RBLs for {addr}, please be patient.".format(
            count=num_rbls, addr=addr
        )
        rbl_queue = queue.Queue()
        result_queue = queue.Queue()
        for rbl in self.rbl_list:
            rbl_queue.put(rbl)
        for _ in range(args.threads):
            t = ThreadedRBLLookup(addr, rbl_queue, result_queue)
            t.setDaemon(True)
            t.start()

        num_results = 0
        num_blacklisted = 0
        while num_results < num_rbls:
            rbl, state, reason = result_queue.get(timeout=120)
            num_results += 1

            if state == RBL_LISTED:
                yield "{addr} is blacklisted on {rbl} ({reason}).".format(
                    addr=addr, rbl=rbl, reason=reason)
                num_blacklisted += 1
            elif state == RBL_ERROR:
                yield "Querying {rbl} failed with: {reason}".format(
                    rbl=rbl, reason=reason)
        yield "{addr} is blacklisted on {blacklisted} out of {total} RBLs.".format(
            addr=addr, blacklisted=num_blacklisted, total=num_rbls)
