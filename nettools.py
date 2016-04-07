import gzip
import logging
import os
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


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False
    return True


class Nettools(BotPlugin):
    """Various tools to query info about IPs, networks and domain names"""

    def activate(self):
        self.gi = None
        if GeoIP is not None:
            threading.Thread(target=self.init_geoip).start()
        super(Nettools, self).activate()

    def deactivate(self):
        self.gi = None

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

        if is_valid_ipv4_address(args.address):
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
