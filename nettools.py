import gzip
import os
import GeoIP
import socket
import threading
import whois

from errbot import arg_botcmd, BotPlugin
try:
    from urllib.request import urlretrieve
except ImportError:
    # Python 2
    from urllib import urlretrieve


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
        threading.Thread(target=self.init_geoip).start()
        super(Nettools, self).activate()

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

    def deactivate(self):
        self.gi = None

    @arg_botcmd("address", help="a hostname or IP address to look up", unpack_args=False)
    def geoip(self, mess, args):
        """
        Display geographical information about the given hostname or IP address.
        """
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
