import dpkt
import socket
import pygeoip

# Initialize GeoIP with the path to the GeoLiteCity.dat file
gi = pygeoip.GeoIP('GeoLiteCity.dat')


def retKML(dstip, srcip):
    try:
        # Perform GeoIP lookup for the destination IP
        dst = gi.record_by_name('102.184.159.7')
        # Perform GeoIP lookup for the source IP (even if it's private)
        src = gi.record_by_name('172.16.20.65')

        # Check if the GeoIP lookup for the destination was successful
        if dst is None:
            print(f"GeoIP lookup failed for destination IP: {dstip}")
            return ''

        # For the source IP, we can still get the coordinates even if it's private
        srclongitude = src['longitude'] if src else None
        srclatitude = src['latitude'] if src else None

        dstlongitude = dst['longitude']
        dstlatitude = dst['latitude']

        kml = (
                  '<Placemark>\n'
                  '<name>%s</name>\n'
                  '<extrude>1</extrude>\n'
                  '<tessellate>1</tessellate>\n'
                  '<styleUrl>#transBluePoly</styleUrl>\n'
                  '<LineString>\n'
                  '<coordinates>%6f,%6f\n%6f,%6f</coordinates>\n'
                  '</LineString>\n'
                  '</Placemark>\n'
              ) % (
              dstip, dstlongitude, dstlatitude, srclongitude if srclongitude else 0, srclatitude if srclatitude else 0)

        return kml
    except Exception as e:
        print(f"Error in retKML: {e}")
        return ''


def plotIps(pcap):
    kmlPts = ''
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)  # Parse Ethernet frame
            ip = eth.data  # Extract IP layer

            # Check if the packet is an IP packet
            if isinstance(ip, dpkt.ip.IP):
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                print(f"Processing packet: src={src}, dst={dst}")  # Debugging output
                KML = retKML(dst, src)
                kmlPts += KML
            else:
                print("Packet is not an IP packet.")
        except Exception as e:
            print(f"Error processing packet: {e}")
            continue
    return kmlPts


def main():
    with open('data1.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        kmlheader = '<?xml version="1.0" encoding="UTF-8"?>\n' \
                    '<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n' \
                    '<Style id="transBluePoly">' \
                    '<LineStyle>' \
                    '<width>1.5</width>' \
                    '<color>501400E6</color>' \
                    '</LineStyle>' \
                    '</Style>'
        kmlfooter = '</Document>\n</kml>\n'
        kml_data = plotIps(pcap)
        kmldoc = kmlheader + kml_data + kmlfooter

        # Print the KML document
        if kml_data:
            print(kmldoc)
        else:
            print("No KML data generated.")


if __name__ == "__main__":
    main()