from django.shortcuts import render
from django.core.files.storage import FileSystemStorage
from django.conf import settings
import os
from werkzeug.utils import secure_filename
import dpkt
import socket
import pygeoip
from datetime import datetime

ALLOWED_EXTENSIONS = set(['pcap'])
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS 

gi = pygeoip.GeoIP('GeoDB/GeoLiteCity.dat')

def retKML(dstip, srcip):
    dst = gi.record_by_name(dstip)
    src = gi.record_by_name('84.36.228.131')
        
    try:

        dstlongitude = dst['longitude']
        dstlatitude = dst['latitude']
            
        srclongitude = src['longitude']
        srclatitude = src['latitude']
            
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
        )%(dstip, dstlongitude, dstlatitude, srclongitude, srclatitude)
            
        return kml
    except:
        return ''

def plotIPs(pcap):
    kmlPts = ''
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            KML = retKML(dst, src)
            kmlPts = kmlPts + KML
        except:
            pass
        
    return kmlPts


def build(data_file):
    f = open(data_file, 'rb')

    pcap = dpkt.pcap.Reader(f)

    kmlheader = '<?xml version="1.0" encoding="UTF-8"?> \n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n'\
        '<Style id="transBluePoly">' \
                    '<LineStyle>' \
                    '<width>1.5</width>' \
                    '<color>501400E6</color>' \
                    '</LineStyle>' \
                    '</Style>'

    kmlfooter = '</Document>\n</kml>\n'

    kmldoc = kmlheader + plotIPs(pcap) + kmlfooter

    return kmldoc


def home(request):
    KML_file = ''
    is_KML = False
    if request.method == 'POST':
        uploaded_file = request.FILES['wireshark']
        
        File_System = FileSystemStorage()
        if uploaded_file and allowed_file(uploaded_file.name):
            filename = secure_filename(uploaded_file.name)
            File_System.save(filename, uploaded_file)

        data_file = 'upload_temp/'+ uploaded_file.name
        KML_Result = build(data_file)
        now = datetime.now().strftime("%m_%d_%y%H_%M_%S")
        strNow = str(now)
        KML_file = 'KML_files/' + strNow + '.kml'
        KML_Out = open(KML_file, 'x')
        KML_Out.write(KML_Result)
        is_KML = True


    return render(request, 'index.html', {"kml" : KML_file, "is_kml" : is_KML})


