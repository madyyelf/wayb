from scapy.all import *
from pygle import network
from gmplot import gmplot
import random
import requests
from prettytable import PrettyTable

apList = []
deviceList = []



class wifiDevice():
    mac = "00:00:00:00:00:00"
    vendor = "None"
    color = "red"
    beacons = []

    def __init__(self,p_mac):
        self.mac = p_mac
        self.vendor = self.getVendor()
        self.color = "red"
        self.beacons = []
    def __str__(self):
        value = str("MAC: "+self.mac+" ("+self.vendor+")")
        return self.mac
    def setColor(self,p_color):
        self.color=p_color
    def getVendor(self):
        try:
            response = requests.get('http://api.macvendors.com/'+self.mac).text
            if response == '{"errors":{"detail":"Page not found"}}':
                return "None"
            else:
                return response
        except ValueError:
            return "None"
    def addBeacon(self,p_ssid):
        self.beacons.append(p_ssid)

class AP():
    ssid = ""
    locations = []

    def __init__(self,p_ssid):
        self.ssid = p_ssid
        self.locations = []
    def __str__(self):
        return self.ssid
    def localize(self):
        try:
            results = network.search(lastupdt="20180101",ssid=self.ssid,resultsPerPage=1000)['results']
        except ValueError:
            results = []
        for result in results:
            self.locations.append({"lat":result["trilat"],"long":result["trilong"]})

class apPlot():
    gmap = None
    file = None

    def __init__(self,p_file):
        self.gmap = gmplot.GoogleMapPlotter (41.73804855,1.827618,3)
        self.file = p_file
    def plot(self,p_devices,p_APs):
        for device in p_devices:
            for beacon in device.beacons:
                for ap in p_APs:
                    if beacon == ap.ssid:
                        for location in ap.locations:
                            self.gmap.marker(location["lat"],location["long"],title=ap.ssid ,color=device.color)
        self.gmap.draw("wayb.html")

        

def sniffProbe(p):
    # macAddress = []
    map = apPlot("wayb.html")
    colors = ["gray","green","orange","purple","red","white","yellow","black","blue","brown"]    
    if p.haslayer(Dot11ProbeReq):
        netName = p.getlayer(Dot11ProbeReq).info
        deviceMAC = p.addr2
        if netName != "":
            if not any(deviceMAC in dev.mac for dev in deviceList):
                newDevice = wifiDevice(deviceMAC)
                newDevice.setColor(colors[len(deviceList)%len(colors)])
                deviceList.append(newDevice)
                
            for device in deviceList:
                if device.mac == deviceMAC:
                    if netName not in device.beacons:
                        device.addBeacon(netName)
                
            if not any(netName in ap.ssid for ap in apList):
                newAP = AP(netName)
                newAP.localize()
                apList.append(newAP)
            printResults(deviceList,apList)
            map.plot(deviceList,apList)
            

def printResults(p_devices,p_APs):
    table = PrettyTable(['ID','MAC','VENDOR','COLOR','SSID','LOCATED'])
    for device in p_devices:
        table.add_row([p_devices.index(device),device.mac,device.vendor,device.color,'',''])
        for ap in device.beacons:
            located = "No"
            for ap2 in p_APs:
                if ap == ap2.ssid and len(ap2.locations)>0:
                    located = "Yes"
            table.add_row(['','','','',ap,located])

    print "\033[H\033[J"
    print "[+] Devices detecte:"
    print table
    print "[+] Map plotted, press Ctrl+C to exit..."
     

if __name__ == '__main__':
    interface = 'wlan0mon'
    sniff(iface=interface, prn=sniffProbe)
    for i in range(10):
        print "blucle",i
