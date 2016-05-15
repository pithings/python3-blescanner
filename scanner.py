# BLE iBeaconScanner based on https://github.com/adamf/BLE/blob/master/ble-scanner.py
# BLE scanner based on https://github.com/adamf/BLE/blob/master/ble-scanner.py
# BLE scanner, based on https://code.google.com/p/pybluez/source/browse/trunk/examples/advanced/inquiry-with-rssi.py

# https://github.com/pauloborges/bluez/blob/master/tools/hcitool.c for lescan
# https://kernel.googlesource.com/pub/scm/bluetooth/bluez/+/5.6/lib/hci.h for opcodes
# https://github.com/pauloborges/bluez/blob/master/lib/hci.c#L2782 for functions used by lescan

import os
import sys
import struct

LE_META_EVENT = 0x3e
LE_PUBLIC_ADDRESS=0x00
LE_RANDOM_ADDRESS=0x01
LE_SET_SCAN_PARAMETERS_CP_SIZE=7
OGF_LE_CTL=0x08
OCF_LE_SET_SCAN_PARAMETERS=0x000B
OCF_LE_SET_SCAN_ENABLE=0x000C
OCF_LE_CREATE_CONN=0x000D

LE_ROLE_MASTER = 0x00
LE_ROLE_SLAVE = 0x01

# these are actually subevents of LE_META_EVENT
EVT_LE_CONN_COMPLETE=0x01
EVT_LE_ADVERTISING_REPORT=0x02
EVT_LE_CONN_UPDATE_COMPLETE=0x03
EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE=0x04

# Advertisment event types
ADV_IND=0x00
ADV_DIRECT_IND=0x01
ADV_SCAN_IND=0x02
ADV_NONCONN_IND=0x03
ADV_SCAN_RSP=0x04

from enum import Enum

class BeaconType(Enum):
  UNKNOWN = 0
  IBEACON = 1

class Beacon:
  beacontype = BeaconType.UNKNOWN
  mac = None
  udid = None
  major = 0
  minor = 0
  txPower = 0

  def getType(self): return self.beacontype

  def getUniqueId(self): return bytesToString(self.udid) + bytesToString(self.major) + bytesToString(self.minor)

  def setMac(self,mac): self.mac = mac
  def getMac(self): return bytesToString(self.mac)
  def getPrintableMac(self): return bytesToStringWithColumns(self.mac)

  def setUDID(self,udid): self.udid = udid
  def getUDID(self): return self.udid
  def getPrintableUDID(self): return bytesToStringWithColumns(self.udid)

  def setMajor(self, major): self.major = major
  def getMajor(self): return self.major
  def getPrintableMajor(self): return bytesToStringWithColumns(self.major)

  def setMinor(self, minor): self.minor = minor
  def getMinor(self): return self.minor
  def getPrintableMinor(self): return bytesToStringWithColumns(self.minor)

  def setTxPower(self, txPower): self.txPower = int.from_bytes(txPower, byteorder='big', signed=False)
  def getTxPower(self): return self.txPower

  def print(self):
    if self.beacontype != BeaconType.UNKNOWN:
      print("Type: ", self.beacontype)
      print("Mac: ", self.getPrintableMac())
      print("UDID:", self.getPrintableUDID())
      print("Major:", self.getPrintableMajor())
      print("Minor:", self.getPrintableMinor())
      print("TxPower:", self.txPower)

class IBeacon(Beacon):
  def __init__(self):
    self.beacontype = BeaconType.IBEACON

class BeaconFactory(object):
  MAC_START_INDEX = 3
  MAC_END_INDEX = 9
  UDID_START_INDEX = 19
  UDID_END_INDEX = 35
  MAJOR_START_INDEX = 35
  MAJOR_END_INDEX = 37
  MINOR_START_INDEX = 37
  MINOR_END_INDEX = 39
  ADVERTISING_FLAGS = 10
  ADVERTISING_HEADER = 13
  COMPANY_ID = 15
  IBEACON_TYPE = 17
  IBEACON_LENGTH = 18
  TX_POWER = 39

  IBEACON_PREFIX = [0x02,0x01,0x06,0x1a,0xff,0x4c,0x00,0x02,0x15]

  @staticmethod
  def create(pkt):
    beacon = None
    ibeaconTest = True
    index = 0
    while (ibeaconTest and index < len(BeaconFactory.IBEACON_PREFIX)):
      ibeaconTest = (BeaconFactory.IBEACON_PREFIX[index] == pkt[BeaconFactory.ADVERTISING_FLAGS+index])
      index = index + 1
    if ibeaconTest:
      beacon = IBeacon()
      beacon.setMac(pkt[BeaconFactory.MAC_START_INDEX:BeaconFactory.MAC_END_INDEX])
      beacon.setUDID(pkt[BeaconFactory.UDID_START_INDEX:BeaconFactory.UDID_END_INDEX])
      beacon.setMajor(pkt[BeaconFactory.MAJOR_START_INDEX:BeaconFactory.MAJOR_END_INDEX])
      beacon.setMinor(pkt[BeaconFactory.MINOR_START_INDEX:BeaconFactory.MINOR_END_INDEX])
      beacon.setTxPower(pkt[BeaconFactory.TX_POWER:BeaconFactory.TX_POWER+1])
    else:
      beacon = Beacon()
    return beacon

def bytesToStringWithSep(separator, bytes):
  return separator.join("%02x" % int(b) for b in bytes)

def bytesToString(bytes):
  return bytesToStringWithSep("",bytes)

def bytesToStringWithColumns(bytes):
  return bytesToStringWithSep(":",bytes)
  
class IBeaconDiscoveryService:
  import bluetooth._bluetooth as bluez

  sock = 0
  dev_id = 0
  discovered = []

  def __init__(self,d=0):
    self.dev_id = d
    self.sock = self.bluez.hci_open_dev(self.dev_id)
    self.hci_enable_le_scan()

  def scan(self,debug=False):
    old_filter = self.sock.getsockopt( self.bluez.SOL_HCI, self.bluez.HCI_FILTER, 14)

    # perform a device inquiry on bluetooth device #0
    # The inquiry should last 8 * 1.28 = 10.24 seconds
    # before the inquiry is performed, bluez should flush its cache of
    # previously discovered devices
    flt = self.bluez.hci_filter_new()
    self.bluez.hci_filter_all_events(flt)
    self.bluez.hci_filter_set_ptype(flt, self.bluez.HCI_EVENT_PKT)
    self.sock.setsockopt( self.bluez.SOL_HCI, self.bluez.HCI_FILTER, flt )

    print(self.parse_events(20,debug))

    self.sock.setsockopt( self.bluez.SOL_HCI, self.bluez.HCI_FILTER, old_filter )

  def close(self):
    self.hci_disable_le_scan()

  def hci_enable_le_scan(self):
    self.hci_toggle_le_scan(0x01)

  def hci_disable_le_scan(self):
    self.hci_toggle_le_scan(0x00)

  def hci_toggle_le_scan(self, enable):
    cmd_pkt = struct.pack("<BB", enable, 0x00)
    self.bluez.hci_send_cmd(self.sock, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, cmd_pkt)

  def parse_events(self, loop_count=100, debug=False):
    devicesFound = {}
    for i in range(0, loop_count):
      pkt = self.sock.recv(255)
      if debug:
        print("fullpacket: ", bytesToStringWithColumns(pkt))

      ptype, event, plen = struct.unpack("BBB", pkt[:3])
      if event == LE_META_EVENT:
        subevent, = struct.unpack("B", pkt[3:4])
        pkt = pkt[4:]
        if subevent == EVT_LE_ADVERTISING_REPORT:
          num_reports = struct.unpack("B", pkt[0:1])[0]
          report_pkt_offset = 0
          for i in range(0, num_reports):
            beacon = BeaconFactory.create(pkt)
            if beacon != None:
              if beacon.getType() == BeaconType.IBEACON:
                devicesFound[beacon.getUniqueId()] = beacon.getMac()

              if debug:
                beacon.print()
                print("=====")

    return devicesFound
