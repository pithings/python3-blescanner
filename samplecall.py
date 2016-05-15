import scanner

beaconScanner = scanner.IBeaconDiscoveryService()
try:
  beaconScanner.scan(debug=False)
finally:
  beaconScanner.close()
