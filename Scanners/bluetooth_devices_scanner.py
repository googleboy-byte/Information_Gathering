import bluetooth
import sys

def get_b_devices():

    print("\nScanning started...")
    nearby_devices = bluetooth.discover_devices(lookup_names = True)
    print("found %d devices" % len(nearby_devices))
    for name, addr in nearby_devices:
        print(" %s - %s" % (addr, name))

if __name__ == "__main__":

    start_scan = input("Start scan ? y/n: ")
    if "y" in start_scan:
        get_b_devices()
    else:
        sys.exit(1)
