# Pivot Detection Agent
```
usage: stitch.py [-h] [-s SIZE] [-t TIME] [-m MASK] [-l LOGDIR] [-d DEVICES]
                 [-e ENDPOINTTHRESHOLD]

Monitor specified interfaces for suspicious lateral movement.

options:
  -h, --help            show this help message and exit
  -s SIZE, --size SIZE  Size window in bytes
  -t TIME, --time TIME  Time window in miliseconds
  -m MASK, --mask MASK  Endpoint IP mask in 0x<hex-value> (e.g. 0xFFFFFFFF)
  -l LOGDIR, --logDir LOGDIR
                        Output to specified log directory
  -d DEVICES, --devices DEVICES
                        Devices to monitor (comma separated list)
  -e ENDPOINTTHRESHOLD, --endpointThreshold ENDPOINTTHRESHOLD
                        Number of visits after which endpoints are ignored.
```
