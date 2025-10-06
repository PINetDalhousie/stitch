import argparse
import pathlib

DEFAULT_T = 1000
DEFAULT_S = 6500
DEFAULT_D = 'eno1'
DEFAULT_M = 0xFFFFFFFF
DEFAULT_E = 10

def args_parser():
    parser = argparse.ArgumentParser(description='Monitor specified interfaces for suspicious lateral movement.')

    parser.add_argument('-s', '--size', type=int, default=DEFAULT_S, help="Size window in bytes")
    parser.add_argument('-t', '--time', type=int, default=DEFAULT_T, help="Time window in miliseconds")
    parser.add_argument('-m', '--mask', type=str, default=DEFAULT_M, help="Endpoint IP mask in 0x<hex-value> (e.g. 0xFFFFFFFF)")
    parser.add_argument('-l', '--logDir', type=pathlib.Path, help="Output to specified log directory")
    parser.add_argument('-d', '--devices', type=str, default=DEFAULT_D, help="Devices to monitor (comma separated list)")
    parser.add_argument('-e', '--endpointThreshold', type=str, default=DEFAULT_E, help="Number of visits after which endpoints are ignored.")


    args = parser.parse_args()
    return args