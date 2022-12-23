#!/usr/bin/python3

####################################################################
# Build for multiple targets.
# Targets names and toolchains are read from /etc/multibuild.yaml
####################################################################

import yaml
import os

def main():
    with open("/etc/multibuild.yaml", 'r') as stream:
        document = yaml.safe_load(stream)
        for key in document:
            toolchain = document[key]
            print("Build for {} with {}".format(key, toolchain))
            os.system("O=build-{} CC={} make all -j13".format(key, toolchain))

if __name__ == "__main__":
    main()
