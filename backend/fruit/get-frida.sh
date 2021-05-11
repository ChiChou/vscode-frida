#!/bin/sh

if ! sysctl machdep.cpu.brand_string | grep -q "Apple processor"; then
  echo "This script is for Apple device only"
  echo "Usage: ssh ios 'sh -s' < $0"
  exit -1
fi

FILE=/etc/apt/sources.list.d/cydia.list

if ! grep -q build.frida.re $FILE; then
  echo "deb https://build.frida.re/ ./" >> $FILE
fi

apt-get update

#define CPUFAMILY_ARM_VORTEX_TEMPEST    0x07d34b9f
#define CPUFAMILY_ARM_LIGHTNING_THUNDER 0x462504d2

if sysctl hw.cpufamily | grep -Eq "^hw.cpufamily: (131287967|-3118136110)$"
then
  # A12
  PKG=re.frida.server64
elif sysctl hw.optional.arm64 | grep -q "hw.optional.arm64: 1"
then
  # ARM64
  PKG=re.frida.server
else
  # 32bit
  PKG=re.frida.server32
fi

echo apt-get install $PKG