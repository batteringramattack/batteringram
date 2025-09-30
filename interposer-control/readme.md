# Simple open-drain switcher using Pi Pico

This directory contains the RPi Pico code to drive the simple open-drain switches on the DDR4 interposer. This code has been tested using the Pico 1 and Pico 2.

## Building

Assuming you have the Pi Pico SDK in `~/pico/pico-sdk/`, do the following:

```
export PICO_SDK_PATH=~/pico/pico-sdk/
mkdir build
cd build 
cmake ..
make
```

## Installing

Now, plugin the Pi Pico with the button pressed, and copy `build/pico-gpio.uf2` to the appearing USB disk.

## Usage

Simply open a serial terminal to the virtual COM port (which appears after installation). Send `e` to pull switch low ("enable"), and `d` to put switch output into high-Z ("disable"). LED reflects the current state. A `p` will pulse the switch for 5 ms.

Below is a list of all commands:
- `e`: Enable the switches: Connect output of switches to ground.
- `d`: Disable the switches: Connect switch input to output.
- `p`: Pulse the switches: Enable the switches for 5ms and disable again.
- `v`: Print version
- `l`: Print ALERTn log
- `c`: Clear ALERTn log
