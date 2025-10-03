# Battering RAM: Low-Cost Interposer Attacks on Confidential Computing via Dynamic Memory Aliasing

This repository contains the hardware design and firmware for the interposer, tools, and proof-of-concept and end-to-end attacks presented in our paper.



## Directory structure

This repository is organized as follows.

* `./ddr4-interposer` contains the hardware design for the DDR4 interposer.
* `./interposer-control` contains the firmware for the DDR4 interposer.
* `./scalable-sgx-attacks` contains contains the PoC and E2E attacks on Scalable SGX.


## Getting started

### Hardware requirements

This artifact requires a custom DDR4 interposer to introduce dynamic memory aliases. The hardware schematic and PCB files for this interposer can be found in `./ddr4-interposer`. Below is the bill of materials.

| **Component**     | **Cost**  | **Qty.** | **Part number**        |
|-------------------|-------|:----:|---------------------|
| DIMM Connector    | $16   | 1    | CONN-DDR4-288-SM    |
| Raspberry Pi Pico | $5    | 1    | Raspberry Pi Pico 2 |
| Analog Switches   | $4    | 2    | ADG902BRMZ          |
| Voltage regulator | $0.65 | 1    | LD1117S25TR         |
| Resistor, 0402, 1kOhm     | $0.005 | 2    |            |
| Capacitor, 0603, 1uF      | $0.099 | 3    |            |
| Capacitor, 1206, 10uF     | $0.018 | 1    |            |

### Creating aliases

The interposer creates aliases by tying certain row address lines to ground. This causes aliases in the CPU's physical memory space as the DIMM now always sees a low signal, regardless of the address sent out by the CPU.

The interposer has five footprints that can be populated with switches. These footprints are labeled in the silkscreen. These include three footprints for inserting the switches on the A11, A13, and A17 lines (labeled "A11->A11", "A13->A13", and "A17->A17", respectively).
If a switch is not installed in a footprint, a jumper must be soldered in its place to connect the CPU and DIMM lines without interruption.

Additionally, to bypass RCD parity checking, two additional footprints optionally allow the A11 or A13 signals to be redirected to A17 (labeled "A11->A17" and "A13->A17", respectively).
Note that only one of these footprints can be occupied at a time. These switches can also not be used in conjunction with the "A17->A17" switch. When installing a switch on these footprints, you must also connect the corresponding jumper to connect it to the A17 line on the DIMM side.

### Mapping out unstable and aliased regions in Linux

When RCD parity is enabled, unstable memory regions are created where only a single bit is flipped, resulting in a parity error. Additionally, writes to aliased memory regions while the interposer is active may accidentally overwrite critical memory regions, potentially causing the system to crash.
To avoid these issues, the use of both the unstable regions and aliased regions can be prevented by using the `memmap` kernel parameter:
```
memmap=nn$ss
```
This will mark region `ss` to `ss+nn` as reserved. Note that using this parameter in GRUB requires escaping the `$` as `\$`. If you enter it through `/etc/default/grub`, you also have to escape the `\`:
```
GRUB_CMDLINE_LINUX_DEFAULT="memmap=nn\\\$ss"
```

## Cite

```
@inproceedings{batteringramsp26,
  title     = {{Battering RAM}: Low-Cost Interposer Attacks on Confidential Computing via Dynamic Memory Aliasings},
  author    = {De Meulemeester, Jesse and Oswald, David and Verbauwhede, Ingrid and Van Bulck, Jo},
  booktitle = {47th {IEEE} Symposium on Security and Privacy ({S\&P})},
  month     = May,
  year      = 2026,
}
```
