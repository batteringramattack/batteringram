# Battering RAM interposer

This directory contains the schematics and PCB layout (KiCad) of the Battering RAM interposer.

The interposer is configurable: it has several footprints for analog switches, of which only a few are populated, depending on which address lines you want to manipulate. The sections below describe which parts are always required, which depend on the configuration, and the configurations we used in the paper.

## Bill of materials

| Description               | Reference             | Part number         | Populate          |
|---------------------------|-----------------------|---------------------|-------------------|
| DDR4 DIMM connector       | J2                    | CONN-DDR4-288-SM    | Always            |
| Raspberry Pi Pico 2       | U3                    | Raspberry Pi Pico 2 | Always            |
| Voltage regulator, 2.5 V  | U8                    | LD1117S25TR         | Always            |
| Capacitor, 1206, 10 µF    | C9                    |                     | Always            |
| Capacitor, 0603, 100 nF   | C8                    |                     | Always            |
| Analog switch             | U1, U2, U4–U7, U9     | ADG902BRMZ          | Per configuration |
| Resistor, 0402, 1 kΩ      | R1–R7                 |                     | Per configuration |
| Capacitor, 0603, 100 nF   | C1–C7                 |                     | Per configuration |
| Jumper, 0402, 0 Ω         | R8, R9, R11, R13, R17 |                     | Per configuration |

## Switch positions

The interposer has seven switch positions:

- **In-line switches** (U4, U1, U6) sit in the path of the A11, A13 and A17 command/address (CA) lines. They are labeled `Axx -> Axx` on the silkscreen.
- **Redirect switches** (U5, U2) connect the CPU-side A11 or A13 line to the DIMM-side A17 line. They are labeled `Axx -> A17` on the silkscreen. To connect the switch output to the DIMM, the output jumper must be populated.
- **General-purpose switches** (U7, U9) are not connected to any signal. They can be wired to any signal by cutting the bridged jumpers and connecting them to the test points using using thin enameled (magnet) wire.

Each switch has its own pull-up resistor and decoupling capacitor. Each in-line switch also has a passthrough jumper that connects the line directly when the switch is not populated.

| Switch  | CPU-side line | DIMM-side line | Passthrough jumper | Pull-up | Decoupling cap | Output Jumper |
|:-------:|:-------------:|:--------------:|:------------------:|:-------:|:--------------:|:-------------:|
| U4      | A11           | A11            | R11                | R4      | C2             | -             |
| U1      | A13           | A13            | R13                | R1      | C3             | -             |
| U6      | A17           | A17            | R17                | R5      | C5             | -             |
| U5      | A11           | A17            | –                  | R3      | C4             | R8            |
| U2      | A13           | A17            | –                  | R2      | C1             | R9            |
| U7      | TP2 / TP11    | TP6 / TP12     | –                  | R6      | C6             | -             |
| U9      | TP8 / TP9     | TP7 / TP10     | –                  | R7      | C7             | -             |

## Configuring the interposer
 
Each populated switch needs a pull-up resistor (1 kΩ) and a 100 nF decoupling capacitor, see the table above. In-line switches (U4, U1, U6) that are left unpopulated need their passthrough jumper instead, otherwise the corresponding address line is not connected to the DIMM. The exception is A17 when one of the redirect switches (U5, U2) is installed: the redirect switch then drives A17, so R17 is left unpopulated.
 
> [!NOTE]
> Each DIMM-side line must be driven by exactly one path: its in-line switch, its passthrough jumper, or (for A17) one of the redirect switches. For example, populating both U5 (A11 -> A17) and U6 (A17 -> A17), or U2 (A13 -> A17) together with R17, is invalid, as both would drive A17 on the DIMM.
 


### Bridged jumpers on other signals

Besides the switch positions, many other signals pass through 0402 jumper footprints (JP1–JP20 and JP23–JP43) that are bridged on the PCB by default. This includes most of the CA bus (all address lines except A11, A13 and A17, which go through the switch positions), the clock, reset and chip-select lines, among others. These signals work as-is without populating anything.

To manipulate one of these signals, cut the bridge between the jumper pads to interrupt the line, and wire the two pads to one of the general-purpose switches (U7, U9). To restore the original connection later, simply solder a 0402 0 Ω resistor onto the footprint.

## Configurations used in the paper

### Single switch (Figure 5a)

| Populate                               | Passthrough jumpers |
|----------------------------------------|---------------------|
| U1 (A13 -> A13) with R1, C3            | R11, R17            |

### Redirecting an address line (Figure 5b)

| Populate                               | Passthrough jumpers |
|----------------------------------------|---------------------|
| U1 (A13 -> A13) with R1, C3            | R11                 |
| U2 (A13 -> A17) with R2, C1, R9        |                     |

### Dual switches (Figure 5c)

| Populate                               | Passthrough jumpers |
|----------------------------------------|---------------------|
| U4 (A11 -> A11) with R4, C2            | R17                 |
| U1 (A13 -> A13) with R1, C3            |                     |

## Fabrication

Recommended settings when ordering the PCB:

- Layers: 4
- PCB thickness: 1.6 mm (or 1.4 mm if available, see note below)
- Min via: 0.2 mm drill / 0.35 mm diameter
- Surface finish: ENIG
- Copper weight: 1 oz outer / 0.5 oz inner
- Everything else: fab default settings (no controlled impedance or special stack-up required)

> [!NOTE]
> 1.6 mm is slightly thicker than regular DDR4 memory modules (1.4 mm). To avoid damaging the motherboard's DIMM socket, it is recommended to use a DDR4 DIMM extender between the motherboard and the interposer.
