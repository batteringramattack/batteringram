EESchema Schematic File Version 4
EELAYER 30 0
EELAYER END
$Descr USLetter 8500 11000 portrait
encoding utf-8
Sheet 5 5
Title "Drivers that are injecting faults located on the interposer"
Date "2019-11-01"
Rev "1"
Comp ""
Comment1 "For simplicity, the faults are injected in the PARITY signal"
Comment2 "This is how the faults are injected"
Comment3 ""
Comment4 ""
$EndDescr
$Comp
L power:GND #PWR02
U 1 1 5DBA4610
P 1400 2500
F 0 "#PWR02" H 1400 2250 50  0001 C CNN
F 1 "GND" V 1405 2372 50  0000 R CNN
F 2 "" H 1400 2500 50  0001 C CNN
F 3 "" H 1400 2500 50  0001 C CNN
	1    1400 2500
	0    -1   -1   0   
$EndComp
Text GLabel 1400 2600 0    50   Input ~ 0
VSS_MB
Text GLabel 1400 2400 0    50   Input ~ 0
VSS_DIMM
Wire Wire Line
	1400 2600 1400 2500
Connection ~ 1400 2500
Wire Wire Line
	1400 2500 1400 2400
Text GLabel 1450 3050 0    50   Input ~ 0
VDD_MB
Text GLabel 1450 2850 0    50   Input ~ 0
VDD_DIMM
Wire Wire Line
	1450 3050 1450 2850
Text GLabel 1850 1200 1    50   Input ~ 0
WE_n_A14_DIMM
$Comp
L power:GND #PWR04
U 1 1 5DBAA8E7
P 2350 2350
F 0 "#PWR04" H 2350 2100 50  0001 C CNN
F 1 "GND" H 2355 2177 50  0000 C CNN
F 2 "" H 2350 2350 50  0001 C CNN
F 3 "" H 2350 2350 50  0001 C CNN
	1    2350 2350
	1    0    0    -1  
$EndComp
Text GLabel 1600 1950 0    50   Input ~ 0
INJ0_ENA_CMD
Wire Wire Line
	5850 2950 6700 2950
Text GLabel 5850 2950 0    50   Input ~ 0
PARITY_DIMM
Text GLabel 6700 2950 2    50   Input ~ 0
PARITY_MB
Text GLabel 1900 4050 0    50   Input ~ 0
ALERT_n_MB
Text GLabel 1900 4150 0    50   Input ~ 0
ALERT_n_DIMM
$Comp
L RF_Switch:ADG902BRMZ U1
U 1 1 5E0E95F4
P 2350 1750
F 0 "U1" H 2894 1796 50  0000 L CNN
F 1 "ADG902BRMZ" H 2894 1705 50  0000 L CNN
F 2 "Package_SO:MSOP-8_3x3mm_P0.65mm" H 2350 1300 50  0001 C CNN
F 3 "https://www.analog.com/media/en/technical-documentation/data-sheets/ADG901_902.pdf" H 2350 1950 50  0001 C CNN
	1    2350 1750
	1    0    0    -1  
$EndComp
Wire Wire Line
	1850 1950 1600 1950
Wire Wire Line
	2350 2350 2350 2250
$Comp
L power:GND #PWR03
U 1 1 5E0EDE03
P 3000 1550
F 0 "#PWR03" H 3000 1300 50  0001 C CNN
F 1 "GND" H 3005 1377 50  0000 C CNN
F 2 "" H 3000 1550 50  0001 C CNN
F 3 "" H 3000 1550 50  0001 C CNN
	1    3000 1550
	0    -1   -1   0   
$EndComp
Wire Wire Line
	3000 1550 2850 1550
$Comp
L power:Vdrive #PWR01
U 1 1 5E0EED7F
P 2350 1050
F 0 "#PWR01" H 2150 900 50  0001 C CNN
F 1 "Vdrive" H 2367 1223 50  0000 C CNN
F 2 "" H 2350 1050 50  0001 C CNN
F 3 "" H 2350 1050 50  0001 C CNN
	1    2350 1050
	1    0    0    -1  
$EndComp
Wire Wire Line
	2350 1250 2350 1050
Wire Wire Line
	1550 1550 1850 1550
Wire Wire Line
	1850 1200 1850 1550
Connection ~ 1850 1550
Text GLabel 1550 1550 0    50   Input ~ 0
WE_n_A14_MB
Wire Wire Line
	5850 3400 6600 3400
Text GLabel 5850 3400 0    50   Input ~ 0
WE_n_A14_DIMM
Text GLabel 6600 3400 2    50   Input ~ 0
WE_n_A14_MB
$Comp
L ti-switch:SN74AUC1G66DCKR U2
U 1 1 5EC70225
P 1900 4050
F 0 "U2" H 2900 4437 60  0000 C CNN
F 1 "SN74AUC1G66DCKR" H 2900 4331 60  0000 C CNN
F 2 "fi-library:SN74AUC1G66DCKR" H 2900 4290 60  0001 C CNN
F 3 "" H 1900 4050 60  0000 C CNN
	1    1900 4050
	1    0    0    -1  
$EndComp
$Comp
L power:GND #PWR05
U 1 1 5EC715A2
P 3900 4250
F 0 "#PWR05" H 3900 4000 50  0001 C CNN
F 1 "GND" V 3905 4122 50  0000 R CNN
F 2 "" H 3900 4250 50  0001 C CNN
F 3 "" H 3900 4250 50  0001 C CNN
	1    3900 4250
	0    -1   -1   0   
$EndComp
Text GLabel 3900 4050 2    50   Input ~ 0
VDD_DIMM
Text GLabel 3900 4150 2    50   Input ~ 0
ALERT_n_ENA_CMD
$EndSCHEMATC
