import * as rp2040js from 'rp2040js';
import { LogLevel, ConsoleLogger, USBCDC } from 'rp2040js';
import { bootromB1 } from './src/bootrom';
import * as path from 'path';
import { loadUF2, loadFlashImage } from './src/load-flash';

const path_to_firmware = path.join(__dirname, '..', 'firmware', 'firmware.uf2');
const path_to_filesystem = path.join(__dirname, 'fat12.img');

const mcu = new rp2040js.RP2040();
mcu.loadBootrom(bootromB1);
mcu.logger = new ConsoleLogger(LogLevel.Error);

loadUF2(path_to_firmware, mcu);
loadFlashImage(path_to_filesystem, mcu);

const cdc = new USBCDC(mcu.usbCtrl);

const startMainPyCmd = () => {
    cdc.sendSerialByte(4); // CTRL+D to restart the REPL and load main.py
};

const stopMainPyCmd = () => {
    let returnCode = 0;
    if (errorDetected) {
        console.log('\x1b[31m%s\x1b[0m', "Error detected, simulation failed");
        returnCode = 1
    } else {
        console.log('\x1b[32m%s\x1b[0m', "Simulation successful");
    }

    process.stdout.write('Waiting for stdout to drain...', () => {
        mcu.stop();
    });

};

const tracebackCmd = () => {
    errorDetected = true;
};

const commands = [
    { grep: /Press any key to enter the REPL.*/, fn: startMainPyCmd },
    { grep: /Adafruit CircuitPython.*/, fn: startMainPyCmd },
    { grep: /Traceback (most recent call last)*/, fn: tracebackCmd },
    { grep: /Code done running.*/, fn: stopMainPyCmd },
];

let errorDetected = false;
let currentLine = '';
cdc.onSerialData = (value) => {
    process.stdout.write(value);

    for (const byte of value) {
        const char = String.fromCharCode(byte);
        if (char === '\n') {
            for (const command of commands) {
                if (command.grep.test(currentLine)) {
                    command.fn();
                }
            }
            currentLine = '';
        } else {
            currentLine += char;
        }
    }
};

mcu.core.PC = 0x10000000;
console.log("Starting emulation...")
mcu.execute();