#!/usr/bin/node
/*
* HCDecryptor v1.0.4
* Copyright (c) HCTools Group - 2020
* Ported to Javascript by P7COMunications LLC
*
* License: GPL-V3
* This program comes with a LICENSE file that you must read if you want to modify or redistribute it.
*/
const CryptoJS = require('crypto-js');
const crypto = require('crypto');
const fs = require('fs');
var fileToDecrypt = "";
var keyFile = "";
var showHelp = false;
var jsonOutput = false;
var rawOutput = false;
var forceDecode2 = false;
var forceDecode3 = false;
var useDefaultKeyFile = true;
for(c = 0; c < process.argv.length; c++) {
    switch(process.argv[c]) {
        case "--file":
        case "-f":
            fileToDecrypt = fs.readFileSync(process.argv[c+1]);
            break;
        case "--keyFile":
        case "-k":
            useDefaultKeyFile = false;
            keyFile = fs.readFileSync(process.argv[c+1]).toString();
            break;
        case "--json":
        case "-j":
            jsonOutput = true;
            break;
        case "--raw":
        case "-r":
            rawOutput = true;
            break;
        case "--decode2":
        case "-d2":
            forceDecode2 = true;
            break;
        case "--decode3":
        case "-d3":
            forceDecode3 = true;
            break;
        case "--help":
        case "-h":
            showHelp = true;
            break;
    }
}
var hcKeys = [];
const xorValues = ['。', '〃', '〄', '々', '〆', '〇', '〈', '〉', '《', '》', '「', '」', '『', '』', '【', '】', '〒', '〓', '〔', '〕'];
//splash
console.log("HCDecryptor v1.0.4\r\nCopyright (c) HCTools Group - 2020\r\nPorted to Javascript by P7COMunications LLC");
if(showHelp) {
    const helpContent = [
        "Usage: node script.js [--args, -a...]",
        "",
        "--file, -f\tLoad file to decrypt",
        "--key, -k\tLoad key file",
        "--json, -j\tFormat output to JSON",
        "--raw , -r\tInclude RAW decoded data",
        "--decode2, -d2\tForce second decoding stage",
        "--decode3, -d3\tForce third decoding stage",
        "--help, -h\tDisplay this help"
    ];
    for(d = 0; d < helpContent.length; d++) {
        console.log(helpContent[d]);
    }
    process.exit();
}
/*
* Automatic key loading (basically load keys.dat if found or something)
*/
if(useDefaultKeyFile) {
    var defKeyArr = fs.readFileSync(__dirname + "/keys.dat").toString().split("\n");
    for(e = 0; e < defKeyArr.length; e++) {
        if(defKeyArr[e].indexOf("\r") != -1) {
            hcKeys.push(defKeyArr[e].substring(0, defKeyArr[e].length-1));
        } else {
            hcKeys.push(defKeyArr[e]);
        }
    }
}
if(fileToDecrypt == "") {
    console.log("[ERROR] - No file loaded.");
    process.exit();
} else if(keyFile == "") {
    console.log("[WARNING] - No key file loaded.");
} else if(keyFile.length > 0) {
    //loading keys
    var keyArr = keyFile.split("\n");
    for(e = 0; e < keyArr.length; e++) {
        if(keyArr[e].indexOf("\r") != -1) {
            hcKeys.push(keyArr[e].substring(0, keyArr[e].length-1));
        } else {
            hcKeys.push(keyArr[e]);
        }
    }
} else if(hcKeys.length == 0) {
    console.log("[ERROR] - No keys available!");
    process.exit();
}
console.log("[INFO] - Loaded " + hcKeys.length + " keys.");
function xorDeobfs(file) {
    //xor deobfs
    var deobfs_val = "";
    for(a = 0, b = 0; a < file.length; a++, b++) {
        if(b >= xorValues.length) {b = 0}
        deobfs_val += String.fromCharCode(file.charCodeAt(a) ^ xorValues[b].charCodeAt(0));
    }
    return deobfs_val;
}
function sha1crypt(data) {
    var outp1 = crypto.createHash("sha1");
    outp1.update(data);
    outp1=outp1.digest('hex');
    return outp1.substring(0, outp1.length-8);
}
function aesDecrypt(data, key) {
    var aesoutp1 = CryptoJS.AES.decrypt(data, CryptoJS.enc.Hex.parse(key), {mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7});
    return aesoutp1.toString(CryptoJS.enc.Utf8);
}
function aesDecrypt2(data, key) {
    var aesoutp2 = CryptoJS.AES.decrypt(Buffer.from(data).toString("base64"), CryptoJS.enc.Hex.parse(key), {mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7});
    return aesoutp2.toString(CryptoJS.enc.Utf8);
}
function parseDecoded(data) {
    var st1 = data.split("[splitConfig]");
    var outp1 = "";
    var outp2 = {};
    if(jsonOutput) {
        outp2["payload"] = st1[0];
        outp2["proxyURL"] = st1[1];
        outp2["blockedRoot"] = st1[2];
        outp2["lockPayloadAndServers"] = st1[3];
        outp2["expireDate"] = st1[4];
        outp2["containsNotes"] = st1[5];
        outp2["note1"] = st1[6];
        outp2["sshAddr"] = st1[7];
        outp2["mobileData"] = st1[8];
        outp2["unlockProxy"] = st1[9];
        outp2["unknown"] = st1[10];
        outp2["VPNAddr"] = st1[11];
        outp2["sslsni"] = st1[12];
        outp2["connectSSH"] = st1[13];
        outp2["udpgwPort"] = st1[14];
        outp2["lockPayload"] = st1[15];
        outp2["hwidEnabled"] = st1[16];
        outp2["hwidValue"] = st1[17];
        outp2["note2"] = st1[18];
        outp2["unlockUserAndPassword"] = st1[19];
        outp2["sslPayloadMode"] = st1[20];
        outp2["passwordProtected"] = st1[21];
        outp2["passwordValue"] = st1[22];
        if(rawOutput) {
            outp2["raw"] = data;
        }
        return JSON.stringify(outp2);
    }
    outp1+="Payload: " + st1[0] + "\r\n";
    outp1+="Proxy URL: " + st1[1] + "\r\n";
    outp1+="Blocked for root devices: " + st1[2] + "\r\n";
    outp1+="Lock payload and servers: " + st1[3] + "\r\n";
    outp1+="Expiration Date: " + st1[4] + "\r\n";
    outp1+="Contains Notes: " + st1[5] + "\r\n";
    outp1+="Note Field 1: " + st1[6] + "\r\n";
    outp1+="SSH Address: " + st1[7] + "\r\n";
    outp1+="Only Mobile Data: " + st1[8] + "\r\n";
    outp1+="Unlock Remote Proxy field: " + st1[9] + "\r\n";
    outp1+="unknown value: " + st1[10] + "\r\n";
    outp1+="VPN Address: " + st1[11] + "\r\n";
    outp1+="SSL/SNI Hostname: " + st1[12] + "\r\n";
    outp1+="Connect using SSH: " + st1[13] + "\r\n";
    outp1+="Custom UDPGW Port: " + st1[14] + "\r\n";
    outp1+="Lock Payload: " + st1[15] + "\r\n";
    outp1+="HWID included: " + st1[16] + "\r\n";
    outp1+="HWID value: " + st1[17] + "\r\n";
    outp1+="Note Field 2: " + st1[18] + "\r\n";
    outp1+="Unlock User and Password: " + st1[19] + "\r\n";
    outp1+="SSL and Payload Mode: " + st1[20] + "\r\n";
    outp1+="Password Protected: " + st1[21] + "\r\n";
    outp1+="Password: " + st1[22] + "\r\n";
    if(rawOutput) {
        outp1+="RAW Decoded Data: " + data + "\r\n";
    }
    return outp1;
}
//final decoding
var decodedData = "";
var decodedData2 = "";
var complete = false;
var completev2 = false;
var completev3 = false;
// [19/09/2020] - TODO: Improve this fucking spaghetti-if hell section
if(forceDecode3) {
    for(c = 0; c < hcKeys.length; c++) {
        try {
            console.log("[INFO] - Trying to decode with key \"" + hcKeys[c] + "\" (" + (c+1) + "/" + hcKeys.length + ")");
            decodedData = aesDecrypt2(fileToDecrypt, sha1crypt(hcKeys[c]));
            if(decodedData.length > 2) {
                completev3 = true;
            } else {
                throw "False UTF8";
            }
        } catch(error) {
            console.log("[ERROR] - Key \"" + hcKeys[c] + "\" invalid.");
        }
        if(completev3) {
            console.log("[INFO] - Decoding complete!");
            //at this point we need to parse the decoded file so we can understand it more nicely
            console.log(parseDecoded(decodedData));
            process.exit();
        }
    }
}
if(!forceDecode2) {
    for(c = 0; c < hcKeys.length; c++) {
        try {
            console.log("[INFO] - Trying to decode with key \"" + hcKeys[c] + "\" (" + (c+1) + "/" + hcKeys.length + ")");
            decodedData = aesDecrypt(xorDeobfs(fileToDecrypt.toString("utf-8")), sha1crypt(hcKeys[c]));
            if(decodedData.length > 2) {
                complete = true;
            } else {
                throw "False UTF8 response"
            }
        } catch(error) {
            console.log("[ERROR] - Key \"" + hcKeys[c] + "\" invalid.");
        }
        if(complete) {
            console.log("[INFO] - Decoding complete!");
            //at this point we need to parse the decoded file so we can understand it more nicely
            console.log(parseDecoded(decodedData));
            break;
        }
    }
}
if(!complete) {
    console.log("[ERROR] - First decoding stage failed, starting next decoding stage...");
    for(c = 0; c < hcKeys.length; c++) {
        try {
            console.log("[INFO] - Trying to decode with key \"" + hcKeys[c] + "\" (" + (c+1) + "/" + hcKeys.length + ")");
            decodedData2 = aesDecrypt2(fileToDecrypt, sha1crypt(hcKeys[c]));
            if(decodedData2.length > 2) {
                completev2 = true;
            } else {
                throw "False UTF8 response"
            }
        } catch(error) {
            console.log("[ERROR] - Key \"" + hcKeys[c] + "\" invalid.");
        }
        if(completev2) {
            console.log("[INFO] - Decoding complete!");
            //at this point we need to parse the decoded file so we can understand it more nicely
            console.log(parseDecoded(decodedData2));
            break;
        }
    }
    if(!completev2) {
        console.log("[ERROR] - Ran out of keys and decoding methods, aborting...");
        process.exit();
    }
}
