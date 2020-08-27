# HCDecryptor
Decryptor for HTTP Custom configuration files.
### This is an javascript port of HCDecryptor tool made by the HCTools Group

# Requirements
- Download Node.JS [Download Here](https://nodejs.org/en/download/ "Node.JS Download")
- Once installed Node.JS, execute "install-dep" .sh/.bat script depending on your platform, or...
- ... execute `npm update --save` in the same folder as the script.

# Usage
- Move your .hc file to the same folder where the script is located
- Execute `node index.js -f (your hc file).hc -k keys.dat`
- The decoded output will be displayed to console.