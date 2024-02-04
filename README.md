# V2ray (Xray) Config Tester for Sub Links

## Description

This tool is designed to test V2ray (Xray) configurations from subscription links. Before running the tool, make sure to install the required dependencies listed in `requirements.txt`. Additionally, you need to have `xray.exe` on Windows or `xray` on Linux, which can be downloaded from [Xray-core releases](https://github.com/XTLS/Xray-core/releases).

### Features

The program offers two types of built-in tests:

1. **Deep Test:**
   - This test is executed for each configuration provided in the subscription links.
   - Download speed is measured using 1KB of data by default.
   - This fast test helps identify configurations that won't work.

2. **Level 2 Test:**
   - A more thorough test conducted on 250 of the best configurations identified from the Deep Test.
   - Measures download speed, upload speed, and latency using larger data sizes.

## Modes of Operation

The program can be run in three modes using command line arguments:

1. **-all:**
   - Executes both Deep Test and Level 2 Test.

2. **-level2:**
   - Runs only the Level 2 Test (Deep Test must have been run at least once beforehand).

3. **-update_sub:**
   - Generates a `sub.txt` file containing, by default, 30 of the best configurations found in the Level 2 Test.
   - Optionally, if GitHub details are provided, the `sub.txt` file is uploaded to GitHub. This uploaded file can be used as a subscription link in apps like V2rayNG.

## Usage

1. Install dependencies: `pip install -r requirements.txt`
2. Download `xray.exe` from [Xray-core releases](https://github.com/XTLS/Xray-core/releases) and place it in the appropriate location.
3. Run the program using one of the specified modes.

```bash
python main.py -all
or
python main.py -level2
or
python main.py -update_sub
```
## Credits:
V2ray to JSON converter base code by: https://github.com/Am-Delta/v2ray-to-json/tree/main
## License
This project is licensed under the MIT License.
