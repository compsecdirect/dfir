import yara
import os.path
import glob
import argparse


def info():
    """
    #MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXOkOKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM TODO: Remove shameless branding ¯\_(?)_/¯
    #MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNk:`````;dKMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
    # MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMO;``````````oNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM Follow us on Social Media
    # MMMMMMMMMMMMMMMMMMMMMMMMMMMMMk,````;dO00ko;:0MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM L: company/compsec-direct
    # MMMMMMMMMMMMMMMMMMMMMMMMMMMWd````,oNMMMMMMNo,kMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM T: @CompSecDirect / @jfersec
    # MMMMMMMMMMMMMMMMMMMMMMMMMMMk````,kMMMMMMMMMWk:KMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM FB: /CompSecDirect/
    # MMMMMMMMMMMMMMMMMMMMMMMMMMX;````kMMMMMMMMMMMMKlNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
    # MMMMMMMMMMMMMMMMMMMMMMMMMMo````dWMMMMMMMMMMMMMOoWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
    # MMMMMMMMMMMMMMMMMMMMMMMMMO,```lWMMMMMMMMMMMMMMMO0MMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
    # MMMMMMMMMMMMMMMMMMMMMMMMN:```,KMMMMMMMMMMMMMMMMMKMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
    # MMMMMMMMMMMMMMMMMMMMMMMMk````lMMMMMMMMMMMMMMMMMMWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
    # MMMMMMMMMMMMMMMMMMMMMMMMc````0MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
    # MMMMMMMMMMMMMMMMMMMMMMMK,```cWMMMMMMMMMMMMMWNXKKKXNWMMMMMMMMMMMMMMMMMMMMMMMMMMM
    # MMMMMMMMMMMMMMMMMMMMMMMk````OMMMMMMMMMMMMWKkkkkkkkkkKWMMMMMMMMMMMMMMMMMMMMMMMMM
    # MMMMMMMMMMMMMMMMMMMMMMMo```;NMMMMMMMMMMMNkkkkkkkkkkkkONMMMMMMMMMMMMMMMMMMMMMMMM
    # MMMMMMMMMMMMMMMMMMMMMMW:```oMMMMMMMMMWOX0kkkkkkkkkkkkkKMMMMMMMMMMMMMMMMMMMMMMMM
    # MMMMMMMMMMMMMMMMMMMMNOo,```lKNMMMMNKx:`K0kkkkkkkkkkkkkKMMMMMMMMMMMMMMMMMMMMMMMM MULTI yarGen FROM jfersec @CompSecDirect
    # MMMMMMMMMMMMMMMMMMXo;````````,;::;,````oNOkkkkkkkkkkkkk0XWMMMMMMMMMMMMMMMMMMMMM Version 0.1, Rapid proof
    # MMMMMMMMMMMMMMMMMN:```````````````,lk0KXWMKkkkkkkkkkkkkkkkKNMMMMMMMMMMMMMMMMMMM Date Aug 18, 2022
    # MMMMMMMMMMMMMMMMMk``````````````;kNMMMMMMMM0kkkkk0NWWX0kkkkkOXWMMMMMMMMMMMMMMMM
    # MMMMMMMMMMMMMMMMM0`````````````cXMMMMMMMMMMNkkkkKMMMMMMNKkkkkkkKWMMMMMMMMMMMMMM MIT License, StreamWare
    # MMMMMMMMMMMMMMMMMMd,``````````oNNMMMMMMMMMMNkkk0MMMMMMMMMWKOkkkkk0NMMMMMMMMMMMM No ownership rights expressed
    # MMMMMMMMMMMWXWMMMMMKd;`````,lO0ooXMMMMMMMMM0kkxXMMMMMMMMMMMMNOkkkkk0NMMMMMMMMMM Make this script not suck: Hit up github
    # MMMMMMMMMN0KWMMMMMMMMWXK00KXKxccccd0XWMMMMNKK0O0MMMMMMMMMMMMMMN0kkkkk0WMMMMMMMM Github: github.com/CompSecDirect/dfir
    # MMMMMMMW0kNMMMMMMMMMMMMMMMMMMMN0xcccclodddoodk0XWMMMMMMMMMMMMMMMNOkkkkkKWMMMMMM
    # MMMMMMKdOWMMMMMMMMMMMMMMMMMMMMMMMKocccccccccccclOWMMMMMMMMMMMMMMMMXkkkkkONMMMMM Work Ratio: Neo23x0 99.9 / jfersec 0.1
    # MMMMMOlKMMMMMMMMMMMMMMMMMMMMMMMMMMWdcccccccccccccOMMMMMMMMMMMMMMMMMNOkkkkkNMMMM
    # MMMWxc0MMMMMMMMMMMMMMMMMMMMMMMMMMMM0cccccccccccccdMMMMMMMMMMMMMMMMMMW0kkkkkXMMM
    # MMMxclNMMMMMMMMMMMMMMMMMMMMMMMMNKkdlccccccccccccckMMMMMMMMMMMMMMMMMMMNkkkkkOMMM
    # MMKcccKMMMMMMMMMMMMMMMMMMWN0OxocccccccccccccccccdNMMMMMMMMMMMMMMMMMMMWkkkkkkWMM
    # MMkccclkKNWWMMMWWNXK0OkxolccccccccoxOK0dlccccokKWMMMMMMMMMMMMMMMMMMMN0kkkkkKMMM
    # MMOcccccccclllllcccccccccccccoxOKWMMMMMMWNNNWMMMMMMMWWWNNXXXXXXXXK0OkkkkOKNMMMM
    # MMWklcccccccccccccccclodkO0XWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWWNNXXXXXXXNWWMMMMMMM
    # MMMMWX0kxxdddxxkOOKXNWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
    # MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM

    """


def folder_search(path):
    try:
        # focus being exe files.
        _exe_found = (glob.glob(os.path.join(path, "*.exe"), recursive=True))
        if _exe_found:
            print("[+] Found %s exe file(s)" % len(_exe_found))
            return _exe_found
        else:
            print("[-] No exe file(s) found")
    except Exception as search_error:
        print("[-] Error on:  %s " % search_error)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', dest='path', help='Enter folder to parse for samples, -p FilePath in quotes', type=str)
    parser.add_argument('-r', dest='rules', help='Enter Rule Files path, -r FilePath in quotes', type=str)
    options = parser.parse_args()
    # Compile rule file to use for searching, accepts multiple entries as dict with meta 
    path_entry = options.path
    rules_entry = options.rules
    try:
        yara_rules = yara.compile(filepath=rules_entry)
        # example working rules = yara.compile(filepath='C:\\Users\\Administrator\\Desktop\\rulesout')
        print("[+] Rules compiled")
        # match does not accept folders?
        scandir = folder_search(path_entry)
        if scandir:
            for entries in scandir:
                matches = yara_rules.match(entries)
                if matches:
                    for match_entries in matches:
                        # add breakpoints to print to inspect which patterns matched.
                        print(match_entries)
                    print(f"[+] Match found: {matches} in sample {entries}")
        else:
            print(f"[-] No matches to analyze?")
    except Exception as main_error:
        print("[-] Error on:  %s " %main_error)

if __name__ == '__main__':
    info()
    main()
