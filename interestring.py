#!/usr/bin/env python3

import argparse
import sys
import re
import tldextract
from os import path
from ipaddress import ip_address

from DATA import DICT_DLL, DICT_KNOWN_STR, DICT_REGISTRY
from WIN32_API import DICT_WIN32_API

TLD_EXTRACT = tldextract.TLDExtract(cache_file='tld_set')
REGISTRY_ROOTS = {
    "HKEY_LOCAL_MACHINE": "HKLM",
    "HKEY_CURRENT_CONFIG": "HKCC",
    "HKEY_CLASSES_ROOT": "HKCR",
    "HKEY_USERS": "HKU",
    "HKEY_CURRENT_USER": "HKCU",
    "HKEY_PERFORMANCE_DATA": "HKEY_PERFORMANCE_DATA",
    "HKEY_DYN_DATA": "HKEY_DYN_DATA",
    "HKLM": "HKLM",
    "HKCC": "HKCC",
    "HKCR": "HKCR",
    "HKU": "HKU",
    "HKCU": "HKCU",
}

def readlines_file(filename):
    """Short helper method to read in a file.
    
    Args:
        filename: String, the name (eg path) of the file

    Returns:
        List of the lines in the file.
    """
    with open(filename, 'r') as fin:
        return fin.readlines()

def check_registry(line):
    """Check if a given string is a registry entry.

    If the string starts with a registry root key, it's likely a registry
    entry. If so, look it up in the registry dictionary.

    Args:
        line: String, the current line of strings input.

    Returns:
        The registry dictionary entry, if there is one, else empty string.
    """
    # backslashes are annoying, so i'm storing keys with | instead
    line = re.sub(r'\\+', '|', line).upper()
    split_line = line.split("|", 1)
    root_key = REGISTRY_ROOTS.get(split_line[0], '')
    line = f"{root_key}|{split_line[1]}"
    return DICT_REGISTRY.get(line, '')

def is_valid_ip_address(line):
    """Check if a string is a valid IP address.

    Args:
        line: String, the current line of strings input.

    Returns:
        True if it's a valid IP address, else False.
    """
    try:
        ip_address(line)
        return True
    except:
        return False

def is_interwebs(line, all_tlds):
    """Check if a line is related to internet/web stuff.

    This will include things like IP addresses, website names, UA strings, 
    and so on.

    Args:
        line: String, the current line of strings input.
        all_tlds: list, the list of valid TLDs from IANA.

    Returns:
        True if the line deals with interwebs stuff, else False.
    """
    line = line.lower()
    extracted = TLD_EXTRACT(line)
    if is_valid_ip_address(extracted.domain):
        return True
    elif (extracted.suffix in all_tlds) and len(extracted.domain) > 3:
        return True
    else:
        return False

def is_format_string(line):
    """
    #TODO
    """
    # print format strings like %s
    # time format strings like HH:mm:ss
    return re.match("%[#l+]?\d{0,5}\.?\d{0,5}[diuoxXfFeEgGaAcsPn%]\W", line)

def check_dll(line):
    """
    #TODO
    """
    line = line.upper()
    try:
        return DICT_DLL[line]
    except:
        return "Likely DLL"

def clean_line(line):
    """Strip off line number and string type info.

    Some strings tools prepend line number, address, or type info. We need to
    remove that extra info and get out the raw string.

    Args:
        line: String of the current line.

    Returns:
        String of the line without the extra on the beginning.
    """
    cleaned_line = line
    string_types = ("(ascii)", "(16-le)", "(stack8)", "(stack16)", "(stack32)")
    for t in string_types:
        if t in line:
            cleaned_line = line.split(t)[-1].strip()
    return cleaned_line

def is_header(line):
    """Check if the line is a known header line from a strings program.

    Programs like FLOSS group strings results, with each group having a
    header. We don't want to provide annotation for those lines.

    Args:
        line: String, the current line.

    Returns:
        True if it's a header, otherwise False.
    """
    # TODO: only accounting for FLOSS right now. Check other strings programs.
    if line.startswith(("FLOSS decoded", "FLOSS static", "FLOSS extracted")):
        return True
    else:
        return False

def annotate_line(line, all_tlds):
    """Look up the given line and provide relevant information.

    Try to determine the meaning of the string by checking the dictionary
    of data, pattern matching, etc. If no extra data is found, try to provide
    at least a tag.
    
    Args:
        line: String, the current line of strings input.
        all_tlds: list, the list of valid TLDs from IANA.

    Returns:
        A string of the current line and (hopefully) a helpful annotation.
    """
    win32_line = line[:-1] if (line.endswith('A') or (line.endswith('W') and line[-2:-1].islower())) else line
    upper_line = line.upper()
    possible_registry_key = any(s in upper_line for s in ["CURRENTVERSION", "MICROSOFT\\\\WINDOWS"])
    
    if line in DICT_KNOWN_STR:  
        return f"> KNOWN STRING: {DICT_KNOWN_STR[line]}"
    elif line in DICT_WIN32_API or win32_line in DICT_WIN32_API:
        return f"> MSDN: {DICT_WIN32_API.get(line, DICT_WIN32_API.get(win32_line, ''))}"
    elif upper_line in DICT_DLL:
        return f"> DLL: {DICT_DLL[upper_line]}"
    # have to deal with being able to use full key names or abbreviations
    elif upper_line.startswith(tuple(REGISTRY_ROOTS.keys())) or possible_registry_key:
        return f"> REGISTRY: {check_registry(line)}"
    elif is_interwebs(line, all_tlds):
        return "> INTERWEBS " #TODO add dict lookup
    elif is_format_string(line):
        return "> FORMAT STRING "#TODO add dict lookup
    else:
        return ''

def annotate_strings(input_list, col_width, silence):
    """Iterate through the strings and annotate them.

    Provide annotations, tags, highlighting, and other useful information
    for the list of strings. 
    
    Args:
       input_list: The list of original strings.
       col_with: The default width of the output column.
       silence: Toggle to display only annotated lines.

    Returns:
        A new list of strings with extra annotations.
    """
    all_tlds = tuple(tld.strip().lower() for tld in readlines_file("IANA_TLDs.txt")[1:])
    annotated_list = []
    for line in input_list:
        line = line.strip()
        if is_header(line):
            annotation = ''#'|'
        else:
            cleaned_line = clean_line(line)
            annotation = annotate_line(cleaned_line, all_tlds)
        # if user selected -a, only show annotated lines
        if not silence or (silence and annotation): #not annotation == ''):
            annotated_list.append(f"{line:<{col_width}}\t{annotation:<40}")
    return annotated_list

def get_arguments():
    """Get user-provided arguments.

    Get input provided either as an argument or piped in via stdin.

    Returns:
        User-provided arguments as Namespace
    """
    parser = argparse.ArgumentParser(description=("Learn more about strings"))
    parser.add_argument(
            "strings_input", 
            nargs='?', 
            type=str, 
            help="A term or file to annotate (or pipe it in via stdin)")
    parser.add_argument(
            "-a",
            "--annotated",
            action="store_true",
            help="Only show annotated output")
    args = parser.parse_args()
    
    # use input that's piped in, if there is any
    num_args = len(sys.argv)
    if not sys.stdin.isatty():
        pass
    elif not (num_args > 1 and num_args <= 3):
        parser.print_help()
        sys.exit(1)
    return args

def get_input(strings_input):
    """Get the input to annotate.

    Input will be piped in via stdin or passed in as an argument.
    Args:
        strings_input: The input source.
    Returns:
        Tuple of list of input strings, output column width
    """
    input_list = []
    col_width = 50
    # if the user passed in something as an argument
    if strings_input:
        # if it's a file in the directory, use that
        if path.exists(strings_input):
            input_list = readlines_file(strings_input)
        # otherwise, treat it as a word the user is looking up
        else:
            input_list = [strings_input]
            col_width = len(strings_input)
    # no command line arg means it should be being piped in
    elif sys.stdin:
        input_list = sys.stdin.readlines()
    else:
        print("[!] Error: failed getting input.")
        exit(1)
    return (input_list, col_width)

def main():
    """Parse and annotate a strings input file."""
    args = get_arguments()
    input_list, col_width = get_input(args.strings_input)
    args = get_arguments()
    annotated_list = annotate_strings(input_list, col_width, args.annotated)
    [print(line) for line in annotated_list]

if __name__ == "__main__":
    main()
