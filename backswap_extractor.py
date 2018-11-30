""" BackSwap Banker Information Extractor
This is a radare2-based Python3 script which can be used to decrypt and
extract information from several versions of BackSwap including its
position-indepndent payload. If possible, the script will decrypt the payload.

Usage: python3 backswap_extractor.py <full-path-to-sample>
"""

__author__  = "Itay Cohen, aka @megabeets_"
__company__ = "Check Point Software Technologies Ltd"

import sys
import os

import binwalk  # binwalk should be installed on the machine
import r2pipe   # radare2 and r2pipe should be installed on the machine




# Note: Works for the majority of BacckSwap samples which has BMP images embedded
def decrypt_bmp_shellcode(dirname):
    for f in os.listdir(dirname):
        if f.endswith(".bmp"):
            fname = os.path.join(dirname, f)
            # Open the file with radare2
            r2 = r2pipe.open(fname)

            # Enable caching mode
            r2.cmd('e io.cache=true')

            # Search for the following instructions
            #     ffe0           jmp rax
            #     e8b7ffffff     call 0xffffffbe
            jmp_call_search_result = r2.cmdj('/xj ffe0e8b7ffffff')
            if not jmp_call_search_result:
                return
            jmp_call_search_result = jmp_call_search_result[0]


            # Get the address of the inital key
            initial_key_address = jmp_call_search_result['offset']+7

            # Temporarily set endiannes to big-endian and read 4 bytes
            r2.cmd('e cfg.bigendian = true')
            initial_key = r2.cmdj("pxwj 4 @ %d" % initial_key_address)[0] & (2**32-1)
            r2.cmd('e cfg.bigendian = false')

            # Search for the following instructions
            #     0fc9           bswap ecx
            #     43             inc ebx
            #     31d9           xor ecx, ebx
            bswap_inc_xor_result = r2.cmdj("/xj 0fc94331d9")[0]

            # Get the address of the comparison
            constant_address = bswap_inc_xor_result['offset']+5

            # Get the constant to be compared
            constant_value = r2.cmdj('pdj 1 @ %d' % constant_address)[0]['val']

            # Calculate the final XOR key
            final_key = constant_value ^ initial_key
            print ("[+] Found encryption key: %x" % final_key)

            # XOR the file
            r2.cmd('wox %x @ %d!$s' % (final_key, initial_key_address+4))
            # Write the decrypted function to a file
            decryption_status = r2.cmd('wtf! %s.decrypted' % (fname) )
            
            # Get the jump from the BMP. The jump address might indicate the campaign
            jmp = r2.cmd('pi 1 @ 2')
            print ("[+] Jump is: %s" % (jmp))
            r2.quit()




# Extract the BMP image using binwalk
def extract_bmp(fname):
    binwalk_args = ['--dd=bitmap:bmp', '-C=%s/' % (os.path.dirname(fname)), fname]
    for module in binwalk.scan(*binwalk_args, signature=True, quiet=True, extract=True):
        for result in module.results:
            if any(header in result.description for header in ["bitmap", "Bitman", "BMP"]):
                if result.file.path in module.extractor.output:
                    if result.offset in module.extractor.output[result.file.path].extracted:
                        return module.extractor.output[result.file.path].directory
    # A BMP wasn't found in the file. Return with nothing
    return



# Constants
BLOCK_SIZE = 50000 # Bytes
MAX_KEY = 2 ** 8

# Decode up to BLOCK_SIZE bytes to avoid extra-work.
# The function assumes the presence of either
# "document" or"function" within the first BLOCK_SIZE bytes.
def decode_block(block):
    ba_data = block
    
    for k in range(1, MAX_KEY):
        out = []
        for i in range(len(ba_data)):
            out.append(chr(ba_data[i] ^ k))
        txt = "".join(out)
        # Search for Javascript keywords
        if "function" in txt and "document." in txt:
            return (k)  
    return -1


def get_internal_name(r2):
    info = r2.cmd("iV")
    name = ''
    for i in info.split('\n'):
        if "OriginalFilename:" in i:
            name = i.split(": ")[1]
    if name != '':
        print ("[+] Original software name is: %s" %(name))

def decrypt_javscript_rsrc(fname):
    # Open file in radare2
    r2 = r2pipe.open(fname)

    # Check if file is a pe
    info = r2.cmdj("ij")

    bintype = info["core"]["format"]

    if bintype != "pe":
        print ("[X] Not a PE file. Bye")
        exit()

    # Get list of all resources
    resources = r2.cmdj("iRj")
    
    numOfResources = 0
    if resources:
        # Iterate the resources
        for rsrc in resources:
            # Check if resource type is RCDATA
            if rsrc["type"] == "RCDATA":
                # Make sure size is not smaller than BLOCK_SIZE to avoid reading extra bytes
                sz = BLOCK_SIZE if BLOCK_SIZE < rsrc["size"] else rsrc["size"]
                # Brute force the bytes and get the key if succeed
                key = decode_block(r2.cmdj("pxj %d @ %d" % (sz, rsrc["vaddr"])))
                # Check if we was able to decode the resource
                if key > 0:
                    # Allow temporarily writing to the file (not affect the file on disk)
                    r2.cmd("e io.cache=true")
                    # XOR the resource with the found key
                    r2.cmd("wox %02x @ %d!%d" % (key, rsrc["vaddr"], rsrc["size"]))
                    # Get the contet of the resource
                    xord_bytes = r2.cmdj('pxj %d @ %d' % (rsrc["size"], rsrc["vaddr"]))
                    # Save the decoded resource to a file
                    dirname =  os.path.dirname(fname)
                    filename = "%s/_%s.extracted/javascript/RSRC_DUMP_0x%x.js" % (dirname, os.path.basename(fname), rsrc["vaddr"])
                    os.makedirs(os.path.dirname(filename), exist_ok=True)
                    f = open(filename, 'w')
                    f.write(''.join([chr(c) for c in xord_bytes]))

                    print("[+] Resource at 0x%x, of size %d bytes, decrypted with key: 0x%x" % (rsrc["vaddr"], rsrc["size"], key))
                    numOfResources += 1
        
        print("[+] Number of resources (WebInjects): %d" %(numOfResources))
    get_internal_name(r2)
    r2.quit()


def main():
    # Check if there is a file passed as argument 
    if len(sys.argv) < 2:
        print ("Usage: %s <fullpath>" %(sys.argv[0]))
        exit()
    
    input_file = sys.argv[1]
    print("[!] EXTRACTION STARTED FOR: %s" % (input_file))

    # Extract BMP file
    directory = extract_bmp(input_file)

    # Decrypt Javascript resources
    decrypt_javscript_rsrc(input_file)

    if directory != None:
        # Decrypt the BMP file
        decrypt_bmp_shellcode (directory)
    else:
        print("[X] No BMP image found. New version of BackSwap or not BackSwap at all")



if __name__ == '__main__':
    main()
