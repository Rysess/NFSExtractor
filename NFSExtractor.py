import argparse
import pyshark
import os


def get_filename(input_file:str) -> dict:
    # Open input file and extract NFS OPEN (18) packets
    cap = pyshark.FileCapture(input_file,display_filter='nfs && nfs.main_opcode == 18',use_ek=True)
    name_dict = {}
    request_dict = {}
    response_dict = {}

    extract_request_response(cap, request_dict, response_dict)

    # Iterate over the request packets and store the filename in the name_dict
    for seqid in request_dict:
        if 2 in response_dict[seqid]['nfs'].status:
            continue
        if request_dict[seqid]['nfs'].open_claim_type == 0:
            name_dict[response_dict[seqid]['nfs'].stateid_other_hash[1]] = request_dict[seqid]['nfs'].pathname_component
        else:
            
            name_dict[response_dict[seqid]['nfs'].stateid_other_hash[1]] = "unknown_" + str(seqid)
    return name_dict


def extract_file_content(input_file:str, name_dict:dict) -> None:
    # Open input file and extract NFS READ (25) packets
    cap = pyshark.FileCapture(input_file,display_filter='nfs && nfs.main_opcode == 25',use_ek=True)
    request_dict = {}
    response_dict = {}
    file_dict = {}    

    extract_request_response(cap, request_dict, response_dict)
    
    # Iterate over the request packets and store the file content in the file_dict
    for seqid in request_dict:
        if request_dict[seqid]['nfs'].stateid_other_hash not in file_dict:
            file_dict[request_dict[seqid]['nfs'].stateid_other_hash] = b""
        file_dict[request_dict[seqid]['nfs'].stateid_other_hash] += response_dict[seqid].nfs.data
        # If the file is completely read, write it to disk
        if response_dict[seqid].nfs.eof == 1:
            with open(os.path.join("out",name_dict[request_dict[seqid]['nfs'].stateid_other_hash]), "wb") as f:
                f.write(file_dict[request_dict[seqid]['nfs'].stateid_other_hash])
                print(f"[+] File \"{name_dict[request_dict[seqid]['nfs'].stateid_other_hash]}\" found !")

def extract_request_response(cap:pyshark.FileCapture, request_dict:dict, response_dict:dict) -> None:
    """
    Extracts NFS request and response packets from the capture file and stores them in the respective dictionaries
    """
    for packet in cap:
        if type(packet['nfs'].seqid) is list:
            seqid = packet['nfs'].seqid[0]
        else:
            seqid = packet['nfs'].seqid
        if packet['rpc'].msgtyp == 0:
            request_dict[seqid] = packet
        else:
            response_dict[seqid] = packet
            
        

def main(input_file:str) :
    if not os.path.exists("out"):
        os.makedirs("out")
    name_dict = get_filename(input_file)
    extract_file_content(input_file, name_dict)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="Input file to extract NFS packets from",required=True)
    args = parser.parse_args()
    assert os.path.exists(args.input), "Input file does not exist"
    main(args.input)