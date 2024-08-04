import argparse
import pyshark
import os


def get_filename(input_file):
    cap = pyshark.FileCapture(input_file,display_filter='nfs && nfs.main_opcode == 18')
    name_dict = {}
    
    request_dict = {}
    response_dict = {}

    extract_request_response(cap, request_dict, response_dict)
    for seqid in request_dict:
        if response_dict[seqid]['nfs'].status == "2":
            continue
        
        print(response_dict[seqid]['nfs'])
        for attr in dir(response_dict[seqid]['nfs']):
            print(getattr(response_dict[seqid]['nfs'],attr))
        break
        if request_dict[seqid]['nfs'].open_claim_type == "0":
            name_dict[response_dict[seqid]['nfs'].stateid_other_hash] = request_dict[seqid]['nfs'].pathname_component
        else:
            name_dict[response_dict[seqid]['nfs'].stateid_other_hash] = "file_" + seqid
    print(name_dict)
    return name_dict

def main(input_file):
    if not os.path.exists("out"):
        os.makedirs("out")
    name_dict = get_filename(input_file)
    extract_file_content(input_file, name_dict)

def extract_file_content(input_file, name_dict):
    cap = pyshark.FileCapture(input_file,display_filter='nfs && nfs.main_opcode == 25')
    request_dict = {}
    response_dict = {}
    file_dict = {}    

    extract_request_response(cap, request_dict, response_dict)
    
    for seqid in request_dict:
        print(response_dict[seqid]['nfs'])
        print(response_dict[seqid]['nfs'].__dir__())
        break
        if request_dict[seqid]['nfs'].stateid_other_hash not in file_dict:
            file_dict[request_dict[seqid]['nfs'].stateid_other_hash] = b""
        file_dict[request_dict[seqid]['nfs'].stateid_other_hash] += bytes.fromhex(response_dict[seqid].nfs.data.replace(':',''))
        if response_dict[seqid].nfs.eof == "1":
            with open(os.path.join("out",name_dict[request_dict[seqid]['nfs'].stateid_other_hash]), "wb") as f:
                f.write(file_dict[request_dict[seqid]['nfs'].stateid_other_hash])
                print(f"File {request_dict[seqid]['nfs'].stateid_other_hash} written")

def extract_request_response(cap, request_dict, response_dict):
    for packet in cap:
        if packet['rpc'].msgtyp == "0":
            request_dict[packet['nfs'].seqid] = packet
        else:
            response_dict[packet['nfs'].seqid] = packet
            
        

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="Input file to extract NFS packets from",required=True)
    args = parser.parse_args()
    main(args.input)