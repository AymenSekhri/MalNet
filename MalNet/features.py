from xml.dom import minidom
import pyperclip
import numpy as np
import json
import tqdm
import multiprocessing
import lief
import re

class ImportsFeatures(object): 
    dim = 1000
    APIsList = []
    def FindApi(self,ApiName,ApiList):
        for x in range(len(ApiList)) :
            if ApiList[x] == ApiName:
                return x
        return -1 
    def GetAPIList(self):
        f = open("MalNet\\apis.txt", "r")
        data = f.readlines()
        return [x.strip() for x in data]
    def VectorizeFromJson(self,y):
        APis_Features = np.zeros(shape=(len(self.APIsList)))
        for lib in y["imports"]:
            for api in y["imports"][lib]:
                apiindex = self.FindApi(api,self.APIsList)
                if apiindex != -1:
                    APis_Features[apiindex] = 1
        return APis_Features
    def VectorizeFromRaw(self,PE):
        APis_Features = np.zeros(shape=(len(self.APIsList)))
        for lib in PE.imports:
            for api in lib.entries:
                apiindex = self.FindApi(api.name,self.APIsList)
                if apiindex != -1:
                    APis_Features[apiindex] = 1
        return APis_Features
    def __init__(self):
        self.APIsList = self.GetAPIList()
class ExtraFeatures(object):
    dim = 11
    def FindEntryChar(self,PE):

        try:
            return [str(char).split(".")[1] for char in PE.section_from_rva(PE.entrypoint-PE.optional_header.imagebase).characteristics_lists]
        except lief.not_found:
            return None
    def FindSection(self,y,names):
        for x in y["section"]["sections"]:
            for i in names:
                if i == x["name"]:
                    return x
        return ""
    def checklist(self,list,value):
        for x in list:
            if x == value:
                return 1
        return 0
    def VectorizeFromJson(self,y):
        is_EXECUTABLE_IMAGE = self.checklist(y["header"]["coff"]["characteristics"],"EXECUTABLE_IMAGE")
        is_DLL = self.checklist(y["header"]["coff"]["characteristics"],"DLL")
        is_reloc_stripped = self.checklist(y["header"]["coff"]["characteristics"],"RELOCS_STRIPPED")
        is_LARGE_ADDRESS_AWARE = self.checklist(y["header"]["coff"]["characteristics"],"LARGE_ADDRESS_AWARE")

        is_Win_GUI = self.checklist(y["header"]["optional"]["subsystem"],"WINDOWS_GUI")

        is_HIGH_ENTROPY_VA = self.checklist(y["header"]["optional"]["dll_characteristics"],"HIGH_ENTROPY_VA")
        is_NX_COMPAT = self.checklist(y["header"]["optional"]["dll_characteristics"],"NX_COMPAT")
        is_DYNAMIC_BASE = self.checklist(y["header"]["optional"]["dll_characteristics"],"DYNAMIC_BASE")
        is_GUARD_CF = self.checklist(y["header"]["optional"]["dll_characteristics"],"GUARD_CF")
        is_EP_in_writable_section = 0
        if y["section"]["entry"] != "":
            is_EP_in_writable_section = self.checklist(self.FindSection(y,[y["section"]["entry"]])["props"],"MEM_WRITE")
        has_writable_executable_section = 0
        for x in y["section"]["sections"]:
            if self.checklist(x,"MEM_WRITE") and self.checklist(x,"MEM_EXECUTE") :
                has_writable_executable_section = 1

        return [is_EXECUTABLE_IMAGE,is_DLL,is_reloc_stripped,is_LARGE_ADDRESS_AWARE,is_Win_GUI,is_HIGH_ENTROPY_VA,
                is_NX_COMPAT,is_DYNAMIC_BASE,is_GUARD_CF,is_EP_in_writable_section,has_writable_executable_section]
    def VectorizeFromRaw(self,PE):
        exe_char = [str(c).split('.')[1] for c in PE.header.characteristics_list]
        is_EXECUTABLE_IMAGE = self.checklist(exe_char,"EXECUTABLE_IMAGE")
        is_DLL = self.checklist(exe_char,"DLL")
        is_reloc_stripped = self.checklist(exe_char,"RELOCS_STRIPPED")
        is_LARGE_ADDRESS_AWARE = self.checklist(exe_char,"LARGE_ADDRESS_AWARE")

        is_Win_GUI = self.checklist([str(PE.optional_header.subsystem).split('.')[1]],"WINDOWS_GUI")

        dll_char = [str(c).split('.')[1] for c in PE.optional_header.dll_characteristics_lists]
        is_HIGH_ENTROPY_VA = self.checklist(dll_char,"HIGH_ENTROPY_VA")
        is_NX_COMPAT = self.checklist(dll_char,"NX_COMPAT")
        is_DYNAMIC_BASE = self.checklist(dll_char,"DYNAMIC_BASE")
        is_GUARD_CF = self.checklist(dll_char,"GUARD_CF")

        is_EP_in_writable_section = 0
        Entry_char = self.FindEntryChar(PE)
        if Entry_char != None:
            is_EP_in_writable_section = self.checklist(Entry_char,"MEM_WRITE")
        
        has_writable_executable_section = 0
        for x in PE.sections:
            section_char = [str(char).split(".")[1] for char in x.characteristics_lists]
            if self.checklist(section_char,"MEM_WRITE") and self.checklist(section_char,"MEM_EXECUTE"):
                has_writable_executable_section = 1
                break
        return [is_EXECUTABLE_IMAGE,is_DLL,is_reloc_stripped,is_LARGE_ADDRESS_AWARE,is_Win_GUI,is_HIGH_ENTROPY_VA,
                is_NX_COMPAT,is_DYNAMIC_BASE,is_GUARD_CF,is_EP_in_writable_section,has_writable_executable_section]
class SectionsFeatures(object):
    dim = 21
    def checklist(self,list,value):
        for x in list:
            if x == value:
                return 1
        return 0
    def FindSection(self,y,names):
        for x in y["section"]["sections"]:
            for i in names:
                if i == x["name"]:
                    return x
        return ""
    def FindSectionRaw(self,PEsections,names):
        for x in PEsections:
            for i in names:
                if x.name == i:
                    return x
        return None
    def VectorizeFromJson(self,y):
        VSectionsFeautues = []
        code = self.FindSection(y,[".text","CODE"])
        if code != "":
            VSectionsFeautues[0:6] = [code["size"],code["entropy"],code["vsize"],self.checklist(code["props"],"CNT_CODE"),self.checklist(code["props"],"MEM_EXECUTE"),self.checklist(code["props"],"MEM_READ"),self.checklist(code["props"],"MEM_WRITE")]
        else:
            VSectionsFeautues[0:6] = [0,0,0,0,0,0,0]
        rsrc = self.FindSection(y,[".rsrc"])
        if rsrc != "":
             VSectionsFeautues[7:13] = [rsrc["size"],rsrc["entropy"],rsrc["vsize"],self.checklist(rsrc["props"],"CNT_CODE"),self.checklist(rsrc["props"],"MEM_EXECUTE"),self.checklist(rsrc["props"],"MEM_READ"),self.checklist(rsrc["props"],"MEM_WRITE")]
        else:
            VSectionsFeautues[7:13] = [0,0,0,0,0,0,0]
        data = self.FindSection(y,[".data","DATA"])
        if data != "":
            VSectionsFeautues[14:20] = [data["size"],data["entropy"],data["vsize"],self.checklist(data["props"],"CNT_CODE"),self.checklist(data["props"],"MEM_EXECUTE"),self.checklist(data["props"],"MEM_READ"),self.checklist(data["props"],"MEM_WRITE")]
        else:
            VSectionsFeautues[14:20] = [0,0,0,0,0,0,0]
        return VSectionsFeautues
    def GetSectionFeaturesRaw(self,PESections,SectionNames):
        code = self.FindSectionRaw(PESections,SectionNames)
        if code is not None:
            code_char = [str(char).split(".")[1] for char in code.characteristics_lists]
            return [code.size,code.entropy,code.virtual_size,self.checklist(code_char,"CNT_CODE"),self.checklist(code_char,"MEM_EXECUTE"),self.checklist(code_char,"MEM_READ"),self.checklist(code_char,"MEM_WRITE")]
        else:
           return  [0,0,0,0,0,0,0]
    def VectorizeFromRaw(self,PE):
        VSectionsFeautues = []
        VSectionsFeautues[0:6] = self.GetSectionFeaturesRaw(PE.sections,[".text","CODE"])
        VSectionsFeautues[7:13] = self.GetSectionFeaturesRaw(PE.sections,[".rsrc"])
        VSectionsFeautues[14:20] = self.GetSectionFeaturesRaw(PE.sections,[".data","DATA"])
        return VSectionsFeautues
class DataDirectoryFeatures(object):
    dim = 15 * 2
    def VectorizeFromJson(self,y):
        VDataDirectory = []
        for x in y["datadirectories"]:
            VDataDirectory.append(x["size"])
            VDataDirectory.append(x["virtual_address"])
        if len(VDataDirectory) == 0:
            return [0] * 30
        return VDataDirectory
    def VectorizeFromRaw(self,PE):
        VDataDirectory = []
        for data_directory in PE.data_directories:
            d = data_directory.type
            VDataDirectory.append(data_directory.size)
            VDataDirectory.append(data_directory.rva)
        return VDataDirectory
class HeadersFeatures(object):
    dim = 29
    def GetEntropy(self,allstrings):
        # map printable characters 0x20 - 0x7f to an int array consisting of
        # 0-95, inclusive
        as_shifted_string = [b - ord(b'\x20') for b in b''.join(allstrings)]
        c = np.bincount(as_shifted_string, minlength=96)  # histogram count
        # distribution of characters in printable strings
        csum = c.sum()
        p = c.astype(np.float32) / csum
        wh = np.where(c)[0]
        H = np.sum(-p[wh] * np.log2(p[wh]))  # entropy
        return H
    def VectorizeFromJson(self,y):
        return [y["strings"]["numstrings"],y["strings"]["avlength"],y["strings"]["printables"],y["strings"]["entropy"],y["strings"]["paths"],y["strings"]["urls"],y["strings"]["registry"],y["strings"]["MZ"],
                                               y["general"]["size"], y["general"]["vsize"], y["general"]["has_debug"], y["general"]["exports"], y["general"]["imports"], y["general"]["has_relocations"], y["general"]["has_resources"], y["general"]["has_signature"], y["general"]["has_tls"], y["general"]["symbols"],
                                               y["header"]["optional"]["major_image_version"],y["header"]["optional"]["minor_image_version"],y["header"]["optional"]["major_linker_version"],y["header"]["optional"]["minor_linker_version"],y["header"]["optional"]["major_operating_system_version"],y["header"]["optional"]["minor_operating_system_version"],y["header"]["optional"]["major_subsystem_version"],y["header"]["optional"]["minor_subsystem_version"],
                                               y["header"]["optional"]["sizeof_code"],y["header"]["optional"]["sizeof_headers"],y["header"]["optional"]["sizeof_heap_commit"]]  
    def VectorizeFromRaw(self,Bytes,PE):
        allstrings = re.compile(b'[\x20-\x7f]{5,}').findall(Bytes)
        string_lengths = [len(s) for s in allstrings]
        paths = len(re.compile(b'c:\\\\', re.IGNORECASE).findall(Bytes))
        urls = len(re.compile(b'https?://', re.IGNORECASE).findall(Bytes))
        registry = len(re.compile(b'HKEY_').findall(Bytes))
        MZ = len(re.compile(b'MZ').findall(Bytes))

        return [len(allstrings),sum(string_lengths) / len(allstrings),len(allstrings),
                self.GetEntropy(allstrings),paths,urls,registry,MZ,
                len(Bytes),int(PE.virtual_size),int(PE.has_debug),len(PE.exported_functions),len(PE.imported_functions),
                int(PE.has_relocations),int(PE.has_resources),int(PE.has_signature),int(PE.has_tls),len(PE.symbols),
                PE.optional_header.major_image_version,PE.optional_header.minor_image_version,PE.optional_header.major_linker_version,PE.optional_header.minor_linker_version,PE.optional_header.major_operating_system_version,PE.optional_header.minor_operating_system_version,PE.optional_header.major_subsystem_version,PE.optional_header.minor_subsystem_version,
                PE.optional_header.sizeof_code,PE.optional_header.sizeof_headers,PE.optional_header.sizeof_heap_commit]
class EntropyFeatures(object):
    dim = 256
    step = 1024
    window = 2048
    def _entropy_bin_counts(self, block):
        # coarse histogram, 16 bytes per bin
        c = np.bincount(block >> 4, minlength=16)  # 16-bin histogram
        p = c.astype(np.float32) / self.window
        wh = np.where(c)[0]
        H = np.sum(-p[wh] * np.log2(p[wh])) * 2  # * x2 b.c.  we reduced information by half: 256 bins (8 bits) to 16 bins (4
                                                 # bits)
        Hbin = int(H * 2)  # up to 16 bins (max entropy is 8 bits)
        if Hbin == 16:  # handle entropy = 8.0 bits
            Hbin = 15
        return Hbin, c
    def VectorizeFromJson(self,y):
        return y["byteentropy"]
    def VectorizeFromRaw(self, bytes):
        output = np.zeros((16, 16), dtype=np.int)
        a = np.frombuffer(bytes, dtype=np.uint8)
        if a.shape[0] < self.window:
            Hbin, c = self._entropy_bin_counts(a)
            output[Hbin, :] += c
        else:
            shape = a.shape[:-1] + (a.shape[-1] - self.window + 1, self.window)
            strides = a.strides + (a.strides[-1],)
            blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::self.step, :]
            # from the blocks, compute histogram
            for block in blocks:
                Hbin, c = self._entropy_bin_counts(block)
                output[Hbin, :] += c
        return output.flatten().tolist()
class Features(object):
    dim = 0
    def VectorizeFromJson(self,features_json):
        y = json.loads(features_json)
        Entropy = EntropyFeatures()
        Headers = HeadersFeatures()
        Imports = ImportsFeatures()
        Sections = SectionsFeatures()
        DataDirectory = DataDirectoryFeatures()
        Extra = ExtraFeatures()
        X_file = np.concatenate([Entropy.VectorizeFromJson(y),
                                 Headers.VectorizeFromJson(y),
                                 Imports.VectorizeFromJson(y),
                                 Sections.VectorizeFromJson(y),
                                 DataDirectory.VectorizeFromJson(y),
                                 Extra.VectorizeFromJson(y)])
        return X_file,int(y["label"])
    def VectorizeFromRawFile(self,FilePath):
        bytes = []
        with open(FilePath,"rb") as f:
            bytes = f.read()
        PE = lief.parse(FilePath)
        if PE == None:
            return None
        Entropy = EntropyFeatures()
        Headers = HeadersFeatures()
        Imports = ImportsFeatures()
        Sections = SectionsFeatures()
        DataDirectory = DataDirectoryFeatures()
        Extra = ExtraFeatures()
        
        X_file = np.concatenate([Entropy.VectorizeFromRaw(bytes),
                                 Headers.VectorizeFromRaw(bytes,PE),
                                 Imports.VectorizeFromRaw(PE),
                                 Sections.VectorizeFromRaw(PE),
                                 DataDirectory.VectorizeFromRaw(PE),
                                 Extra.VectorizeFromRaw(PE)])
        return X_file
    def __init__(self):
        self.dim = EntropyFeatures.dim + HeadersFeatures.dim + ImportsFeatures.dim + SectionsFeatures.dim + DataDirectoryFeatures.dim + ExtraFeatures.dim 


