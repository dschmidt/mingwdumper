#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>


#define printhex(description, value) printf("%s: %#x\n", description, value)
#define printptr(value) printf("p:%p\n", value)

struct PeHeader {
    uint32_t mMagic; // PE\0\0 or 0x00004550
    uint16_t mMachine;
    uint16_t mNumberOfSections;
    uint32_t mTimeDateStamp;
    uint32_t mPointerToSymbolTable;
    uint32_t mNumberOfSymbols;
    uint16_t mSizeOfOptionalHeader;
    uint16_t mCharacteristics;
};

struct PeOptionalHeader {
    uint16_t mMagic; // 0x010b - PE32, 0x020b - PE32+ (64 bit)
    uint8_t  mMajorLinkerVersion;
    uint8_t  mMinorLinkerVersion;
    uint32_t mSizeOfCode;
    uint32_t mSizeOfInitializedData;
    uint32_t mSizeOfUninitializedData;
    uint32_t mAddressOfEntryPoint;
    uint32_t mBaseOfCode;
    uint32_t mBaseOfData;
    uint32_t mImageBase;
    uint32_t mSectionAlignment;
    uint32_t mFileAlignment;
    uint16_t mMajorOperatingSystemVersion;
    uint16_t mMinorOperatingSystemVersion;
    uint16_t mMajorImageVersion;
    uint16_t mMinorImageVersion;
    uint16_t mMajorSubsystemVersion;
    uint16_t mMinorSubsystemVersion;
    uint32_t mWin32VersionValue;
    uint32_t mSizeOfImage;
    uint32_t mSizeOfHeaders;
    uint32_t mCheckSum;
    uint16_t mSubsystem;
    uint16_t mDllCharacteristics;
    uint32_t mSizeOfStackReserve;
    uint32_t mSizeOfStackCommit;
    uint32_t mSizeOfHeapReserve;
    uint32_t mSizeOfHeapCommit;
    uint32_t mLoaderFlags;
    uint32_t mNumberOfRvaAndSizes;
};

#define IMAGE_SIZEOF_SHORT_NAME 8
typedef unsigned char BYTE;
typedef uint32_t DWORD;
typedef uint16_t WORD;
struct IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
};

struct PeSymbol
{
    union {
        char     n_name[8];  /* Symbol Name */
        struct {
            uint32_t n_first4bytes;
            uint32_t n_second4bytes;
        };
    };

    uint32_t n_value;    /* Value of Symbol */
    uint16_t n_scnum;    /* Section Number */
    uint16_t n_type;     /* Symbol Type */
    uint8_t  n_sclass;   /* Storage Class */
    uint8_t  n_numaux;   /* Auxiliary Count */
};

int main(int argc, char** argv)
{
    char* filename = argv[1];

    // code from breakpad
    int obj_fd = open(filename, O_RDONLY);
    if (obj_fd < 0) {
        fprintf(stderr, "Failed to open PE file '%s': %s\n",
                filename, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(obj_fd, &st) != 0 && st.st_size <= 0) {
        fprintf(stderr, "Unable to fstat PE file '%s': %s\n",
                filename, strerror(errno));
        return -1;
    }

    void* obj_base = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, obj_fd, 0);
    printhex("obj_base", obj_base);

    // offset 0x3c - find the real start of peheader here
    int32_t* peOffsetPtr = (int32_t*) ( (int32_t*) obj_base + 60/4);
    printhex("peOffsetPtr", peOffsetPtr);

    // real offset
    printhex("real offset", *peOffsetPtr);

    // pe header
    PeHeader* peHeader = (PeHeader*) ((uint32_t*)obj_base+((*peOffsetPtr)/4));
    printhex("PeHeader Address", peHeader);
    printhex("mmagic", peHeader->mMagic);

    // optional pe header
    PeOptionalHeader* peOptionalHeader = (PeOptionalHeader*) ( (int32_t*) peHeader + 6);;
    printhex("pe header optional", peOptionalHeader);

    printhex("mmagic optional", peOptionalHeader->mMagic);

    printhex("image base", peOptionalHeader->mImageBase);

    uint64_t peOptionalHeaderOffset = (uint64_t) peOptionalHeader - (uint64_t) obj_base + 1;
    printhex("peOptionalHeader offset",  peOptionalHeaderOffset);
    printhex("peOptionalHeader + SizeOfOptionalHeader", peOptionalHeaderOffset + peHeader->mSizeOfOptionalHeader);

    int64_t sectionHeaderOffset = peOptionalHeaderOffset + peHeader->mSizeOfOptionalHeader;
    IMAGE_SECTION_HEADER* foobar = (IMAGE_SECTION_HEADER*) ((uint32_t*)obj_base+(sectionHeaderOffset/4));

    for(int i=0;i<peHeader->mNumberOfSections;i++)
    {
        printf("section name:  %.8s\n", foobar[i].Name);
    }


    PeSymbol* symbols = (PeSymbol*) ((int32_t*) obj_base + peHeader->mPointerToSymbolTable/4);
    for(uint i=0;i<peHeader->mNumberOfSymbols;i++)
    {

//         if( symbols[i].n_first4bytes == 0)
//             printf("symbol name: too long, offset %#x\n", symbols[i].n_second4bytes);
//         else
            printf("symbol name:  %s\n", symbols[i].n_name);
    }
}
