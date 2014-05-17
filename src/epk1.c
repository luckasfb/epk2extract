#include <sys/mman.h>
#include <fcntl.h>
#include <epk1.h>
#include <errno.h>
#include <formats.h>


const char EPK1_MAGIC[] = "epak";
int type;
struct epk1Header_t *epk1 = NULL;
struct epk1NewHeader_t *epk1n = NULL;
struct epk1BeHeader_t *epk1b = NULL;

int isFileEPK1(const char *epk_file) {
	FILE *file = fopen(epk_file, "r");
	if (file == NULL) {
		printf("Can't open file %s", epk_file);
		exit(1);
	}
	size_t header_size = sizeof(struct epk1Header_t);
	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * header_size);
	int read = fread(buffer, 1, header_size, file);
	if (read != header_size) return 0;
	fclose(file);
	int result = !memcmp(((struct epk1Header_t*)(buffer))->epakMagic, EPK1_MAGIC, 4);
	free(buffer);
	return result;
}

void printHeaderInfo(int *type) {
    if(*type != EPAK_OLD_BE) printf("\nFirmware otaID: ");
    switch(*type){
	case EPAK_OLD:
	    printf("%s\n", epk1->otaID);
	    break;
	case EPAK_NEW:
	    printf("%s\n", epk1n->otaID);
	    break;
    }
    printf("Firmware version: ");
    switch(*type){
	case EPAK_OLD:
	    printf("%02x.%02x.%02x.%02x\n", epk1->fwVer[3], epk1->fwVer[2], epk1->fwVer[1], epk1->fwVer[0]);
	    break;
	case EPAK_OLD_BE:
	    printf("%02x.%02x.%02x.%02x\n", epk1b->fwVer[3], epk1b->fwVer[2], epk1b->fwVer[1], epk1b->fwVer[0]);
	    break;
	case EPAK_NEW:
	    printf("%02x.%02x.%02x.%02x\n", epk1n->fwVer[3], epk1n->fwVer[2], epk1n->fwVer[1], epk1n->fwVer[0]);
	    break;
    }
    printf("PAK count: %d\n",epk1->pakCount);
    printf("PAKs total size: %d\n\n", epk1->fileSize);
    
    
}

void constructVerString(char *fw_version, int *type) {
    switch(*type){
	case EPAK_OLD:
	    sprintf(fw_version, "%02x.%02x.%02x-%s", epk1->fwVer[2], epk1->fwVer[1], epk1->fwVer[0], epk1->otaID);
	    break;
	case EPAK_OLD_BE:
	    sprintf(fw_version, "%02x.%02x.%02x", epk1b->fwVer[2], epk1b->fwVer[1], epk1b->fwVer[0]);
	    break;
	case EPAK_NEW:
	    sprintf(fw_version, "%02x.%02x.%02x-%s", epk1n->fwVer[2], epk1n->fwVer[1], epk1n->fwVer[0], epk1n->otaID);
	    break;
    }
}

void extract_epk1_file(const char *epk_file, struct config_opts_t *config_opts) {
	FILE *file;
	uint32_t pakcount;
	size_t headerSize;
	int fileLength, index;
	char *pheader;
	void *header;
	
	
	file=fopen(epk_file, "rb");
	if(file == NULL) {
		printf("\nCan't open file %s\n", epk_file);
		exit(1);
	}
	struct stat statbuf;
	if (fstat(fileno(file), &statbuf) < 0) {
		printf("\nfstat error\n"); 
		exit(1);
	}
	fileLength = statbuf.st_size;
	printf("File size: %d bytes\n", fileLength);
	char verString[1024];
	char targetFolder[1024]="";
	fseek(file, 8, SEEK_SET);
	fread(&pakcount, 4, 1, file);
	if ( (int)pakcount >> 8 != 0 )
	    type = EPAK_OLD_BE;
	else if(pakcount < 21)
	    type = EPAK_OLD;
	else
	    type = EPAK_NEW;
	fseek(file, 0, SEEK_SET);
	
	switch(type){
	    case EPAK_OLD:
		headerSize=sizeof(struct epk1Header_t);
		printf("\nFirmware type is EPK1...\n");
		break;
	    case EPAK_OLD_BE:
		headerSize=sizeof(struct epk1BeHeader_t);
		printf("\nFirmware type is EPK1 Big Endian...\n");
		break;
	    case EPAK_NEW:
		headerSize=sizeof(struct epk1NewHeader_t);
		printf("\nFirmware type is EPK1(new)...\n");
		break;
	}
	header=malloc(headerSize);
	epk1=(struct epk1Header_t *)header;
	epk1b=(struct epk1BeHeader_t *)header;
	epk1n=(struct epk1NewHeader_t *)header;
	fread(header, headerSize, 1, file);
	
	if(type == EPAK_OLD_BE){
	    SWAP(pakcount);
	    SWAP(epk1b->fileSize);
	    SWAP(epk1b->pakCount);
	    SWAP(epk1b->fwVer);
	}
	
	printHeaderInfo(&type);
	constructVerString(verString, &type);
	constructPath(targetFolder, config_opts->dest_dir, verString, NULL);
	createFolder(targetFolder);
	for (index = 0; index < pakcount; index++) {
	    struct pakRec_t pakRecord;
	    switch(type){
		case EPAK_OLD: pakRecord = epk1->pakRecs[index]; break;
		case EPAK_OLD_BE:
		    pakRecord = epk1b->pakRecs[index];
		    SWAP(pakRecord.offset);
		    SWAP(pakRecord.size);
		    break;
		case EPAK_NEW: pakRecord = epk1n->pakRecs[index]; break;
	    }
	    pheader=malloc(sizeof(struct pakHeader_t));
	    struct pakHeader_t *pakHeader = (struct pakHeader_t*)pheader;
	    fseek(file, pakRecord.offset, SEEK_SET);
	    fread(pheader, sizeof(struct pakHeader_t), 1, file);
	    if(type == EPAK_OLD_BE)
		SWAP(pakHeader->pakSize);
	    char pakName[5] = "";
	    sprintf(pakName, "%.*s", 4, pakHeader->pakName);
	    char filename[255] = "";
	    constructPath(filename, targetFolder, pakName, ".pak");
	    printf("#%u/%u saving PAK  (%s) to file %s\n", index + 1, pakcount, pakName, filename);
	    if(pakRecord.size == 0 || pakRecord.offset == 0){
		printf("Skipping empty/invalid PAK \"%s\"\n", pakName);
		continue;
	    }
	    FILE *outfile = fopen(((const char*) filename), "w");
	    size_t size=0, done=0;
	    char buf[BUFSIZ];
	    
	    while ((size = fread(buf, 1, BUFSIZ, file)) && done<=(pakRecord.size-132)) {
		done+=fwrite(buf, 1, size, outfile);
	    }
	    fflush(outfile);
	    ftruncate(fileno(outfile), pakRecord.size-132);
	    //fwrite(pakHeader->pakName + sizeof(struct pakHeader_t), 1, pakRecord.size - 132, outfile);
	    fclose(outfile);
	    processExtractedFile(filename, targetFolder, pakName);
	}
	fclose(file);
}

