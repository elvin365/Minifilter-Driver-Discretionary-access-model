/*++

Module Name:

    FsFilter2.c

Abstract:

    This is the main module of the FsFilter2 miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include<suppress.h>
#include <wchar.h>
#include<errno.h>
//#include<string.h>
#define tag 'file'
struct info_acc
{
	
	WCHAR path[100];
	int block_path;
	PVOID buffer;
	int write;
	int read;
};
struct info_acc protection;
int is_read = 0;
PFLT_FILTER FilterHandle = NULL;
NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_POSTOP_CALLBACK_STATUS MiniPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext, FLT_POST_OPERATION_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS MiniPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS MiniPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
//FLT_PREOP_CALLBACK_STATUS MiniPreRead(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

void read_file();
WCHAR		fname[30]={'\0'};
wchar_t* wcstok1(wchar_t * s1,  wchar_t * s2,wchar_t ** ptr) {
	wchar_t* p;

	if (s1 == NULL)
		s1 = *ptr;
	while (*s1 && wcschr(s2, *s1))
		s1++;
	if (!*s1) {
		*ptr = s1;
		return NULL;
	}
	for (p = s1; *s1 && !wcschr(s2, *s1); s1++)
		continue;
	if (*s1)
		*s1++ = L'\0';
	*ptr = s1;
	return p;
}

const FLT_OPERATION_REGISTRATION Callbacks[] = { //HERE WE DECIDE WHAT WE CAN OR CAN'T DO 
	{IRP_MJ_CREATE,0,/*Preoperation callbacks*/MiniPreCreate,MiniPostCreate},
	//{IRP_MJ_READ,0,MiniPreRead,NULL},
	{IRP_MJ_WRITE,0,MiniPreWrite,NULL},
	
	//I/0 request packet
	{IRP_MJ_OPERATION_END}//LET WINDOWS KNOW THAT IT IS THE END OF STRUCTURE ARRAY
};

const FLT_REGISTRATION FilterRegistration =
{
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,//VERSION
	0,//flag
	NULL,//contex registration member
	Callbacks,//register callbacks
	MiniUnload,//regist Unload function
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
};
void read_file()
{
	
	OBJECT_ATTRIBUTES obj_attributeR;
	NTSTATUS status;
	HANDLE filehandleR=NULL;
	IO_STATUS_BLOCK IostatusblockR = {0};
	UNICODE_STRING filenameR = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume2\\conf.txt");
	InitializeObjectAttributes(&obj_attributeR, &filenameR, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status=ZwCreateFile(&filehandleR, GENERIC_READ, &obj_attributeR, &IostatusblockR, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,NULL,0);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("openingfaild");
	}
	NTSTATUS status2;
	IO_STATUS_BLOCK iostatusblock = { 0 };
	PVOID buffer=NULL;
	ULONG length;
	LARGE_INTEGER offset = { 0 };
	length = 4096;//4096
	buffer = ExAllocatePoolWithTag(NonPagedPool, length, tag);
	memset(buffer, 0, sizeof(WCHAR)*2000);
	if (buffer == NULL)
	{
		KdPrint(("Error alloc"));
		return;
	}
	while (1)
	{
		length = 4096;
		status2 = ZwReadFile(filehandleR, NULL, NULL, NULL, &iostatusblock, buffer, length, &offset, NULL);
		KdPrint((buffer));
		//KdPrint(("%ws \r\n", buffer));
		if (!NT_SUCCESS(status2))
		{
			//KdPrint((buffer));
			if (status2 == STATUS_END_OF_FILE)
			{
				break;
			}
		}
		length = iostatusblock.Information;
		offset.QuadPart += length;
		//RtlInitUnicodeString(&uniName, L"\\Device\\HarddiskVolume2\\conf.txt");  // or L"\\SystemRoot\\example.txt"
	}
	//ExFreePool(buffer);
	wmemset(protection.path, 0, 100);
	memcpy(protection.path, L"\\Device\\HarddiskVolume2\\toprotect",wcslen(L"\\Device\\HarddiskVolume2\\toprotect"));
	char mass[2] = "\0";
	int counter = 0;
	/*for (; ((*(WCHAR*)buffer!=L' ') && (*(WCHAR*)buffer !=L'\0')) ; ((WCHAR*)buffer)++)
	{
		
		//memcpy(mass, (WCHAR*)buffer,sizeof(WCHAR));
		memcpy(mass, (WCHAR*)buffer, sizeof(WCHAR));
		//KdPrint(("%s",mass));
		
		if (counter == 0)
		{
			if ( (mass[0] == '1' || mass[1] == ' '))
			{
				protection.block_path = 1;
				counter++;
				//continue;
				mass[0] = '\0';
				mass[1] = '\0';
			}
			else if (mass[0] == '0' || mass[1] == ' ')
			{
				protection.block_path = 0;
				counter++;
				//continue;
				mass[0] = '\0';
				mass[1] = '\0';
			}
			else if (mass[0] == 't' || mass[1] == '1')
			{
				protection.block_path = 1;
				mass[1] = '\0';
				counter++;
			}
			else if (mass[0] == 't' || mass[1] == '0')
			{
				protection.block_path = 0;
				mass[1] = '\0';
				counter++;
			}
			//memcpy((WCHAR)protection.path[i], mass, 2);
			
			wcscat((WCHAR*)protection.path, (WCHAR*)mass);
			i++;
			continue;
		}
		if (counter ==1)
		{
			if (mass[0] == '1' || mass[1] == '1')
			{
				protection.write = 1;
				counter++;
			}
			else if (mass[0] == '0' || mass[1] == '0')
			{
				protection.write = 0;
				counter++;
			}
			continue;

		}
		if (counter == 2)
		{
			if (mass[0] == '1' || mass[1] == '1')
			{
				protection.read = 1;
				counter++;
			}
			else if (mass[0] == '0' || mass[1] == '0')
			{
				protection.read = 0;
				counter++;
			}
		}
		if (counter == 3)
			break;
		memset(mass, 0, 2);
	}
	//wchar_t* forstr = NULL;
	//memset(((WCHAR)buffer+400), 0,sizeof(WCHAR)*90);
	/*int k = 0;
	forstr = wcstok1((WCHAR*)(protection.buffer), L" ",&forstr);
	KdPrint(("%ws \r\n", forstr));
	
	int counter = 0;
	while (forstr)
	{
		if (counter == 0)
		{
			//protection.path = forstr;
			//wsprintf()
			swprintf(protection.path,forstr);
			KdPrint(("%ws \r\n", protection.path));
		}
		if (counter == 1)
		{
			if (wcsstr(forstr, L"1"))// looking for 1/0 in write
			{
				protection.write = 1;
			}
			else
			{
				protection.write = 0;
			}
		}
		if (counter == 2)
		{
			if (wcsstr(forstr, L"1"))// looking for 1/0 in read
			{
				protection.write = 1;
			}
			else
			{
				protection.write = 0;
			}
			break;
		}


		counter++;
		forstr = wcstok1(NULL, L" ",&forstr);
	}
	//DbgPrint(((PCSTR)protection.path));
	//DbgPrint("%x",protection.write);*/
	
	for (; ((*(WCHAR*)buffer != L' ') && (*(WCHAR*)buffer != L'\0')); ((WCHAR*)buffer)++)
	{
		memcpy(mass, (WCHAR*)buffer, sizeof(WCHAR));
		if (counter == 0)
		{
			if ((mass[0] == '1' || mass[1] == ' '))
			{
				protection.block_path = 1;
				counter++;
				//continue;
				mass[0] = '\0';
				mass[1] = '\0';
			}
			else if (mass[0] == '0' || mass[1] == ' ')
			{
				protection.block_path = 0;
				counter++;
				//continue;
				mass[0] = '\0';
				mass[1] = '\0';
			}
			
			continue;
				
		}
		if (counter == 1)
		{
			if (mass[0] == '1' || mass[1] == '1')
			{
				protection.write = 1;
				counter++;
			}
			else if (mass[0] == '0' || mass[1] == '0')
			{
				protection.write = 0;
				counter++;
			}
			continue;
		}
		if (counter == 2)
		{
			if (mass[0] == '1' || mass[1] == '1')
			{
				protection.read = 1;
				counter++;
			}
			else if (mass[0] == '0' || mass[1] == '0')
			{
				protection.read = 0;
				counter++;
			}
		}
		if (counter == 3)
		{
			break;
		}



	}
	KdPrint(("%x", protection.read));
	///////////////////////////
	HANDLE	FileHandle;
	NTSTATUS status3;
	OBJECT_ATTRIBUTES	ourAttributes;
	IO_STATUS_BLOCK	ourStatBlock;
	PVOID		FileInformation;
	BOOLEAN	RestartScan = TRUE;
	UNICODE_STRING		sysDir;
	UNICODE_STRING		fileSpec;
	ULONG		myTag = 0xAABBCCDD;
	//WCHAR		fname[30];
	unsigned char* addr;
	PFILE_DIRECTORY_INFORMATION	pDir;
	int		offset1;
	wmemset(fname, 0, 30);
	RtlInitUnicodeString(&sysDir, L"\\Device\\HarddiskVolume2\\toprotect");
	RtlInitUnicodeString(&fileSpec, L"*.txt");

	InitializeObjectAttributes(&ourAttributes, &sysDir, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_OPENIF, NULL, NULL);

	status3 = ZwCreateFile(&FileHandle, 0x21, &ourAttributes, &ourStatBlock, NULL, 0, 3, 1, 0x21, 0, 0);

	if (!NT_SUCCESS(status3))
	{
#if DBG
		DbgPrint("GetFrdFile : ZwCreateFile failed\n");
#endif

		//return 10;
	}

	FileInformation = ExAllocatePoolWithTag(NonPagedPool, 0x1000, myTag);

	if (FileInformation == NULL)
	{
#if DBG
		DbgPrint("GetFrdFile : ExAllocatePoolWithTag failed\n");
#endif

		return ;
	}

	// will return a FILE_DIRECTORY_INFORMATION struct for each file
	status3 = ZwQueryDirectoryFile(FileHandle, NULL, NULL, NULL, &ourStatBlock, FileInformation, 0x1000, FileDirectoryInformation, 0, &fileSpec, RestartScan);

	if (!NT_SUCCESS(status3))
	{
#if DBG
		DbgPrint("GetFrdFile : ZwQueryDirectoryFile failed\n");
#endif

		return ;
	}
	else
	{
#if DBG
		DbgPrint("GetFrdFile : ZwQueryDirectoryFile got %x bytes\n", ourStatBlock.Information);
#endif
		addr = (unsigned char*)FileInformation;

		do
		{
			pDir = (PFILE_DIRECTORY_INFORMATION)addr;
			memset(fname, 0x00, 2 * 30);
			wcscpy(fname, pDir->FileName);
			fname[8] = 0x0000;
#if DBG
			DbgPrint("GetFrdFile : ZwQueryDirectoryFile found matching file :%ws\n", fname);
#endif
			offset1 = pDir->NextEntryOffset;
			addr += offset1;
		} while (offset1 != 0);

	}

	ExFreePoolWithTag(FileInformation, myTag);
	//ExFreePool(buffer);
	return;
}

NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	KdPrint(("driver unload \r\n"));
	//unregist filter
	FltUnregisterFilter(FilterHandle);
	return STATUS_SUCCESS;
}
FLT_POSTOP_CALLBACK_STATUS MiniPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
	
	KdPrint(("post create is running \r\n"));
	return FLT_POSTOP_FINISHED_PROCESSING;
}
FLT_PREOP_CALLBACK_STATUS MiniPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
	
	PFLT_FILE_NAME_INFORMATION FileNameInfo;
	NTSTATUS status;
	WCHAR Name[280] = { 0 };
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
	
	if (NT_SUCCESS(status))
	{
		status =FltParseFileNameInformation(FileNameInfo);
		if (NT_SUCCESS(status))
		{
			if (FileNameInfo->Name.MaximumLength < 260)
			{
				RtlCopyMemory(Name, FileNameInfo->Name.Buffer, FileNameInfo->Name.MaximumLength);
				//if (!wcscmp(Name, L"\\Device\\HarddiskVolume2\\Users\\Ёльвин\\Documents\\toprotect") && )
				if (!wcscmp(Name, protection.path)&& protection.block_path==0)
				{
					//KdPrint(("Here"));
					KdPrint(("create file: %ws blocked\r\n", Name));
					Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
					Data->IoStatus.Information = 0;
					FltReleaseFileNameInformation(FileNameInfo);
					return  FLT_PREOP_COMPLETE;
					
				}
				else
				KdPrint(("create file: %ws \r\n",Name));
			}
			///////////////////
			
				//KdPrint(("isit"));
			////////////
		}
		FltReleaseFileNameInformation(FileNameInfo);
	}
	return  FLT_PREOP_SUCCESS_WITH_CALLBACK;// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Pre
}
FLT_PREOP_CALLBACK_STATUS MiniPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
	PFLT_FILE_NAME_INFORMATION FileNameInfo;
	NTSTATUS status;
	WCHAR Name[280] = { 0 };

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
	if (NT_SUCCESS(status))
	{
		status = FltParseFileNameInformation(FileNameInfo);
		if (NT_SUCCESS(status))
		{
			if (FileNameInfo->Name.MaximumLength < 260)
			{
				RtlCopyMemory(Name, FileNameInfo->Name.Buffer, FileNameInfo->Name.MaximumLength);
				_wcsupr(Name);
				_wcsupr(fname);
				if (is_read == 0)
				{
					read_file();
					is_read = 1; 
				}
				//if(wcsstr(Name,L"OPENME.TXT")!=NULL)
				if ((wcsstr(Name,fname) != NULL) && protection.write==0)
					{

					KdPrint(("write file: %ws blocked\r\n",Name));
					Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
					Data->IoStatus.Information = 0;
					FltReleaseFileNameInformation(FileNameInfo);
					return  FLT_PREOP_COMPLETE;
					}
				//KdPrint(("create file: %ws \r\n", Name));
			}
			 
		}
		FltReleaseFileNameInformation(FileNameInfo);
	}

	return  FLT_PREOP_SUCCESS_NO_CALLBACK;// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!! No Because we don't want to implement writing 
}
/*FLT_PREOP_CALLBACK_STATUS MiniPreRead(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
	PFLT_FILE_NAME_INFORMATION FileNameInfo;
	NTSTATUS status;
	WCHAR Name[280] = { 0 };

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
	if (NT_SUCCESS(status))
	{
		status = FltParseFileNameInformation(FileNameInfo);
		if (NT_SUCCESS(status))
		{
			if (FileNameInfo->Name.MaximumLength < 280)
			{
				RtlCopyMemory(Name, FileNameInfo->Name.Buffer, FileNameInfo->Name.MaximumLength);
				_wcsupr(Name);
				_wcsupr(fname);
				/*if (is_read == 0)
				{
					read_file();
					is_read = 1;
				}
				//if(wcsstr(Name,L"OPENME.TXT")!=NULL)
				if ((wcsstr(Name, fname) != NULL) && protection.read == 0)
				{

					KdPrint(("read file: %ws blocked\r\n", Name));
					Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
					Data->IoStatus.Pointer = NULL;
					Data->IoStatus.Information = 0;
					Data->Flags = FLTFL_CALLBACK_DATA_REISSUE_MASK;
					FltReleaseFileNameInformation(FileNameInfo);
					return  FLT_PREOP_COMPLETE;
				}
				//KdPrint(("create file: %ws \r\n", Name));
			}

		}
		FltReleaseFileNameInformation(FileNameInfo);
	}

	return  FLT_PREOP_SUCCESS_NO_CALLBACK;// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!! No Because we don't want to implement writing 
}*/

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	
	
	
	NTSTATUS status;
	status = FltRegisterFilter(DriverObject, &FilterRegistration, &FilterHandle);
	if (NT_SUCCESS(status))
	{
		status=FltStartFiltering(FilterHandle);
		/*if (is_read == 0)
		{
			read_file();
			is_read = 1;
		}*/
		
		//now start the filter
		if (!NT_SUCCESS(status))
		{
			//if fails - unregist 
			FltUnregisterFilter(FilterHandle);
		}
	}
	
	return status;
}