#include <ntddk.h>
#include <windef.h>
#include <intrin.h>
#pragma intrinsic(__readmsr)
//NtReadVirtualMemory函数
NTSTATUS(NTAPI* Ptr_NtReadVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	OUT PVOID               Buffer,
	IN ULONG                NumberOfBytesToRead,
	OUT PULONG              NumberOfBytesReaded);

//ssdt表结构
typedef struct _KeServiceDescriptorTable
{
	PVOID ServiceTableBase; 
	PULONG ServiceCounterTableBase; 
	ULONG NumberOfService; 
	PULONG ParamTableBase; 

}KeServiceDescriptorTable, * PKeServiceDescriptorTable;

//获取ssdt表函数
ULONGLONG Get_SSTD_Base()
{
	PUCHAR Base = (PUCHAR)__readmsr(0xC0000082);      
	PUCHAR Address = Base + 0x500; 

	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;                     
	ULONG templong = 0;
	ULONGLONG addr = 0;                              
	for (i = Base; i < Address; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *i; b2 = *(i + 1); b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15)  
			{
				memcpy(&templong, i + 3, 4);              

				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				return addr;
			}
		}
	}
	return 0;

}

//获取函数地址函数
ULONGLONG Get_Function_add(PKeServiceDescriptorTable keservicedescriptortable, DWORD index)
{
	if (keservicedescriptortable != NULL && index > 0)
	{
		PULONG tablebase = keservicedescriptortable->ServiceTableBase;
		ULONGLONG temp = tablebase[index];
		temp = temp >> 4;
		ULONGLONG funaddr = (ULONGLONG)tablebase + temp;
		return funaddr;
	}
	else
	{
		DbgPrint("获取失败");
		return 0;
	}
}

//获取进程句柄
VOID Get_Process_Handle(PHANDLE phandle,DWORD id)
{
	CLIENT_ID clientid;
	clientid.UniqueProcess = (HANDLE)id;//进程id
	clientid.UniqueThread = (HANDLE)0;

	OBJECT_ATTRIBUTES ProcAttr = { 0 };
	InitializeObjectAttributes(&ProcAttr, 0, 0, 0, 0);

	ZwOpenProcess(phandle, PROCESS_ALL_ACCESS, &ProcAttr, &clientid);
}
void Unload(PDRIVER_OBJECT driverobj)
{
	DbgPrint("卸载成功");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driverobj, PUNICODE_STRING seg_path)
{
	DbgPrint("驱动开始加载");

	//获取NtReadVirtualMemory函数
	const PKeServiceDescriptorTable servicetable = Get_SSTD_Base();
	if (servicetable == 0)
	{
		DbgPrint("获取ssdt表失败");
		return STATUS_SUCCESS;
	}
	Ptr_NtReadVirtualMemory = Get_Function_add(servicetable, 63);
	if (Ptr_NtReadVirtualMemory == 0)
	{
		DbgPrint("获取NtReadVirtualMemory错误");
		return STATUS_SUCCESS;
	}

	//获取进程句柄并读取内存
	HANDLE processhandle = NULL;
	DWORD processid = 666;//进程id
	Get_Process_Handle(&processhandle, processid);
	PVOID64 readaddr = 0x88888888;//要读取的地址
	ULONG readdata = 0;//读取到的数据
	ULONG renum = 0;//实际读取到的字节数
	(*Ptr_NtReadVirtualMemory)(processhandle, readaddr, (PVOID)&readdata, 4, &renum);
	DbgPrint("读到的数据:%d", readdata);
	driverobj->DriverUnload = Unload;
	return STATUS_SUCCESS;
}