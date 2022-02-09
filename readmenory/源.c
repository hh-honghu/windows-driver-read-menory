#include <ntddk.h>
#include <windef.h>
#include <intrin.h>
#pragma intrinsic(__readmsr)
//NtReadVirtualMemory����
NTSTATUS(NTAPI* Ptr_NtReadVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	OUT PVOID               Buffer,
	IN ULONG                NumberOfBytesToRead,
	OUT PULONG              NumberOfBytesReaded);

//ssdt��ṹ
typedef struct _KeServiceDescriptorTable
{
	PVOID ServiceTableBase; 
	PULONG ServiceCounterTableBase; 
	ULONG NumberOfService; 
	PULONG ParamTableBase; 

}KeServiceDescriptorTable, * PKeServiceDescriptorTable;

//��ȡssdt����
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

//��ȡ������ַ����
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
		DbgPrint("��ȡʧ��");
		return 0;
	}
}

//��ȡ���̾��
VOID Get_Process_Handle(PHANDLE phandle,DWORD id)
{
	CLIENT_ID clientid;
	clientid.UniqueProcess = (HANDLE)id;//����id
	clientid.UniqueThread = (HANDLE)0;

	OBJECT_ATTRIBUTES ProcAttr = { 0 };
	InitializeObjectAttributes(&ProcAttr, 0, 0, 0, 0);

	ZwOpenProcess(phandle, PROCESS_ALL_ACCESS, &ProcAttr, &clientid);
}
void Unload(PDRIVER_OBJECT driverobj)
{
	DbgPrint("ж�سɹ�");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driverobj, PUNICODE_STRING seg_path)
{
	DbgPrint("������ʼ����");

	//��ȡNtReadVirtualMemory����
	const PKeServiceDescriptorTable servicetable = Get_SSTD_Base();
	if (servicetable == 0)
	{
		DbgPrint("��ȡssdt��ʧ��");
		return STATUS_SUCCESS;
	}
	Ptr_NtReadVirtualMemory = Get_Function_add(servicetable, 63);
	if (Ptr_NtReadVirtualMemory == 0)
	{
		DbgPrint("��ȡNtReadVirtualMemory����");
		return STATUS_SUCCESS;
	}

	//��ȡ���̾������ȡ�ڴ�
	HANDLE processhandle = NULL;
	DWORD processid = 666;//����id
	Get_Process_Handle(&processhandle, processid);
	PVOID64 readaddr = 0x88888888;//Ҫ��ȡ�ĵ�ַ
	ULONG readdata = 0;//��ȡ��������
	ULONG renum = 0;//ʵ�ʶ�ȡ�����ֽ���
	(*Ptr_NtReadVirtualMemory)(processhandle, readaddr, (PVOID)&readdata, 4, &renum);
	DbgPrint("����������:%d", readdata);
	driverobj->DriverUnload = Unload;
	return STATUS_SUCCESS;
}